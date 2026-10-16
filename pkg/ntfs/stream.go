// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfs

import (
	"errors"
	"fmt"
	"io"
	"sort"
)

// ErrNoStream is returned when a file has no data stream of the requested name.
var ErrNoStream = errors.New("ntfs: no such data stream")

// run maps length clusters starting at vcn to lcn; lcn < 0 marks a sparse run.
type run struct{ vcn, lcn, n int64 }

// decodeRuns decodes a mapping-pairs array (runlist).
func decodeRuns(b []byte, vcn int64) ([]run, error) {
	var runs []run
	var lcn int64
	for len(b) > 0 && b[0] != 0 {
		nl, no := int(b[0]&0xF), int(b[0]>>4)
		if nl == 0 || nl > 8 || no > 8 || 1+nl+no > len(b) {
			return nil, errors.New("ntfs: bad runlist")
		}
		n := int64(leUint(b[1 : 1+nl]))
		r := run{vcn: vcn, n: n, lcn: -1}
		if no > 0 {
			lcn += leInt(b[1+nl : 1+nl+no])
			if lcn < 0 {
				return nil, errors.New("ntfs: negative LCN in runlist")
			}
			r.lcn = lcn
		}
		if n <= 0 {
			return nil, errors.New("ntfs: bad run length")
		}
		runs = append(runs, r)
		vcn += n
		b = b[1+nl+no:]
	}
	return runs, nil
}

func leUint(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func leInt(b []byte) int64 {
	v := int64(leUint(b))
	shift := uint(64 - 8*len(b))
	return v << shift >> shift // sign-extend
}

// Stream is one attribute's contents (a data stream or an index allocation).
// It implements io.ReaderAt and is not safe for concurrent use.
type Stream struct {
	v        *Volume
	resident []byte
	isRes    bool
	size     int64
	initSize int64
	runs     []run
	unit     int64 // compression unit in bytes, 0 if not compressed

	cacheIdx int64
	cache    []byte
}

// Size returns the stream's logical size in bytes.
func (s *Stream) Size() int64 { return s.size }

// stream assembles the attribute typ/name from all its extents.
func (v *Volume) stream(attrs []*attribute, typ uint32, name string) (*Stream, error) {
	var ext []*attribute
	for _, a := range attrs {
		if a.typ == typ && a.name == name {
			ext = append(ext, a)
		}
	}
	if len(ext) == 0 {
		return nil, ErrNoStream
	}
	return v.newStream(ext)
}

func (v *Volume) newStream(ext []*attribute) (*Stream, error) {
	if ext[0].resident {
		return &Stream{v: v, isRes: true, resident: ext[0].value, size: int64(len(ext[0].value)), cacheIdx: -1}, nil
	}
	sort.Slice(ext, func(i, j int) bool { return ext[i].startVCN < ext[j].startVCN })
	first := ext[0]
	if first.startVCN != 0 {
		return nil, errors.New("ntfs: first attribute extent missing")
	}
	s := &Stream{v: v, size: first.dataSize, initSize: min(first.initSize, first.dataSize), cacheIdx: -1}
	for _, a := range ext {
		if a.resident {
			return nil, errors.New("ntfs: mixed resident and non-resident extents")
		}
		s.runs = append(s.runs, a.runs...)
	}
	if first.flags&attrFlagCompressed != 0 && first.compUnit > 0 {
		s.unit = v.clusterSize << first.compUnit
	}
	if s.size < 0 || s.initSize < 0 {
		return nil, errors.New("ntfs: bad stream size")
	}
	return s, nil
}

// ReadAt implements io.ReaderAt.
func (s *Stream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("ntfs: negative offset")
	}
	if off >= s.size {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), s.size-off))
	var err error
	switch {
	case s.isRes:
		copy(p, s.resident[off:])
	case s.unit > 0:
		err = s.readCompressed(p[:n], off)
	default:
		err = s.readValid(p[:n], off)
	}
	if err != nil {
		return 0, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// readValid reads p at off, returning zeros past the initialized size.
func (s *Stream) readValid(p []byte, off int64) error {
	if off+int64(len(p)) > s.initSize {
		valid := max(s.initSize-off, 0)
		clear(p[valid:])
		p = p[:valid]
	}
	return s.readRaw(p, off)
}

// readRaw reads p at off by mapping clusters through the runlist.
func (s *Stream) readRaw(p []byte, off int64) error {
	cs := s.v.clusterSize
	for len(p) > 0 {
		vcn := off / cs
		i := sort.Search(len(s.runs), func(i int) bool { return s.runs[i].vcn+s.runs[i].n > vcn })
		if i == len(s.runs) || s.runs[i].vcn > vcn {
			return fmt.Errorf("ntfs: VCN %d not mapped", vcn)
		}
		r := s.runs[i]
		n := int(min(int64(len(p)), (r.vcn+r.n)*cs-off))
		if r.lcn < 0 {
			clear(p[:n])
		} else if _, err := s.v.r.ReadAt(p[:n], (r.lcn+vcn-r.vcn)*cs+off%cs); err != nil {
			return err
		}
		p, off = p[n:], off+int64(n)
	}
	return nil
}

func (s *Stream) readCompressed(p []byte, off int64) error {
	for len(p) > 0 {
		idx := off / s.unit
		if idx != s.cacheIdx {
			if err := s.loadUnit(idx); err != nil {
				return err
			}
		}
		n := copy(p, s.cache[off-idx*s.unit:])
		p, off = p[n:], off+int64(n)
	}
	return nil
}

// loadUnit decodes compression unit idx into the cache. A unit is stored
// sparse (all zeros), as is (fully allocated) or LZNT1-compressed in its
// leading clusters with the rest sparse.
func (s *Stream) loadUnit(idx int64) error {
	cs := s.v.clusterSize
	clusters := s.unit / cs
	start := idx * clusters
	var alloc int64
	for _, r := range s.runs {
		lo, hi := max(r.vcn, start), min(r.vcn+r.n, start+clusters)
		if lo < hi && r.lcn >= 0 {
			alloc += hi - lo
		}
	}
	if s.cache == nil {
		s.cache = make([]byte, s.unit)
	}
	s.cacheIdx = -1
	unitOff := idx * s.unit
	switch {
	case alloc == 0:
		clear(s.cache)
	case alloc == clusters:
		if err := s.readRaw(s.cache, unitOff); err != nil {
			return err
		}
	default:
		comp := make([]byte, alloc*cs)
		if err := s.readRaw(comp, unitOff); err != nil {
			return err
		}
		n, err := lznt1Decompress(s.cache, comp)
		if err != nil {
			return fmt.Errorf("compression unit %d: %w", idx, err)
		}
		clear(s.cache[n:])
	}
	if v := s.initSize - unitOff; v < s.unit {
		clear(s.cache[max(v, 0):])
	}
	s.cacheIdx = idx
	return nil
}

// lznt1Decompress decodes an LZNT1 buffer into dst and returns the bytes written.
func lznt1Decompress(dst, src []byte) (int, error) {
	out := 0
	for len(src) >= 2 {
		h := int(src[0]) | int(src[1])<<8
		if h == 0 {
			break
		}
		size := h&0xFFF + 1
		if 2+size > len(src) {
			return out, errors.New("ntfs: truncated LZNT1 chunk")
		}
		chunk := src[2 : 2+size]
		src = src[2+size:]
		const chunkSize = 4096
		base := out
		end := min(out+chunkSize, len(dst))
		if h&0x8000 == 0 {
			out += copy(dst[out:end], chunk)
		} else if err := lznt1Chunk(dst[:end], chunk, &out, base); err != nil {
			return out, err
		}
		if len(src) >= 2 && (src[0] != 0 || src[1] != 0) && out < end {
			clear(dst[out:end])
			out = end
		}
	}
	return out, nil
}

// lznt1Chunk decodes one compressed chunk into dst[*out:], with the chunk's
// output starting at base.
func lznt1Chunk(dst, chunk []byte, out *int, base int) error {
	end := len(dst)
	for len(chunk) > 0 && *out < end {
		flags := chunk[0]
		chunk = chunk[1:]
		for bit := 0; bit < 8 && len(chunk) > 0 && *out < end; bit++ {
			if flags&(1<<bit) == 0 {
				dst[*out] = chunk[0]
				*out++
				chunk = chunk[1:]
				continue
			}
			if len(chunk) < 2 {
				return errors.New("ntfs: truncated LZNT1 token")
			}
			tok := int(chunk[0]) | int(chunk[1])<<8
			chunk = chunk[2:]
			pos := *out - base
			lenMask, offShift := 0xFFF, 12
			for p := pos - 1; p >= 0x10; p >>= 1 {
				lenMask >>= 1
				offShift--
			}
			back := tok>>offShift + 1
			n := tok&lenMask + 3
			if back > pos {
				return errors.New("ntfs: bad LZNT1 back-reference")
			}
			for k := 0; k < n && *out < end; k++ { // may overlap: copy bytewise
				dst[*out] = dst[*out-back]
				*out++
			}
		}
	}
	return nil
}
