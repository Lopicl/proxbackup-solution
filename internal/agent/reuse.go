// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"io"
	"slices"
	"strings"

	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

// Change detection modes of a file job (api.JobSpec.ChangeDetection).
const (
	changeLegacy   = "legacy"   // pxar v1, one archive, every file read
	changeData     = "data"     // pxar v2 split archives, every file read
	changeMetadata = "metadata" // pxar v2, unchanged files reuse the previous payload chunks
)

// reusePaddingThreshold caps the bytes of reused chunks that belong to no file
// of the new archive (leftovers of changed or deleted files), as a fraction of
// the payload archive. Beyond it unchanged files are read again, so a payload
// archive doesn't keep dead data forever. proxmox-backup-client uses 10% too.
const reusePaddingThreshold = 0.1

// prevTree walks the previous snapshot's metadata archive in lockstep with the
// live tree. Both are in the same order (depth first, names sorted bytewise),
// so a lookup only ever moves forward.
type prevTree struct {
	dec  *pxar.Decoder
	cur  *pxar.Entry
	err  error // decoding failed; no further matches
	done bool
}

func newPrevTree(r io.Reader) *prevTree { return &prevTree{dec: pxar.NewDecoder(r)} }

// lookup returns the previous entry at rel ("" is the root), or nil.
func (p *prevTree) lookup(rel string) *pxar.Entry {
	for !p.done && p.err == nil {
		if p.cur == nil {
			e, err := p.dec.Next()
			if err == io.EOF {
				p.done = true
				return nil
			}
			if err != nil {
				p.err = err
				return nil
			}
			p.cur = e
		}
		switch c := comparePaths(p.cur.Path, rel); {
		case c == 0:
			return p.cur
		case c > 0:
			return nil
		}
		p.cur = nil
	}
	return nil
}

// comparePaths orders slash separated paths depth first: component by
// component, a directory before its contents.
func comparePaths(a, b string) int {
	for {
		if a == "" || b == "" {
			return len(a) - len(b)
		}
		ah, at, _ := strings.Cut(a, "/")
		bh, bt, _ := strings.Cut(b, "/")
		if c := strings.Compare(ah, bh); c != 0 {
			return c
		}
		a, b = at, bt
	}
}

// unchanged reports whether a file's previous entry matches its live metadata
// and size, so its contents can be taken from the previous payload archive.
func unchanged(prev *pxar.Entry, m pxar.Metadata, size uint64) bool {
	if prev == nil || prev.Kind != pxar.KindFile || !prev.PayloadRef || prev.Size != size {
		return false
	}
	p := prev.Meta
	if p.Mode != m.Mode || p.Flags != m.Flags || p.UID != m.UID || p.GID != m.GID ||
		p.MtimeSecs != m.MtimeSecs || p.MtimeNanos != m.MtimeNanos || len(p.Xattrs) != len(m.Xattrs) {
		return false
	}
	byName := func(a, b pxar.Xattr) int { return bytes.Compare(a.Name, b.Name) }
	px, mx := slices.SortedFunc(slices.Values(p.Xattrs), byName), slices.SortedFunc(slices.Values(m.Xattrs), byName)
	return slices.EqualFunc(px, mx, func(a, b pxar.Xattr) bool {
		return bytes.Equal(a.Name, b.Name) && bytes.Equal(a.Value, b.Value)
	})
}

// chunkInjector is the payload archive writer (*pbs.ArchiveWriter).
type chunkInjector interface {
	InjectChunks([]pbs.IndexEntry) error
}

// Limits of a pending range, so memory stays bounded and a range that ends
// up re-read isn't huge.
const (
	maxRangeChunks = 64
	maxRangeOps    = 1 << 16
)

// payloadReuse takes the contents of unchanged files from the previous
// payload archive.
//
// Unchanged files that sit next to each other in the previous payload archive
// are collected into a range, with the entries around them queued as encoder
// operations. When the range ends (a file must be read, the next unchanged
// file is elsewhere, or a limit is hit), the chunks covering it are injected
// into the new payload archive and the files point into them. Chunk bytes no
// file of the range uses are padding (leftovers of changed or deleted files);
// if they exceed reusePaddingThreshold of the range, its files are read and
// encoded again instead, which drops that padding for good. proxmox-backup-
// client decides the same way.
type payloadReuse struct {
	w    chunkInjector
	enc  *pxar.Encoder
	prev *pbs.Index

	// The pending range: queued operations, its files, the previous chunks
	// they lie in (from is the first one to inject; earlier ones were injected
	// by the chain), and their payload bytes in total and before chunk from.
	ops              []func(reuse bool) error
	files            int
	from, last       int
	usedEnd          uint64 // previous offset after the range's last file
	used, usedBefore uint64
	first            int    // first chunk of the chain the range belongs to
	base             uint64 // new offset of chunk first

	// The chain: chunks first..chainLast were injected back to back, and the
	// payload stream hasn't moved since, so the next range can point into
	// them too instead of injecting a boundary chunk twice.
	chain        bool
	chainLast    int
	chainUsedEnd uint64

	// Totals for the log.
	reusedFiles, reusedBytes, chunks, waste, rereadFiles uint64
}

func (r *payloadReuse) pending() bool { return len(r.ops) > 0 }

// do runs op now, or queues it behind a pending range. Operations that write
// to the payload stream must call flush first instead.
func (r *payloadReuse) do(op func() error) error {
	if !r.pending() {
		return op()
	}
	r.ops = append(r.ops, func(bool) error { return op() })
	return nil
}

func (r *payloadReuse) chainValid() bool {
	ents := r.prev.Entries
	return r.chain && r.enc.PayloadPosition() == r.base+ents[r.chainLast].End-ents[r.first].Start
}

// queue adds an unchanged file whose PAYLOAD item is at prevOffset in the
// previous payload archive. op is run when the range is decided: with reuse
// it calls ref, otherwise it encodes the file from disk. It returns false
// (and queues nothing) when the previous archive doesn't hold the file.
func (r *payloadReuse) queue(prevOffset, size uint64, op func(reuse bool) error) (bool, error) {
	start, end := prevOffset, prevOffset+pxar.HeaderSize+size
	if end > r.prev.Size || end < start {
		return false, nil
	}
	s, _ := r.prev.Find(start)
	e, _ := r.prev.Find(end - 1)
	if r.pending() && (start < r.usedEnd || s > r.last+1 || e-r.from >= maxRangeChunks || len(r.ops) >= maxRangeOps) {
		if err := r.flush(); err != nil {
			return false, err
		}
	}
	if r.files == 0 {
		if r.chainValid() && start >= r.chainUsedEnd && s <= r.chainLast+1 {
			r.from, r.last = r.chainLast+1, r.chainLast
		} else {
			r.chain = false
			r.first, r.from, r.last = s, s, s
		}
	}
	r.last = max(r.last, e)
	// Bytes in chunks the chain already injected are not part of this range's span.
	boundary := r.prev.Size
	if r.from < len(r.prev.Entries) {
		boundary = r.prev.Entries[r.from].Start
	}
	if start < boundary {
		r.usedBefore += min(end, boundary) - start
	}
	r.usedEnd = end
	r.used += end - start
	r.files++
	r.ops = append(r.ops, op)
	return true, nil
}

// flush decides the pending range and runs its queued operations.
func (r *payloadReuse) flush() error {
	if !r.pending() {
		return nil
	}
	ops, files, total := r.ops, r.files, r.used
	used := r.used - r.usedBefore
	r.ops, r.files, r.used, r.usedBefore = nil, 0, 0, 0
	var reuse bool
	if files > 0 {
		var ents []pbs.IndexEntry
		var span uint64
		if r.last >= r.from {
			ents = r.prev.Entries[r.from : r.last+1]
			span = ents[len(ents)-1].End - ents[0].Start
		}
		padding := span - used
		if reuse = float64(padding) <= reusePaddingThreshold*float64(span); reuse {
			if !r.chain {
				// InjectChunks ends the current chunk; the stream position doesn't move.
				r.base = r.enc.PayloadPosition()
			}
			if len(ents) > 0 {
				if err := r.w.InjectChunks(ents); err != nil {
					return err
				}
				if err := r.enc.SkipPayload(span); err != nil {
					return err
				}
				r.chainLast = r.last
			}
			r.chain, r.chainUsedEnd = true, r.usedEnd
			r.reusedFiles += uint64(files)
			r.reusedBytes += total
			r.chunks += uint64(len(ents))
			r.waste += padding
		} else {
			r.chain = false
			r.rereadFiles += uint64(files)
		}
	}
	r.usedEnd = 0
	for _, op := range ops {
		if err := op(reuse); err != nil {
			return err
		}
	}
	return nil
}

// ref adds a queued file as a reference into the injected range.
func (r *payloadReuse) ref(name []byte, m pxar.Metadata, size, prevOffset uint64) error {
	return r.enc.AddPayloadRef(name, m, size, r.base+prevOffset-r.prev.Entries[r.first].Start)
}
