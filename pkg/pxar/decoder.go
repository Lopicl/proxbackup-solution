// SPDX-License-Identifier: AGPL-3.0-or-later

package pxar

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
)

// Kind is the type of a decoded entry.
type Kind int

const (
	KindDir Kind = iota
	KindFile
	KindSymlink
	KindHardlink
	KindDevice
	KindFifo
	KindSocket
)

func (k Kind) String() string {
	return [...]string{"dir", "file", "symlink", "hardlink", "device", "fifo", "socket"}[k]
}

// Entry is one decoded archive member.
type Entry struct {
	Path   string // slash separated, "" for the archive root
	Kind   Kind
	Meta   Metadata
	Size   uint64 // file size
	Target string // symlink / hardlink target
}

// Decoder reads a pxar archive sequentially.
type Decoder struct {
	r       *bufio.Reader
	pos     uint64
	dirs    []string // path stack; len 0 before root
	pending []byte   // FILENAME seen, waiting for its ENTRY
	payload int64    // unread payload bytes of the current file
	started bool
	done    bool
}

// NewDecoder creates a decoder over r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: bufio.NewReaderSize(r, 256<<10)}
}

func (d *Decoder) readFull(b []byte) error {
	n, err := io.ReadFull(d.r, b)
	d.pos += uint64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (d *Decoder) skip(n int64) error {
	k, err := io.CopyN(io.Discard, d.r, n)
	d.pos += uint64(k)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (d *Decoder) header() (uint64, uint64, error) {
	var h [headerSize]byte
	if err := d.readFull(h[:]); err != nil {
		return 0, 0, err
	}
	t := binary.LittleEndian.Uint64(h[0:])
	size := binary.LittleEndian.Uint64(h[8:])
	if size < headerSize {
		return 0, 0, fmt.Errorf("pxar: bad item size %d at %d", size, d.pos-headerSize)
	}
	return t, size - headerSize, nil
}

func (d *Decoder) content(n uint64, limit int) ([]byte, error) {
	if n > uint64(limit) {
		return nil, fmt.Errorf("pxar: item too large (%d bytes)", n)
	}
	b := make([]byte, n)
	return b, d.readFull(b)
}

// Contents returns a reader for the current file's data. It must be consumed
// (or ignored) before calling Next again.
func (d *Decoder) Contents() io.Reader { return &payloadReader{d} }

type payloadReader struct{ d *Decoder }

func (p *payloadReader) Read(b []byte) (int, error) {
	if p.d.payload <= 0 {
		return 0, io.EOF
	}
	if int64(len(b)) > p.d.payload {
		b = b[:p.d.payload]
	}
	n, err := p.d.r.Read(b)
	p.d.pos += uint64(n)
	p.d.payload -= int64(n)
	if err == io.EOF && p.d.payload > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// Next returns the next entry, or io.EOF at the end of the archive.
func (d *Decoder) Next() (*Entry, error) {
	if d.done {
		return nil, io.EOF
	}
	if d.payload > 0 {
		if err := d.skip(d.payload); err != nil {
			return nil, err
		}
		d.payload = 0
	}
	for {
		t, n, err := d.header()
		if err != nil {
			if !d.started && errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, io.EOF
			}
			return nil, err
		}
		switch t {
		case TypeFormatVersion:
			b, err := d.content(n, 8)
			if err != nil {
				return nil, err
			}
			if len(b) != 8 || binary.LittleEndian.Uint64(b) != 2 {
				return nil, errors.New("pxar: unsupported format version")
			}
			return nil, errors.New("pxar: split (v2) archives are not supported yet")
		case TypeFilename:
			b, err := d.content(n, maxFilenameLen+1)
			if err != nil {
				return nil, err
			}
			if len(b) == 0 || b[len(b)-1] != 0 {
				return nil, errors.New("pxar: filename not NUL terminated")
			}
			name := b[:len(b)-1]
			if err := ValidateFilename(name); err != nil {
				return nil, err
			}
			d.pending = name
		case TypeEntry:
			if n != entrySize {
				return nil, fmt.Errorf("pxar: bad entry size %d", n)
			}
			return d.entry()
		case TypeHardlink:
			// hardlink entries have no ENTRY: FILENAME HARDLINK{offset u64, target\0}
			b, err := d.content(n, maxFilenameLen*4)
			if err != nil {
				return nil, err
			}
			if len(b) < 9 {
				return nil, errors.New("pxar: short hardlink")
			}
			e := &Entry{Path: d.childPath(), Kind: KindHardlink, Target: string(bytes.TrimRight(b[8:], "\x00"))}
			d.pending = nil
			return e, nil
		case TypeGoodbye:
			if err := d.skip(int64(n)); err != nil {
				return nil, err
			}
			if len(d.dirs) == 0 {
				return nil, errors.New("pxar: unexpected goodbye")
			}
			d.dirs = d.dirs[:len(d.dirs)-1]
			if len(d.dirs) == 0 {
				d.done = true
				return nil, io.EOF
			}
		default:
			return nil, fmt.Errorf("pxar: unexpected item %#x at offset %d", t, d.pos-headerSize)
		}
	}
}

func (d *Decoder) childPath() string {
	if len(d.dirs) == 0 {
		return ""
	}
	return path.Join(d.dirs[len(d.dirs)-1], string(d.pending))
}

func (d *Decoder) entry() (*Entry, error) {
	var b [entrySize]byte
	if err := d.readFull(b[:]); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	e := &Entry{Meta: Metadata{
		Mode:       le.Uint64(b[0:]),
		Flags:      le.Uint64(b[8:]),
		UID:        le.Uint32(b[16:]),
		GID:        le.Uint32(b[20:]),
		MtimeSecs:  int64(le.Uint64(b[24:])),
		MtimeNanos: le.Uint32(b[32:]),
	}}
	if d.started && d.pending == nil {
		return nil, errors.New("pxar: entry without filename")
	}
	e.Path = d.childPath()
	d.pending = nil
	d.started = true

	// Metadata items until the type-specific item (or directory contents).
	for {
		peek, err := d.r.Peek(headerSize)
		if err != nil {
			return nil, fmt.Errorf("pxar: truncated entry %q: %w", e.Path, io.ErrUnexpectedEOF)
		}
		t := le.Uint64(peek)
		switch t {
		case TypeXattr:
			_, n, _ := d.header()
			data, err := d.content(n, maxXattrLen)
			if err != nil {
				return nil, err
			}
			i := bytes.IndexByte(data, 0)
			if i <= 0 {
				return nil, errors.New("pxar: malformed xattr")
			}
			e.Meta.Xattrs = append(e.Meta.Xattrs, Xattr{Name: data[:i], Value: data[i+1:]})
		case TypeACLUser, TypeACLGroup, TypeACLGroupObj, TypeACLDefault, TypeACLDefaultUser,
			TypeACLDefaultGroup, TypeFCaps, TypeQuotaProjID:
			_, n, _ := d.header()
			if err := d.skip(int64(n)); err != nil {
				return nil, err
			}
		case TypePayload:
			_, n, _ := d.header()
			e.Kind, e.Size = KindFile, n
			d.payload = int64(n)
			return e, nil
		case TypeSymlink:
			_, n, _ := d.header()
			data, err := d.content(n, maxSymlinkLen+1)
			if err != nil {
				return nil, err
			}
			e.Kind, e.Target = KindSymlink, string(bytes.TrimRight(data, "\x00"))
			return e, nil
		case TypeDevice:
			_, n, _ := d.header()
			if err := d.skip(int64(n)); err != nil {
				return nil, err
			}
			e.Kind = KindDevice
			return e, nil
		default:
			switch e.Meta.Mode & ModeIFMT {
			case ModeIFDIR:
				e.Kind = KindDir
				d.dirs = append(d.dirs, e.Path)
			case ModeIFIFO:
				e.Kind = KindFifo
			case ModeIFSOCK:
				e.Kind = KindSocket
			case ModeIFREG:
				e.Kind = KindFile // empty file without payload item is not produced by pxar, but be lenient
			default:
				return nil, fmt.Errorf("pxar: entry %q has unexpected item %#x", e.Path, t)
			}
			return e, nil
		}
	}
}
