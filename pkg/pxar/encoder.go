// SPDX-License-Identifier: AGPL-3.0-or-later

package pxar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
)

// Encoder writes a pxar archive to a sequential stream: a v1 archive
// (NewEncoder), or the metadata and payload streams of a v2 split archive
// (NewSplitEncoder).
//
// Usage: NewEncoder(root) → CreateDir/AddFile/AddSymlink/FinishDir … → Close.
// Children of a directory must be added in strictly ascending byte order of name.
type Encoder struct {
	w     io.Writer
	pos   uint64
	stack []*dirState
	buf   []byte
	err   error

	// Split archives only: the payload stream, its position, and the end of
	// the last payload referenced (references must not go backwards, so
	// sequential readers can follow them).
	payload    io.Writer
	ppos       uint64
	lastRefEnd uint64
}

type dirState struct {
	entryOffset uint64 // start of this directory's ENTRY
	fileOffset  uint64 // start of this directory's FILENAME (unused for root)
	name        []byte
	items       []goodbyeItem
	lastName    []byte
}

// NewEncoder starts a v1 archive whose root directory has metadata root.
func NewEncoder(w io.Writer, root Metadata) (*Encoder, error) {
	return newEncoder(w, nil, root)
}

// NewSplitEncoder starts a v2 split archive: the entry tree goes to meta, file
// contents to payload.
func NewSplitEncoder(meta, payload io.Writer, root Metadata) (*Encoder, error) {
	if payload == nil {
		return nil, errors.New("pxar: split archive needs a payload stream")
	}
	return newEncoder(meta, payload, root)
}

func newEncoder(w, payload io.Writer, root Metadata) (*Encoder, error) {
	if !root.IsDir() {
		return nil, errors.New("pxar: root metadata must be a directory")
	}
	e := &Encoder{w: w, payload: payload, buf: make([]byte, 0, 256)}
	if payload != nil {
		var v [8]byte
		binary.LittleEndian.PutUint64(v[:], formatVersion2)
		if err := e.writeItem(TypeFormatVersion, v[:], false); err != nil {
			return nil, err
		}
		var h [headerSize]byte
		putHeader(h[:], TypePayloadStart, headerSize)
		if err := e.writePayload(h[:]); err != nil {
			return nil, err
		}
		e.lastRefEnd = e.ppos
	}
	// The root's goodbye tail points at offset 0 even in v2 archives, i.e. at
	// FORMAT_VERSION rather than the root ENTRY (as pxar's encoder does).
	e.stack = append(e.stack, &dirState{entryOffset: 0})
	if err := e.writeMetadata(root); err != nil {
		return nil, err
	}
	return e, nil
}

// Position returns the number of bytes written so far (to the metadata stream
// of a split archive).
func (e *Encoder) Position() uint64 { return e.pos }

// PayloadPosition returns the size of the payload stream so far (split archives).
func (e *Encoder) PayloadPosition() uint64 { return e.ppos }

func (e *Encoder) write(p []byte) error { return e.writeTo(e.w, &e.pos, p) }

func (e *Encoder) writePayload(p []byte) error { return e.writeTo(e.payload, &e.ppos, p) }

func (e *Encoder) writeTo(w io.Writer, pos *uint64, p []byte) error {
	if e.err != nil {
		return e.err
	}
	n, err := w.Write(p)
	*pos += uint64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	e.err = err
	return err
}

func (e *Encoder) writeItem(htype uint64, data []byte, nul bool) error {
	size := uint64(headerSize + len(data))
	if nul {
		size++
	}
	b := e.buf[:headerSize]
	putHeader(b, htype, size)
	b = append(b, data...)
	if nul {
		b = append(b, 0)
	}
	e.buf = b[:0]
	return e.write(b)
}

func (e *Encoder) writeMetadata(m Metadata) error {
	var b [headerSize + entrySize]byte
	putHeader(b[:], TypeEntry, headerSize+entrySize)
	le := binary.LittleEndian
	le.PutUint64(b[16:], m.Mode)
	le.PutUint64(b[24:], m.Flags)
	le.PutUint32(b[32:], m.UID)
	le.PutUint32(b[36:], m.GID)
	le.PutUint64(b[40:], uint64(m.MtimeSecs))
	le.PutUint32(b[48:], m.MtimeNanos)
	if err := e.write(b[:]); err != nil {
		return err
	}
	xattrs := slices.Clone(m.Xattrs)
	slices.SortFunc(xattrs, func(a, b Xattr) int { return bytes.Compare(a.Name, b.Name) })
	for _, x := range xattrs {
		if len(x.Name) == 0 || bytes.IndexByte(x.Name, 0) >= 0 {
			return fmt.Errorf("pxar: invalid xattr name %q", x.Name)
		}
		data := make([]byte, 0, len(x.Name)+1+len(x.Value))
		data = append(append(append(data, x.Name...), 0), x.Value...)
		if len(data) > maxXattrLen {
			return fmt.Errorf("pxar: xattr %q too large", x.Name)
		}
		if err := e.writeItem(TypeXattr, data, false); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFilename applies the same rules as pxar's validate_filename.
func ValidateFilename(name []byte) error {
	switch {
	case len(name) == 0:
		return errors.New("pxar: empty file name")
	case bytes.IndexByte(name, '/') >= 0:
		return fmt.Errorf("pxar: file name %q contains '/'", name)
	case bytes.IndexByte(name, 0) >= 0:
		return fmt.Errorf("pxar: file name %q contains NUL", name)
	case string(name) == "." || string(name) == "..":
		return fmt.Errorf("pxar: illegal file name %q", name)
	case len(name) >= maxFilenameLen:
		return fmt.Errorf("pxar: file name too long (%d bytes)", len(name))
	}
	return nil
}

func (e *Encoder) cur() (*dirState, error) {
	if e.err != nil {
		return nil, e.err
	}
	if len(e.stack) == 0 {
		return nil, errors.New("pxar: encoder already closed")
	}
	return e.stack[len(e.stack)-1], nil
}

// startEntry writes FILENAME + ENTRY and returns the FILENAME offset.
func (e *Encoder) startEntry(name []byte, m Metadata) (*dirState, uint64, error) {
	d, err := e.cur()
	if err != nil {
		return nil, 0, err
	}
	if err := ValidateFilename(name); err != nil {
		return nil, 0, err
	}
	if d.lastName != nil && bytes.Compare(name, d.lastName) <= 0 {
		return nil, 0, fmt.Errorf("pxar: entries out of order (%q after %q)", name, d.lastName)
	}
	d.lastName = append(d.lastName[:0], name...)
	off := e.pos
	if err := e.writeItem(TypeFilename, name, true); err != nil {
		return nil, 0, err
	}
	if err := e.writeMetadata(m); err != nil {
		return nil, 0, err
	}
	return d, off, nil
}

// FileResult reports how the file contents matched the declared size.
type FileResult struct {
	// Short is true when the reader returned less than size bytes (zero padded).
	Short bool
	// Grew is true when the reader had more than size bytes (truncated).
	Grew bool
}

// AddFile adds a regular file of exactly size bytes read from r. In a split
// archive the contents go to the payload stream.
func (e *Encoder) AddFile(name []byte, m Metadata, size uint64, r io.Reader) (FileResult, error) {
	var res FileResult
	m.Mode = m.Mode&^ModeIFMT | ModeIFREG
	d, off, err := e.startEntry(name, m)
	if err != nil {
		return res, err
	}
	var h [headerSize]byte
	putHeader(h[:], TypePayload, headerSize+size)
	out := e.write
	if e.payload != nil {
		out = e.writePayload
		if err := e.writePayloadRef(e.ppos, size); err != nil {
			return res, err
		}
		e.lastRefEnd = e.ppos + headerSize + size
	}
	if err := out(h[:]); err != nil {
		return res, err
	}
	// The goodbye item covers the metadata stream only; e.pos doesn't move
	// while a split archive's contents are written.
	n, err := io.Copy(encWriter(out), io.LimitReader(r, int64(size)))
	if err != nil {
		if e.err != nil {
			return res, e.err
		}
		// Read error: keep the archive consistent by zero padding, report the error.
		if perr := e.pad(out, size-uint64(n)); perr != nil {
			return res, perr
		}
		d.items = append(d.items, goodbyeItem{HashFilename(name), off, e.pos - off})
		return FileResult{Short: true}, fmt.Errorf("pxar: reading %q: %w", name, err)
	}
	if uint64(n) < size {
		res.Short = true
		if err := e.pad(out, size-uint64(n)); err != nil {
			return res, err
		}
	} else {
		var one [1]byte
		if k, _ := r.Read(one[:]); k > 0 {
			res.Grew = true
		}
	}
	d.items = append(d.items, goodbyeItem{HashFilename(name), off, e.pos - off})
	return res, nil
}

func (e *Encoder) writePayloadRef(offset, size uint64) error {
	var ref [payloadRefSize]byte
	binary.LittleEndian.PutUint64(ref[0:], offset)
	binary.LittleEndian.PutUint64(ref[8:], size)
	return e.writeItem(TypePayloadRef, ref[:], false)
}

// SkipPayload records that n bytes were appended to the payload stream
// outside the encoder, e.g. chunks of a previous payload archive reused as is.
func (e *Encoder) SkipPayload(n uint64) error {
	if e.payload == nil {
		return errors.New("pxar: SkipPayload on a v1 archive")
	}
	e.ppos += n
	return nil
}

// AddPayloadRef adds a regular file whose PAYLOAD item (header and size bytes
// of contents) is already in the payload stream at offset, typically inside
// chunks reused with SkipPayload. References must be in stream order.
func (e *Encoder) AddPayloadRef(name []byte, m Metadata, size, offset uint64) error {
	if e.payload == nil {
		return errors.New("pxar: payload references need a split archive")
	}
	if offset < e.lastRefEnd || offset+headerSize+size > e.ppos {
		return fmt.Errorf("pxar: payload reference %d+%d outside [%d, %d)", offset, size, e.lastRefEnd, e.ppos)
	}
	m.Mode = m.Mode&^ModeIFMT | ModeIFREG
	d, off, err := e.startEntry(name, m)
	if err != nil {
		return err
	}
	if err := e.writePayloadRef(offset, size); err != nil {
		return err
	}
	e.lastRefEnd = offset + headerSize + size
	d.items = append(d.items, goodbyeItem{HashFilename(name), off, e.pos - off})
	return nil
}

func (e *Encoder) pad(out func([]byte) error, n uint64) error {
	zero := make([]byte, min(n, 1<<20))
	for n > 0 {
		k := min(n, uint64(len(zero)))
		if err := out(zero[:k]); err != nil {
			return err
		}
		n -= k
	}
	return nil
}

type encWriter func([]byte) error

func (w encWriter) Write(p []byte) (int, error) {
	if err := w(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// AddSymlink adds a symbolic link pointing to target.
func (e *Encoder) AddSymlink(name []byte, m Metadata, target []byte) error {
	if len(target) == 0 || len(target) >= maxSymlinkLen || bytes.IndexByte(target, 0) >= 0 {
		return fmt.Errorf("pxar: invalid symlink target %q", target)
	}
	m.Mode = m.Mode&^ModeIFMT | ModeIFLNK
	d, off, err := e.startEntry(name, m)
	if err != nil {
		return err
	}
	if err := e.writeItem(TypeSymlink, target, true); err != nil {
		return err
	}
	d.items = append(d.items, goodbyeItem{HashFilename(name), off, e.pos - off})
	return nil
}

// CreateDir starts a subdirectory; call FinishDir when its contents are written.
func (e *Encoder) CreateDir(name []byte, m Metadata) error {
	m.Mode = m.Mode&^ModeIFMT | ModeIFDIR
	_, off, err := e.startEntry(name, m)
	if err != nil {
		return err
	}
	e.stack = append(e.stack, &dirState{
		entryOffset: off + uint64(headerSize+len(name)+1), // ENTRY follows the FILENAME item
		fileOffset:  off,
		name:        bytes.Clone(name),
	})
	return nil
}

// FinishDir writes the goodbye table of the current directory.
func (e *Encoder) FinishDir() error {
	if len(e.stack) <= 1 {
		return errors.New("pxar: FinishDir without matching CreateDir (use Close for the root)")
	}
	return e.finishCurrent()
}

// Close finishes the root directory. The archive is complete afterwards.
func (e *Encoder) Close() error {
	if len(e.stack) != 1 {
		return fmt.Errorf("pxar: %d directories not finished", len(e.stack)-1)
	}
	if err := e.finishCurrent(); err != nil {
		return err
	}
	if e.payload != nil {
		var h [headerSize]byte
		putHeader(h[:], TypePayloadTail, headerSize)
		return e.writePayload(h[:])
	}
	return nil
}

func (e *Encoder) finishCurrent() error {
	d, err := e.cur()
	if err != nil {
		return err
	}
	goodbyeOffset := e.pos
	items := d.items
	slices.SortFunc(items, func(a, b goodbyeItem) int {
		switch {
		case a.hash < b.hash:
			return -1
		case a.hash > b.hash:
			return 1
		}
		return 0
	})
	tableSize := uint64(len(items)+1) * goodbyeItemSize
	out := make([]byte, headerSize+tableSize)
	putHeader(out, TypeGoodbye, headerSize+tableSize)
	le := binary.LittleEndian
	bstPermute(len(items), func(src, dst int) {
		it := items[src]
		p := out[headerSize+dst*goodbyeItemSize:]
		le.PutUint64(p[0:], it.hash)
		le.PutUint64(p[8:], goodbyeOffset-it.offset)
		le.PutUint64(p[16:], it.size)
	})
	tail := out[headerSize+len(items)*goodbyeItemSize:]
	le.PutUint64(tail[0:], GoodbyeTailMarker)
	le.PutUint64(tail[8:], goodbyeOffset-d.entryOffset)
	le.PutUint64(tail[16:], headerSize+tableSize)
	if err := e.write(out); err != nil {
		return err
	}
	e.stack = e.stack[:len(e.stack)-1]
	if len(e.stack) > 0 {
		parent := e.stack[len(e.stack)-1]
		parent.items = append(parent.items, goodbyeItem{HashFilename(d.name), d.fileOffset, e.pos - d.fileOffset})
	}
	return nil
}
