package pbs

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// CatalogArchiveName is the archive the PBS GUI file browser (and
// proxmox-backup-client catalog) reads to list a snapshot's contents.
const CatalogArchiveName = "catalog.pcat1.didx"

// Catalog entry types (pbs-datastore/src/catalog.rs, CatalogEntryType).
const (
	CatalogDir     = 'd'
	CatalogFile    = 'f'
	CatalogSymlink = 'l'
)

// CatalogWriter streams a "Proxmox Backup Catalog file v1.0".
//
// Layout: magic, then one table per directory in post-order (a directory's
// table is written when it is closed, after all of its subdirectories), then
// the root table and finally the root table's offset as a little-endian u64.
// A table is varint(len) followed by varint(count) and its entries; a
// subdirectory entry stores the distance back to that subdirectory's table.
//
// The root directory's entries are the archives (e.g. "c-users.pxar.didx");
// the PBS GUI shows them as top-level folders.
type CatalogWriter struct {
	w     *bufio.Writer
	pos   uint64
	stack []*catalogDir
	err   error
}

type catalogDir struct {
	name    string
	entries []byte
	count   uint64
}

func NewCatalogWriter(w io.Writer) (*CatalogWriter, error) {
	c := &CatalogWriter{w: bufio.NewWriterSize(w, 1<<16), stack: []*catalogDir{{}}}
	c.write(MagicCatalogFile[:])
	return c, c.err
}

// Err returns the first write error; once set, all further calls are no-ops.
func (c *CatalogWriter) Err() error { return c.err }

func (c *CatalogWriter) write(p []byte) {
	if c.err != nil {
		return
	}
	_, c.err = c.w.Write(p)
	c.pos += uint64(len(p))
}

func (c *CatalogWriter) cur() *catalogDir { return c.stack[len(c.stack)-1] }

func (c *CatalogWriter) addEntry(typ byte, name string) *catalogDir {
	d := c.cur()
	d.entries = append(d.entries, typ)
	d.entries = binary.AppendUvarint(d.entries, uint64(len(name)))
	d.entries = append(d.entries, name...)
	d.count++
	return d
}

// StartDirectory opens a subdirectory of the current directory. Entries must be
// added in the same order as in the archive (bytewise sorted names).
func (c *CatalogWriter) StartDirectory(name string) {
	c.stack = append(c.stack, &catalogDir{name: name})
}

// EndDirectory closes the directory opened by the matching StartDirectory.
func (c *CatalogWriter) EndDirectory() error {
	if len(c.stack) < 2 {
		return errors.New("pbs: catalog: EndDirectory without StartDirectory")
	}
	d := c.cur()
	c.stack = c.stack[:len(c.stack)-1]
	start := c.writeTable(d)
	p := c.addEntry(CatalogDir, d.name)
	// Distance from the parent's table (written later, at a higher offset) back
	// to this one. The parent's offset is unknown yet, so store the absolute
	// position for now and convert it in writeTable.
	p.entries = binary.AppendUvarint(p.entries, start)
	return c.err
}

func (c *CatalogWriter) AddFile(name string, size uint64, mtime int64) {
	d := c.addEntry(CatalogFile, name)
	d.entries = binary.AppendUvarint(d.entries, size)
	d.entries = appendCatalogI64(d.entries, mtime)
}

func (c *CatalogWriter) AddSymlink(name string) { c.addEntry(CatalogSymlink, name) }

// Finish writes the root table and the trailing root offset.
func (c *CatalogWriter) Finish() error {
	if len(c.stack) != 1 {
		return fmt.Errorf("pbs: catalog: %d directories left open", len(c.stack)-1)
	}
	start := c.writeTable(c.stack[0])
	c.write(binary.LittleEndian.AppendUint64(nil, start))
	if c.err == nil {
		c.err = c.w.Flush()
	}
	return c.err
}

// writeTable writes d's table and returns its offset. Subdirectory entries were
// recorded with their absolute table offset; the format wants start-offset.
func (c *CatalogWriter) writeTable(d *catalogDir) uint64 {
	start := c.pos
	table := binary.AppendUvarint(nil, d.count)
	for b := d.entries; len(b) > 0; {
		typ := b[0]
		n, k := binary.Uvarint(b[1:])
		end := 1 + k + int(n)
		table = append(table, b[:end]...)
		b = b[end:]
		switch typ {
		case CatalogDir:
			off, k := binary.Uvarint(b)
			table = binary.AppendUvarint(table, start-off)
			b = b[k:]
		case CatalogFile:
			_, k := binary.Uvarint(b)
			k2 := catalogI64Len(b[k:])
			table = append(table, b[:k+k2]...)
			b = b[k+k2:]
		}
	}
	c.write(binary.AppendUvarint(nil, uint64(len(table))))
	c.write(table)
	return start
}

// appendCatalogI64 encodes v like catalog_encode_i64: 7-bit groups, low first;
// negative numbers store -v and end with a continuation byte followed by 0.
func appendCatalogI64(b []byte, v int64) []byte {
	var d uint64
	if v < 0 {
		d = uint64(-(v + 1)) + 1
	} else {
		d = uint64(v)
	}
	for d >= 128 {
		b = append(b, byte(d&127)|128)
		d >>= 7
	}
	if v < 0 {
		return append(b, byte(d)|128, 0)
	}
	return append(b, byte(d))
}

func catalogI64Len(b []byte) int {
	for i, x := range b {
		if x&128 == 0 {
			return i + 1
		}
	}
	return len(b)
}

func decodeCatalogI64(b []byte) (int64, int, error) {
	var d uint64
	for i, x := range b {
		if i > 0 && x == 0 && b[i-1]&128 != 0 {
			return -int64(d), i + 1, nil
		}
		if i >= 10 {
			break
		}
		d |= uint64(x&127) << (7 * i)
		if x&128 == 0 {
			return int64(d), i + 1, nil
		}
	}
	return 0, 0, errors.New("pbs: catalog: bad i64")
}

// CatalogEntry is one directory entry read back from a catalog.
type CatalogEntry struct {
	Type  byte // CatalogDir, CatalogFile, CatalogSymlink, ...
	Name  string
	Size  uint64
	Mtime int64
	table uint64 // directories: offset of their table
}

// CatalogReader reads a catalog from random-access storage.
type CatalogReader struct {
	r    io.ReaderAt
	root uint64
}

func NewCatalogReader(r io.ReaderAt, size int64) (*CatalogReader, error) {
	if size < 16 {
		return nil, errors.New("pbs: catalog too short")
	}
	var b [8]byte
	if _, err := r.ReadAt(b[:], 0); err != nil {
		return nil, err
	}
	if b != MagicCatalogFile {
		return nil, errors.New("pbs: not a catalog file")
	}
	if _, err := r.ReadAt(b[:], size-8); err != nil {
		return nil, err
	}
	return &CatalogReader{r: r, root: binary.LittleEndian.Uint64(b[:])}, nil
}

func (c *CatalogReader) readTable(start uint64) ([]CatalogEntry, error) {
	var hdr [binary.MaxVarintLen64]byte
	n, _ := c.r.ReadAt(hdr[:], int64(start))
	tlen, k := binary.Uvarint(hdr[:n])
	if k <= 0 || tlen > 1<<30 {
		return nil, fmt.Errorf("pbs: catalog: bad table at %d", start)
	}
	b := make([]byte, tlen)
	if _, err := c.r.ReadAt(b, int64(start)+int64(k)); err != nil {
		return nil, err
	}
	count, k := binary.Uvarint(b)
	b = b[k:]
	bad := fmt.Errorf("pbs: catalog: corrupt table at %d", start)
	entries := make([]CatalogEntry, 0, count)
	for i := uint64(0); i < count; i++ {
		if len(b) < 2 {
			return nil, bad
		}
		e := CatalogEntry{Type: b[0]}
		nlen, k := binary.Uvarint(b[1:])
		if k <= 0 || uint64(len(b)) < 1+uint64(k)+nlen {
			return nil, bad
		}
		e.Name = string(b[1+k : 1+k+int(nlen)])
		b = b[1+k+int(nlen):]
		switch e.Type {
		case CatalogDir:
			off, k := binary.Uvarint(b)
			if k <= 0 || off > start {
				return nil, bad
			}
			e.table = start - off
			b = b[k:]
		case CatalogFile:
			var k int
			if e.Size, k = binary.Uvarint(b); k <= 0 {
				return nil, bad
			}
			b = b[k:]
			var err error
			if e.Mtime, k, err = decodeCatalogI64(b); err != nil {
				return nil, err
			}
			b = b[k:]
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// ListDir lists the directory at p ("/" for the archives, "/archive/dir/...").
func (c *CatalogReader) ListDir(p string) ([]CatalogEntry, error) {
	table := c.root
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" {
			continue
		}
		entries, err := c.readTable(table)
		if err != nil {
			return nil, err
		}
		found := false
		for _, e := range entries {
			if e.Name == part {
				if e.Type != CatalogDir {
					return nil, fmt.Errorf("pbs: catalog: %s is not a directory", part)
				}
				table, found = e.table, true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("pbs: catalog: %s not found", part)
		}
	}
	return c.readTable(table)
}
