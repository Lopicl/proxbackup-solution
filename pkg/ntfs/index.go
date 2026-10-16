// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// DirEntry is one name in a directory. Size and Mtime come from the index
// copy of $FILE_NAME, which Windows does not always keep current; use
// Volume.Get for exact values.
type DirEntry struct {
	Name  string
	Ref   uint64 // MFT record number
	IsDir bool
	Size  int64
	Mtime time.Time
}

const (
	fnNamespaceDOS  = 2
	fnFlagDirectory = 0x10000000

	ieHasSubnode = 0x1
	ieLast       = 0x2
)

// ReadDir lists a directory in index ($I30) order. DOS 8.3 aliases and the
// root's "." entry are left out; hard links appear once per name.
func (f *File) ReadDir() ([]DirEntry, error) {
	if !f.IsDir {
		return nil, errors.New("ntfs: not a directory")
	}
	root := findAttr(f.attrs, attrIndexRoot, "$I30")
	if root == nil || !root.resident || len(root.value) < 32 {
		return nil, fmt.Errorf("ntfs: directory %d has no index root", f.Ref)
	}
	d := &dirReader{f: f, seen: map[int64]bool{}}
	d.recSize = int64(binary.LittleEndian.Uint32(root.value[8:]))
	if alloc, err := f.v.stream(f.attrs, attrIndexAlloc, "$I30"); err == nil {
		d.alloc = alloc
	} else if !errors.Is(err, ErrNoStream) {
		return nil, err
	}
	if err := d.node(root.value[16:], 0); err != nil {
		return nil, err
	}
	return d.out, nil
}

type dirReader struct {
	f       *File
	alloc   *Stream
	recSize int64
	seen    map[int64]bool
	out     []DirEntry
}

// node walks one index node (header + entries) in order, descending into subnodes.
func (d *dirReader) node(hdr []byte, depth int) error {
	if depth > 32 || len(hdr) < 16 {
		return errors.New("ntfs: malformed directory index")
	}
	off := int(binary.LittleEndian.Uint32(hdr[0:]))
	end := min(int(binary.LittleEndian.Uint32(hdr[4:])), len(hdr))
	for off+16 <= end {
		e := hdr[off:]
		elen := int(binary.LittleEndian.Uint16(e[8:]))
		klen := int(binary.LittleEndian.Uint16(e[10:]))
		flags := binary.LittleEndian.Uint16(e[12:])
		if elen < 16 || off+elen > end {
			return errors.New("ntfs: bad index entry")
		}
		if flags&ieHasSubnode != 0 {
			if err := d.child(int64(binary.LittleEndian.Uint64(e[elen-8:])), depth); err != nil {
				return err
			}
		}
		if flags&ieLast != 0 {
			break
		}
		if klen >= 66 && 16+klen <= elen {
			d.add(binary.LittleEndian.Uint64(e[0:])&refMask, e[16:16+klen])
		}
		off += elen
	}
	return nil
}

func (d *dirReader) add(ref uint64, fn []byte) {
	n := int(fn[64])
	if fn[65] == fnNamespaceDOS || 66+2*n > len(fn) || ref == d.f.Ref {
		return
	}
	d.out = append(d.out, DirEntry{
		Name:  utf16le(fn[66 : 66+2*n]),
		Ref:   ref,
		IsDir: binary.LittleEndian.Uint32(fn[56:])&fnFlagDirectory != 0,
		Size:  int64(binary.LittleEndian.Uint64(fn[48:])),
		Mtime: filetime(fn[16:]),
	})
}

// child reads the index record (INDX) at vcn and walks its node.
func (d *dirReader) child(vcn int64, depth int) error {
	if d.alloc == nil || d.recSize <= 0 {
		return errors.New("ntfs: index subnode without allocation")
	}
	// Index VCNs count clusters, or 512-byte blocks when records are
	// smaller than a cluster.
	unit := d.f.v.clusterSize
	if d.recSize < unit {
		unit = 512
	}
	off := vcn * unit
	if d.seen[off] {
		return errors.New("ntfs: index loop")
	}
	d.seen[off] = true
	buf := make([]byte, d.recSize)
	if _, err := d.alloc.ReadAt(buf, off); err != nil {
		return fmt.Errorf("ntfs: index record of directory %d: %w", d.f.Ref, err)
	}
	if string(buf[:4]) != "INDX" {
		return fmt.Errorf("ntfs: index record of directory %d: bad magic", d.f.Ref)
	}
	if err := applyFixups(buf); err != nil {
		return err
	}
	return d.node(buf[24:], depth+1)
}
