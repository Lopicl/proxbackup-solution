// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ntfs is a read-only NTFS reader over an io.ReaderAt (a volume image).
// It lists directories and reads file contents, including fragmented, sparse
// and LZNT1-compressed files and files whose attributes spill over into
// extension MFT records. It never writes and needs no journal replay: images
// come from VSS snapshots, which are crash-consistent.
package ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"
)

// Attribute types.
const (
	attrStandardInfo   = 0x10
	attrAttributeList  = 0x20
	attrFileName       = 0x30
	attrData           = 0x80
	attrIndexRoot      = 0x90
	attrIndexAlloc     = 0xA0
	attrReparsePoint   = 0xC0
	attrEnd            = 0xFFFFFFFF
	attrFlagCompressed = 0x0001
	attrFlagEncrypted  = 0x4000
)

// Windows file attribute bits (FILE_ATTRIBUTE_*) reported in File.Attrs.
const (
	AttrReadonly     = 0x1
	AttrHidden       = 0x2
	AttrSystem       = 0x4
	AttrDirectory    = 0x10
	AttrArchive      = 0x20
	AttrSparse       = 0x200
	AttrReparsePoint = 0x400
	AttrCompressed   = 0x800
	AttrEncrypted    = 0x4000
)

// Reparse tags of interest.
const (
	ReparseTagMountPoint = 0xA0000003
	ReparseTagSymlink    = 0xA000000C
	ReparseTagDedup      = 0x80000013
	ReparseTagWof        = 0x80000017
)

// RootRef is the MFT record number of the root directory. Records below
// FirstUserRef hold NTFS metadata files ($MFT, $LogFile, $Bitmap, ...).
const (
	RootRef      = 5
	FirstUserRef = 24
)

// ErrNotExist is returned by Lookup for a missing path.
var ErrNotExist = errors.New("ntfs: file does not exist")

// Volume is an open NTFS file system.
type Volume struct {
	r           io.ReaderAt
	clusterSize int64
	recordSize  int64
	indexSize   int64 // default index record size from the boot sector
	mft         *Stream
}

// Open reads the boot sector and the $MFT's own record.
func Open(r io.ReaderAt) (*Volume, error) {
	var bs [512]byte
	if _, err := r.ReadAt(bs[:], 0); err != nil {
		return nil, fmt.Errorf("ntfs: boot sector: %w", err)
	}
	if string(bs[3:11]) != "NTFS    " || bs[510] != 0x55 || bs[511] != 0xAA {
		return nil, errors.New("ntfs: not an NTFS volume")
	}
	bps := int64(binary.LittleEndian.Uint16(bs[11:]))
	spc := int64(bs[13])
	if spc > 0x80 { // 2^-n encoding for clusters > 64 KiB
		spc = 1 << (256 - spc)
	}
	v := &Volume{r: r, clusterSize: bps * spc}
	if bps < 256 || bps&(bps-1) != 0 || v.clusterSize == 0 || v.clusterSize > 2<<20 {
		return nil, errors.New("ntfs: invalid geometry")
	}
	sizeOf := func(b byte) int64 {
		if n := int8(b); n < 0 {
			return 1 << -n
		}
		return int64(b) * v.clusterSize
	}
	v.recordSize = sizeOf(bs[0x40])
	v.indexSize = sizeOf(bs[0x44])
	if v.recordSize < 512 || v.recordSize > 64<<10 {
		return nil, errors.New("ntfs: invalid MFT record size")
	}
	mftLCN := int64(binary.LittleEndian.Uint64(bs[0x30:]))

	// Bootstrap: record 0 sits at the start of the MFT, so its $DATA runs
	// can be read before the MFT itself is mapped.
	buf := make([]byte, v.recordSize)
	if _, err := r.ReadAt(buf, mftLCN*v.clusterSize); err != nil {
		return nil, fmt.Errorf("ntfs: $MFT record: %w", err)
	}
	rec, err := v.parseRecord(buf, 0)
	if err != nil {
		return nil, err
	}
	attrs := rec.attrs
	if v.mft, err = v.stream(attrs, attrData, ""); err != nil {
		return nil, fmt.Errorf("ntfs: $MFT data: %w", err)
	}
	// A heavily fragmented $MFT keeps the rest of its runs in extension
	// records, readable through the runs known so far.
	if al := findAttr(attrs, attrAttributeList, ""); al != nil {
		if attrs, err = v.expand(rec, al); err != nil {
			return nil, err
		}
		if v.mft, err = v.stream(attrs, attrData, ""); err != nil {
			return nil, fmt.Errorf("ntfs: $MFT data: %w", err)
		}
	}
	return v, nil
}

// ClusterSize returns the volume's cluster size in bytes.
func (v *Volume) ClusterSize() int64 { return v.clusterSize }

type record struct {
	ref   uint64
	flags uint16
	base  uint64
	attrs []*attribute
}

type attribute struct {
	typ      uint32
	name     string
	flags    uint16
	resident bool
	value    []byte // resident only

	// non-resident only
	startVCN, lastVCN int64
	compUnit          int
	allocSize         int64
	dataSize          int64
	initSize          int64
	runs              []run
}

const (
	recInUse = 0x1
	recIsDir = 0x2
)

func (v *Volume) readRecord(ref uint64) (*record, error) {
	buf := make([]byte, v.recordSize)
	if _, err := v.mft.ReadAt(buf, int64(ref)*v.recordSize); err != nil {
		return nil, fmt.Errorf("ntfs: MFT record %d: %w", ref, err)
	}
	return v.parseRecord(buf, ref)
}

// applyFixups checks and undoes the update sequence array protecting multi-sector structures.
func applyFixups(buf []byte) error {
	off := int(binary.LittleEndian.Uint16(buf[4:]))
	n := int(binary.LittleEndian.Uint16(buf[6:]))
	if n == 0 || off+2*n > len(buf) || (n-1)*512 > len(buf) {
		return errors.New("ntfs: bad update sequence")
	}
	usn := buf[off : off+2]
	for i := 1; i < n; i++ {
		end := i*512 - 2
		if !bytes.Equal(buf[end:end+2], usn) {
			return errors.New("ntfs: torn multi-sector record")
		}
		copy(buf[end:end+2], buf[off+2*i:off+2*i+2])
	}
	return nil
}

func (v *Volume) parseRecord(buf []byte, ref uint64) (*record, error) {
	if string(buf[:4]) != "FILE" {
		return nil, fmt.Errorf("ntfs: MFT record %d: bad magic", ref)
	}
	if err := applyFixups(buf); err != nil {
		return nil, fmt.Errorf("MFT record %d: %w", ref, err)
	}
	rec := &record{
		ref:   ref,
		flags: binary.LittleEndian.Uint16(buf[22:]),
		base:  binary.LittleEndian.Uint64(buf[32:]) & refMask,
	}
	used := min(int(binary.LittleEndian.Uint32(buf[24:])), len(buf))
	off := int(binary.LittleEndian.Uint16(buf[20:]))
	for off+8 <= used {
		typ := binary.LittleEndian.Uint32(buf[off:])
		if typ == attrEnd {
			break
		}
		length := int(binary.LittleEndian.Uint32(buf[off+4:]))
		if length < 16 || off+length > used {
			return nil, fmt.Errorf("ntfs: MFT record %d: bad attribute length", ref)
		}
		a, err := parseAttr(buf[off : off+length])
		if err != nil {
			return nil, fmt.Errorf("ntfs: MFT record %d: %w", ref, err)
		}
		rec.attrs = append(rec.attrs, a)
		off += length
	}
	return rec, nil
}

func parseAttr(b []byte) (*attribute, error) {
	a := &attribute{
		typ:      binary.LittleEndian.Uint32(b),
		resident: b[8] == 0,
		flags:    binary.LittleEndian.Uint16(b[12:]),
	}
	if n, off := int(b[9]), int(binary.LittleEndian.Uint16(b[10:])); n > 0 {
		if off+2*n > len(b) {
			return nil, errors.New("bad attribute name")
		}
		a.name = utf16le(b[off : off+2*n])
	}
	if a.resident {
		n, off := int(binary.LittleEndian.Uint32(b[16:])), int(binary.LittleEndian.Uint16(b[20:]))
		if off+n > len(b) {
			return nil, errors.New("bad resident attribute")
		}
		a.value = b[off : off+n]
		return a, nil
	}
	if len(b) < 64 {
		return nil, errors.New("short non-resident attribute")
	}
	a.startVCN = int64(binary.LittleEndian.Uint64(b[16:]))
	a.lastVCN = int64(binary.LittleEndian.Uint64(b[24:]))
	a.compUnit = int(binary.LittleEndian.Uint16(b[34:]))
	a.allocSize = int64(binary.LittleEndian.Uint64(b[40:]))
	a.dataSize = int64(binary.LittleEndian.Uint64(b[48:]))
	a.initSize = int64(binary.LittleEndian.Uint64(b[56:]))
	var err error
	a.runs, err = decodeRuns(b[binary.LittleEndian.Uint16(b[32:]):], a.startVCN)
	return a, err
}

func findAttr(attrs []*attribute, typ uint32, name string) *attribute {
	for _, a := range attrs {
		if a.typ == typ && a.name == name {
			return a
		}
	}
	return nil
}

const refMask = 1<<48 - 1

// expand gathers a file's attributes from the extension records named in its attribute list.
func (v *Volume) expand(rec *record, al *attribute) ([]*attribute, error) {
	var list []byte
	if al.resident {
		list = al.value
	} else {
		s, err := v.newStream([]*attribute{al})
		if err != nil {
			return nil, err
		}
		list = make([]byte, s.size)
		if _, err := s.ReadAt(list, 0); err != nil {
			return nil, fmt.Errorf("ntfs: attribute list: %w", err)
		}
	}
	attrs := rec.attrs
	seen := map[uint64]bool{rec.ref: true}
	for off := 0; off+26 <= len(list); {
		n := int(binary.LittleEndian.Uint16(list[off+4:]))
		if n < 26 {
			return nil, errors.New("ntfs: bad attribute list entry")
		}
		ref := binary.LittleEndian.Uint64(list[off+16:]) & refMask
		off += n
		if seen[ref] {
			continue
		}
		seen[ref] = true
		ext, err := v.readRecord(ref)
		if err != nil {
			return nil, err
		}
		if ext.base != rec.ref {
			return nil, fmt.Errorf("ntfs: MFT record %d is not an extension of %d", ref, rec.ref)
		}
		attrs = append(attrs, ext.attrs...)
	}
	return attrs, nil
}

// File is one MFT entry (file or directory) with its standard information.
type File struct {
	v     *Volume
	Ref   uint64
	IsDir bool
	// Attrs are the FILE_ATTRIBUTE_* bits from $STANDARD_INFORMATION.
	Attrs               uint32
	Ctime, Mtime, Atime time.Time
	ReparseTag          uint32
	attrs               []*attribute
}

// Get loads the MFT record ref with all its attributes.
func (v *Volume) Get(ref uint64) (*File, error) {
	rec, err := v.readRecord(ref)
	if err != nil {
		return nil, err
	}
	if rec.flags&recInUse == 0 {
		return nil, fmt.Errorf("ntfs: MFT record %d is not in use", ref)
	}
	if rec.base != 0 {
		return nil, fmt.Errorf("ntfs: MFT record %d is an extension record", ref)
	}
	f := &File{v: v, Ref: ref, IsDir: rec.flags&recIsDir != 0, attrs: rec.attrs}
	if al := findAttr(rec.attrs, attrAttributeList, ""); al != nil {
		if f.attrs, err = v.expand(rec, al); err != nil {
			return nil, err
		}
	}
	if si := findAttr(f.attrs, attrStandardInfo, ""); si != nil && len(si.value) >= 36 {
		f.Ctime = filetime(si.value[0:])
		f.Mtime = filetime(si.value[8:])
		f.Atime = filetime(si.value[24:])
		f.Attrs = binary.LittleEndian.Uint32(si.value[32:])
	}
	if rp := findAttr(f.attrs, attrReparsePoint, ""); rp != nil && rp.resident && len(rp.value) >= 4 {
		f.ReparseTag = binary.LittleEndian.Uint32(rp.value)
	}
	return f, nil
}

// Root returns the root directory.
func (v *Volume) Root() (*File, error) { return v.Get(RootRef) }

// Lookup resolves a slash- or backslash-separated path relative to the root,
// comparing names case-insensitively like Windows does.
func (v *Volume) Lookup(p string) (*File, error) {
	f, _, err := v.Resolve(p)
	return f, err
}

// Resolve is Lookup that also returns the path as stored on the volume
// (slash-separated, with the names' real case).
func (v *Volume) Resolve(p string) (*File, string, error) {
	f, err := v.Root()
	if err != nil {
		return nil, "", err
	}
	var names []string
	for _, name := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if !f.IsDir {
			return nil, "", ErrNotExist
		}
		ents, err := f.ReadDir()
		if err != nil {
			return nil, "", err
		}
		found := false
		for _, e := range ents {
			if strings.EqualFold(e.Name, name) {
				if f, err = v.Get(e.Ref); err != nil {
					return nil, "", err
				}
				names = append(names, e.Name)
				found = true
				break
			}
		}
		if !found {
			return nil, "", ErrNotExist
		}
	}
	return f, strings.Join(names, "/"), nil
}

// Size returns the size of the unnamed data stream (0 for directories).
func (f *File) Size() int64 {
	s, err := f.Open()
	if err != nil {
		return 0
	}
	return s.Size()
}

// Encrypted reports whether the data is EFS-encrypted (unreadable without the user's key).
func (f *File) Encrypted() bool {
	if a := findAttr(f.attrs, attrData, ""); a != nil {
		return a.flags&attrFlagEncrypted != 0
	}
	return f.Attrs&AttrEncrypted != 0
}

// Open returns the unnamed data stream.
func (f *File) Open() (*Stream, error) { return f.OpenStream("") }

// OpenStream returns a named data stream (alternate data stream), or the
// unnamed one for "".
func (f *File) OpenStream(name string) (*Stream, error) {
	return f.v.stream(f.attrs, attrData, name)
}

// Streams lists the names of the file's alternate data streams.
func (f *File) Streams() []string {
	var names []string
	for _, a := range f.attrs {
		if a.typ == attrData && a.name != "" && (a.resident || a.startVCN == 0) {
			names = append(names, a.name)
		}
	}
	return names
}

// filetime converts an NTFS timestamp (100 ns since 1601) to time.Time.
func filetime(b []byte) time.Time {
	ft := int64(binary.LittleEndian.Uint64(b))
	if ft == 0 {
		return time.Time{}
	}
	return time.Unix(0, (ft-116444736000000000)*100)
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}
