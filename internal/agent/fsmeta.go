package agent

import (
	"encoding/binary"
	"io/fs"
	"time"

	"pbspc/pkg/pxar"
)

// Extended attributes used to preserve Windows-specific metadata in pxar.
const (
	xattrAttrs = "user.pbspc.attrs" // u32 LE FILE_ATTRIBUTE_* bits
	xattrCtime = "user.pbspc.ctime" // i64 LE creation time, unix nanoseconds
)

// Windows file attribute bits we care about.
const (
	attrReadonly           = 0x1
	attrHidden             = 0x2
	attrSystem             = 0x4
	attrArchive            = 0x20
	attrOffline            = 0x1000
	attrRecallOnOpen       = 0x40000
	attrRecallOnDataAccess = 0x400000
)

// winMeta is the platform-neutral view of a file's metadata.
type winMeta struct {
	attrs uint32
	ctime time.Time
	mtime time.Time
	// cloudPlaceholder is set for OneDrive/Files-On-Demand style placeholders
	// whose content would be downloaded (or fail) on read.
	cloudPlaceholder bool
}

func toPxarMeta(fi fs.FileInfo, m winMeta) pxar.Metadata {
	md := pxar.Metadata{
		MtimeSecs:  m.mtime.Unix(),
		MtimeNanos: uint32(m.mtime.Nanosecond()),
	}
	switch {
	case fi.IsDir():
		md.Mode = pxar.ModeIFDIR | 0o755
	case fi.Mode()&fs.ModeSymlink != 0:
		md.Mode = pxar.ModeIFLNK | 0o777
	default:
		md.Mode = pxar.ModeIFREG | 0o644
		if m.attrs&attrReadonly != 0 {
			md.Mode = pxar.ModeIFREG | 0o444
		}
	}
	if m.attrs&attrHidden != 0 {
		md.Flags |= pxar.FlagHidden
	}
	if m.attrs&attrSystem != 0 {
		md.Flags |= pxar.FlagSystem
	}
	if m.attrs&attrArchive != 0 {
		md.Flags |= pxar.FlagArchive
	}
	if m.attrs != 0 {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], m.attrs)
		md.Xattrs = append(md.Xattrs, pxar.Xattr{Name: []byte(xattrAttrs), Value: b[:]})
	}
	if !m.ctime.IsZero() {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(m.ctime.UnixNano()))
		md.Xattrs = append(md.Xattrs, pxar.Xattr{Name: []byte(xattrCtime), Value: b[:]})
	}
	return md
}

// fromPxarMeta extracts Windows attributes and creation time stored by toPxarMeta.
func fromPxarMeta(md pxar.Metadata) (attrs uint32, hasAttrs bool, ctime time.Time) {
	for _, x := range md.Xattrs {
		switch string(x.Name) {
		case xattrAttrs:
			if len(x.Value) == 4 {
				attrs, hasAttrs = binary.LittleEndian.Uint32(x.Value), true
			}
		case xattrCtime:
			if len(x.Value) == 8 {
				ctime = time.Unix(0, int64(binary.LittleEndian.Uint64(x.Value)))
			}
		}
	}
	if !hasAttrs {
		if md.Flags&pxar.FlagHidden != 0 {
			attrs |= attrHidden
		}
		if md.Flags&pxar.FlagSystem != 0 {
			attrs |= attrSystem
		}
		if md.Mode&0o222 == 0 && md.Mode&pxar.ModeIFMT == pxar.ModeIFREG {
			attrs |= attrReadonly
		}
	}
	return attrs, hasAttrs, ctime
}
