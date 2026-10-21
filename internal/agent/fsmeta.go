// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"strings"
	"time"
	"unicode/utf8"

	"proxbackup/pkg/pxar"
)

// Extended attributes used to preserve Windows-specific metadata in pxar.
const (
	xattrAttrs = "user.proxbackup.attrs" // u32 LE FILE_ATTRIBUTE_* bits
	xattrCtime = "user.proxbackup.ctime" // i64 LE creation time, unix nanoseconds
	// i64 LE NTFS ChangeTime (any data or metadata change), unix nanoseconds.
	// Only written with change detection; it catches edits that put the old
	// LastWriteTime back. Not restored.
	xattrChangeTime = "user.proxbackup.chtime"
	// Self-relative security descriptor: owner, group and DACL.
	xattrSD = "user.proxbackup.ntsd"
	// Prefix of an alternate data stream's contents, followed by its name.
	xattrADSPrefix = "user.proxbackup.ads."

	// Names written before the rename to ProxBackup; still read on restore.
	xattrAttrsLegacy = "user.pbspc.attrs"
	xattrCtimeLegacy = "user.pbspc.ctime"
)

// Alternate data streams larger than this aren't backed up: it is the
// largest value Linux accepts for an xattr, so stock pxar tools can restore it.
const maxADSSize = 64 << 10

// maxXattrName is the longest xattr name Linux accepts.
const maxXattrName = 255

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
	// chtime is the change time, set by the walker for change detection only.
	chtime time.Time
	// cloudPlaceholder is set for OneDrive/Files-On-Demand style placeholders
	// whose content would be downloaded (or fail) on read.
	cloudPlaceholder bool
	nt               ntExtras
}

// ntExtras is NTFS metadata kept in xattrs: the security descriptor and the
// alternate data streams.
type ntExtras struct {
	sd      []byte
	streams []adsStream
}

type adsStream struct {
	name string // without the leading ':' and the ':$DATA' type
	data []byte
}

// validStreamName reports whether name can be stored and written back as
// "file:name": no separators, colons or NULs, and short enough for an xattr.
func validStreamName(name string) bool {
	return name != "" && utf8.ValidString(name) && !strings.ContainsAny(name, ":\\/\x00") &&
		len(xattrADSPrefix)+len(name) <= maxXattrName
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
	if md.Mode&pxar.ModeIFMT == pxar.ModeIFLNK {
		// Linux refuses user.* xattrs on symlinks, so proxmox-backup-client
		// would abort a restore on them. HIDDEN/SYSTEM survive in the flags.
		return md
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
	if !m.chtime.IsZero() {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(m.chtime.UnixNano()))
		md.Xattrs = append(md.Xattrs, pxar.Xattr{Name: []byte(xattrChangeTime), Value: b[:]})
	}
	if len(m.nt.sd) > 0 {
		md.Xattrs = append(md.Xattrs, pxar.Xattr{Name: []byte(xattrSD), Value: m.nt.sd})
	}
	for _, s := range m.nt.streams {
		md.Xattrs = append(md.Xattrs, pxar.Xattr{Name: []byte(xattrADSPrefix + s.name), Value: s.data})
	}
	return md
}

// ntFromPxar extracts the security descriptor and alternate data streams
// stored by toPxarMeta. Stream names that couldn't be written back are dropped.
func ntFromPxar(md pxar.Metadata) ntExtras {
	var nt ntExtras
	for _, x := range md.Xattrs {
		if string(x.Name) == xattrSD {
			nt.sd = x.Value
		} else if name, ok := bytes.CutPrefix(x.Name, []byte(xattrADSPrefix)); ok && validStreamName(string(name)) {
			nt.streams = append(nt.streams, adsStream{string(name), x.Value})
		}
	}
	return nt
}

// fromPxarMeta extracts Windows attributes and creation time stored by toPxarMeta.
func fromPxarMeta(md pxar.Metadata) (attrs uint32, hasAttrs bool, ctime time.Time) {
	for _, x := range md.Xattrs {
		switch string(x.Name) {
		case xattrAttrs, xattrAttrsLegacy:
			if len(x.Value) == 4 {
				attrs, hasAttrs = binary.LittleEndian.Uint32(x.Value), true
			}
		case xattrCtime, xattrCtimeLegacy:
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
