// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pxar implements the Proxmox file archive format (version 1), as
// produced by proxmox-backup-client for *.pxar.didx archives.
//
// Format reference: pxar.git src/format/mod.rs. All integers are little-endian.
// An archive is a single directory tree:
//
//	ENTRY(root) [XATTR...]
//	  FILENAME ENTRY [XATTR...] (PAYLOAD | SYMLINK | <dir contents> GOODBYE)
//	  ...
//	GOODBYE
package pxar

import (
	"encoding/binary"
	"math/bits"

	"github.com/dchest/siphash"
)

// Item types.
const (
	TypeEntry           uint64 = 0xd5956474e588acef
	TypeEntryV1         uint64 = 0x11da850a1c1cceff
	TypeFormatVersion   uint64 = 0x730f6c75df16a40d
	TypePrelude         uint64 = 0xe309d79d9f7b771b
	TypeFilename        uint64 = 0x16701121063917b3
	TypeSymlink         uint64 = 0x27f971e7dbf5dc5f
	TypeDevice          uint64 = 0x9fc9e906586d5ce9
	TypeXattr           uint64 = 0x0dab0229b57dcd03
	TypeACLUser         uint64 = 0x2ce8540a457d55b8
	TypeACLGroup        uint64 = 0x136e3eceb04c03ab
	TypeACLGroupObj     uint64 = 0x10868031e9582876
	TypeACLDefault      uint64 = 0xbbbb13415a6896f5
	TypeACLDefaultUser  uint64 = 0xc89357b40532cd1f
	TypeACLDefaultGroup uint64 = 0xf90a8a5816038ffe
	TypeFCaps           uint64 = 0x2da9dd9db5f7fb67
	TypeQuotaProjID     uint64 = 0xe07540e82f7d1cbb
	TypeHardlink        uint64 = 0x51269c8422bd7275
	TypePayload         uint64 = 0x28147a1b0b7c1a25
	TypePayloadRef      uint64 = 0x419d3d6bc4ba977e
	TypeGoodbye         uint64 = 0x2fec4fa642d5731d
	GoodbyeTailMarker   uint64 = 0xef5eed5b753e1555
	hashKey1            uint64 = 0x83ac3f1cfbb450db
	hashKey2            uint64 = 0xaa4f1b6879369fbd
	headerSize                 = 16
	entrySize                  = 40 // mode, flags, uid, gid, mtime{secs, nanos, pad}
	goodbyeItemSize            = 24
	maxFilenameLen             = 4 * 1024
	maxXattrLen                = 64*1024 + 255 + 1
	maxSymlinkLen              = 4 * 1024
)

// Mode bits (Linux st_mode).
const (
	ModeIFMT   uint64 = 0o170000
	ModeIFSOCK uint64 = 0o140000
	ModeIFLNK  uint64 = 0o120000
	ModeIFREG  uint64 = 0o100000
	ModeIFBLK  uint64 = 0o060000
	ModeIFDIR  uint64 = 0o040000
	ModeIFCHR  uint64 = 0o020000
	ModeIFIFO  uint64 = 0o010000
)

// Feature flags stored in Entry.Flags (pbs-client/src/pxar/flags.rs). Only the
// FAT/NTFS-relevant attribute bits are used by the Windows agent.
const (
	FlagHidden  uint64 = 0x2000
	FlagSystem  uint64 = 0x4000
	FlagArchive uint64 = 0x8000
)

// Xattr is one extended attribute.
type Xattr struct {
	Name  []byte
	Value []byte
}

// Metadata is the stat() data of an entry.
type Metadata struct {
	Mode       uint64 // file type bits | permission bits
	Flags      uint64
	UID, GID   uint32
	MtimeSecs  int64
	MtimeNanos uint32
	Xattrs     []Xattr
}

// IsDir reports whether Mode denotes a directory.
func (m Metadata) IsDir() bool { return m.Mode&ModeIFMT == ModeIFDIR }

// HashFilename is SipHash-2-4 of name with the pxar keys.
func HashFilename(name []byte) uint64 { return siphash.Hash(hashKey1, hashKey2, name) }

type goodbyeItem struct {
	hash, offset, size uint64
}

func putHeader(b []byte, htype, fullSize uint64) {
	binary.LittleEndian.PutUint64(b[0:], htype)
	binary.LittleEndian.PutUint64(b[8:], fullSize)
}

// bstPermute calls fn(src, dst) to lay out a sorted array as an implicit binary
// search tree, exactly like pxar's binary_tree_array::copy.
func bstPermute(n int, fn func(src, dst int)) {
	if n == 0 {
		return
	}
	e := 63 - bits.LeadingZeros64(uint64(n))
	bstCopyInner(fn, n, 0, e, 0)
}

func bstCopyInner(fn func(src, dst int), n, o, e, i int) {
	p := 1 << e
	t := p + (p >> 1) - 1
	var m int
	if n > t {
		m = p - 1
	} else {
		m = p - 1 - (t - n)
	}
	fn(o+m, i)
	if m > 0 {
		bstCopyInner(fn, m, o, e-1, i*2+1)
	}
	if m+1 < n {
		bstCopyInner(fn, n-m-1, o+m+1, e-1, i*2+2)
	}
}
