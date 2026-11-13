// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Security descriptors. Since NTFS 3.0 a file's $STANDARD_INFORMATION holds a
// security ID, and the descriptors themselves are stored once each in the
// $SDS stream of $Secure (MFT record 9). Older volumes, and the odd file,
// keep their own in a $SECURITY_DESCRIPTOR attribute.

const (
	attrSecurityDescriptor = 0x50
	secureRef              = 9
	// $SDS is written in 256 KiB blocks, each followed by a mirror copy.
	sdsBlock = 256 << 10
	// Upper bound for one descriptor (a DACL is at most 64 KiB).
	maxSD = 1 << 17
)

// ErrNoSecurity is returned by SecurityDescriptor for a file without one.
var ErrNoSecurity = errors.New("ntfs: no security descriptor")

// SecurityDescriptor returns the file's security descriptor in self-relative
// form (owner, group, DACL and SACL as stored), as GetSecurityInfo would.
func (f *File) SecurityDescriptor() ([]byte, error) {
	if a := findAttr(f.attrs, attrSecurityDescriptor, ""); a != nil {
		if a.resident {
			return validSD(a.value)
		}
		s, err := f.v.newStream([]*attribute{a})
		if err != nil {
			return nil, err
		}
		if s.Size() > maxSD {
			return nil, errors.New("ntfs: security descriptor too large")
		}
		b := make([]byte, s.Size())
		if _, err := s.ReadAt(b, 0); err != nil {
			return nil, fmt.Errorf("ntfs: security descriptor: %w", err)
		}
		return validSD(b)
	}
	if f.securityID == 0 {
		return nil, ErrNoSecurity
	}
	if err := f.v.loadSDS(); err != nil {
		return nil, err
	}
	sd, ok := f.v.sds[f.securityID]
	if !ok {
		return nil, fmt.Errorf("ntfs: security ID %d not in $Secure", f.securityID)
	}
	return sd, nil
}

// loadSDS reads every descriptor in $Secure:$SDS once. Descriptors are never
// removed from it, and a volume has a few thousand at most.
func (v *Volume) loadSDS() error {
	if v.sds != nil || v.sdsErr != nil {
		return v.sdsErr
	}
	v.sdsErr = func() error {
		f, err := v.Get(secureRef)
		if err != nil {
			return fmt.Errorf("ntfs: $Secure: %w", err)
		}
		s, err := v.stream(f.attrs, attrData, "$SDS")
		if err != nil {
			return fmt.Errorf("ntfs: $Secure:$SDS: %w", err)
		}
		v.sds = map[uint32][]byte{}
		buf := make([]byte, sdsBlock)
		for b := int64(0); b < s.Size(); b += 2 * sdsBlock {
			blk := buf[:min(sdsBlock, s.Size()-b)]
			if _, err := s.ReadAt(blk, b); err != nil {
				return fmt.Errorf("ntfs: $Secure:$SDS: %w", err)
			}
			// Entries: hash, security ID, own offset in $SDS, length (with
			// this 20-byte header), the descriptor; 16-byte aligned. The
			// rest of a block after the last one is zero.
			for pos := 0; pos+20 <= len(blk); {
				id := binary.LittleEndian.Uint32(blk[pos+4:])
				off := int64(binary.LittleEndian.Uint64(blk[pos+8:]))
				n := int(binary.LittleEndian.Uint32(blk[pos+16:]))
				if n <= 20 || pos+n > len(blk) || off != b+int64(pos) {
					break
				}
				if sd, err := validSD(blk[pos+20 : pos+n]); err == nil {
					if _, dup := v.sds[id]; !dup {
						v.sds[id] = append([]byte(nil), sd...)
					}
				}
				pos += (n + 15) &^ 15
			}
		}
		return nil
	}()
	return v.sdsErr
}

// validSD checks that b looks like a self-relative security descriptor whose
// parts lie inside it, and returns it.
func validSD(b []byte) ([]byte, error) {
	if len(b) < 20 || b[0] != 1 || binary.LittleEndian.Uint16(b[2:])&0x8000 == 0 {
		return nil, errors.New("ntfs: malformed security descriptor")
	}
	for _, o := range []int{4, 8, 12, 16} {
		if off := binary.LittleEndian.Uint32(b[o:]); off != 0 && (off < 20 || int(off) >= len(b)) {
			return nil, errors.New("ntfs: malformed security descriptor")
		}
	}
	return b, nil
}
