// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfs

import (
	"errors"
	"fmt"
	"io"
)

// bitmapRef is the MFT record of $Bitmap, the cluster allocation bitmap.
const bitmapRef = 6

// Allocation tells which clusters of a volume are in use. Byte offsets are
// relative to the start of the volume (cluster 0 is at offset 0 on NTFS).
// Anything past the file system's last cluster, such as the backup boot
// sector, counts as in use.
type Allocation struct {
	clusterSize int64
	clusters    int64
	bits        []byte // bit i%8 of byte i/8 is set when cluster i is in use
}

// Allocation reads $Bitmap.
func (v *Volume) Allocation() (*Allocation, error) {
	if v.clusters <= 0 {
		return nil, errors.New("ntfs: boot sector reports no clusters")
	}
	f, err := v.Get(bitmapRef)
	if err != nil {
		return nil, fmt.Errorf("ntfs: $Bitmap: %w", err)
	}
	s, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("ntfs: $Bitmap: %w", err)
	}
	need := (v.clusters + 7) / 8
	if s.Size() < need {
		return nil, fmt.Errorf("ntfs: $Bitmap holds %d bytes, %d clusters need %d", s.Size(), v.clusters, need)
	}
	bits := make([]byte, need)
	if _, err := s.ReadAt(bits, 0); err != nil && err != io.EOF {
		return nil, fmt.Errorf("ntfs: $Bitmap: %w", err)
	}
	return &Allocation{clusterSize: v.clusterSize, clusters: v.clusters, bits: bits}, nil
}

// Size returns the size of the file system's clusters in bytes.
func (a *Allocation) Size() int64 { return a.clusters * a.clusterSize }

// ClusterSize returns the size of one cluster in bytes.
func (a *Allocation) ClusterSize() int64 { return a.clusterSize }

func (a *Allocation) used(c int64) bool {
	return c >= a.clusters || a.bits[c>>3]&(1<<(c&7)) != 0
}

// UsedBytes returns how many bytes of the file system's clusters are in use.
func (a *Allocation) UsedBytes() int64 {
	var n int64
	for c := int64(0); c < a.clusters; c++ {
		if a.bits[c>>3] == 0 && c&7 == 0 && c+8 <= a.clusters {
			c += 7
			continue
		}
		if a.used(c) {
			n++
		}
	}
	return n * a.clusterSize
}

// AnyUsed reports whether any byte in [off, off+n) lies in a used cluster.
func (a *Allocation) AnyUsed(off, n int64) bool {
	if n <= 0 {
		return false
	}
	first, last := off/a.clusterSize, (off+n-1)/a.clusterSize
	if last >= a.clusters {
		return true
	}
	for c := first; c <= last; c++ {
		if c&7 == 0 && c+7 <= last {
			if a.bits[c>>3] != 0 {
				return true
			}
			c += 7
			continue
		}
		if a.used(c) {
			return true
		}
	}
	return false
}

// ZeroFree clears the bytes of p (which holds the volume's data at off) that
// lie in free clusters.
func (a *Allocation) ZeroFree(p []byte, off int64) {
	cs := a.clusterSize
	for len(p) > 0 {
		c := off / cs
		n := int(min(int64(len(p)), (c+1)*cs-off))
		if !a.used(c) {
			clear(p[:n])
		}
		p, off = p[n:], off+int64(n)
	}
}
