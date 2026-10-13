// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

const indexHeaderSize = 4096

// IndexEntry is one chunk reference in an index file.
type IndexEntry struct {
	Start, End uint64
	Digest     [32]byte
}

// Index is a parsed .didx or .fidx file.
type Index struct {
	Dynamic   bool
	Size      uint64
	ChunkSize uint64 // fixed indexes only
	Csum      [32]byte
	Entries   []IndexEntry
}

// ParseIndex decodes a dynamic or fixed index file as stored by PBS.
//
//	didx: magic(8) uuid(16) ctime(8) csum(32) reserved(4032) | {end u64le, digest[32]}...
//	fidx: magic(8) uuid(16) ctime(8) csum(32) size(8) chunk_size(8) reserved(4016) | digest[32]...
func ParseIndex(data []byte) (*Index, error) {
	if len(data) < indexHeaderSize {
		return nil, errors.New("index too short")
	}
	idx := &Index{}
	copy(idx.Csum[:], data[32:64])
	body := data[indexHeaderSize:]
	switch {
	case bytes.Equal(data[:8], MagicDynamicIndex[:]):
		idx.Dynamic = true
		if len(body)%40 != 0 {
			return nil, errors.New("dynamic index has trailing bytes")
		}
		var start uint64
		for i := 0; i < len(body); i += 40 {
			e := IndexEntry{Start: start, End: binary.LittleEndian.Uint64(body[i:])}
			copy(e.Digest[:], body[i+8:i+40])
			if e.End < start {
				return nil, errors.New("dynamic index offsets not monotonic")
			}
			idx.Entries = append(idx.Entries, e)
			start = e.End
		}
		idx.Size = start
	case bytes.Equal(data[:8], MagicFixedIndex[:]):
		idx.Size = binary.LittleEndian.Uint64(data[64:72])
		idx.ChunkSize = binary.LittleEndian.Uint64(data[72:80])
		if idx.ChunkSize == 0 || len(body)%32 != 0 {
			return nil, errors.New("malformed fixed index")
		}
		for i, off := 0, uint64(0); i < len(body); i, off = i+32, off+idx.ChunkSize {
			e := IndexEntry{Start: off, End: min(off+idx.ChunkSize, idx.Size)}
			copy(e.Digest[:], body[i:i+32])
			idx.Entries = append(idx.Entries, e)
		}
	default:
		return nil, errors.New("unknown index magic")
	}
	return idx, nil
}

// ComputeCsum recomputes the index checksum (as the server does on close).
func (idx *Index) ComputeCsum() [32]byte {
	c := NewIndexCsum(idx.Dynamic)
	for _, e := range idx.Entries {
		c.Add(e.End, e.Digest)
	}
	return c.Sum()
}

// Find returns the entry index containing offset.
func (idx *Index) Find(offset uint64) (int, error) {
	if offset >= idx.Size {
		return 0, fmt.Errorf("offset %d beyond index size %d", offset, idx.Size)
	}
	i := sort.Search(len(idx.Entries), func(i int) bool { return idx.Entries[i].End > offset })
	return i, nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
