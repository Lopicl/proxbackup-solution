// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"math/bits"
)

const (
	// DefaultChunkSize is the average dynamic chunk size used by proxmox-backup-client.
	DefaultChunkSize = 4 << 20
	// FixedChunkSize is the chunk size PBS uses for fixed (image) indexes.
	FixedChunkSize = 4 << 20

	chunkerWindowSize = 64
)

// Chunker is a port of the buzhash content-defined chunker in
// proxmox-backup pbs-datastore/src/chunker.rs. Using the identical algorithm
// and table means chunk boundaries (and therefore deduplication) match the
// official client.
type Chunker struct {
	h                uint32
	windowSize       int
	chunkSize        int
	chunkSizeMin     int
	chunkSizeMax     int
	breakTestMask    uint32
	breakTestMinimum uint32
	window           [chunkerWindowSize]byte
}

// NewChunker creates a chunker; avg must be a power of two.
func NewChunker(avg int) *Chunker {
	if bits.OnesCount(uint(avg)) != 1 {
		panic("pbs: chunk size must be a power of two")
	}
	mask := uint32(avg*2 - 1)
	return &Chunker{
		chunkSizeMin:     avg >> 2,
		chunkSizeMax:     avg << 2,
		breakTestMask:    mask,
		breakTestMinimum: mask - 2,
	}
}

func (c *Chunker) shallBreak() bool {
	if c.chunkSize >= c.chunkSizeMax {
		return true
	}
	if c.chunkSize < c.chunkSizeMin {
		return false
	}
	return c.h&c.breakTestMask >= c.breakTestMinimum
}

// Scan consumes data and returns the position just after a chunk boundary,
// or 0 if no boundary was found in data (all of data belongs to the current chunk).
func (c *Chunker) Scan(data []byte) int {
	pos := 0
	if c.windowSize < chunkerWindowSize {
		need := chunkerWindowSize - c.windowSize
		n := min(need, len(data))
		for range n {
			b := data[pos]
			c.window[c.windowSize] = b
			c.h = bits.RotateLeft32(c.h, 1) ^ buzhashTable[b]
			pos++
			c.windowSize++
		}
		c.chunkSize += n
		if c.windowSize < chunkerWindowSize {
			return 0
		}
	}
	idx := c.chunkSize & 0x3f
	for pos < len(data) {
		enter := data[pos]
		leave := c.window[idx]
		c.h = bits.RotateLeft32(c.h, 1) ^ buzhashTable[leave] ^ buzhashTable[enter]
		c.chunkSize++
		pos++
		c.window[idx] = enter
		if c.shallBreak() {
			c.Reset()
			return pos
		}
		idx = c.chunkSize & 0x3f
	}
	return 0
}

// Reset clears the rolling state, e.g. when forcing a boundary.
func (c *Chunker) Reset() {
	c.h, c.chunkSize, c.windowSize = 0, 0, 0
}

// ChunkStream splits r into content-defined chunks and calls fn for each.
// The slice passed to fn is only valid for the duration of the call.
func ChunkStream(r io.Reader, avg int, fn func(chunk []byte) error) error {
	ch := NewChunker(avg)
	buf := make([]byte, 0, avg*4+64<<10)
	readBuf := make([]byte, 256<<10)
	for {
		n, rerr := r.Read(readBuf)
		data := readBuf[:n]
		for len(data) > 0 {
			k := ch.Scan(data)
			if k == 0 {
				buf = append(buf, data...)
				break
			}
			buf = append(buf, data[:k]...)
			if err := fn(buf); err != nil {
				return err
			}
			buf = buf[:0]
			data = data[k:]
		}
		if rerr == io.EOF {
			if len(buf) > 0 {
				return fn(buf)
			}
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// IndexCsum accumulates the index checksum the server verifies on *_close.
// Dynamic: sha256(Σ end_offset_le64 || digest). Fixed: sha256(Σ digest).
type IndexCsum struct {
	h       hash.Hash
	dynamic bool
}

// NewIndexCsum creates a checksum accumulator for a dynamic or fixed index.
func NewIndexCsum(dynamic bool) *IndexCsum {
	return &IndexCsum{h: sha256.New(), dynamic: dynamic}
}

// Add records one chunk (endOffset is ignored for fixed indexes).
func (c *IndexCsum) Add(endOffset uint64, digest [32]byte) {
	if c.dynamic {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], endOffset)
		c.h.Write(b[:])
	}
	c.h.Write(digest[:])
}

// Sum returns the final checksum.
func (c *IndexCsum) Sum() [32]byte {
	var out [32]byte
	c.h.Sum(out[:0])
	return out
}
