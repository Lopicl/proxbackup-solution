// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestMagicsMatchUpstreamDerivation(t *testing.T) {
	cases := map[string][8]byte{
		"Proxmox Backup uncompressed blob v1.0":              MagicUncompressed,
		"Proxmox Backup zstd compressed blob v1.0":           MagicCompressed,
		"Proxmox Backup encrypted blob v1.0":                 MagicEncrypted,
		"Proxmox Backup zstd compressed encrypted blob v1.0": MagicEncrCompr,
		"Proxmox Backup fixed sized chunk index v1.0":        MagicFixedIndex,
		"Proxmox Backup dynamic sized chunk index v1.0":      MagicDynamicIndex,
		"Proxmox Backup Catalog file v1.0":                   MagicCatalogFile,
	}
	for s, want := range cases {
		sum := sha256.Sum256([]byte(s))
		if !bytes.Equal(sum[:8], want[:]) {
			t.Errorf("magic for %q: got %v want %v", s, sum[:8], want)
		}
	}
}

func randBytes(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func TestBlobRoundTrip(t *testing.T) {
	var key [32]byte
	copy(key[:], randBytes(32, 1))
	crypt, err := NewCryptConfig(key)
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{{}, []byte("hello"), bytes.Repeat([]byte("abc"), 100000), randBytes(1<<20, 2)}
	for _, in := range inputs {
		for _, c := range []*CryptConfig{nil, crypt} {
			for _, compress := range []bool{false, true} {
				raw, err := EncodeBlob(in, c, compress)
				if err != nil {
					t.Fatal(err)
				}
				out, err := DecodeBlob(raw, c)
				if err != nil {
					t.Fatalf("decode (crypt=%v compress=%v len=%d): %v", c != nil, compress, len(in), err)
				}
				if !bytes.Equal(in, out) {
					t.Fatalf("round trip mismatch (crypt=%v compress=%v len=%d)", c != nil, compress, len(in))
				}
				raw[len(raw)-1] ^= 0xff
				if len(in) > 0 {
					if _, err := DecodeBlob(raw, c); err == nil {
						t.Fatal("corrupted blob decoded without error")
					}
				}
			}
		}
	}
	// Compressible data must use the compressed magic.
	raw, _ := EncodeBlob(bytes.Repeat([]byte{0}, 4096), nil, true)
	if !bytes.Equal(raw[:8], MagicCompressed[:]) {
		t.Fatal("expected compressed magic")
	}
	// Random data must fall back to uncompressed.
	raw, _ = EncodeBlob(randBytes(4096, 3), nil, true)
	if !bytes.Equal(raw[:8], MagicUncompressed[:]) {
		t.Fatal("expected uncompressed magic")
	}
}

func TestChunkerBoundsAndDeterminism(t *testing.T) {
	const avg = 64 << 10
	data := randBytes(8<<20, 4)
	var sizes []int
	err := ChunkStream(bytes.NewReader(data), avg, func(c []byte) error {
		sizes = append(sizes, len(c))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for i, s := range sizes {
		total += s
		if s > avg*4 {
			t.Fatalf("chunk %d too large: %d", i, s)
		}
		if i < len(sizes)-1 && s < avg/4 {
			t.Fatalf("chunk %d too small: %d", i, s)
		}
	}
	if total != len(data) {
		t.Fatalf("chunks cover %d bytes, want %d", total, len(data))
	}
	// Feeding in different block sizes must give identical boundaries.
	var sizes2 []int
	ch := NewChunker(avg)
	cur := 0
	for off := 0; off < len(data); {
		n := min(7919, len(data)-off)
		blk := data[off : off+n]
		for len(blk) > 0 {
			k := ch.Scan(blk)
			if k == 0 {
				cur += len(blk)
				break
			}
			sizes2 = append(sizes2, cur+k)
			cur = 0
			blk = blk[k:]
		}
		off += n
	}
	if cur > 0 {
		sizes2 = append(sizes2, cur)
	}
	if len(sizes) != len(sizes2) {
		t.Fatalf("boundary count differs: %d vs %d", len(sizes), len(sizes2))
	}
	for i := range sizes {
		if sizes[i] != sizes2[i] {
			t.Fatalf("boundary %d differs", i)
		}
	}
	// Content-defined: inserting a byte at the start only changes the first chunk(s).
	shifted := append([]byte{42}, data...)
	var sizes3 []int
	ChunkStream(bytes.NewReader(shifted), avg, func(c []byte) error { sizes3 = append(sizes3, len(c)); return nil })
	same := 0
	for i := 1; i <= min(len(sizes), len(sizes3))-1; i++ {
		if sizes[len(sizes)-i] == sizes3[len(sizes3)-i] {
			same++
		}
	}
	if same < len(sizes)/2 {
		t.Fatalf("chunker not content defined: only %d/%d trailing chunks resynced", same, len(sizes))
	}
}

func TestParseIndexAndCsum(t *testing.T) {
	// Build a didx by hand and check ParseIndex/ComputeCsum agree with IndexCsum.
	digests := [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))}
	ends := []uint64{100, 250}
	buf := make([]byte, indexHeaderSize)
	copy(buf, MagicDynamicIndex[:])
	c := NewIndexCsum(true)
	for i, d := range digests {
		var e [40]byte
		binary.LittleEndian.PutUint64(e[:], ends[i])
		copy(e[8:], d[:])
		buf = append(buf, e[:]...)
		c.Add(ends[i], d)
	}
	idx, err := ParseIndex(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !idx.Dynamic || idx.Size != 250 || len(idx.Entries) != 2 || idx.Entries[1].Start != 100 {
		t.Fatalf("bad parse: %+v", idx)
	}
	if idx.ComputeCsum() != c.Sum() {
		t.Fatal("csum mismatch")
	}
	if i, _ := idx.Find(150); i != 1 {
		t.Fatalf("Find(150) = %d", i)
	}
}

func TestFingerprintFormat(t *testing.T) {
	var s [32]byte
	s[0], s[31] = 0xab, 0x01
	f := FormatFingerprint(s)
	if len(f) != 95 || f[:3] != "ab:" || f[len(f)-2:] != "01" {
		t.Fatalf("bad fingerprint %q", f)
	}
	if NormalizeFingerprint(f) != NormalizeFingerprint(f[:]) || len(NormalizeFingerprint(f)) != 64 {
		t.Fatal("normalize failed")
	}
}

func TestArchiveNames(t *testing.T) {
	for _, ok := range []string{"c-users.pxar.didx", "drive-c.img.fidx", "index.json.blob", "client.log.blob"} {
		if !ValidArchiveName(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"-x.pxar.didx", "c users.pxar.didx", "x.didx", "x.pxar"} {
		if ValidArchiveName(bad) {
			t.Errorf("%s should be invalid", bad)
		}
	}
}

func TestIndexReaderAt(t *testing.T) {
	data := randBytes(10*1000+123, 7)
	chunks := map[[32]byte][]byte{}
	idx := &Index{Size: uint64(len(data)), ChunkSize: 1000}
	for off := 0; off < len(data); off += 1000 {
		c := data[off:min(off+1000, len(data))]
		d := sha256.Sum256(c)
		chunks[d] = c
		idx.Entries = append(idx.Entries, IndexEntry{Start: uint64(off), End: uint64(off + len(c)), Digest: d})
	}
	ra := newIndexReaderAt(t.Context(), idx, 4, func(_ context.Context, d [32]byte) ([]byte, error) {
		return chunks[d], nil
	})
	r := rand.New(rand.NewPCG(1, 2))
	for range 500 {
		off := r.IntN(len(data) + 10)
		buf := make([]byte, r.IntN(3000))
		n, err := ra.ReadAt(buf, int64(off))
		want := data[min(off, len(data)):min(off+len(buf), len(data))]
		if n != len(want) || !bytes.Equal(buf[:n], want) {
			t.Fatalf("ReadAt(%d, %d): got %d bytes", off, len(buf), n)
		}
		if (n < len(buf)) != (err == io.EOF) {
			t.Fatalf("ReadAt(%d, %d): n=%d err=%v", off, len(buf), n, err)
		}
	}
	// A sequential read fetches each chunk once, thanks to the cache.
	var seqFetches atomic.Int64
	ra = newIndexReaderAt(t.Context(), idx, 4, func(_ context.Context, d [32]byte) ([]byte, error) {
		seqFetches.Add(1)
		return chunks[d], nil
	})
	got, err := io.ReadAll(io.NewSectionReader(ra, 0, ra.Size()))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("sequential read: %v", err)
	}
	if n := seqFetches.Load(); n != int64(len(idx.Entries)) {
		t.Errorf("sequential read fetched %d chunks, want %d", n, len(idx.Entries))
	}
}

func TestZeroChunkDigestCache(t *testing.T) {
	crypt, err := NewCryptConfig([32]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*CryptConfig{nil, crypt} {
		b := &BackupSession{opts: BackupOptions{Crypt: c}, zeroDigests: map[int][32]byte{}}
		for _, n := range []int{FixedChunkSize, FixedChunkSize, 12345} {
			zero := make([]byte, n)
			if b.digest(zero) != c.ComputeDigest(zero) {
				t.Errorf("zero chunk of %d bytes: wrong digest", n)
			}
		}
		data := make([]byte, FixedChunkSize)
		data[len(data)-1] = 1
		if b.digest(data) != c.ComputeDigest(data) {
			t.Error("non-zero chunk: wrong digest")
		}
		if len(b.zeroDigests) != 2 {
			t.Errorf("cached %d sizes, want 2", len(b.zeroDigests))
		}
	}
}

// A chunk the client encrypted can hide a zstd bomb from PBS: decoding stops
// at the size limit instead of allocating whatever the frame expands to.
func TestBlobDecompressionLimit(t *testing.T) {
	var key [32]byte
	c, _ := NewCryptConfig(key)
	big := make([]byte, MaxChunkSize+1)

	// With and without a declared content size.
	frames := [][]byte{zstdEnc.EncodeAll(big, nil)}
	var buf bytes.Buffer
	zw, _ := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedFastest))
	zw.Write(big)
	zw.Close()
	frames = append(frames, buf.Bytes())
	for i, frame := range frames {
		for _, crypt := range []*CryptConfig{nil, c} {
			raw := rawCompressedBlob(t, frame, crypt)
			if _, err := decodeChunk(raw, crypt); err == nil {
				t.Errorf("frame %d, encrypted %v: oversized chunk decoded", i, crypt != nil)
			}
			if out, err := DecodeBlob(raw, crypt); err != nil || len(out) != len(big) {
				t.Errorf("frame %d, encrypted %v: blob: %d bytes, %v", i, crypt != nil, len(out), err)
			}
		}
	}
	ok, _ := EncodeBlob(big[:MaxChunkSize], c, true)
	if out, err := decodeChunk(ok, c); err != nil || len(out) != MaxChunkSize {
		t.Errorf("max size chunk: %d bytes, %v", len(out), err)
	}
}

// rawCompressedBlob wraps an already compressed payload as a blob.
func rawCompressedBlob(t *testing.T, payload []byte, crypt *CryptConfig) []byte {
	t.Helper()
	magic := MagicCompressed
	var out []byte
	if crypt != nil {
		magic = MagicEncrCompr
		var iv [16]byte
		sealed := crypt.gcm.Seal(nil, iv[:], payload, nil)
		out = make([]byte, encryptedBlobHeaderSize)
		copy(out[28:44], sealed[len(sealed)-16:])
		out = append(out, sealed[:len(sealed)-16]...)
	} else {
		out = append(make([]byte, blobHeaderSize), payload...)
	}
	copy(out, magic[:])
	binary.LittleEndian.PutUint32(out[8:12], crc32.ChecksumIEEE(out[headerSize(magic):]))
	return out
}
