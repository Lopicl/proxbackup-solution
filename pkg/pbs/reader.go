// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ReaderSession is an open PBS reader (restore) session for one snapshot.
type ReaderSession struct {
	sess  *h2Session
	ref   SnapshotRef
	crypt *CryptConfig
}

// Manifest is the decoded index.json.blob of a snapshot.
type Manifest struct {
	BackupType  string          `json:"backup-type"`
	BackupID    string          `json:"backup-id"`
	BackupTime  int64           `json:"backup-time"`
	Files       []FileInfo      `json:"files"`
	Unprotected json.RawMessage `json:"unprotected,omitempty"`
	Signature   *string         `json:"signature"`
}

// StartReader opens a reader session for ref.
func (c *Client) StartReader(ctx context.Context, ref SnapshotRef, crypt *CryptConfig) (*ReaderSession, error) {
	s, err := c.upgrade(ctx, "reader", ref.params(), protocolReaderV1)
	if err != nil {
		return nil, err
	}
	return &ReaderSession{sess: s, ref: ref, crypt: crypt}, nil
}

// Close ends the session.
func (r *ReaderSession) Close() error { return r.sess.Close() }

// DownloadRaw fetches a file of the snapshot as stored (blob or index).
// Downloading an index also authorises fetching its chunks.
func (r *ReaderSession) DownloadRaw(ctx context.Context, name string) ([]byte, error) {
	return r.sess.download(ctx, "download", map[string]any{"file-name": name})
}

// Manifest downloads and decodes index.json.blob. With a crypt config, the
// signature of an encrypted snapshot's manifest is verified.
func (r *ReaderSession) Manifest(ctx context.Context) (*Manifest, error) {
	raw, err := r.DownloadRaw(ctx, "index.json.blob")
	if err != nil {
		return nil, err
	}
	// A manifest is a few KiB; the chunk limit keeps a crafted one from
	// expanding to the 128 MiB a blob may have.
	data, err := decodeChunk(raw, nil)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if err := verifyManifest(data, &m, r.crypt); err != nil {
		return nil, err
	}
	return &m, nil
}

// Blob downloads and decodes a .blob file.
func (r *ReaderSession) Blob(ctx context.Context, name string) ([]byte, error) {
	raw, err := r.DownloadRaw(ctx, name)
	if err != nil {
		return nil, err
	}
	return DecodeBlob(raw, r.crypt)
}

// Index downloads and parses an index, verifying it against the manifest entry when given.
func (r *ReaderSession) Index(ctx context.Context, name string, want *FileInfo) (*Index, error) {
	raw, err := r.DownloadRaw(ctx, name)
	if err != nil {
		return nil, err
	}
	idx, err := ParseIndex(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if want != nil {
		csum := idx.ComputeCsum()
		if hex.EncodeToString(csum[:]) != want.Csum || idx.Size != want.Size {
			return nil, fmt.Errorf("%s: index does not match manifest", name)
		}
	}
	return idx, nil
}

// Chunk downloads, decodes and verifies one chunk.
func (r *ReaderSession) Chunk(ctx context.Context, digest [32]byte) ([]byte, error) {
	raw, err := r.sess.download(ctx, "chunk", map[string]any{"digest": hex.EncodeToString(digest[:])})
	if err != nil {
		return nil, err
	}
	data, err := decodeChunk(raw, r.crypt)
	if err != nil {
		return nil, err
	}
	// Unencrypted chunks are addressed by plain sha256, even with a key loaded.
	crypt := r.crypt
	if !BlobIsEncrypted(raw) {
		crypt = nil
	}
	if crypt.ComputeDigest(data) != digest {
		return nil, errors.New("pbs: chunk digest mismatch")
	}
	return data, nil
}

// IndexReader exposes an index as a sequential io.Reader, prefetching chunks.
type IndexReader struct {
	ctx     context.Context
	r       *ReaderSession
	idx     *Index
	next    int
	cur     []byte
	futures chan *chunkFuture
	once    sync.Once
	cancel  context.CancelFunc
}

type chunkFuture struct {
	data []byte
	err  error
	done chan struct{}
}

// OpenIndex returns a streaming reader over an archive's contents.
func (r *ReaderSession) OpenIndex(ctx context.Context, idx *Index, prefetch int) *IndexReader {
	if prefetch <= 0 {
		prefetch = 4
	}
	ctx, cancel := context.WithCancel(ctx)
	ir := &IndexReader{ctx: ctx, r: r, idx: idx, futures: make(chan *chunkFuture, prefetch), cancel: cancel}
	go ir.fetchLoop()
	return ir
}

func (ir *IndexReader) fetchLoop() {
	defer close(ir.futures)
	for _, e := range ir.idx.Entries {
		f := &chunkFuture{done: make(chan struct{})}
		select {
		case ir.futures <- f:
		case <-ir.ctx.Done():
			return
		}
		go func(e IndexEntry) {
			f.data, f.err = ir.r.Chunk(ir.ctx, e.Digest)
			if f.err == nil && uint64(len(f.data)) != e.End-e.Start {
				f.err = fmt.Errorf("pbs: chunk size mismatch (%d != %d)", len(f.data), e.End-e.Start)
			}
			close(f.done)
		}(e)
	}
}

func (ir *IndexReader) Read(p []byte) (int, error) {
	for len(ir.cur) == 0 {
		f, ok := <-ir.futures
		if !ok {
			if err := ir.ctx.Err(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		<-f.done
		if f.err != nil {
			ir.Close()
			return 0, f.err
		}
		ir.cur = f.data
	}
	n := copy(p, ir.cur)
	ir.cur = ir.cur[n:]
	return n, nil
}

// Close stops prefetching.
func (ir *IndexReader) Close() error {
	ir.once.Do(ir.cancel)
	return nil
}

// IndexReaderAt gives random access to an archive's contents, for formats
// that are read out of order (file systems inside volume images). It keeps
// the most recently used chunks and reads a few chunks ahead of sequential
// access. Safe for concurrent use.
type IndexReaderAt struct {
	ctx       context.Context
	fetch     func(ctx context.Context, digest [32]byte) ([]byte, error)
	idx       *Index
	cacheSize int

	mu    sync.Mutex
	cache map[int]*chunkFuture
	lru   []int // chunk numbers, least recently used first
	last  int   // previously read chunk, to detect sequential access
}

// readAhead is how many chunks IndexReaderAt prefetches during sequential reads.
const readAhead = 2

// OpenIndexAt returns a random-access reader caching up to cacheChunks chunks.
func (r *ReaderSession) OpenIndexAt(ctx context.Context, idx *Index, cacheChunks int) *IndexReaderAt {
	return newIndexReaderAt(ctx, idx, cacheChunks, r.Chunk)
}

func newIndexReaderAt(ctx context.Context, idx *Index, cacheChunks int, fetch func(context.Context, [32]byte) ([]byte, error)) *IndexReaderAt {
	return &IndexReaderAt{ctx: ctx, fetch: fetch, idx: idx, cacheSize: max(cacheChunks, readAhead+2), cache: map[int]*chunkFuture{}, last: -2}
}

// Size returns the archive size.
func (ra *IndexReaderAt) Size() int64 { return int64(ra.idx.Size) }

// ReadAt implements io.ReaderAt.
func (ra *IndexReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("pbs: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := uint64(off) + uint64(n)
		if pos >= ra.idx.Size {
			return n, io.EOF
		}
		i, err := ra.idx.Find(pos)
		if err != nil {
			return n, err
		}
		data, err := ra.chunk(i)
		if err != nil {
			return n, err
		}
		n += copy(p[n:], data[pos-ra.idx.Entries[i].Start:])
	}
	return n, nil
}

func (ra *IndexReaderAt) chunk(i int) ([]byte, error) {
	ra.mu.Lock()
	f := ra.start(i)
	ra.touch(i) // before read-ahead, so it can't evict chunk i
	if i == ra.last+1 {
		for k := 1; k <= readAhead && i+k < len(ra.idx.Entries); k++ {
			ra.start(i + k)
		}
	}
	ra.last = i
	ra.mu.Unlock()
	<-f.done
	if f.err != nil {
		ra.mu.Lock()
		if ra.cache[i] == f { // retry on the next read
			delete(ra.cache, i)
		}
		ra.mu.Unlock()
	}
	return f.data, f.err
}

// start returns the cached or in-flight fetch of chunk i, starting one if needed.
func (ra *IndexReaderAt) start(i int) *chunkFuture {
	if f, ok := ra.cache[i]; ok {
		return f
	}
	f := &chunkFuture{done: make(chan struct{})}
	ra.cache[i] = f
	ra.lru = append(ra.lru, i)
	e := ra.idx.Entries[i]
	go func() {
		f.data, f.err = ra.fetch(ra.ctx, e.Digest)
		if f.err == nil && uint64(len(f.data)) != e.End-e.Start {
			f.err = fmt.Errorf("pbs: chunk size mismatch (%d != %d)", len(f.data), e.End-e.Start)
		}
		close(f.done)
	}()
	for len(ra.cache) > ra.cacheSize {
		old := ra.lru[0]
		ra.lru = ra.lru[1:]
		delete(ra.cache, old)
	}
	return f
}

// touch marks chunk i as most recently used.
func (ra *IndexReaderAt) touch(i int) {
	for k, c := range ra.lru {
		if c == i {
			ra.lru = append(append(ra.lru[:k:k], ra.lru[k+1:]...), i)
			return
		}
	}
}
