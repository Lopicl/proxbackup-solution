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

// Manifest downloads and decodes index.json.blob.
func (r *ReaderSession) Manifest(ctx context.Context) (*Manifest, error) {
	raw, err := r.DownloadRaw(ctx, "index.json.blob")
	if err != nil {
		return nil, err
	}
	data, err := DecodeBlob(raw, nil)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
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
	data, err := DecodeBlob(raw, r.crypt)
	if err != nil {
		return nil, err
	}
	if r.crypt.ComputeDigest(data) != digest {
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
