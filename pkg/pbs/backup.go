package pbs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// SnapshotRef identifies a snapshot (backup group + time) inside a datastore namespace.
type SnapshotRef struct {
	Store string
	NS    string // namespace path, "" for root
	Type  string // "host", "vm" or "ct"; Windows PCs use "host"
	ID    string
	Time  int64 // unix epoch seconds
}

func (r SnapshotRef) params() map[string]any {
	p := map[string]any{
		"store":       r.Store,
		"backup-type": r.Type,
		"backup-id":   r.ID,
		"backup-time": r.Time,
	}
	if r.NS != "" {
		p["ns"] = r.NS
	}
	return p
}

// String renders the snapshot like PBS: "host/pc-01/2026-10-12T09:30:00Z".
func (r SnapshotRef) String() string {
	return fmt.Sprintf("%s/%s/%s", r.Type, r.ID, time.Unix(r.Time, 0).UTC().Format(time.RFC3339))
}

var archiveNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._\-]*\.(pxar|mpxar|ppxar|img|conf|log|json|pcat1)\.(didx|fidx|blob)$`)

// ValidArchiveName reports whether name is acceptable to the PBS server.
func ValidArchiveName(name string) bool { return archiveNameRe.MatchString(name) }

// BackupOptions tune a backup session.
type BackupOptions struct {
	Crypt *CryptConfig
	// Compress chunks with zstd (default true via NewBackupOptions).
	Compress bool
	// Concurrency is the number of chunks hashed/compressed/uploaded in parallel.
	Concurrency int
	// Debug asks the server to log verbosely into the backup task log.
	Debug bool
	// OnUpload, if set, is called with the encoded size of every chunk sent,
	// as it is sent (for live progress; Stats only arrive when an archive closes).
	OnUpload func(encodedBytes int)
}

// FileInfo is one entry in the snapshot manifest.
type FileInfo struct {
	Filename  string `json:"filename"`
	CryptMode string `json:"crypt-mode"`
	Size      uint64 `json:"size"`
	Csum      string `json:"csum"`
}

// Stats summarise what an archive upload did.
type Stats struct {
	Size          uint64 // logical archive size
	Chunks        int
	NewChunks     int
	ReusedChunks  int
	UploadedBytes uint64 // encoded bytes sent over the wire
	Duration      time.Duration
}

// BackupSession is an open PBS backup writer session.
type BackupSession struct {
	sess  *h2Session
	ref   SnapshotRef
	opts  BackupOptions
	mu    sync.Mutex
	files []FileInfo
	// known holds digests the server already has (from previous indexes or uploaded this session).
	known map[[32]byte]struct{}
	done  bool
}

// StartBackup opens a backup session for ref. ref.Time must be newer than the
// last snapshot in the group.
func (c *Client) StartBackup(ctx context.Context, ref SnapshotRef, opts BackupOptions) (*BackupSession, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	params := ref.params()
	if opts.Debug {
		params["debug"] = true
	}
	s, err := c.upgrade(ctx, "backup", params, protocolBackupV1)
	if err != nil {
		return nil, err
	}
	return &BackupSession{sess: s, ref: ref, opts: opts, known: map[[32]byte]struct{}{}}, nil
}

// Ref returns the snapshot this session writes.
func (b *BackupSession) Ref() SnapshotRef { return b.ref }

func (b *BackupSession) cryptMode() string {
	if b.opts.Crypt != nil {
		return "encrypt"
	}
	return "none"
}

// PreviousBackupTime returns the time of the last snapshot in the group, if any.
func (b *BackupSession) PreviousBackupTime(ctx context.Context) (int64, bool, error) {
	var t *int64
	if err := b.sess.call(ctx, http.MethodGet, "previous_backup_time", nil, nil, "", &t); err != nil {
		return 0, false, err
	}
	if t == nil {
		return 0, false, nil
	}
	return *t, true, nil
}

// LoadPreviousIndex downloads archive from the previous snapshot. This both
// registers its chunks on the server and lets us skip re-uploading them.
// Returns false if there is no previous snapshot/archive.
func (b *BackupSession) LoadPreviousIndex(ctx context.Context, archive string) (bool, error) {
	data, err := b.sess.download(ctx, "previous", map[string]any{"archive-name": archive})
	if err != nil {
		if IsNotFound(err) {
			return false, nil
		}
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusBadRequest {
			return false, nil // archive missing in previous snapshot
		}
		return false, err
	}
	idx, err := ParseIndex(data)
	if err != nil {
		return false, fmt.Errorf("pbs: previous index %s: %w", archive, err)
	}
	b.mu.Lock()
	for _, e := range idx.Entries {
		b.known[e.Digest] = struct{}{}
	}
	b.mu.Unlock()
	return true, nil
}

// UploadBlob stores a small file (< 128 MiB) like index.json.blob or client.log.blob.
func (b *BackupSession) UploadBlob(ctx context.Context, name string, data []byte, encrypt bool) error {
	var crypt *CryptConfig
	if encrypt {
		crypt = b.opts.Crypt
	}
	raw, err := EncodeBlob(data, crypt, true)
	if err != nil {
		return err
	}
	params := map[string]any{"file-name": name, "encoded-size": len(raw)}
	if err := b.sess.call(ctx, http.MethodPost, "blob", params, raw, "application/octet-stream", nil); err != nil {
		return err
	}
	mode := "none"
	if crypt != nil {
		mode = "encrypt"
	}
	b.addFile(FileInfo{Filename: name, CryptMode: mode, Size: uint64(len(raw)), Csum: sha256Hex(raw)})
	return nil
}

func (b *BackupSession) addFile(fi FileInfo) {
	b.mu.Lock()
	b.files = append(b.files, fi)
	b.mu.Unlock()
}

// Finish uploads the manifest and commits the snapshot. Without Finish the
// server discards everything when the connection closes.
func (b *BackupSession) Finish(ctx context.Context) error {
	b.mu.Lock()
	manifest := map[string]any{
		"backup-type": b.ref.Type,
		"backup-id":   b.ref.ID,
		"backup-time": b.ref.Time,
		"files":       b.files,
		"unprotected": map[string]any{},
		"signature":   nil,
	}
	b.mu.Unlock()
	if b.opts.Crypt != nil {
		return errors.New("pbs: manifest signing for encrypted backups is not implemented yet")
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw, err := EncodeBlob(data, nil, true)
	if err != nil {
		return err
	}
	params := map[string]any{"file-name": "index.json.blob", "encoded-size": len(raw)}
	if err := b.sess.call(ctx, http.MethodPost, "blob", params, raw, "application/octet-stream", nil); err != nil {
		return fmt.Errorf("pbs: upload manifest: %w", err)
	}
	if err := b.sess.call(ctx, http.MethodPost, "finish", nil, nil, "", nil); err != nil {
		return fmt.Errorf("pbs: finish: %w", err)
	}
	b.done = true
	return nil
}

// Close tears down the session. If Finish was not called the snapshot is discarded.
func (b *BackupSession) Close() error { return b.sess.Close() }

// ArchiveWriter streams one archive into a dynamic (.didx) or fixed (.fidx) index.
type ArchiveWriter struct {
	b       *BackupSession
	ctx     context.Context
	cancel  context.CancelFunc
	name    string
	dynamic bool
	wid     int

	chunker *Chunker
	buf     []byte
	offset  uint64

	order   chan *chunkJob
	sem     chan struct{}
	applied chan error
	errOnce sync.Once
	err     atomic.Value

	csum  *IndexCsum
	stats Stats
	start time.Time
}

type chunkJob struct {
	offset uint64
	size   uint64
	data   []byte
	digest [32]byte
	isNew  bool
	encLen int
	err    error
	done   chan struct{}
}

// NewDynamicArchive starts a .didx archive (e.g. "c-users.pxar.didx"). Data written
// is split with the buzhash chunker.
func (b *BackupSession) NewDynamicArchive(ctx context.Context, name string) (*ArchiveWriter, error) {
	if !ValidArchiveName(name) || len(name) < 6 || name[len(name)-5:] != ".didx" {
		return nil, fmt.Errorf("pbs: invalid dynamic archive name %q", name)
	}
	var wid int
	if err := b.sess.call(ctx, http.MethodPost, "dynamic_index", map[string]any{"archive-name": name}, nil, "", &wid); err != nil {
		return nil, err
	}
	w := b.newWriter(ctx, name, wid, true)
	w.chunker = NewChunker(DefaultChunkSize)
	return w, nil
}

// NewFixedArchive starts a .fidx archive of exactly size bytes (e.g. "drive-c.img.fidx").
func (b *BackupSession) NewFixedArchive(ctx context.Context, name string, size uint64) (*ArchiveWriter, error) {
	if !ValidArchiveName(name) || name[len(name)-5:] != ".fidx" {
		return nil, fmt.Errorf("pbs: invalid fixed archive name %q", name)
	}
	var wid int
	if err := b.sess.call(ctx, http.MethodPost, "fixed_index", map[string]any{"archive-name": name, "size": size}, nil, "", &wid); err != nil {
		return nil, err
	}
	return b.newWriter(ctx, name, wid, false), nil
}

func (b *BackupSession) newWriter(ctx context.Context, name string, wid int, dynamic bool) *ArchiveWriter {
	ctx, cancel := context.WithCancel(ctx)
	w := &ArchiveWriter{
		b: b, ctx: ctx, cancel: cancel, name: name, dynamic: dynamic, wid: wid,
		buf:     make([]byte, 0, FixedChunkSize),
		order:   make(chan *chunkJob, b.opts.Concurrency*2),
		sem:     make(chan struct{}, b.opts.Concurrency),
		applied: make(chan error, 1),
		csum:    NewIndexCsum(dynamic),
		start:   time.Now(),
	}
	go w.appendLoop()
	return w
}

func (w *ArchiveWriter) fail(err error) {
	w.errOnce.Do(func() {
		w.err.Store(err)
		w.cancel()
	})
}

func (w *ArchiveWriter) firstErr() error {
	if e, ok := w.err.Load().(error); ok {
		return e
	}
	return nil
}

// Write implements io.Writer.
func (w *ArchiveWriter) Write(p []byte) (int, error) {
	if err := w.firstErr(); err != nil {
		return 0, err
	}
	n := len(p)
	if !w.dynamic {
		for len(p) > 0 {
			k := min(FixedChunkSize-len(w.buf), len(p))
			w.buf = append(w.buf, p[:k]...)
			p = p[k:]
			if len(w.buf) == FixedChunkSize {
				if err := w.emit(); err != nil {
					return 0, err
				}
			}
		}
		return n, nil
	}
	for len(p) > 0 {
		k := w.chunker.Scan(p)
		if k == 0 {
			w.buf = append(w.buf, p...)
			break
		}
		w.buf = append(w.buf, p[:k]...)
		p = p[k:]
		if err := w.emit(); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// ReadFrom lets io.Copy stream efficiently into the archive.
func (w *ArchiveWriter) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 1<<20)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// emit hands the buffered chunk to the worker pool.
func (w *ArchiveWriter) emit() error {
	data := w.buf
	w.buf = make([]byte, 0, cap(w.buf))
	job := &chunkJob{offset: w.offset, size: uint64(len(data)), data: data, done: make(chan struct{})}
	w.offset += uint64(len(data))
	select {
	case w.order <- job:
	case <-w.ctx.Done():
		return w.ctxErr()
	}
	select {
	case w.sem <- struct{}{}:
	case <-w.ctx.Done():
		job.err = w.ctxErr()
		close(job.done)
		return job.err
	}
	go func() {
		defer func() { <-w.sem }()
		job.err = w.process(job)
		job.data = nil // release memory; only digest/size are needed from here on
		close(job.done)
	}()
	return nil
}

func (w *ArchiveWriter) ctxErr() error {
	if err := w.firstErr(); err != nil {
		return err
	}
	return w.ctx.Err()
}

func (w *ArchiveWriter) process(job *chunkJob) error {
	b := w.b
	job.digest = b.opts.Crypt.ComputeDigest(job.data)
	b.mu.Lock()
	_, known := b.known[job.digest]
	if !known {
		b.known[job.digest] = struct{}{} // reserve; later duplicates wait in append order
	}
	b.mu.Unlock()
	if known {
		return nil
	}
	raw, err := EncodeBlob(job.data, b.opts.Crypt, b.opts.Compress)
	if err != nil {
		return err
	}
	prefix := "dynamic"
	if !w.dynamic {
		prefix = "fixed"
	}
	params := map[string]any{
		"wid":          w.wid,
		"digest":       hex.EncodeToString(job.digest[:]),
		"size":         len(job.data),
		"encoded-size": len(raw),
	}
	if err := b.sess.call(w.ctx, http.MethodPost, prefix+"_chunk", params, raw, "application/octet-stream", nil); err != nil {
		b.mu.Lock()
		delete(b.known, job.digest)
		b.mu.Unlock()
		return err
	}
	job.isNew, job.encLen = true, len(raw)
	if b.opts.OnUpload != nil {
		b.opts.OnUpload(len(raw))
	}
	return nil
}

// appendLoop registers uploaded chunks with the index in stream order.
func (w *ArchiveWriter) appendLoop() {
	const batch = 128
	var digests []string
	var offsets []uint64
	prefix := "dynamic"
	if !w.dynamic {
		prefix = "fixed"
	}
	flush := func() error {
		if len(digests) == 0 {
			return nil
		}
		body, _ := json.Marshal(map[string]any{"wid": w.wid, "digest-list": digests, "offset-list": offsets})
		err := w.b.sess.call(w.ctx, http.MethodPut, prefix+"_index", nil, body, "application/json", nil)
		digests, offsets = digests[:0], offsets[:0]
		return err
	}
	var loopErr error
	for job := range w.order {
		<-job.done
		if loopErr != nil {
			continue // drain
		}
		if job.err != nil {
			loopErr = job.err
			w.fail(loopErr)
			continue
		}
		w.csum.Add(job.offset+job.size, job.digest)
		w.stats.Chunks++
		if job.isNew {
			w.stats.NewChunks++
			w.stats.UploadedBytes += uint64(job.encLen)
		} else {
			w.stats.ReusedChunks++
		}
		digests = append(digests, hex.EncodeToString(job.digest[:]))
		offsets = append(offsets, job.offset)
		if len(digests) >= batch {
			if err := flush(); err != nil {
				loopErr = err
				w.fail(err)
			}
		}
	}
	if loopErr == nil {
		loopErr = flush()
	}
	w.applied <- loopErr
}

// Close flushes the last chunk, waits for all uploads and closes the index on
// the server, recording the archive in the session manifest.
func (w *ArchiveWriter) Close() (Stats, error) {
	var err error
	if w.firstErr() == nil && len(w.buf) > 0 {
		err = w.emit()
	}
	close(w.order)
	if aerr := <-w.applied; err == nil {
		err = aerr
	}
	if err == nil {
		err = w.firstErr()
	}
	defer w.cancel()
	if err != nil {
		return w.stats, err
	}
	w.stats.Size = w.offset
	if w.stats.Chunks == 0 {
		return w.stats, fmt.Errorf("pbs: archive %s is empty", w.name)
	}
	prefix := "dynamic"
	if !w.dynamic {
		prefix = "fixed"
	}
	csum := w.csum.Sum()
	params := map[string]any{
		"wid":         w.wid,
		"chunk-count": w.stats.Chunks,
		"size":        w.stats.Size,
		"csum":        hex.EncodeToString(csum[:]),
	}
	if err := w.b.sess.call(w.ctx, http.MethodPost, prefix+"_close", params, nil, "", nil); err != nil {
		return w.stats, err
	}
	w.stats.Duration = time.Since(w.start)
	w.b.addFile(FileInfo{Filename: w.name, CryptMode: w.b.cryptMode(), Size: w.stats.Size, Csum: hex.EncodeToString(csum[:])})
	return w.stats, nil
}
