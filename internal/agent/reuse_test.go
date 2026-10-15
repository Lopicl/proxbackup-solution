// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

func TestComparePaths(t *testing.T) {
	// Depth first order: a directory, then its contents, then its next sibling.
	order := []string{"", "a", "a/b", "a/b/c", "a/c", "a b", "a-b", "b"}
	for i := range order {
		for k := range order {
			got := comparePaths(order[i], order[k])
			if (got < 0) != (i < k) || (got == 0) != (i == k) {
				t.Fatalf("comparePaths(%q, %q) = %d", order[i], order[k], got)
			}
		}
	}
}

type tfile struct {
	path  string
	data  []byte
	mtime int64
}

// chunkStore plays PBS: it stores chunks, and remembers the index of the
// last payload archive written (cs.indexes[payload stream]).
type chunkStore struct {
	chunks  map[[32]byte][]byte
	indexes map[string]*pbs.Index
}

func newChunkStore() *chunkStore {
	return &chunkStore{chunks: map[[32]byte][]byte{}, indexes: map[string]*pbs.Index{}}
}

// index returns the index under which payload was stored.
func (cs *chunkStore) index(t *testing.T, payload []byte) *pbs.Index {
	idx := cs.indexes[string(payload)]
	if idx == nil {
		t.Fatal("payload stream not stored")
	}
	return idx
}

// payloadBuf is a payload archive writer like pbs.ArchiveWriter: written data
// is chunked by content, InjectChunks forces a boundary and appends chunks.
type payloadBuf struct {
	bytes.Buffer
	cs  *chunkStore
	ch  *pbs.Chunker
	cur []byte
	idx pbs.Index
}

func (p *payloadBuf) emit(c []byte) {
	d := sha256.Sum256(c)
	p.cs.chunks[d] = bytes.Clone(c)
	p.idx.Entries = append(p.idx.Entries, pbs.IndexEntry{Start: p.idx.Size, End: p.idx.Size + uint64(len(c)), Digest: d})
	p.idx.Size += uint64(len(c))
}

func (p *payloadBuf) Write(b []byte) (int, error) {
	p.Buffer.Write(b)
	for rest := b; len(rest) > 0; {
		k := p.ch.Scan(rest)
		if k == 0 {
			p.cur = append(p.cur, rest...)
			break
		}
		p.emit(append(p.cur, rest[:k]...))
		p.cur, rest = p.cur[:0], rest[k:]
	}
	return len(b), nil
}

func (p *payloadBuf) flush() {
	if len(p.cur) > 0 {
		p.emit(p.cur)
		p.cur = p.cur[:0]
	}
	p.ch.Reset()
}

func (p *payloadBuf) InjectChunks(es []pbs.IndexEntry) error {
	p.flush()
	for _, e := range es {
		p.Buffer.Write(p.cs.chunks[e.Digest])
		p.idx.Entries = append(p.idx.Entries, pbs.IndexEntry{Start: p.idx.Size, End: p.idx.Size + e.End - e.Start, Digest: e.Digest})
		p.idx.Size += e.End - e.Start
	}
	return nil
}

func fileMetaAt(mtime int64) pxar.Metadata {
	return pxar.Metadata{Mode: pxar.ModeIFREG | 0o644, MtimeSecs: mtime}
}

// writeSplit encodes files ("dir/name", sorted) as a split archive like the
// walker does, reusing unchanged files from prev when given.
func writeSplit(t *testing.T, files []tfile, cs *chunkStore, prevMeta []byte, prevIdx *pbs.Index) (meta, payload []byte, r *payloadReuse) {
	t.Helper()
	var mb bytes.Buffer
	pb := &payloadBuf{cs: cs, ch: pbs.NewChunker(16 << 10), idx: pbs.Index{Dynamic: true}}
	enc, err := pxar.NewSplitEncoder(&mb, pb, pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755})
	if err != nil {
		t.Fatal(err)
	}
	var tree *prevTree
	if prevMeta != nil {
		tree = newPrevTree(bytes.NewReader(prevMeta))
		r = &payloadReuse{w: pb, enc: enc, prev: prevIdx}
	}
	do := func(op func() error) {
		var err error
		if r != nil {
			err = r.do(op)
		} else {
			err = op()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := ""
	for _, f := range files {
		d, name, _ := strings.Cut(f.path, "/")
		if d != dir {
			if dir != "" {
				do(enc.FinishDir)
			}
			do(func() error { return enc.CreateDir([]byte(d), pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755}) })
			dir = d
		}
		m := fileMetaAt(f.mtime)
		addFile := func() error {
			_, err := enc.AddFile([]byte(name), m, uint64(len(f.data)), bytes.NewReader(f.data))
			return err
		}
		if tree != nil {
			if pe := tree.lookup(f.path); unchanged(pe, m, uint64(len(f.data))) {
				queued, err := r.queue(pe.PayloadOffset, uint64(len(f.data)), func(reuse bool) error {
					if !reuse {
						return addFile()
					}
					return r.ref([]byte(name), m, uint64(len(f.data)), pe.PayloadOffset)
				})
				if err != nil {
					t.Fatal(err)
				}
				if queued {
					continue
				}
			}
			if err := r.flush(); err != nil {
				t.Fatal(err)
			}
		}
		if err := addFile(); err != nil {
			t.Fatal(err)
		}
	}
	do(enc.FinishDir)
	if r != nil {
		if err := r.flush(); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if tree != nil && tree.err != nil {
		t.Fatal(tree.err)
	}
	pb.flush()
	cs.indexes[pb.String()] = &pb.idx
	return mb.Bytes(), pb.Bytes(), r
}

func readSplit(t *testing.T, meta, payload []byte) map[string][]byte {
	t.Helper()
	got := map[string][]byte{}
	dec := pxar.NewSplitDecoder(bytes.NewReader(meta), bytes.NewReader(payload))
	for {
		e, err := dec.Next()
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == pxar.KindFile {
			b, err := io.ReadAll(dec.Contents())
			if err != nil {
				t.Fatal(err)
			}
			got[e.Path] = b
		}
	}
}

func checkFiles(t *testing.T, files []tfile, got map[string][]byte) {
	t.Helper()
	if len(got) != len(files) || len(got) == 0 {
		t.Fatalf("%d files restored, want %d", len(got), len(files))
	}
	for _, f := range files {
		if !bytes.Equal(got[f.path], f.data) {
			t.Fatalf("%s: contents differ (%d vs %d bytes)", f.path, len(got[f.path]), len(f.data))
		}
	}
}

func TestPayloadReuseAcrossRuns(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	randData := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		return b
	}
	var files []tfile
	for i := range 2000 {
		files = append(files, tfile{fmt.Sprintf("d%02d/f%04d", i/40, i), randData(rng.IntN(20 << 10)), 1000})
	}
	cs := newChunkStore()
	meta, payload, _ := writeSplit(t, files, cs, nil, nil)
	checkFiles(t, files, readSplit(t, meta, payload))

	for run := range 10 {
		prevIdx := cs.index(t, payload)
		// Edit a few files, drop one, add one.
		for k := range 3 {
			i := rng.IntN(len(files))
			files[i].data = randData(len(files[i].data) + k)
			files[i].mtime++
		}
		files = slices.Delete(files, 10+run, 11+run)
		files = append(files, tfile{fmt.Sprintf("d%02d/g%04d", run, run), randData(5000), 1000})
		slices.SortFunc(files, func(a, b tfile) int { return strings.Compare(a.path, b.path) })

		var r *payloadReuse
		meta, payload, r = writeSplit(t, files, cs, meta, prevIdx)
		checkFiles(t, files, readSplit(t, meta, payload))
		if r.reusedFiles < uint64(len(files))*8/10 {
			t.Fatalf("run %d: only %d of %d files reused", run, r.reusedFiles, len(files))
		}
		if float64(r.waste) > reusePaddingThreshold*float64(len(payload)) {
			t.Fatalf("run %d: padding %d of %d bytes", run, r.waste, len(payload))
		}
		t.Logf("run %d: %d files reused, %d read again, %d chunks, padding %d of %d",
			run, r.reusedFiles, r.rereadFiles, r.chunks, r.waste, len(payload))
	}
}

func TestPayloadReuseSkipsChangedMetadata(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 8<<10)
	files := []tfile{{"d/a", []byte("aaaa"), 1}, {"d/b", big, 1}}
	cs := newChunkStore()
	meta, payload, _ := writeSplit(t, files, cs, nil, nil)
	files[0].data, files[0].mtime = []byte("AAAA"), 2
	// Same size and mtime: metadata says unchanged, so the old contents are kept.
	files[1].data = bytes.ToUpper(big)
	meta, payload, r := writeSplit(t, files, cs, meta, cs.index(t, payload))
	got := readSplit(t, meta, payload)
	if string(got["d/a"]) != "AAAA" || !bytes.Equal(got["d/b"], big) || r.reusedFiles != 1 {
		t.Fatalf("a=%q, b changed=%v, %d reused", got["d/a"], !bytes.Equal(got["d/b"], big), r.reusedFiles)
	}
}

func TestUnchangedComparesXattrs(t *testing.T) {
	m := fileMetaAt(5)
	m.Xattrs = []pxar.Xattr{{Name: []byte("user.b"), Value: []byte{1}}, {Name: []byte("user.a"), Value: []byte{2}}}
	prev := &pxar.Entry{Kind: pxar.KindFile, PayloadRef: true, Size: 3, Meta: m}
	prev.Meta.Xattrs = []pxar.Xattr{m.Xattrs[1], m.Xattrs[0]}
	if !unchanged(prev, m, 3) {
		t.Fatal("same xattrs in another order counted as a change")
	}
	m2 := m
	m2.Xattrs = []pxar.Xattr{m.Xattrs[0], {Name: []byte("user.a"), Value: []byte{3}}}
	if unchanged(prev, m2, 3) || unchanged(prev, m, 4) {
		t.Fatal("change not detected")
	}
}

// An unchanged tree must give an identical metadata archive (so it dedupes),
// and the payload must not grow from run to run. The previous run's tail
// marker stays in its last chunk, so the second run is 16 bytes longer once.
func TestPayloadReuseUnchangedIsStable(t *testing.T) {
	var files []tfile
	for i := range 50 {
		files = append(files, tfile{fmt.Sprintf("d/f%03d", i), bytes.Repeat([]byte{byte(i)}, 3000+i), 1})
	}
	cs := newChunkStore()
	meta, payload, _ := writeSplit(t, files, cs, nil, nil)
	sizes := []int{len(payload)}
	for range 3 {
		var m []byte
		var r *payloadReuse
		m, payload, r = writeSplit(t, files, cs, meta, cs.index(t, payload))
		if r.reusedFiles != 50 || !bytes.Equal(m, meta) {
			t.Fatalf("reused %d, metadata identical: %v", r.reusedFiles, bytes.Equal(m, meta))
		}
		meta = m
		sizes = append(sizes, len(payload))
	}
	if sizes[1] > sizes[0]+16 || sizes[3] != sizes[1] {
		t.Fatalf("payload sizes over runs: %v", sizes)
	}
}
