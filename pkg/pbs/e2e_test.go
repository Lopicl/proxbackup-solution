// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs_test

// End-to-end test against a real Proxmox Backup Server. Skipped unless
// PROXBACKUP_E2E_HOST, PROXBACKUP_E2E_FINGERPRINT, PROXBACKUP_E2E_TOKEN_FILE and
// PROXBACKUP_E2E_STORE are set (see scripts/e2e-pbs.sh).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

func e2eClient(t *testing.T) (*pbs.Client, string) {
	host := os.Getenv("PROXBACKUP_E2E_HOST")
	if host == "" {
		t.Skip("PROXBACKUP_E2E_HOST not set")
	}
	var tok struct {
		TokenID string `json:"tokenid"`
		Value   string `json:"value"`
	}
	b, err := os.ReadFile(os.Getenv("PROXBACKUP_E2E_TOKEN_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &tok); err != nil {
		t.Fatal(err)
	}
	c, err := pbs.NewClient(pbs.Config{Host: host, Fingerprint: os.Getenv("PROXBACKUP_E2E_FINGERPRINT"), AuthID: tok.TokenID, Secret: tok.Value})
	if err != nil {
		t.Fatal(err)
	}
	return c, os.Getenv("PROXBACKUP_E2E_STORE")
}

type tfile struct {
	name string
	data []byte
}

func rnd(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 7))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// writeTree encodes a small tree; variant changes one file to test incremental reuse.
func writeTree(t *testing.T, w io.Writer, variant int) {
	dir := pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755, MtimeSecs: 1760000000}
	file := pxar.Metadata{Mode: pxar.ModeIFREG | 0o644, MtimeSecs: 1760000000}
	enc, err := pxar.NewEncoder(w, dir)
	if err != nil {
		t.Fatal(err)
	}
	add := func(name string, data []byte) {
		if _, err := enc.AddFile([]byte(name), file, uint64(len(data)), bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
	}
	add("Big.bin", rnd(12<<20, 1)) // several chunks
	if err := enc.CreateDir([]byte("Documents"), dir); err != nil {
		t.Fatal(err)
	}
	add("Notes.txt", []byte(fmt.Sprintf("hello from proxbackup, variant %d\n", variant)))
	if err := enc.CreateDir([]byte("Projects"), dir); err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		add(fmt.Sprintf("file-%02d.dat", i), rnd(1000+i*37, uint64(100+i)))
	}
	enc.FinishDir()
	enc.FinishDir()
	add("z-last.bin", rnd(3<<20, 2))
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestE2EBackupRestore(t *testing.T) {
	c, store := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if v, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("PBS version: %v", v["version"])
	}
	ns := "proxbackup-e2e"
	if err := c.EnsureNamespace(ctx, store, ns+"/sub"); err != nil {
		t.Fatal(err)
	}
	ns += "/sub"
	id := fmt.Sprintf("e2e-%d", time.Now().UnixNano()%1e6)
	image := append(rnd(9<<20, 3), make([]byte, 6<<20+12345)...) // random + zeros, unaligned tail

	run := func(variant int, at int64) pbs.Stats {
		ref := pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: at}
		b, err := c.StartBackup(ctx, ref, pbs.BackupOptions{Compress: true, Concurrency: 4})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		if _, err := b.LoadPreviousIndex(ctx, "root.pxar.didx"); err != nil {
			t.Fatal(err)
		}
		if _, err := b.LoadPreviousIndex(ctx, "disk.img.fidx"); err != nil {
			t.Fatal(err)
		}
		aw, err := b.NewDynamicArchive(ctx, "root.pxar.didx")
		if err != nil {
			t.Fatal(err)
		}
		writeTree(t, aw, variant)
		st, err := aw.Close()
		if err != nil {
			t.Fatal(err)
		}
		fw, err := b.NewFixedArchive(ctx, "disk.img.fidx", uint64(len(image)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(image); err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := b.UploadBlob(ctx, "client.log.blob", []byte("e2e log\n"), false); err != nil {
			t.Fatal(err)
		}
		if err := b.Finish(ctx); err != nil {
			t.Fatal(err)
		}
		t.Logf("backup %d: %+v", variant, st)
		return st
	}
	t0 := time.Now().Unix()
	st1 := run(1, t0)
	st2 := run(2, t0+1)
	if st1.NewChunks == 0 {
		t.Fatal("first backup uploaded nothing")
	}
	if st2.ReusedChunks == 0 || st2.NewChunks >= st1.NewChunks {
		t.Fatalf("incremental backup did not reuse chunks: %+v", st2)
	}

	// Restore second snapshot via the reader protocol.
	ref := pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: t0 + 1}
	r, err := c.StartReader(ctx, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m, err := r.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]pbs.FileInfo{}
	for _, f := range m.Files {
		files[f.Filename] = f
	}
	fi := files["root.pxar.didx"]
	idx, err := r.Index(ctx, "root.pxar.didx", &fi)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	writeTree(t, &want, 2)
	got, err := io.ReadAll(r.OpenIndex(ctx, idx, 4))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("restored pxar differs (%d vs %d bytes)", len(got), want.Len())
	}
	fi = files["disk.img.fidx"]
	fidx, err := r.Index(ctx, "disk.img.fidx", &fi)
	if err != nil {
		t.Fatal(err)
	}
	gotImg, err := io.ReadAll(r.OpenIndex(ctx, fidx, 4))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotImg, image) {
		t.Fatal("restored image differs")
	}
	log, err := r.Blob(ctx, "client.log.blob")
	if err != nil || string(log) != "e2e log\n" {
		t.Fatalf("log blob: %q %v", log, err)
	}

	// Let PBS's own pxar Accessor (goodbye-table lookups) extract a nested file.
	fp := base64.StdEncoding.EncodeToString([]byte("/root.pxar.didx/Documents/Projects/file-17.dat"))
	q := fmt.Sprintf("admin/datastore/%s/pxar-file-download?ns=%s&backup-type=host&backup-id=%s&backup-time=%d&filepath=%s",
		store, ns, id, t0+1, fp)
	body, err := rawGet(ctx, c, q)
	if err != nil {
		t.Fatalf("pxar-file-download: %v", err)
	}
	if !bytes.Equal(body, rnd(1000+17*37, 117)) {
		t.Fatalf("PBS returned wrong file contents (%d bytes)", len(body))
	}

	// Snapshot listing and server-side verification.
	snaps, err := c.ListSnapshots(ctx, store, ns, "host", id)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("list snapshots: %v %d", err, len(snaps))
	}
	var upid string
	if err := c.Call(ctx, http.MethodPost, "admin/datastore/"+store+"/verify",
		map[string]any{"ns": ns, "backup-type": "host", "backup-id": id}, &upid); err != nil {
		t.Fatal(err)
	}
	status := waitTask(ctx, t, c, upid)
	if status != "OK" {
		t.Fatalf("verify task: %s", status)
	}

	// Retention: keep-last 1 must remove the first snapshot.
	res, err := c.PruneGroup(ctx, store, ns, "host", id, pbs.KeepOptions{Last: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, p := range res {
		if p.Keep {
			kept++
		}
	}
	if kept != 1 || len(res) != 2 {
		t.Fatalf("prune result: %+v", res)
	}
}

func waitTask(ctx context.Context, t *testing.T, c *pbs.Client, upid string) string {
	for {
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		node := "localhost"
		if err := c.Call(ctx, http.MethodGet, "nodes/"+node+"/tasks/"+upid+"/status", nil, &st); err != nil {
			t.Fatal(err)
		}
		if st.Status == "stopped" {
			return st.ExitStatus
		}
		select {
		case <-ctx.Done():
			t.Fatal("task timeout")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// rawGet fetches a non-JSON API response using the client's auth and TLS settings.
func rawGet(ctx context.Context, c *pbs.Client, path string) ([]byte, error) {
	var buf bytes.Buffer
	err := c.Download(ctx, path, &buf)
	return buf.Bytes(), err
}

// splitTree is the tree of the split archive test, in encoding order.
func splitTree(variant int) []tfile {
	files := []tfile{{"Big.bin", rnd(12<<20, 1)}}
	for i := range 40 {
		files = append(files, tfile{fmt.Sprintf("Docs/file-%02d.dat", i), rnd(1000+i*37, uint64(100+i))})
	}
	return append(files, tfile{"z-last.txt", []byte(fmt.Sprintf("variant %d\n", variant))})
}

// writeSplitTree encodes splitTree(variant). With prev (the previous metadata
// archive and payload index), all files but the last are reused by injecting
// every chunk of the previous payload archive.
func writeSplitTree(t *testing.T, mw io.Writer, pw *pbs.ArchiveWriter, variant int, prevMeta []byte, prevIdx *pbs.Index) {
	dir := pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755, MtimeSecs: 1760000000}
	file := pxar.Metadata{Mode: pxar.ModeIFREG | 0o644, MtimeSecs: 1760000000}
	enc, err := pxar.NewSplitEncoder(mw, pw, dir)
	if err != nil {
		t.Fatal(err)
	}
	offsets := map[string]uint64{}
	var base uint64
	if prevMeta != nil {
		dec := pxar.NewDecoder(bytes.NewReader(prevMeta))
		for {
			e, err := dec.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			offsets[e.Path] = e.PayloadOffset
		}
		base = enc.PayloadPosition()
		if err := pw.InjectChunks(prevIdx.Entries); err != nil {
			t.Fatal(err)
		}
		enc.SkipPayload(prevIdx.Size)
	}
	inDocs := false
	files := splitTree(variant)
	for i, f := range files {
		name := f.name
		if d, n, ok := strings.Cut(f.name, "/"); ok {
			if !inDocs {
				if err := enc.CreateDir([]byte(d), dir); err != nil {
					t.Fatal(err)
				}
				inDocs = true
			}
			name = n
		} else if inDocs {
			enc.FinishDir()
			inDocs = false
		}
		if off, ok := offsets[f.name]; ok && i < len(files)-1 {
			err = enc.AddPayloadRef([]byte(name), file, uint64(len(f.data)), base+off)
		} else {
			_, err = enc.AddFile([]byte(name), file, uint64(len(f.data)), bytes.NewReader(f.data))
		}
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestE2ESplitArchiveReuse(t *testing.T) {
	c, store := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ns := "proxbackup-e2e"
	if err := c.EnsureNamespace(ctx, store, ns); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("e2e-split-%d", time.Now().UnixNano()%1e6)
	var prevMeta []byte
	run := func(variant int, at int64) (meta, payload pbs.Stats) {
		ref := pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: at}
		b, err := c.StartBackup(ctx, ref, pbs.BackupOptions{Compress: true, Concurrency: 4})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		if _, err := b.LoadPreviousIndex(ctx, "root.mpxar.didx"); err != nil {
			t.Fatal(err)
		}
		prevIdx, err := b.PreviousIndex(ctx, "root.ppxar.didx")
		if err != nil {
			t.Fatal(err)
		}
		mw, err := b.NewDynamicArchive(ctx, "root.mpxar.didx")
		if err != nil {
			t.Fatal(err)
		}
		pw, err := b.NewDynamicArchive(ctx, "root.ppxar.didx")
		if err != nil {
			t.Fatal(err)
		}
		var mbuf bytes.Buffer
		if prevIdx == nil {
			prevMeta = nil
		}
		writeSplitTree(t, io.MultiWriter(mw, &mbuf), pw, variant, prevMeta, prevIdx)
		prevMeta = mbuf.Bytes()
		if meta, err = mw.Close(); err != nil {
			t.Fatal(err)
		}
		if payload, err = pw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := b.Finish(ctx); err != nil {
			t.Fatal(err)
		}
		t.Logf("backup %d: meta %+v payload %+v", variant, meta, payload)
		return meta, payload
	}
	t0 := time.Now().Unix()
	run(1, t0)
	_, p2 := run(2, t0+1)
	if p2.ReusedChunks < 1 || p2.UploadedBytes > 4096 {
		t.Fatalf("second payload archive was not built from reused chunks: %+v", p2)
	}

	ref := pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: t0 + 1}
	r, err := c.StartReader(ctx, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m, err := r.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	open := func(name string) io.Reader {
		for _, f := range m.Files {
			if f.Filename == name {
				idx, err := r.Index(ctx, name, &f)
				if err != nil {
					t.Fatal(err)
				}
				return r.OpenIndex(ctx, idx, 4)
			}
		}
		t.Fatalf("%s missing", name)
		return nil
	}
	dec := pxar.NewSplitDecoder(open("root.mpxar.didx"), open("root.ppxar.didx"))
	want := map[string][]byte{}
	for _, f := range splitTree(2) {
		want[f.name] = f.data
	}
	n := 0
	for {
		e, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind != pxar.KindFile {
			continue
		}
		b, err := io.ReadAll(dec.Contents())
		if err != nil || !bytes.Equal(b, want[e.Path]) {
			t.Fatalf("%s: restored contents differ (%v)", e.Path, err)
		}
		n++
	}
	if n != len(want) {
		t.Fatalf("restored %d of %d files", n, len(want))
	}

	// PBS's own accessor must read our split archive: a reused file and the new one.
	for path, data := range map[string][]byte{"Docs/file-17.dat": want["Docs/file-17.dat"], "z-last.txt": want["z-last.txt"]} {
		fp := base64.StdEncoding.EncodeToString([]byte("/root.mpxar.didx/" + path))
		q := fmt.Sprintf("admin/datastore/%s/pxar-file-download?ns=%s&backup-type=host&backup-id=%s&backup-time=%d&filepath=%s",
			store, ns, id, t0+1, fp)
		body, err := rawGet(ctx, c, q)
		if err != nil {
			t.Fatalf("pxar-file-download %s: %v", path, err)
		}
		if !bytes.Equal(body, data) {
			t.Fatalf("PBS returned wrong contents for %s (%d bytes)", path, len(body))
		}
	}
	var upid string
	if err := c.Call(ctx, http.MethodPost, "admin/datastore/"+store+"/verify",
		map[string]any{"ns": ns, "backup-type": "host", "backup-id": id}, &upid); err != nil {
		t.Fatal(err)
	}
	if status := waitTask(ctx, t, c, upid); status != "OK" {
		t.Fatalf("verify task: %s", status)
	}
}
