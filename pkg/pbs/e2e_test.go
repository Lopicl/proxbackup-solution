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
