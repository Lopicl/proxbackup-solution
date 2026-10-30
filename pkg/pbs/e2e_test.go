// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs_test

// End-to-end test against a real Proxmox Backup Server. Skipped unless
// PROXBACKUP_E2E_HOST, PROXBACKUP_E2E_FINGERPRINT, PROXBACKUP_E2E_TOKEN_FILE and
// PROXBACKUP_E2E_STORE are set (see scripts/e2e-pbs.sh). With
// PROXBACKUP_E2E_USER and PROXBACKUP_E2E_PASSWORD_FILE instead of a token, the
// tests sign in as that user, as the console does (give it DatastoreAdmin on
// /datastore).

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
	if tok.TokenID = os.Getenv("PROXBACKUP_E2E_USER"); tok.TokenID != "" {
		b, err := os.ReadFile(os.Getenv("PROXBACKUP_E2E_PASSWORD_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		tok.Value = strings.TrimSpace(string(b))
	} else if b, err := os.ReadFile(os.Getenv("PROXBACKUP_E2E_TOKEN_FILE")); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(b, &tok); err != nil {
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

// TestE2EEncrypted writes client-side encrypted snapshots (signed manifest)
// and reads them back; PBS must verify them.
func TestE2EEncrypted(t *testing.T) {
	c, store := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ns := "proxbackup-e2e"
	if err := c.EnsureNamespace(ctx, store, ns); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("e2e-enc-%d", time.Now().UnixNano()%1e6)
	var key [32]byte
	copy(key[:], rnd(32, 99))
	crypt, err := pbs.NewCryptConfig(key)
	if err != nil {
		t.Fatal(err)
	}
	image := append(rnd(5<<20, 4), make([]byte, 3<<20)...)
	t0 := time.Now().Unix()
	run := func(variant int, at int64) pbs.Stats {
		b, err := c.StartBackup(ctx, pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: at}, pbs.BackupOptions{Crypt: crypt, Compress: true})
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		for _, a := range []string{"root.pxar.didx", "disk.img.fidx"} {
			if _, err := b.LoadPreviousIndex(ctx, a); err != nil {
				t.Fatal(err)
			}
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
		fw.Write(image)
		if _, err := fw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := b.UploadBlob(ctx, "client.log.blob", []byte("secret log\n"), true); err != nil {
			t.Fatal(err)
		}
		if err := b.Finish(ctx); err != nil {
			t.Fatal(err)
		}
		return st
	}
	run(1, t0)
	if st := run(2, t0+1); st.ReusedChunks == 0 {
		t.Fatalf("encrypted incremental backup reused nothing: %+v", st)
	}

	ref := pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: t0 + 1}
	r, err := c.StartReader(ctx, ref, crypt)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m, err := r.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Encrypted() || m.KeyFingerprint() != crypt.Fingerprint() || m.Signature == nil {
		t.Fatalf("manifest not signed/encrypted: %+v", m)
	}
	for _, f := range m.Files {
		if f.CryptMode != "encrypt" {
			t.Errorf("%s: crypt-mode %s", f.Filename, f.CryptMode)
		}
		if f.Filename == "root.pxar.didx" {
			idx, err := r.Index(ctx, f.Filename, &f)
			if err != nil {
				t.Fatal(err)
			}
			var want bytes.Buffer
			writeTree(t, &want, 2)
			got, err := io.ReadAll(r.OpenIndex(ctx, idx, 4))
			if err != nil || !bytes.Equal(got, want.Bytes()) {
				t.Fatalf("restored pxar differs: %v", err)
			}
		}
	}
	if log, err := r.Blob(ctx, "client.log.blob"); err != nil || string(log) != "secret log\n" {
		t.Fatalf("log blob: %q %v", log, err)
	}

	var other [32]byte
	copy(other[:], rnd(32, 98))
	wrong, _ := pbs.NewCryptConfig(other)
	r2, err := c.StartReader(ctx, ref, wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if _, err := r2.Manifest(ctx); err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("wrong key accepted: %v", err)
	}
	// Without a key the manifest names the key to read it with (the console
	// picks a client's current or old key this way), then verifies.
	r3, err := c.StartReader(ctx, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Close()
	if m, err := r3.Manifest(ctx); err != nil || m.KeyFingerprint() != crypt.Fingerprint() {
		t.Fatalf("manifest without key: %v, %v", m, err)
	}
	r3.SetCrypt(crypt)
	if _, err := r3.Manifest(ctx); err != nil {
		t.Fatalf("manifest verified after SetCrypt: %v", err)
	}
	if log, err := r3.Blob(ctx, "client.log.blob"); err != nil || string(log) != "secret log\n" {
		t.Fatalf("log blob after SetCrypt: %q %v", log, err)
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

// TestE2EProtected checks the lock window primitives: a protected snapshot
// survives prune (and doesn't count towards keep-last), and unprotecting a
// missing snapshot reports not found.
func TestE2EProtected(t *testing.T) {
	c, store := e2eClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ns := "proxbackup-e2e"
	if err := c.EnsureNamespace(ctx, store, ns); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("e2e-lock-%d", time.Now().UnixNano()%1e6)
	t0 := time.Now().Unix()
	for i := range int64(3) {
		b, err := c.StartBackup(ctx, pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: id, Time: t0 + i}, pbs.BackupOptions{Compress: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.UploadBlob(ctx, "client.log.blob", []byte("lock test\n"), false); err != nil {
			t.Fatal(err)
		}
		if err := b.Finish(ctx); err != nil {
			t.Fatal(err)
		}
		b.Close()
	}
	// Protect the oldest; keep-last 1 then keeps it plus the newest.
	if err := c.SetProtected(ctx, store, ns, "host", id, t0, true); err != nil {
		t.Fatal(err)
	}
	res, err := c.PruneGroup(ctx, store, ns, "host", id, pbs.KeepOptions{Last: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[int64]bool{}
	for _, p := range res {
		if p.Keep {
			kept[p.BackupTime] = true
		}
		if p.BackupTime == t0 && (!p.Protected || !p.Keep) {
			t.Fatalf("protected snapshot not kept: %+v", p)
		}
	}
	if len(kept) != 2 || !kept[t0] || !kept[t0+2] {
		t.Fatalf("prune result %+v", res)
	}
	snaps, err := c.ListSnapshots(ctx, store, ns, "host", id)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("snapshots after prune: %+v, %v", snaps, err)
	}
	for _, s := range snaps {
		if !s.Finished() {
			t.Fatalf("finished snapshot without manifest in the list: %+v", s)
		}
	}
	// Console retention forgets snapshots one by one; PBS refuses protected ones.
	if err := c.ForgetSnapshot(ctx, store, ns, "host", id, t0); err == nil {
		t.Fatal("forgot a protected snapshot")
	}
	if err := c.SetProtected(ctx, store, ns, "host", id, t0, false); err != nil {
		t.Fatal(err)
	}
	if err := c.SetProtected(ctx, store, ns, "host", id, t0+1, false); !pbs.IsNotFound(err) {
		t.Fatalf("unprotect of a pruned snapshot: %v (want not found)", err)
	}
	if res, err = c.PruneGroup(ctx, store, ns, "host", id, pbs.KeepOptions{Last: 1}, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range res {
		if p.BackupTime == t0 && p.Keep {
			t.Fatalf("unprotected snapshot still kept: %+v", p)
		}
	}
	if err := c.ForgetSnapshot(ctx, store, ns, "host", id, t0+2); err != nil {
		t.Fatal(err)
	}
	if snaps, err = c.ListSnapshots(ctx, store, ns, "host", id); err != nil || len(snaps) != 0 {
		t.Fatalf("snapshots after forget: %+v, %v", snaps, err)
	}
	c.Call(ctx, http.MethodDelete, "admin/datastore/"+store+"/groups", map[string]any{"ns": ns, "backup-type": "host", "backup-id": id}, nil)
}

// TestE2EProvisionAsUser runs the console's provisioning as an unprivileged
// user: it manages its own tokens and their ACLs, and the tokens never get
// more than the user has.
func TestE2EProvisionAsUser(t *testing.T) {
	c, store := e2eClient(t)
	user := os.Getenv("PROXBACKUP_E2E_USER")
	if user == "" {
		t.Skip("PROXBACKUP_E2E_USER not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var stores []struct {
		Store string `json:"store"`
	}
	if err := c.Call(ctx, http.MethodGet, "admin/datastore", nil, &stores); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range stores {
		found = found || s.Store == store
	}
	if !found {
		t.Fatalf("datastore %s not listed: %+v", store, stores)
	}
	if st, err := c.DatastoreStatus(ctx, store); err != nil || st.Total == 0 {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if _, err := c.DatastoreRRD(ctx, store, "day"); err != nil {
		t.Fatal(err)
	}

	ns := "proxbackup-e2e/prov"
	if err := c.EnsureNamespace(ctx, store, ns); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("e2e-%d", time.Now().UnixNano()%1e6)
	tokenID, secret, err := c.CreateToken(ctx, user, name, "proxbackup e2e")
	if err != nil {
		t.Fatal(err)
	}
	defer c.DeleteToken(context.WithoutCancel(ctx), user, name)
	if err := c.GrantACL(ctx, pbs.DatastoreACLPath(store, ns), "DatastoreBackup", tokenID); err != nil {
		t.Fatalf("ACL for its own token: %v", err)
	}
	if err := c.GrantACL(ctx, pbs.DatastoreACLPath(store, ns), "DatastoreBackup", "root@pam"); err == nil {
		t.Fatal("set an ACL for another auth id")
	}

	tokenClient := func(secret string) *pbs.Client {
		tc, err := pbs.NewClient(pbs.Config{Host: os.Getenv("PROXBACKUP_E2E_HOST"), Fingerprint: os.Getenv("PROXBACKUP_E2E_FINGERPRINT"), AuthID: tokenID, Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		return tc
	}
	// PBS applies new ACLs only after a few seconds, like agents see after
	// their enrollment.
	if err := tokenClient(secret).AwaitAccess(ctx, store, ns, 30*time.Second, nil); err != nil {
		t.Fatalf("token access to its namespace: %v", err)
	}
	backup := func(secret, ns string) error {
		tc := tokenClient(secret)
		b, err := tc.StartBackup(ctx, pbs.SnapshotRef{Store: store, NS: ns, Type: "host", ID: name, Time: time.Now().Unix()}, pbs.BackupOptions{})
		if err != nil {
			return err
		}
		defer b.Close()
		if err := b.UploadBlob(ctx, "client.log.blob", []byte("provision test\n"), false); err != nil {
			return err
		}
		return b.Finish(ctx)
	}
	if err := backup(secret, ns); err != nil {
		t.Fatalf("token backup in its namespace: %v", err)
	}
	if err := backup(secret, "proxbackup-e2e"); err == nil {
		t.Fatal("token backed up outside its namespace")
	}
	// A token is capped at its user's privileges, even with Admin on /.
	if err := c.GrantACL(ctx, "/", "Admin", tokenID); err != nil {
		t.Fatal(err)
	}
	tc := tokenClient(secret)
	// Wait for the new ACL, so the checks below don't pass only because PBS
	// hasn't applied it yet. Best effort: the token only gets the parent
	// namespace if its user has rights there.
	tc.AwaitAccess(ctx, store, "proxbackup-e2e", 15*time.Second, nil)
	if err := tc.Call(ctx, http.MethodGet, "access/users", nil, nil); err == nil {
		var users []map[string]any
		tc.Call(ctx, http.MethodGet, "access/users", nil, &users)
		if len(users) > 1 {
			t.Fatalf("token with Admin on / lists other users: %v", users)
		}
	}
	if err := tc.Call(ctx, http.MethodGet, "nodes/localhost/status", nil, nil); err == nil {
		t.Fatal("token with Admin on / reads the node status")
	}

	newSecret, err := c.RegenerateToken(ctx, user, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := backup(secret, ns); err == nil {
		t.Fatal("old secret still works after regenerate")
	}
	if err := backup(newSecret, ns); err != nil {
		t.Fatal(err)
	}
	c.Call(ctx, http.MethodDelete, "admin/datastore/"+store+"/namespace", map[string]any{"ns": ns, "delete-groups": true}, nil)
}
