// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

func testCatalogFile(t *testing.T) *os.File {
	f, err := os.CreateTemp(t.TempDir(), "cat")
	if err != nil {
		t.Fatal(err)
	}
	w, _ := pbs.NewCatalogWriter(f)
	w.StartDirectory("c-users.pxar.didx")
	w.StartDirectory("alice")
	w.AddFile("notes.txt", 5, 1700000000)
	w.EndDirectory()
	w.EndDirectory()
	if err := w.Finish(); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCatalogCache(t *testing.T) {
	var cc catalogCache
	var loads atomic.Int32
	req := catalogReq{client: 1, who: "user 1"}
	load := func(context.Context, func(int64) error) (*os.File, error) {
		loads.Add(1)
		return testCatalogFile(t), nil
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := cc.get(context.Background(), "a", req, load)
			if err != nil {
				t.Error(err)
				return
			}
			es, err := r.ListDir("/c-users.pxar.didx/alice")
			if err != nil || len(es) != 1 || es[0].Name != "notes.txt" || es[0].Size != 5 {
				t.Errorf("ListDir = %+v, %v", es, err)
			}
		}()
	}
	wg.Wait()
	if n := loads.Load(); n != 1 {
		t.Errorf("loaded %d times, want 1", n)
	}

	// Failures aren't cached.
	fail := func(context.Context, func(int64) error) (*os.File, error) { return nil, errNoCatalog }
	if _, err := cc.get(context.Background(), "b", req, fail); !errors.Is(err, errNoCatalog) {
		t.Fatalf("err = %v", err)
	}
	if _, err := cc.get(context.Background(), "b", req, load); err != nil {
		t.Fatalf("retry: %v", err)
	}

	// A panic while loading fails the request instead of the process.
	boom := func(context.Context, func(int64) error) (*os.File, error) { panic("crafted catalog") }
	if _, err := cc.get(context.Background(), "p", req, boom); err == nil || !strings.Contains(err.Error(), "crafted catalog") {
		t.Fatalf("panic: err = %v", err)
	}

	// The least recently used catalog goes once too many are open.
	for i := range catalogMaxOpen + 2 {
		if _, err := cc.get(context.Background(), string(rune('c'+i)), req, load); err != nil {
			t.Fatal(err)
		}
	}
	if len(cc.entries) > catalogMaxOpen {
		t.Errorf("%d catalogs open", len(cc.entries))
	}
}

// Requests for many snapshots, given up before their catalogs loaded, start
// only a few loads; the others are refused until one ends.
func TestCatalogCacheLoadLimits(t *testing.T) {
	var cc catalogCache
	release := make(chan struct{})
	var running atomic.Int32
	slow := func(ctx context.Context, _ func(int64) error) (*os.File, error) {
		running.Add(1)
		defer running.Add(-1)
		<-release
		return testCatalogFile(t), nil
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	busy := 0
	for i := range 40 {
		_, err := cc.get(gone, fmt.Sprint("pc1-", i), catalogReq{client: 1, who: "pc 1"}, slow)
		if errors.Is(err, errCatalogBusy) {
			busy++
		} else if !errors.Is(err, context.Canceled) {
			t.Fatalf("get %d: %v", i, err)
		}
	}
	if busy != 40-catalogMaxClientLoads {
		t.Errorf("%d of 40 refused, want %d", busy, 40-catalogMaxClientLoads)
	}
	// Other clients share the global limit.
	for i := range 10 {
		cc.get(gone, fmt.Sprint("pc", i+2), catalogReq{client: int64(i + 2), who: fmt.Sprint("pc ", i+2)}, slow)
	}
	cc.mu.Lock()
	n := len(cc.entries)
	cc.mu.Unlock()
	if n != catalogMaxLoads {
		t.Errorf("%d loads started, want %d", n, catalogMaxLoads)
	}
	// A snapshot already loading is no new load.
	if _, err := cc.get(gone, "pc1-0", catalogReq{client: 1, who: "pc 1"}, slow); !errors.Is(err, context.Canceled) {
		t.Errorf("joining a load: %v", err)
	}
	close(release)
	for running.Load() > 0 {
		time.Sleep(time.Millisecond)
	}
	if _, err := cc.get(context.Background(), "pc1-0", catalogReq{client: 1, who: "pc 1"}, slow); err != nil {
		t.Errorf("after the loads: %v", err)
	}
	if _, err := cc.get(context.Background(), "pc1-new", catalogReq{client: 1, who: "pc 1"}, slow); err != nil {
		t.Errorf("new load after the loads: %v", err)
	}
}

// Each requester may start only so many loads; catalogs already loaded are free.
func TestCatalogCacheLoadRate(t *testing.T) {
	var cc catalogCache
	load := func(context.Context, func(int64) error) (*os.File, error) { return testCatalogFile(t), nil }
	me, other := catalogReq{client: 1, who: "pc 1"}, catalogReq{client: 1, who: "user 7"}
	for i := range catalogLoadsBurst {
		if _, err := cc.get(context.Background(), fmt.Sprint(i), me, load); err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
	}
	if _, err := cc.get(context.Background(), "more", me, load); !errors.Is(err, errCatalogRate) {
		t.Errorf("past the burst: %v", err)
	}
	if _, err := cc.get(context.Background(), fmt.Sprint(catalogLoadsBurst-1), me, load); err != nil {
		t.Errorf("cached catalog: %v", err)
	}
	if _, err := cc.get(context.Background(), "more", other, load); err != nil {
		t.Errorf("another requester: %v", err)
	}
}

// The temp files of all catalogs stay under catalogMaxBytes: a load evicts
// the least recently used catalogs, or fails if only loads hold the space.
func TestCatalogCacheBytes(t *testing.T) {
	var cc catalogCache
	req := catalogReq{client: 1, who: "user 1"}
	sized := func(n int64) catalogLoader {
		return func(_ context.Context, charge func(int64) error) (*os.File, error) {
			if err := charge(n); err != nil {
				return nil, err
			}
			return testCatalogFile(t), nil
		}
	}
	for _, k := range []string{"a", "b"} {
		if _, err := cc.get(context.Background(), k, req, sized(catalogMaxBytes/2)); err != nil {
			t.Fatal(err)
		}
	}
	cc.get(context.Background(), "b", req, nil) // a is now the least recently used
	if _, err := cc.get(context.Background(), "c", req, sized(1)); err != nil {
		t.Fatal(err)
	}
	if _, ok := cc.entries["a"]; ok || cc.entries["b"] == nil || cc.bytes != catalogMaxBytes/2+1 {
		t.Errorf("after c: a evicted %v, b kept %v, %d bytes", !ok, cc.entries["b"] != nil, cc.bytes)
	}

	// Space held by a load in progress isn't evicted.
	release := make(chan struct{})
	held := make(chan struct{})
	hold := func(_ context.Context, charge func(int64) error) (*os.File, error) {
		if err := charge(catalogMaxBytes - 10); err != nil {
			return nil, err
		}
		close(held)
		<-release
		return testCatalogFile(t), nil
	}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	cc.get(gone, "big", req, hold)
	<-held
	if _, err := cc.get(context.Background(), "d", catalogReq{client: 2, who: "user 2"}, sized(100)); !errors.Is(err, errCatalogFull) {
		t.Errorf("over the budget: %v", err)
	}
	close(release)
	if _, err := cc.get(context.Background(), "big", req, nil); err != nil {
		t.Fatal(err)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.bytes != catalogMaxBytes-10 || len(cc.entries) != 1 {
		t.Errorf("%d bytes in %d catalogs", cc.bytes, len(cc.entries))
	}
}

// A split archive's metadata stream becomes the same listing the agent's
// catalog had.
func TestBuildCatalogFromMetadata(t *testing.T) {
	dir := pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755, MtimeSecs: 1700000000}
	file := pxar.Metadata{Mode: pxar.ModeIFREG | 0o644, MtimeSecs: 1700000001}
	link := pxar.Metadata{Mode: pxar.ModeIFLNK | 0o777, MtimeSecs: 1700000002}
	archives := map[string][]byte{}
	for _, name := range []string{"c-users.mpxar.didx", "d-data.mpxar.didx"} {
		var m, p bytes.Buffer
		enc, err := pxar.NewSplitEncoder(&m, &p, dir)
		if err != nil {
			t.Fatal(err)
		}
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(enc.CreateDir([]byte("alice"), dir))
		must(enc.CreateDir([]byte("docs"), dir))
		_, err = enc.AddFile([]byte("a.txt"), file, 3, strings.NewReader("abc"))
		must(err)
		must(enc.FinishDir())
		must(enc.AddSymlink([]byte("link"), link, []byte("docs")))
		_, err = enc.AddFile([]byte("notes.txt"), file, 5, strings.NewReader("hello"))
		must(err)
		must(enc.FinishDir())
		_, err = enc.AddFile([]byte("top.txt"), file, 1, strings.NewReader("x"))
		must(err)
		must(enc.Close())
		archives[name] = m.Bytes()
	}
	files := []*pbs.FileInfo{{Filename: "c-users.mpxar.didx"}, {Filename: "d-data.mpxar.didx"}}
	f, err := os.CreateTemp(t.TempDir(), "cat")
	if err != nil {
		t.Fatal(err)
	}
	err = buildCatalog(f, files, func(fi *pbs.FileInfo, fn func(io.Reader) error) error {
		return fn(bytes.NewReader(archives[fi.Filename]))
	})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	r, err := pbs.NewCatalogReader(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	list := func(p string) string {
		es, err := r.ListDir(p)
		if err != nil {
			t.Fatalf("ListDir(%q): %v", p, err)
		}
		var out []string
		for _, e := range es {
			s := string(e.Type) + ":" + e.Name
			if e.Type == pbs.CatalogFile {
				s += fmt.Sprintf(":%d:%d", e.Size, e.Mtime)
			}
			out = append(out, s)
		}
		return strings.Join(out, " ")
	}
	for p, want := range map[string]string{
		"/":                              "d:c-users.mpxar.didx d:d-data.mpxar.didx",
		"/c-users.mpxar.didx":            "d:alice f:top.txt:1:1700000001",
		"/d-data.mpxar.didx/alice":       "d:docs l:link f:notes.txt:5:1700000001",
		"/d-data.mpxar.didx/alice/docs/": "f:a.txt:3:1700000001",
	} {
		if got := list(p); got != want {
			t.Errorf("ListDir(%q) = %q, want %q", p, got, want)
		}
	}
}
