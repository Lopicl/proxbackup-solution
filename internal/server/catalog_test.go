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
	load := func(context.Context) (*os.File, error) {
		loads.Add(1)
		return testCatalogFile(t), nil
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := cc.get(context.Background(), "a", load)
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
	fail := func(context.Context) (*os.File, error) { return nil, errNoCatalog }
	if _, err := cc.get(context.Background(), "b", fail); !errors.Is(err, errNoCatalog) {
		t.Fatalf("err = %v", err)
	}
	if _, err := cc.get(context.Background(), "b", load); err != nil {
		t.Fatalf("retry: %v", err)
	}

	// A panic while loading fails the request instead of the process.
	boom := func(context.Context) (*os.File, error) { panic("crafted catalog") }
	if _, err := cc.get(context.Background(), "p", boom); err == nil || !strings.Contains(err.Error(), "crafted catalog") {
		t.Fatalf("panic: err = %v", err)
	}

	// The least recently used catalog goes once too many are open.
	for i := range catalogMaxOpen + 2 {
		if _, err := cc.get(context.Background(), string(rune('c'+i)), load); err != nil {
			t.Fatal(err)
		}
	}
	if len(cc.entries) > catalogMaxOpen {
		t.Errorf("%d catalogs open", len(cc.entries))
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
