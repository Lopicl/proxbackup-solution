// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"proxbackup/pkg/pbs"
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
