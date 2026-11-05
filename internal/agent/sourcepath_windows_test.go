// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A junction on the way to a source, or standing for it, fails the source:
// a user who owns a folder there could otherwise point the backup at files
// they can't read and restore them from the tray.
func TestSourceRefusesJunctions(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	os.MkdirAll(filepath.Join(secret, "sub"), 0o755)
	os.WriteFile(filepath.Join(secret, "sub", "key.txt"), []byte("secret"), 0o644)
	mklinkJ(t, filepath.Join(dir, "docs"), secret)

	snaps := newSnapshotSet(false, func(string, string, ...any) {})
	for _, src := range []string{filepath.Join(dir, "docs"), filepath.Join(dir, "docs", "sub")} {
		if _, _, err := snaps.Source(src); err == nil || !strings.Contains(err.Error(), "junction") {
			t.Errorf("Source(%s) = %v, want a junction error", src, err)
		}
	}
	read, g, err := snaps.Source(filepath.Join(dir, "secret", "sub"))
	if err != nil {
		t.Fatalf("Source of a plain folder: %v", err)
	}
	if !g.live() || !strings.EqualFold(read, filepath.Join(dir, "secret", "sub")) {
		t.Errorf("Source = %q, live %v", read, g.live())
	}
}

// Without a snapshot, a folder swapped for a junction after it was listed is
// not read: the guard compares what was opened with where it was listed.
func TestSourceGuardDetectsSwap(t *testing.T) {
	dir := t.TempDir()
	src, outside := filepath.Join(dir, "src"), filepath.Join(dir, "outside")
	os.MkdirAll(filepath.Join(src, "a"), 0o755)
	os.MkdirAll(outside, 0o755)
	os.WriteFile(filepath.Join(src, "a", "f.txt"), []byte("mine"), 0o644)
	os.WriteFile(filepath.Join(outside, "f.txt"), []byte("not mine"), 0o644)

	_, g, err := newSnapshotSet(false, func(string, string, ...any) {}).Source(src)
	if err != nil {
		t.Fatal(err)
	}
	w := &walker{guard: g}
	if _, err := w.readDir(filepath.Join(src, "a")); err != nil {
		t.Fatalf("readDir before the swap: %v", err)
	}
	f, err := os.Open(filepath.Join(src, "a", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.checkFile(f, filepath.Join(src, "a", "f.txt")); err != nil {
		t.Errorf("checkFile before the swap: %v", err)
	}
	f.Close()

	if err := os.Rename(filepath.Join(src, "a"), filepath.Join(src, "a.old")); err != nil {
		t.Fatal(err)
	}
	mklinkJ(t, filepath.Join(src, "a"), outside)
	if _, err := w.readDir(filepath.Join(src, "a")); !errors.Is(err, errRedirected) {
		t.Errorf("readDir through the junction = %v, want errRedirected", err)
	}
	f, err = os.Open(filepath.Join(src, "a", "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := g.checkFile(f, filepath.Join(src, "a", "f.txt")); !errors.Is(err, errRedirected) {
		t.Errorf("checkFile through the junction = %v, want errRedirected", err)
	}
	var m winMeta
	if warns := readExtras(filepath.Join(src, "a", "f.txt"), &m, false, g); len(warns) == 0 || m.nt.sd != nil {
		t.Errorf("readExtras through the junction read %d bytes of security descriptor (warnings %q)", len(m.nt.sd), warns)
	}
}
