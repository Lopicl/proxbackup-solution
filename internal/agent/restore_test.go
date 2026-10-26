// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"proxbackup/internal/api"
	"proxbackup/pkg/pxar"
)

func TestWithinDir(t *testing.T) {
	sep := string(filepath.Separator)
	root := filepath.Join(sep, "data", "restore")
	for target, want := range map[string]bool{
		root:                                   true,
		filepath.Join(root, "a", "b"):          true,
		filepath.Join(sep, "data", "restorex"): false,
		filepath.Join(sep, "data"):             false,
	} {
		if got := withinDir(root, target); got != want {
			t.Errorf("withinDir(%q, %q) = %v", root, target, got)
		}
	}
	// A filesystem/drive root ends in a separator already.
	if !withinDir(sep, filepath.Join(sep, "Users", "alice")) {
		t.Error("files below the root rejected")
	}
}

type nopReporter struct{}

func (nopReporter) Log(level, msg string) {}
func (nopReporter) Progress(api.Progress) {}

// linkDir makes link point to the folder target: a junction on Windows, the
// link standard users can create, else a symbolic link.
func linkDir(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink: %v %s", err, out)
		}
		return
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// restoreArchive restores a pxar archive holding sub/file.txt and top.txt
// into target.
func restoreArchive(t *testing.T, target, overwrite string) *job {
	t.Helper()
	var buf bytes.Buffer
	dm := pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755, MtimeSecs: 1700000000}
	fm := pxar.Metadata{Mode: pxar.ModeIFREG | 0o644, MtimeSecs: 1700000001}
	enc, err := pxar.NewEncoder(&buf, dm)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(enc.CreateDir([]byte("sub"), dm))
	_, err = enc.AddFile([]byte("file.txt"), fm, 7, strings.NewReader("payload"))
	must(err)
	must(enc.FinishDir())
	_, err = enc.AddFile([]byte("top.txt"), fm, 3, strings.NewReader("new"))
	must(err)
	must(enc.Close())

	j := &job{rep: nopReporter{}}
	root, err := openRestoreRoot(target)
	must(err)
	defer root.Close()
	must(j.restorePxar(context.Background(), root, pxar.NewDecoder(&buf), &api.RestoreSpec{TargetDir: target, Overwrite: overwrite}))
	return j
}

// A user who can write to the target replaces a restored folder with a link
// to a system folder: the restore must not write there.
func TestRestoreDoesNotFollowLinks(t *testing.T) {
	target, outside := t.TempDir(), t.TempDir()
	linkDir(t, outside, filepath.Join(target, "sub"))
	j := restoreArchive(t, target, "overwrite")
	if _, err := os.Stat(filepath.Join(outside, "file.txt")); err == nil {
		t.Fatal("restore wrote through a link in the target")
	}
	if j.skipped.Load() == 0 {
		t.Error("linked folder not reported as skipped")
	}
	if b, err := os.ReadFile(filepath.Join(target, "top.txt")); err != nil || string(b) != "new" {
		t.Errorf("top.txt = %q, %v", b, err)
	}
}

// A link to a file is replaced, not written through.
func TestRestoreReplacesFileLink(t *testing.T) {
	target, outside := t.TempDir(), t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("system"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(target, "top.txt")); err != nil {
		t.Skipf("symbolic links: %v", err)
	}
	restoreArchive(t, target, "overwrite")
	if b, _ := os.ReadFile(secret); string(b) != "system" {
		t.Fatalf("link target overwritten: %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(target, "top.txt")); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("top.txt not replaced by a file: %v %v", fi, err)
	}
}

// A symbolic link restored earlier (or a crafted archive's) is no path to
// write through either, and neither is a link in the target's own path.
func TestRestoreRootRefusesLinks(t *testing.T) {
	target, outside := t.TempDir(), t.TempDir()
	root, err := openRestoreRoot(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Symlink("a", outside); err != nil {
		t.Skipf("symbolic links: %v", err)
	}
	if err := root.MkdirAll(filepath.Join("a", "b")); !errors.Is(err, errNotFollowed) {
		t.Errorf("MkdirAll through a link: %v", err)
	}
	if f, err := root.Create(filepath.Join("a", "x")); !errors.Is(err, errNotFollowed) {
		if err == nil {
			f.Discard()
		}
		t.Errorf("Create through a link: %v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("wrote %v outside the target", entries)
	}

	if runtime.GOOS != "windows" {
		return // development builds follow links above the target (macOS's /var is one)
	}
	link := filepath.Join(t.TempDir(), "link")
	linkDir(t, outside, link)
	if r, err := openRestoreRoot(filepath.Join(link, "restore")); err == nil {
		r.Close()
		t.Error("target below a link accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "restore")); err == nil {
		t.Error("target folder created through a link")
	}
}
