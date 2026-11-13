// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// Symlink looks at the target only on a local drive and without following
// reparse points (a UNC target would make SYSTEM authenticate to it).
func TestPlainLocalDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(dir, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, sub).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if err := os.Mkdir(filepath.Join(sub, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		dir: true, sub: true, `C:\`: true, file: false, junction: false,
		filepath.Join(junction, "inner"): false, filepath.Join(dir, "missing"): false,
		`\\127.0.0.1\C$`: false, `\\?\` + sub: false, `\\?\UNC\127.0.0.1\C$`: false, `C:relative`: false,
	} {
		if got := plainLocalDir(p); got != want {
			t.Errorf("plainLocalDir(%s) = %v", p, got)
		}
	}
}

func TestRestoreSymlinkKind(t *testing.T) {
	needAdmin(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := openRestoreRoot(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for name, target := range map[string]string{"dirlink": "sub", "unclink": `\\127.0.0.1\C$`, "abslink": filepath.Join(dir, "sub")} {
		if err := r.Symlink(name, target); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, wantDir := range map[string]bool{"dirlink": true, "abslink": true, "unclink": false} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		isDir := fi.Sys().(*syscall.Win32FileAttributeData).FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if isDir != wantDir {
			t.Errorf("%s: directory link %v", name, isDir)
		}
	}
}

// A file restored with its own permissions is SYSTEM/Administrators only
// until SetSecurity; one without keeps the folder's inherited permissions.
func TestRestoreCreatePrivate(t *testing.T) {
	needAdmin(t)
	dir := t.TempDir()
	r, err := openRestoreRoot(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	dacl := func(e *restoreEntry) string {
		t.Helper()
		sd, err := windows.GetSecurityInfo(e.h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	f, err := r.Create("private.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := dacl(f); got != "D:P(A;;FA;;;SY)(A;;FA;;;BA)" {
		t.Errorf("private temp file: %s", got)
	}
	f.Discard()
	f, err = r.Create("plain.txt", false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Discard()
	if got := dacl(f); got == "D:P(A;;FA;;;SY)(A;;FA;;;BA)" || !strings.Contains(got, "ID;") {
		t.Errorf("plain temp file: %s", got)
	}
}
