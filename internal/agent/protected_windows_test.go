// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLoadProtected(t *testing.T) {
	pf, err := loadProtected()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramData"),
		strings.ToUpper(os.Getenv("SystemRoot")), os.Getenv("SystemDrive") + `\PROGRA~1`} {
		if _, err := os.Stat(p); err != nil {
			continue // no 8.3 names on this volume
		}
		if !pf.has(p) {
			t.Errorf("%s not protected", p)
		}
	}
	if pf.has(os.Getenv("SystemDrive") + `\`) {
		t.Error("drive root protected")
	}
	// The console only knows names; the agent recognizes the folder itself.
	short := os.Getenv("SystemDrive") + `\PROGRA~1`
	if _, err := os.Stat(short); err == nil {
		if r, err := openRestoreRoot(short+`\proxbackup-test`, pf); !errors.Is(err, errProtected) {
			if err == nil {
				r.Close()
			}
			t.Errorf("target below %s: %v", short, err)
		}
		if _, err := os.Stat(short + `\proxbackup-test`); err == nil {
			t.Errorf("%s\\proxbackup-test created", short)
		}
	}
}

// protectFolder returns protectedFolders holding only dir.
func protectFolder(t *testing.T, dir string) protectedFolders {
	t.Helper()
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(dir), windows.FILE_READ_ATTRIBUTES, shareAll, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	k, err := handleKey(h)
	if err != nil {
		t.Fatal(err)
	}
	return protectedFolders{k: dir}
}

// A target in a protected folder is refused before anything is created; a
// target above one gets everything but what would land in it.
func TestRestoreKeepsOutOfProtected(t *testing.T) {
	target := t.TempDir()
	prot := filepath.Join(target, "sub")
	if err := os.Mkdir(prot, 0o755); err != nil {
		t.Fatal(err)
	}
	pf := protectFolder(t, prot)

	if r, err := openRestoreRoot(filepath.Join(prot, "x"), pf); !errors.Is(err, errProtected) {
		if err == nil {
			r.Close()
		}
		t.Errorf("target in a protected folder: %v", err)
	}
	// By another name for the same folder.
	if short, err := shortName(prot); err == nil && short != prot {
		if r, err := openRestoreRoot(short, pf); !errors.Is(err, errProtected) {
			if err == nil {
				r.Close()
			}
			t.Errorf("target %s: %v", short, err)
		}
	}
	if _, err := os.Stat(filepath.Join(prot, "x")); err == nil {
		t.Error("target folder created in a protected folder")
	}

	j := restoreArchiveProtected(t, target, "overwrite", pf)
	if _, err := os.Stat(filepath.Join(prot, "file.txt")); err == nil {
		t.Error("restore wrote into a protected folder")
	}
	if j.skipped.Load() != 1 {
		t.Errorf("skipped = %d, want 1", j.skipped.Load())
	}
	if b, err := os.ReadFile(filepath.Join(target, "top.txt")); err != nil || string(b) != "new" {
		t.Errorf("top.txt = %q, %v", b, err)
	}

	// Protected by name: a missing Startup folder isn't created.
	sys, err := loadProtected()
	if err != nil {
		t.Fatal(err)
	}
	startup := os.Getenv("SystemDrive") + `\Users\proxbackup-test-nobody\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
	if r, err := openRestoreRoot(startup, sys); !errors.Is(err, errProtected) {
		if err == nil {
			r.Close()
		}
		t.Errorf("target %s: %v", startup, err)
	}
	if _, err := os.Stat(startup); err == nil {
		t.Errorf("%s created", startup)
	}
	os.RemoveAll(os.Getenv("SystemDrive") + `\Users\proxbackup-test-nobody`)
}

func shortName(p string) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(windows.StringToUTF16Ptr(p), &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// Files directly in a drive root (C:\Program.exe against an unquoted
// service path) are refused unless the restore may write system folders.
func TestRestoreKeepsFilesOutOfDriveRoot(t *testing.T) {
	pf, err := loadProtected()
	if err != nil {
		t.Fatal(err)
	}
	drive := os.Getenv("SystemDrive") + `\`
	r, err := openRestoreRoot(drive, pf)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Create("Program.exe", false); !errors.Is(err, errProtected) {
		t.Errorf("file in %s: %v", drive, err)
	}
	if err := r.Symlink("proxbackup-test-link", `C:\Windows`); !errors.Is(err, errProtected) {
		t.Errorf("link in %s: %v", drive, err)
	}
	if _, err := os.Lstat(drive + "Program.exe"); err == nil {
		t.Errorf("%sProgram.exe exists", drive)
	}
	// Below the root, and with system folders allowed, files are fine.
	dir := t.TempDir()
	sub, err := openRestoreRoot(dir, pf)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	f, err := sub.Create("file.txt", false)
	if err != nil {
		t.Fatalf("file below the root: %v", err)
	}
	f.Discard()
	free, err := openRestoreRoot(drive, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer free.Close()
	if err := free.checkRootFile(""); err != nil {
		t.Errorf("system folders allowed: %v", err)
	}
}
