// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func sddlOf(t *testing.T, p string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// Needs an elevated prompt (like the service): it sets Administrators as owner.
func TestSecureDataDir(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator rights")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "data")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(filepath.Join(dir, "spool"), 0o700)
	os.MkdirAll(outside, 0o700)
	os.WriteFile(filepath.Join(dir, "jobs.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "spool", "1.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(outside, "victim"), []byte("x"), 0o600)
	// A file owned by Users that only Users may access must be taken back.
	for _, args := range [][]string{{"/setowner", "*S-1-5-32-545"}, {"/inheritance:r", "/grant:r", "*S-1-5-32-545:F"}} {
		if out, err := exec.Command("icacls", append([]string{filepath.Join(dir, "jobs.json")}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v %s", err, out)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(dir, "spool", "junction"), outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if err := os.Link(filepath.Join(outside, "victim"), filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	victimBefore := sddlOf(t, filepath.Join(outside, "victim"))

	removed, err := SecureDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("removed %v", removed)
	if len(removed) != 2 {
		t.Errorf("removed %v, want the junction and the hard link", removed)
	}
	if got := sddlOf(t, dir); got != "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" {
		t.Errorf("data dir: %s", got)
	}
	for _, p := range []string{filepath.Join(dir, "jobs.json"), filepath.Join(dir, "spool", "1.json")} {
		if got := sddlOf(t, p); got != "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)" {
			t.Errorf("%s: %s", p, got)
		}
	}
	if got := sddlOf(t, filepath.Join(dir, "spool")); got != "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)" {
		t.Errorf("spool: %s", got)
	}
	if got := sddlOf(t, filepath.Join(outside, "victim")); got != victimBefore {
		t.Errorf("followed a link: %s became %s", victimBefore, got)
	}
	if _, err := os.Stat(filepath.Join(outside, "victim")); err != nil {
		t.Error(err)
	}

	// Files the agent writes afterwards inherit the same rights.
	if err := writeSecret(filepath.Join(dir, "spool", "2.json"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if got := sddlOf(t, filepath.Join(dir, "spool", "2.json")); !strings.Contains(got, "(A;ID;FA;;;SY)(A;ID;FA;;;BA)") || strings.Contains(got, "S-1-5-32-545") || strings.Contains(got, ";BU)") {
		t.Errorf("new file: %s", got)
	}

	// A data dir that is a junction is refused.
	link := filepath.Join(base, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
	if _, err := SecureDataDir(link); err == nil {
		t.Error("a junction was accepted as the data dir")
	}

	// A new data dir is created protected.
	fresh := filepath.Join(base, "fresh", "proxbackup")
	if _, err := SecureDataDir(fresh); err != nil {
		t.Fatal(err)
	}
	if got := sddlOf(t, fresh); !strings.HasPrefix(got, "O:BAD:P") || strings.Contains(got, ";BU)") {
		t.Errorf("fresh data dir: %s", got)
	}
}
