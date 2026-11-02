// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

func needAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs administrator rights")
	}
}

func icacls(t *testing.T, p string, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", append([]string{p}, args...)...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %s %v: %v %s", p, args, err, out)
	}
}

// giveToUsers makes Users the owner of p, as if a standard user had created it.
func giveToUsers(t *testing.T, p string) {
	t.Helper()
	icacls(t, p, "/setowner", "*S-1-5-32-545")
}

func mklinkJ(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v %s", err, out)
	}
}

// openShared opens p for reading and writing, sharing everything, like the
// handles of a user who planted files in the data dir.
func openShared(t *testing.T, p string, disposition uint32) *os.File {
	t.Helper()
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), p)
	t.Cleanup(func() { f.Close() })
	return f
}

// Needs an elevated prompt (like the service): it sets Administrators as owner.
func TestSecureDataDir(t *testing.T) {
	needAdmin(t)
	base := t.TempDir()
	dir := filepath.Join(base, "data")
	outside := filepath.Join(base, "outside")
	os.MkdirAll(filepath.Join(dir, "spool"), 0o700)
	os.MkdirAll(filepath.Join(dir, "planted-dir", "sub"), 0o700)
	os.MkdirAll(outside, 0o700)
	os.WriteFile(filepath.Join(dir, "jobs.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "spool", "1.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "client.key.tmp"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "planted.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "planted-dir", "sub", "f"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(outside, "victim"), []byte("x"), 0o600)
	// A file of ours that only Users may access must be taken back.
	icacls(t, filepath.Join(dir, "jobs.json"), "/inheritance:r", "/grant:r", "*S-1-5-32-545:F")
	// Entries a user created must go, even if the user locked us out.
	giveToUsers(t, filepath.Join(dir, "planted.json"))
	giveToUsers(t, filepath.Join(dir, "planted-dir"))
	icacls(t, filepath.Join(dir, "planted-dir"), "/inheritance:r", "/grant:r", "*S-1-5-32-545:(OI)(CI)F")
	mklinkJ(t, filepath.Join(dir, "spool", "junction"), outside)
	if err := os.Link(filepath.Join(outside, "victim"), filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	victimBefore := sddlOf(t, filepath.Join(outside, "victim"))

	removed, err := SecureDataDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("removed %v", removed)
	want := []RemovedEntry{
		{filepath.Join(dir, "hardlink"), removedLink},
		{filepath.Join(dir, "planted-dir", "sub", "f"), removedForeign},
		{filepath.Join(dir, "planted-dir", "sub"), removedForeign},
		{filepath.Join(dir, "planted-dir"), removedForeign},
		{filepath.Join(dir, "planted.json"), removedForeign},
		{filepath.Join(dir, "spool", "junction"), removedLink},
	}
	if !slices.Equal(removed, want) {
		t.Errorf("removed %v, want %v", removed, want)
	}
	if got := sddlOf(t, dir); got != "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" {
		t.Errorf("data dir: %s", got)
	}
	for _, p := range []string{filepath.Join(dir, "jobs.json"), filepath.Join(dir, "spool", "1.json"), filepath.Join(dir, "client.key.tmp")} {
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

	// Files the agent writes afterwards inherit the same rights, and are
	// kept when the service starts; leftover temporary files are not.
	if err := writeSecret(filepath.Join(dir, "spool", "2.json"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if got := sddlOf(t, filepath.Join(dir, "spool", "2.json")); !strings.Contains(got, "(A;ID;FA;;;SY)(A;ID;FA;;;BA)") || strings.Contains(got, "S-1-5-32-545") || strings.Contains(got, ";BU)") {
		t.Errorf("new file: %s", got)
	}
	removed, err = SecureDataDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []RemovedEntry{{filepath.Join(dir, "client.key.tmp"), removedTemp}}; !slices.Equal(removed, want) {
		t.Errorf("at start: removed %v, want %v", removed, want)
	}
	for _, name := range []string{"jobs.json", `spool\1.json`, `spool\2.json`} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Error(err)
		}
	}

	// A data dir that is a junction is refused.
	link := filepath.Join(base, "link")
	mklinkJ(t, link, outside)
	if _, err := SecureDataDir(link, false); err == nil {
		t.Error("a junction was accepted as the data dir")
	}

	// A new data dir is created protected.
	fresh := filepath.Join(base, "fresh", "proxbackup")
	if _, err := SecureDataDir(fresh, false); err != nil {
		t.Fatal(err)
	}
	if got := sddlOf(t, fresh); !strings.HasPrefix(got, "O:BAD:P") || strings.Contains(got, ";BU)") {
		t.Errorf("fresh data dir: %s", got)
	}
}

// A data dir a user created is refused, and left as it is.
func TestSecureDataDirForeign(t *testing.T) {
	needAdmin(t)
	dir := filepath.Join(t.TempDir(), "data")
	os.Mkdir(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "agent.json"), []byte("{}"), 0o600)
	giveToUsers(t, dir)
	before := sddlOf(t, dir)
	_, err := SecureDataDir(dir, true)
	if err == nil || !strings.Contains(err.Error(), "not to SYSTEM or Administrators") {
		t.Fatalf("got %v", err)
	}
	t.Log(err)
	if got := sddlOf(t, dir); got != before {
		t.Errorf("changed a foreign data dir: %s became %s", before, got)
	}
}

func TestPrepareDataDir(t *testing.T) {
	needAdmin(t)
	base := t.TempDir()
	prepare := func(dir string) (aside, why string) {
		t.Helper()
		aside, why, err := PrepareDataDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		return aside, why
	}
	movedAside := func(dir, aside string) {
		t.Helper()
		if !strings.HasPrefix(aside, dir+".untrusted-") {
			t.Errorf("%s moved to %q", dir, aside)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Errorf("%s still exists: %v", dir, err)
		}
		if _, err := os.Lstat(aside); err != nil {
			t.Error(err)
		}
	}

	// Kept: missing, empty (an enrollment that failed), or enrolled.
	if aside, why := prepare(filepath.Join(base, "missing")); aside != "" || why != "" {
		t.Errorf("missing dir: %q %q", aside, why)
	}
	empty := filepath.Join(base, "empty")
	if _, err := SecureDataDir(empty, false); err != nil {
		t.Fatal(err)
	}
	if aside, why := prepare(empty); aside != "" || why != "" {
		t.Errorf("empty dir: %q %q", aside, why)
	}
	enrolled := filepath.Join(base, "enrolled")
	os.MkdirAll(filepath.Join(enrolled, "logs"), 0o700)
	os.WriteFile(filepath.Join(enrolled, "agent.json"), []byte("{}"), 0o600)
	if aside, why := prepare(enrolled); aside != "" || why != "" {
		t.Errorf("enrolled dir: %q %q", aside, why)
	}

	// Moved aside: files but no agent.json.
	noConfig := filepath.Join(base, "noconfig")
	os.MkdirAll(filepath.Join(noConfig, "logs"), 0o700)
	aside, why := prepare(noConfig)
	t.Logf("%s: %s", aside, why)
	movedAside(noConfig, aside)

	// Moved aside: a user's folder, with what they planted in it.
	foreign := filepath.Join(base, "foreign")
	os.Mkdir(foreign, 0o700)
	os.WriteFile(filepath.Join(foreign, "agent.json"), []byte("{}"), 0o600)
	giveToUsers(t, foreign)
	aside, why = prepare(foreign)
	t.Logf("%s: %s", aside, why)
	if !strings.Contains(why, "belongs to") {
		t.Errorf("why = %q", why)
	}
	movedAside(foreign, aside)
	if _, err := os.Stat(filepath.Join(aside, "agent.json")); err != nil {
		t.Error(err)
	}
	// The next enrollment gets a new one.
	if _, err := SecureDataDir(foreign, false); err != nil {
		t.Fatal(err)
	}

	// Moved aside: a junction, without touching its target.
	target := filepath.Join(base, "target")
	os.Mkdir(target, 0o700)
	os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600)
	junction := filepath.Join(base, "junction")
	mklinkJ(t, junction, target)
	aside, _ = prepare(junction)
	movedAside(junction, aside)
	if _, err := os.Stat(filepath.Join(target, "keep")); err != nil {
		t.Error(err)
	}

	// A user's folder with a file still open can't be moved: refused.
	held := filepath.Join(base, "held")
	os.Mkdir(held, 0o700)
	openShared(t, filepath.Join(held, "client.key.tmp"), windows.CREATE_NEW)
	giveToUsers(t, held)
	_, why, err := PrepareDataDir(held)
	t.Log(err)
	if err == nil || why == "" {
		t.Errorf("a held foreign dir was accepted: %q %v", why, err)
	}
	if _, err := os.Stat(held); err != nil {
		t.Error(err)
	}
}

// A handle opened on a planted temporary file before the dir was secured
// neither sees nor changes what writeSecret writes.
func TestWriteSecretPlantedHandle(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "client.key")
	planted := openShared(t, key+".tmp", windows.CREATE_NEW)
	if err := writeSecret(key, []byte("SECRET-KEY")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := planted.ReadAt(buf, 0)
	if strings.Contains(string(buf[:n]), "SECRET") {
		t.Fatalf("the planted handle read %q", buf[:n])
	}
	if _, err := planted.WriteAt([]byte("TAMPERED-BY-HANDLE"), 0); err != nil {
		t.Fatal(err)
	}
	if b, err := readSecret(key); err != nil || string(b) != "SECRET-KEY" {
		t.Fatalf("client.key = %q, %v", b, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, de := range entries {
		if de.Name() != "client.key" && de.Name() != "client.key.tmp" {
			t.Errorf("left %s behind", de.Name())
		}
	}
}

// readSecret refuses a file another program has open for writing.
func TestReadSecretOpenWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := writeSecret(p, []byte("CA")); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := readSecret(p); err != nil || string(b) != "CA" {
		t.Errorf("with a reader: %q, %v", b, err)
	}
	reader.Close()
	writer := openShared(t, p, windows.OPEN_EXISTING)
	_, err = readSecret(p)
	t.Log(err)
	if err == nil || !strings.Contains(err.Error(), "open for writing") {
		t.Errorf("with a writer: %v", err)
	}
	writer.Close()
	if _, err := readSecret(p); err != nil {
		t.Error(err)
	}
	if _, err := readSecret(p + ".missing"); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}
