// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceExe(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	write := func(p, s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	read := func(p string) string {
		b, _ := os.ReadFile(p)
		return string(b)
	}

	// Fresh install: nothing to move aside.
	write(exe+".new", "v1")
	if err := ReplaceExe(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	if read(exe) != "v1" {
		t.Fatalf("exe = %q", read(exe))
	}

	// Replace: the previous binary is kept as .old.
	write(exe+".new", "v2")
	if err := ReplaceExe(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	if read(exe) != "v2" || read(exe+".old") != "v1" {
		t.Fatalf("exe = %q, old = %q", read(exe), read(exe+".old"))
	}

	// A missing new binary leaves exe in place.
	if err := ReplaceExe(exe+".missing", exe); err == nil {
		t.Fatal("want an error")
	}
	if read(exe) != "v2" {
		t.Fatalf("exe after failed replace = %q", read(exe))
	}
}
