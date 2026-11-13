// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"proxbackup/internal/api"
)

func TestPolicyDefaults(t *testing.T) {
	// A new install refuses console restores into system folders.
	fresh := t.TempDir()
	if err := initPolicy(fresh); err != nil {
		t.Fatal(err)
	}
	if p, err := LoadPolicy(fresh); err != nil || p.SystemRestoresAllowed() {
		t.Fatalf("new install: %+v, %v", p, err)
	}
	// An install from before the policy keeps them, also when enrolled again.
	old := t.TempDir()
	os.WriteFile(filepath.Join(old, "agent.json"), []byte("{}"), 0o600)
	if err := initPolicy(old); err != nil {
		t.Fatal(err)
	}
	if p, err := LoadPolicy(old); err != nil || !p.SystemRestoresAllowed() {
		t.Fatalf("existing install: %+v, %v", p, err)
	}
	// A PC administrator's choice survives a new enrollment.
	on := true
	if err := SavePolicy(fresh, Policy{ConsoleSystemRestores: &on}); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(fresh, "agent.json"))
	initPolicy(fresh)
	if p, _ := LoadPolicy(fresh); !p.SystemRestoresAllowed() {
		t.Fatal("re-enrollment reset the policy")
	}
}

func TestConsolePolicy(t *testing.T) {
	dir := t.TempDir()
	r := &Runner{cfg: &Config{dir: dir}}
	spec := api.JobSpec{Kind: api.KindRestore, Restore: &api.RestoreSpec{TargetDir: `C:\Windows`, SystemFolders: true}}
	if got := r.consolePolicy(spec, nopReporter{}); !got.Restore.SystemFolders {
		t.Fatal("no policy file: system folders refused")
	}
	initPolicy(dir)
	got := r.consolePolicy(spec, nopReporter{})
	if got.Restore.SystemFolders || !spec.Restore.SystemFolders {
		t.Fatalf("policy off: system_folders=%v (original %v)", got.Restore.SystemFolders, spec.Restore.SystemFolders)
	}
	os.WriteFile(filepath.Join(dir, policyFile), []byte("{not json"), 0o600)
	if got := r.consolePolicy(spec, nopReporter{}); got.Restore.SystemFolders {
		t.Fatal("unreadable policy: system folders allowed")
	}
}
