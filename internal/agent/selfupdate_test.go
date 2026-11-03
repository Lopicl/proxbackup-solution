// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"proxbackup/internal/api"
	"proxbackup/internal/update"
	"proxbackup/internal/update/updatetest"
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

// TestCheckOffer checks that agents take only newer releases whose signed
// SHA256SUMS lists the offered binary, whatever the console says.
func TestCheckOffer(t *testing.T) {
	s, other := updatetest.NewSigner(1), updatetest.NewSigner(2)
	hash := strings.Repeat("ab", 32)
	sums := hash + "  " + update.AgentAsset(runtime.GOARCH) + "\n"
	offer := func(version, sums string, sig []byte) *api.AgentUpdate {
		return &api.AgentUpdate{Version: version, SHA256: hash, Sums: sums, SumsSig: string(sig)}
	}
	signed := func(version string) *api.AgentUpdate {
		return offer(version, sums, s.Sign([]byte(sums), update.SumsComment(version), true))
	}
	r := &Runner{version: "0.2.17.41", releaseKey: s.Pub}
	if ok, err := r.checkOffer(signed("0.2.18.42")); !ok || err != nil {
		t.Fatalf("newer signed release: %v %v", ok, err)
	}
	for name, u := range map[string]*api.AgentUpdate{
		"same version": signed("0.2.17.41"),
		"downgrade":    signed("0.2.16.40"),
	} {
		if ok, err := r.checkOffer(u); ok || err != nil {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
	other42 := offer("0.2.18.42", sums, other.Sign([]byte(sums), update.SumsComment("0.2.18.42"), true))
	forged := signed("0.2.18.42")
	forged.SHA256 = strings.Repeat("cd", 32)
	for name, u := range map[string]*api.AgentUpdate{
		"unsigned":        offer("0.2.18.42", sums, nil),
		"other key":       other42,
		"other binary":    forged,
		"older signature": offer("0.2.18.42", sums, s.Sign([]byte(sums), update.SumsComment("0.2.16.40"), true)),
		"no sums":         offer("0.2.18.42", "", nil),
	} {
		if ok, err := r.checkOffer(u); ok || err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if ok, _ := (&Runner{version: "dev", releaseKey: s.Pub}).checkOffer(signed("0.2.18.42")); ok {
		t.Error("development build updated")
	}
}
