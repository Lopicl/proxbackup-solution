// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"strings"
	"testing"

	"proxbackup/internal/update/updatetest"
)

func TestVerifySums(t *testing.T) {
	s, other := updatetest.NewSigner(1), updatetest.NewSigner(2)
	sums := []byte(strings.Repeat("a", 64) + "  proxbackup-agent-windows-amd64.exe\n")
	good := SumsComment("0.2.16.40")
	for _, prehash := range []bool{true, false} {
		if err := verifySums(s.Pub, "0.2.16.40", sums, s.Sign(sums, good, prehash)); err != nil {
			t.Fatalf("prehash=%v: %v", prehash, err)
		}
	}
	for name, sig := range map[string][]byte{
		"other key":      other.Sign(sums, good, true),
		"older version":  s.Sign(sums, SumsComment("0.2.15.38"), true),
		"changed sums":   s.Sign(append([]byte("x"), sums...), good, true),
		"garbage":        []byte("not a signature"),
		"forged comment": []byte(strings.Replace(string(s.Sign(sums, SumsComment("0.2.15.38"), true)), "0.2.15.38", "0.2.16.40", 1)),
	} {
		if err := verifySums(s.Pub, "0.2.16.40", sums, sig); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A malformed built-in key would make every release fail to verify.
func TestReleaseKeyParses(t *testing.T) {
	if strings.TrimSpace(releaseKey) == "" {
		t.Skip("releases aren't signed")
	}
	if _, err := parseMinisignKey(releaseKey); err != nil {
		t.Fatal(err)
	}
}
