// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// testSigner produces minisign keys and signatures (the formats minisign -G and -S write).
type testSigner struct {
	id   [8]byte
	priv ed25519.PrivateKey
	pub  string
}

func newTestSigner(t *testing.T, id byte) *testSigner {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &testSigner{priv: priv}
	s.id[0] = id
	b := append(append([]byte("Ed"), s.id[:]...), pub...)
	s.pub = "untrusted comment: minisign public key\n" + base64.StdEncoding.EncodeToString(b) + "\n"
	return s
}

func (s *testSigner) sign(msg []byte, comment string, prehash bool) []byte {
	alg, m := "Ed", msg
	if prehash {
		h := blake2b.Sum512(msg)
		alg, m = "ED", h[:]
	}
	sig := ed25519.Sign(s.priv, m)
	global := ed25519.Sign(s.priv, append(append([]byte{}, sig...), comment...))
	b := append(append([]byte(alg), s.id[:]...), sig...)
	return []byte("untrusted comment: signature from minisign secret key\n" + base64.StdEncoding.EncodeToString(b) +
		"\ntrusted comment: " + comment + "\n" + base64.StdEncoding.EncodeToString(global) + "\n")
}

func TestVerifySums(t *testing.T) {
	s, other := newTestSigner(t, 1), newTestSigner(t, 2)
	sums := []byte(strings.Repeat("a", 64) + "  proxbackup-agent-windows-amd64.exe\n")
	good := SumsComment("0.2.16.40")
	for _, prehash := range []bool{true, false} {
		if err := verifySums(s.pub, "0.2.16.40", sums, s.sign(sums, good, prehash)); err != nil {
			t.Fatalf("prehash=%v: %v", prehash, err)
		}
	}
	for name, sig := range map[string][]byte{
		"other key":      other.sign(sums, good, true),
		"older version":  s.sign(sums, SumsComment("0.2.15.38"), true),
		"changed sums":   s.sign(append([]byte("x"), sums...), good, true),
		"garbage":        []byte("not a signature"),
		"forged comment": []byte(strings.Replace(string(s.sign(sums, SumsComment("0.2.15.38"), true)), "0.2.15.38", "0.2.16.40", 1)),
	} {
		if err := verifySums(s.pub, "0.2.16.40", sums, sig); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
