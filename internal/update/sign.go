// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// SigAsset is the minisign signature of SHA256SUMS.
const SigAsset = SumsAsset + ".minisig"

// releaseKey is the minisign public key releases are signed with (the file
// minisign -G writes). Its secret key never goes to GitHub: scripts/release.sh
// --sign signs on the maintainer's machine. While it is empty, SHA256SUMS
// isn't checked for a signature; builds that carry a key accept only signed
// releases from then on.
//
//go:embed release.pub
var releaseKey string

// SumsComment is the trusted comment a release's signature must carry. It
// names the version, so an older signed SHA256SUMS can't be passed off as a
// newer release.
func SumsComment(version string) string { return "ProxBackup " + version + " " + SumsAsset }

type minisignKey struct {
	id  [8]byte
	key ed25519.PublicKey
}

// parseMinisignKey reads a minisign public key, as a file or the bare base64 line.
func parseMinisignKey(s string) (*minisignKey, error) {
	line := ""
	for l := range strings.Lines(s) {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
			break
		}
	}
	b, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(b) != 42 || string(b[:2]) != "Ed" {
		return nil, errors.New("invalid minisign public key")
	}
	k := &minisignKey{key: ed25519.PublicKey(b[10:])}
	copy(k.id[:], b[2:10])
	return k, nil
}

// verifyMinisign checks a minisign signature of msg and returns its trusted comment.
func verifyMinisign(k *minisignKey, msg, sig []byte) (string, error) {
	lines := strings.Split(strings.TrimRight(string(sig), "\r\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[2], "trusted comment: ") {
		return "", errors.New("malformed signature")
	}
	s, err1 := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	global, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err1 != nil || err2 != nil || len(s) != 74 || len(global) != ed25519.SignatureSize {
		return "", errors.New("malformed signature")
	}
	if !bytes.Equal(s[2:10], k.id[:]) {
		return "", fmt.Errorf("signed with key %X, not the release key %X", s[2:10], k.id[:])
	}
	switch string(s[:2]) {
	case "ED": // prehashed, minisign's default
		h := blake2b.Sum512(msg)
		msg = h[:]
	case "Ed":
	default:
		return "", errors.New("unknown signature algorithm")
	}
	if !ed25519.Verify(k.key, msg, s[10:]) {
		return "", errors.New("bad signature")
	}
	comment := strings.TrimSuffix(strings.TrimPrefix(lines[2], "trusted comment: "), "\r")
	if !ed25519.Verify(k.key, append(s[10:], comment...), global) {
		return "", errors.New("bad signature of the trusted comment")
	}
	return comment, nil
}

// verifySums checks the release's signature of its SHA256SUMS with key.
func verifySums(key string, version string, sums, sig []byte) error {
	k, err := parseMinisignKey(key)
	if err != nil {
		return err
	}
	comment, err := verifyMinisign(k, sums, sig)
	if err != nil {
		return fmt.Errorf("%s: %w", SigAsset, err)
	}
	if want := SumsComment(version); comment != want {
		return fmt.Errorf("%s: signed for %q, not %q", SigAsset, comment, want)
	}
	return nil
}
