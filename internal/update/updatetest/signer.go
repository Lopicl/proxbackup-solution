// SPDX-License-Identifier: AGPL-3.0-or-later

// Package updatetest signs fake releases for tests, as minisign does.
package updatetest

import (
	"crypto/ed25519"
	"encoding/base64"

	"golang.org/x/crypto/blake2b"
)

// Signer produces minisign keys and signatures (the formats minisign -G and -S write).
type Signer struct {
	id   [8]byte
	priv ed25519.PrivateKey
	Pub  string // the public key file
}

func NewSigner(id byte) *Signer {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	s := &Signer{priv: priv}
	s.id[0] = id
	b := append(append([]byte("Ed"), s.id[:]...), pub...)
	s.Pub = "untrusted comment: minisign public key\n" + base64.StdEncoding.EncodeToString(b) + "\n"
	return s
}

// Sign signs msg with the trusted comment comment; prehash is minisign's default.
func (s *Signer) Sign(msg []byte, comment string, prehash bool) []byte {
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
