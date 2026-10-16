// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testCrypt(t *testing.T, seed uint64) (*CryptConfig, [32]byte) {
	t.Helper()
	var key [32]byte
	copy(key[:], randBytes(32, seed))
	c, err := NewCryptConfig(key)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func TestCanonicalJSON(t *testing.T) {
	d := json.NewDecoder(strings.NewReader(`{"b":[1,{"z":true,"a":"x<&>"}],"a":18446744073709551615,"c":"é"}`))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := canonicalJSON(v, &buf); err != nil {
		t.Fatal(err)
	}
	if want := `{"a":18446744073709551615,"b":[1,{"a":"x<&>","z":true}],"c":"é"}`; buf.String() != want {
		t.Fatalf("got %s want %s", buf.String(), want)
	}
	if err := canonicalJSON(map[string]any{"a": nil}, &buf); err == nil {
		t.Fatal("null accepted")
	}
}

func TestManifestSignature(t *testing.T) {
	c, _ := testCrypt(t, 7)
	other, _ := testCrypt(t, 8)
	files := []FileInfo{{Filename: "c.pxar.didx", CryptMode: "encrypt", Size: 10, Csum: strings.Repeat("ab", 32)}}
	base := map[string]any{"backup-type": "host", "backup-id": "pc", "backup-time": int64(1760000000), "files": files}
	data, _ := json.Marshal(base)
	sig, err := manifestSignature(data, c)
	if err != nil {
		t.Fatal(err)
	}
	// The signature ignores formatting, key order and the unprotected section.
	signed := map[string]any{"files": files, "backup-id": "pc", "backup-time": int64(1760000000), "backup-type": "host",
		"unprotected": map[string]any{"key-fingerprint": c.Fingerprint()}, "signature": hex.EncodeToString(sig[:])}
	raw, _ := json.MarshalIndent(signed, "", "    ")
	var m Manifest
	json.Unmarshal(raw, &m)
	if err := verifyManifest(raw, &m, c); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.KeyFingerprint() != c.Fingerprint() || !m.Encrypted() {
		t.Fatal("fingerprint/encrypted not reported")
	}
	if err := verifyManifest(raw, &m, other); err == nil || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("other key: %v", err)
	}
	tampered := bytes.Replace(raw, []byte(`"size": 10`), []byte(`"size": 11`), 1)
	json.Unmarshal(tampered, &m)
	if err := verifyManifest(tampered, &m, c); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	c, key := testCrypt(t, 9)
	kf, err := NewKeyFile(key, time.Unix(1760000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(kf, []byte(`"kdf":null`)) || !bytes.Contains(kf, []byte(c.Fingerprint())) {
		t.Fatalf("unexpected key file %s", kf)
	}
	got, err := ParseKeyFile(kf)
	if err != nil || got != key {
		t.Fatalf("parse: %v", err)
	}
	if _, err := ParseKeyFile(bytes.Replace(kf, []byte(`"kdf":null`), []byte(`"kdf":{"Scrypt":{}}`), 1)); err == nil {
		t.Fatal("protected key accepted")
	}
	if len(c.Fingerprint()) != 95 {
		t.Fatalf("fingerprint %q", c.Fingerprint())
	}
}

func TestRSAEncryptedKey(t *testing.T) {
	_, key := testCrypt(t, 10)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pub, err := ParseRSAPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := RSAEncryptedKey(pub, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rsa.DecryptPKCS1v15(nil, priv, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseKeyFile(plain); err != nil || got != key {
		t.Fatalf("recovered key: %v", err)
	}
	if _, err := ParseRSAPublicKey([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
}
