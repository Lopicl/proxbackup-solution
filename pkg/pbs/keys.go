// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
)

// RSAKeyBlobName is the snapshot file holding the encryption key encrypted
// with an RSA master public key (proxmox-backup-client --master-pubkey-file).
const RSAKeyBlobName = "rsa-encrypted.key.blob"

// ErrWrongKey is returned when a snapshot was encrypted with another key.
var ErrWrongKey = errors.New("pbs: wrong key")

// fingerprintInput is sha256("Proxmox Backup Encryption Key Fingerprint"),
// the FINGERPRINT_INPUT of pbs-tools crypt_config.rs.
var fingerprintInput = sha256.Sum256([]byte("Proxmox Backup Encryption Key Fingerprint"))

// GenerateKey returns a new random AES-256 encryption key.
func GenerateKey() ([32]byte, error) {
	var k [32]byte
	_, err := rand.Read(k[:])
	return k, err
}

// Fingerprint identifies the key without revealing it, formatted like PBS
// ("aa:bb:…", 32 bytes). It is stored in signed manifests.
func (c *CryptConfig) Fingerprint() string {
	return FormatFingerprint(c.ComputeDigest(fingerprintInput[:]))
}

// AuthTag is the HMAC-SHA256 of data keyed with the id key (compute_auth_tag).
func (c *CryptConfig) AuthTag(data []byte) [32]byte {
	m := hmac.New(sha256.New, c.idKey[:])
	m.Write(data)
	var t [32]byte
	m.Sum(t[:0])
	return t
}

// KeyFile is the PBS key file format (pbs-key-config KeyConfig), as written by
// "proxmox-backup-client key create --kdf none". Only unprotected keys are
// supported.
type KeyFile struct {
	KDF         any    `json:"kdf"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
	Data        string `json:"data"` // base64 of the raw 32 byte key
	Fingerprint string `json:"fingerprint,omitempty"`
}

// NewKeyFile renders key as a PBS key file, usable with
// "proxmox-backup-client --keyfile".
func NewKeyFile(key [32]byte, created time.Time) ([]byte, error) {
	c, err := NewCryptConfig(key)
	if err != nil {
		return nil, err
	}
	ts := created.UTC().Format(time.RFC3339)
	return json.Marshal(KeyFile{Created: ts, Modified: ts, Data: base64.StdEncoding.EncodeToString(key[:]), Fingerprint: c.Fingerprint()})
}

// ParseKeyFile reads an unprotected PBS key file.
func ParseKeyFile(data []byte) ([32]byte, error) {
	var key [32]byte
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return key, fmt.Errorf("pbs: invalid key file: %w", err)
	}
	if kf.KDF != nil {
		return key, errors.New("pbs: password-protected key files are not supported (re-export it with --kdf none)")
	}
	raw, err := base64.StdEncoding.DecodeString(kf.Data)
	if err != nil || len(raw) != 32 {
		return key, errors.New("pbs: invalid key file: data is not a 32 byte key")
	}
	copy(key[:], raw)
	if kf.Fingerprint != "" {
		c, err := NewCryptConfig(key)
		if err != nil {
			return key, err
		}
		if NormalizeFingerprint(kf.Fingerprint) != NormalizeFingerprint(c.Fingerprint()) {
			return key, errors.New("pbs: key file fingerprint does not match its key")
		}
	}
	return key, nil
}

// ParseRSAPublicKey reads a PEM RSA public key (PKIX "PUBLIC KEY" or PKCS#1
// "RSA PUBLIC KEY", like master-public.pem from create-master-key).
func ParseRSAPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	b, _ := pem.Decode(pemData)
	if b == nil {
		return nil, errors.New("pbs: master key is not PEM")
	}
	var pub any
	var err error
	switch b.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(b.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(b.Bytes)
	default:
		return nil, fmt.Errorf("pbs: master key: unexpected PEM block %q (want a public key)", b.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("pbs: master key: %w", err)
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("pbs: master key is not an RSA key")
	}
	if rk.N.BitLen() < 2048 {
		return nil, errors.New("pbs: master key must have at least 2048 bits")
	}
	return rk, nil
}

// RSAEncryptedKey returns the contents of rsa-encrypted.key.blob: the key file
// of key encrypted with the master public key (PKCS#1 v1.5), as
// proxmox-backup-client uploads it. "proxmox-backup-client key
// import-with-master-key" recovers the key from it with the master private key.
func RSAEncryptedKey(master *rsa.PublicKey, key [32]byte, created time.Time) ([]byte, error) {
	kf, err := NewKeyFile(key, created)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, master, kf)
}

// canonicalJSON renders v like proxmox_serde::json::to_canonical_json: object
// keys sorted, no whitespace. Nulls are not allowed.
func canonicalJSON(v any, out *bytes.Buffer) error {
	switch x := v.(type) {
	case nil:
		return errors.New("pbs: canonical json: unexpected null")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := jsonScalar(k, out); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := canonicalJSON(x[k], out); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := canonicalJSON(e, out); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		return jsonScalar(x, out)
	}
	return nil
}

// jsonScalar writes a string, number or bool like serde_json (no HTML escaping).
func jsonScalar(v any, out *bytes.Buffer) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	out.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return nil
}

// manifestSignature computes the manifest signature over everything but
// "unprotected" and "signature" (BackupManifest::json_signature).
func manifestSignature(manifest []byte, c *CryptConfig) ([32]byte, error) {
	d := json.NewDecoder(bytes.NewReader(manifest))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return [32]byte{}, err
	}
	delete(m, "unprotected")
	delete(m, "signature")
	var buf bytes.Buffer
	if err := canonicalJSON(m, &buf); err != nil {
		return [32]byte{}, err
	}
	return c.AuthTag(buf.Bytes()), nil
}

// KeyFingerprint returns the key fingerprint recorded in a manifest's
// unprotected section ("" when the snapshot is not encrypted).
func (m *Manifest) KeyFingerprint() string {
	var u struct {
		KeyFingerprint string `json:"key-fingerprint"`
	}
	json.Unmarshal(m.Unprotected, &u)
	return u.KeyFingerprint
}

// Encrypted reports whether any file of the snapshot is encrypted.
func (m *Manifest) Encrypted() bool {
	for _, f := range m.Files {
		if f.CryptMode == "encrypt" {
			return true
		}
	}
	return false
}

// verifyManifest checks the signature of raw (the decoded index.json) with c,
// like BackupManifest::from_data.
func verifyManifest(raw []byte, m *Manifest, c *CryptConfig) error {
	if c == nil || m.Signature == nil {
		return nil
	}
	if fp := m.KeyFingerprint(); fp != "" && NormalizeFingerprint(fp) != NormalizeFingerprint(c.Fingerprint()) {
		return fmt.Errorf("%w: snapshot was encrypted with key %s, not %s", ErrWrongKey, fp, c.Fingerprint())
	}
	want, err := manifestSignature(raw, c)
	if err != nil {
		return err
	}
	got, err := hex.DecodeString(*m.Signature)
	if err != nil || !hmac.Equal(got, want[:]) {
		return errors.New("pbs: wrong manifest signature")
	}
	return nil
}
