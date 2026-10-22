// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"proxbackup/internal/api"
)

// Config is the persisted agent state.
type Config struct {
	ServerURL string `json:"server_url"`
	// FallbackURL is the console URL used before the last switch (see
	// Runner.moveServer); tried when ServerURL is unreachable.
	FallbackURL string `json:"fallback_url,omitempty"`
	ClientID    int64  `json:"client_id"`
	ClientName  string `json:"client_name"`

	dir string
}

// DefaultDataDir is where the agent keeps its config and credentials.
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "proxbackup")
	}
	return "/var/lib/proxbackup-agent"
}

func (c *Config) path(name string) string { return filepath.Join(c.dir, name) }

// LoadConfig reads the agent configuration from dir.
func LoadConfig(dir string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, "agent.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("agent is not enrolled (run: proxbackup-agent enroll <token>)")
		}
		return nil, err
	}
	c := &Config{dir: dir}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) save() error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeSecret(c.path("agent.json"), b)
}

func writeSecret(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// TLSConfig returns the mTLS client configuration for the management server.
func (c *Config) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.path("client.pem"), c.path("client.key"))
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(c.path("ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid ca.pem")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// The server certificate is verified against our private CA only; the
		// hostname is not checked because agents may reach the server by IP or alias.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyAgainstPool(pool),
	}, nil
}

func verifyAgainstPool(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("server sent no certificate")
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		inter := x509.NewCertPool()
		for _, r := range raw[1:] {
			if c, err := x509.ParseCertificate(r); err == nil {
				inter.AddCert(c)
			}
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}
}

// ParseEnrollmentToken decodes the token an administrator copied from the UI.
func ParseEnrollmentToken(s string) (*api.EnrollmentToken, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid enrollment token: %w", err)
	}
	var t api.EnrollmentToken
	if err := json.Unmarshal(b, &t); err != nil || t.URL == "" || t.Code == "" || t.CAFingerprint == "" {
		return nil, errors.New("invalid enrollment token")
	}
	return &t, nil
}

// pinnedCAConfig trusts only a server whose chain contains the CA with the given fingerprint.
func pinnedCAConfig(fp string) *tls.Config {
	fp = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			for _, r := range raw {
				sum := sha256.Sum256(r)
				if hex.EncodeToString(sum[:]) == fp {
					ca, err := x509.ParseCertificate(r)
					if err != nil {
						return err
					}
					pool := x509.NewCertPool()
					pool.AddCert(ca)
					return verifyAgainstPool(pool)(raw, nil)
				}
			}
			return errors.New("server CA does not match enrollment token fingerprint")
		},
	}
}

// newKeyAndCSR creates the agent's private key and certificate signing request.
func newKeyAndCSR(hostname string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: hostname, Organization: []string{"proxbackup-agent"}},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}
