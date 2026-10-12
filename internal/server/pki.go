package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKI is the server's internal certificate authority. It issues the server
// TLS certificate and one client certificate per enrolled agent.
type PKI struct {
	CA     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	CAPEM  []byte
	Server tls.Certificate
}

// CAFingerprint is the hex SHA-256 of the CA certificate (pinned by agents at enrollment).
func (p *PKI) CAFingerprint() string {
	sum := sha256.Sum256(p.CA.Raw)
	return hex.EncodeToString(sum[:])
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// LoadOrCreatePKI loads the CA and server certificate from dir, creating them
// on first start. hosts are added as SANs to the server certificate.
func LoadOrCreatePKI(dir string, hosts []string) (*PKI, error) {
	caCertPath, caKeyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	p := &PKI{}
	if _, err := os.Stat(caCertPath); errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber:          randSerial(),
			Subject:               pkix.Name{CommonName: "pbspc internal CA", Organization: []string{"pbspc"}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(20, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLenZero:        true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		if err := writePEM(caCertPath, "CERTIFICATE", der, 0o644); err != nil {
			return nil, err
		}
		kder, _ := x509.MarshalECPrivateKey(key)
		if err := writePEM(caKeyPath, "EC PRIVATE KEY", kder, 0o600); err != nil {
			return nil, err
		}
	}
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(caPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("corrupt CA files")
	}
	if p.CA, err = x509.ParseCertificate(cb.Bytes); err != nil {
		return nil, err
	}
	if p.caKey, err = x509.ParseECPrivateKey(kb.Bytes); err != nil {
		return nil, err
	}
	p.CAPEM = caPEM

	srvCert, srvKey := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	if !serverCertValid(srvCert, hosts) {
		if err := p.issueServerCert(srvCert, srvKey, hosts); err != nil {
			return nil, err
		}
	}
	if p.Server, err = tls.LoadX509KeyPair(srvCert, srvKey); err != nil {
		return nil, err
	}
	p.Server.Certificate = append(p.Server.Certificate, p.CA.Raw) // send chain incl. CA so agents can pin it
	return p, nil
}

func serverCertValid(path string, hosts []string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || time.Until(c.NotAfter) < 30*24*time.Hour {
		return false
	}
	for _, h := range hosts {
		if c.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

func (p *PKI) issueServerCert(certPath, keyPath string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: "pbspc-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range append([]string{"localhost", "127.0.0.1", "::1"}, hosts...) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CA, &key.PublicKey, p.caKey)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return writePEM(keyPath, "EC PRIVATE KEY", kder, 0o600)
}

// SignClientCSR issues an agent certificate. The serial identifies the client.
func (p *PKI) SignClientCSR(csrPEM []byte, clientName string) (certPEM []byte, serial string, err error) {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, "", errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("CSR signature: %w", err)
	}
	sn := randSerial()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: clientName, Organization: []string{"pbspc-agent"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CA, csr.PublicKey, p.caKey)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sn.Text(16), nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}

// Sealer encrypts secrets at rest (PBS token secrets, SMTP password) with AES-256-GCM.
type Sealer struct{ aead cipher.AEAD }

// LoadOrCreateSealer reads the master key from env PBSPC_MASTER_KEY (base64)
// or dir/master.key, generating the file on first start.
func LoadOrCreateSealer(dir string) (*Sealer, error) {
	var key []byte
	if env := os.Getenv("PBSPC_MASTER_KEY"); env != "" {
		k, err := base64.StdEncoding.DecodeString(env)
		if err != nil || len(k) != 32 {
			return nil, errors.New("PBSPC_MASTER_KEY must be 32 bytes, base64 encoded")
		}
		key = k
	} else {
		path := filepath.Join(dir, "master.key")
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			b = make([]byte, 32)
			rand.Read(b)
			if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(b)), 0o600); err != nil {
				return nil, err
			}
			b = []byte(base64.StdEncoding.EncodeToString(b))
		} else if err != nil {
			return nil, err
		}
		if key, err = base64.StdEncoding.DecodeString(string(b)); err != nil || len(key) != 32 {
			return nil, errors.New("master.key is corrupt")
		}
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &Sealer{aead: aead}, nil
}

func (s *Sealer) Seal(plain string) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	rand.Read(nonce)
	return s.aead.Seal(nonce, nonce, []byte(plain), nil)
}

func (s *Sealer) Open(sealed []byte) (string, error) {
	if len(sealed) < s.aead.NonceSize() {
		return "", errors.New("sealed secret too short")
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], nil)
	return string(plain), err
}
