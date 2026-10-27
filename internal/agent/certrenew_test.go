// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"proxbackup/internal/api"
)

// fakeCA signs certificates like the console's internal CA.
type fakeCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	serial int64
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &fakeCA{cert: cert, key: key, serial: 1}
}

func (ca *fakeCA) sign(t *testing.T, pub any, usage x509.ExtKeyUsage) ([]byte, string) {
	t.Helper()
	ca.serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.serial), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), tmpl.SerialNumber.Text(16)
}

// fakeRenewConsole accepts the agent's current certificate and a renewed one
// it hasn't used yet, and revokes the old one at the first use of the new one.
type fakeRenewConsole struct {
	t       *testing.T
	ca      *fakeCA
	mu      sync.Mutex
	serial  string
	pending string
	renew   bool
	seen    []string // serials of authenticated requests
}

func (f *fakeRenewConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "no certificate", http.StatusUnauthorized)
		return
	}
	serial := r.TLS.PeerCertificates[0].SerialNumber.Text(16)
	switch serial {
	case f.serial:
	case f.pending:
		f.serial, f.pending, f.renew = f.pending, "", false
	default:
		http.Error(w, "unknown or revoked client", http.StatusForbidden)
		return
	}
	f.seen = append(f.seen, serial)
	switch r.URL.Path {
	case "/agent/v1/poll":
		var req api.PollRequest
		json.NewDecoder(r.Body).Decode(&req)
		if !slices.Contains(req.Features, api.FeatureCertRenewal) {
			f.t.Errorf("features = %v", req.Features)
		}
		json.NewEncoder(w).Encode(api.PollResponse{RenewCert: f.renew})
	case "/agent/v1/cert":
		var req api.RenewCertRequest
		json.NewDecoder(r.Body).Decode(&req)
		blk, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cert, sn := f.ca.sign(f.t, csr.PublicKey, x509.ExtKeyUsageClientAuth)
		f.pending = sn
		json.NewEncoder(w).Encode(api.RenewCertResponse{CertPEM: string(cert)})
	default:
		http.NotFound(w, r)
	}
}

func TestRenewCert(t *testing.T) {
	ca := newFakeCA(t)
	f := &fakeRenewConsole{t: t, ca: ca, renew: true}
	srv := httptest.NewUnstartedServer(f)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvCert, _ := ca.sign(t, &srvKey.PublicKey, x509.ExtKeyUsageServerAuth)
	srvKeyDER, _ := x509.MarshalECPrivateKey(srvKey)
	pair, err := tls.X509KeyPair(srvCert, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	defer srv.Close()

	// An enrolled agent.
	dir := t.TempDir()
	keyPEM, csrPEM, err := newKeyAndCSR("pc")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csrPEM)
	csr, _ := x509.ParseCertificateRequest(blk.Bytes)
	certPEM, serial := ca.sign(t, csr.PublicKey, x509.ExtKeyUsageClientAuth)
	f.serial = serial
	cfg := &Config{ServerURL: srv.URL, ClientID: 1, ClientName: "pc", dir: dir}
	for name, data := range map[string][]byte{"client.key": keyPEM, "client.pem": certPEM,
		"ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})} {
		if err := writeSecret(cfg.path(name), data); err != nil {
			t.Fatal(err)
		}
	}
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := r.pollOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if f.pending == "" {
		t.Fatal("no certificate requested")
	}
	newKey, _ := os.ReadFile(cfg.path("client.key"))
	if string(newKey) == string(keyPEM) {
		t.Fatal("key not replaced")
	}
	// The next poll uses the new certificate, which revokes the old one.
	if err := r.pollOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if f.renew || f.serial == serial || f.seen[len(f.seen)-1] != f.serial {
		t.Fatalf("console: serial %s (was %s), renew %v, seen %v", f.serial, serial, f.renew, f.seen)
	}
	if _, err := os.Stat(cfg.path("client.renew.pem")); err == nil {
		t.Fatal("renewal files left behind")
	}
	// A restarted agent loads the new pair.
	r2, err := NewRunner(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.pollOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
}

func TestFinishCertRenewal(t *testing.T) {
	write := func(c *Config, files map[string]string) {
		for n, d := range files {
			os.WriteFile(c.path(n), []byte(d), 0o600)
		}
	}
	read := func(c *Config, n string) string {
		b, err := os.ReadFile(c.path(n))
		if err != nil {
			return "-"
		}
		return string(b)
	}

	// Interrupted before the swap: the new pair replaces the old one.
	c := &Config{dir: t.TempDir()}
	write(c, map[string]string{"client.key": "old key", "client.pem": "old cert", "client.renew.key": "new key", "client.renew.pem": "new cert"})
	finishCertRenewal(c)
	if read(c, "client.key") != "new key" || read(c, "client.pem") != "new cert" || read(c, "client.renew.key") != "-" || read(c, "client.renew.pem") != "-" {
		t.Fatal("interrupted renewal not completed")
	}

	// Interrupted before the console replied: the key is kept for the retry.
	c = &Config{dir: t.TempDir()}
	write(c, map[string]string{"client.key": "old key", "client.pem": "old cert", "client.renew.key": "new key"})
	finishCertRenewal(c)
	if read(c, "client.key") != "old key" || read(c, "client.pem") != "old cert" || read(c, "client.renew.key") != "new key" {
		t.Fatal("pending renewal key not kept")
	}

	// Interrupted after the key was swapped: the certificate follows.
	c = &Config{dir: t.TempDir()}
	write(c, map[string]string{"client.key": "new key", "client.pem": "old cert", "client.renew.pem": "new cert"})
	finishCertRenewal(c)
	if read(c, "client.key") != "new key" || read(c, "client.pem") != "new cert" || read(c, "client.renew.pem") != "-" {
		t.Fatal("interrupted renewal not completed")
	}
}

// A retried renewal asks for the same key: the console revokes the client
// on a CSR for a second key.
func TestRenewalRetryKeepsKey(t *testing.T) {
	c := &Config{dir: t.TempDir()}
	pub := func(csrPEM []byte) string {
		blk, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		return string(b)
	}
	key1, csr1, err := renewalKeyAndCSR(c)
	if err != nil {
		t.Fatal(err)
	}
	key2, csr2, err := renewalKeyAndCSR(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(key1) != string(key2) || pub(csr1) != pub(csr2) {
		t.Fatal("retry made a new key")
	}
	// After the swap, the next renewal gets a new key.
	os.Rename(c.path("client.renew.key"), c.path("client.key"))
	if _, csr3, err := renewalKeyAndCSR(c); err != nil || pub(csr3) == pub(csr1) {
		t.Fatalf("next renewal reused the key (err %v)", err)
	}
}
