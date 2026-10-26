// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// fakeTokenPBS serves token regeneration (or, with noRegenerate, refuses it
// like older PBS versions and serves delete, create and the ACL calls instead).
type fakeTokenPBS struct {
	mu           sync.Mutex
	noRegenerate bool
	secret       string // current secret of the token
	calls        []string
}

func (f *fakeTokenPBS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api2/json/"))
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	tokenPath := strings.HasPrefix(r.URL.Path, "/api2/json/access/users/") && strings.Contains(r.URL.Path, "/token/")
	switch {
	case r.Method == http.MethodPut && tokenPath:
		if f.noRegenerate {
			http.Error(w, "parameter verification errors: regenerate: schema does not allow additional properties", http.StatusBadRequest)
			return
		}
		f.secret = "regenerated-" + strconv.Itoa(len(f.calls))
		reply(map[string]any{"secret": f.secret})
	case r.Method == http.MethodDelete && tokenPath:
		f.secret = ""
		reply(nil)
	case r.Method == http.MethodPost && tokenPath:
		f.secret = "created-" + strconv.Itoa(len(f.calls))
		reply(map[string]any{"tokenid": "proxbackup@pbs!pc-1", "value": f.secret})
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/namespace"):
		reply([]map[string]any{{"ns": "pcs"}, {"ns": "pcs/pc-1"}})
	case r.Method == http.MethodPut && r.URL.Path == "/api2/json/access/acl":
		reply(nil)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotImplemented)
	}
}

// rotationTestClient creates client pc-1 on a target served by f.
func rotationTestClient(t *testing.T, s *Server, f http.Handler) *Client {
	t.Helper()
	ctx := context.Background()
	c := groupTestClients(t, s, "pc-1")[0]
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	tg, _ := s.store.Target(ctx, c.TargetID)
	tg.Host, tg.Fingerprint = strings.TrimPrefix(srv.URL, "https://"), pbs.FormatFingerprint(sum)
	if err := s.store.SaveTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	return c
}

// poll runs one poll of c with req (wait=0) and returns the response.
func testPoll(t *testing.T, s *Server, c *Client, req api.PollRequest) api.PollResponse {
	t.Helper()
	b, _ := json.Marshal(req)
	rec := httptest.NewRecorder()
	s.handlePoll(rec, httptest.NewRequest("POST", "/agent/v1/poll?wait=0", strings.NewReader(string(b))), c)
	if rec.Code != 200 {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	var resp api.PollResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp
}

var (
	oldAgent = api.PollRequest{OS: "windows/amd64", AgentVersion: "0.2.14.37"}
	newAgent = api.PollRequest{OS: "windows/amd64", AgentVersion: "0.2.15.38",
		Features: []string{api.FeatureDataDirACL, api.FeatureCertRenewal}}
)

func TestExposedCredentialsRotateOnUpdatedAgent(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	f := &fakeTokenPBS{}
	c := rotationTestClient(t, s, f)

	// An old Windows agent marks its credentials exposed but can't fix them.
	resp := testPoll(t, s, c, oldAgent)
	c, _ = s.store.Client(ctx, c.ID)
	if !c.CredsExposed || c.TokenRotatedAt != 0 || resp.RenewCert || len(f.calls) != 0 {
		t.Fatalf("after old agent: exposed=%v rotated=%d renew=%v calls=%v", c.CredsExposed, c.TokenRotatedAt, resp.RenewCert, f.calls)
	}

	// The updated agent gets a new token secret and is asked for a new certificate.
	resp = testPoll(t, s, c, newAgent)
	c, _ = s.store.Client(ctx, c.ID)
	if c.CredsExposed || c.TokenRotatedAt == 0 || !c.CertRenew || !resp.RenewCert {
		t.Fatalf("after new agent: %+v, renew=%v", c, resp.RenewCert)
	}
	if resp.Config == nil || resp.Config.Target.Secret != f.secret || !strings.HasPrefix(f.secret, "regenerated-") ||
		resp.Config.Target.AuthID != "proxbackup@pbs!pc-1" {
		t.Fatalf("config target = %+v, PBS secret %q", resp.Config, f.secret)
	}

	// Later polls don't rotate again.
	n := len(f.calls)
	testPoll(t, s, c, newAgent)
	if len(f.calls) != n {
		t.Fatalf("rotated again: %v", f.calls[n:])
	}
	// A Linux agent never counts as exposed.
	s.store.TouchClient(ctx, c.ID, api.PollRequest{OS: "linux/amd64"})
	if c, _ = s.store.Client(ctx, c.ID); c.CredsExposed {
		t.Fatal("linux agent marked exposed")
	}
}

func TestManualRotationOfOldAgentStaysExposed(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	f := &fakeTokenPBS{noRegenerate: true}
	c := rotationTestClient(t, s, f)
	testPoll(t, s, c, oldAgent)

	rec := httptest.NewRecorder()
	req := asAdmin(httptest.NewRequest("POST", "/api/clients/1/rotate-credentials", nil))
	req.SetPathValue("id", strconv.FormatInt(c.ID, 10))
	s.handleRotateCredentials(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}
	resp := testPoll(t, s, c, oldAgent)
	c, _ = s.store.Client(ctx, c.ID)
	// PBS without regenerate: the token was replaced under the same id.
	if !strings.HasPrefix(f.secret, "created-") || resp.Config == nil || resp.Config.Target.Secret != f.secret {
		t.Fatalf("secret %q, config %+v, calls %v", f.secret, resp.Config, f.calls)
	}
	// The old agent keeps the new secret readable and can't renew its certificate.
	if !c.CredsExposed || c.RotateToken || !c.CertRenew || resp.RenewCert {
		t.Fatalf("client = %+v, renew=%v", c, resp.RenewCert)
	}
	// Once updated, it rotates again and renews the certificate.
	if resp = testPoll(t, s, c, newAgent); !resp.RenewCert {
		t.Fatal("updated agent not asked to renew its certificate")
	}
	if c, _ = s.store.Client(ctx, c.ID); c.CredsExposed {
		t.Fatal("still exposed after the update")
	}
}

func TestRotationRetriesAfterPBSFailure(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := rotationTestClient(t, s, http.NotFoundHandler())
	s.store.RequestRotation(ctx, c.ID)
	resp := testPoll(t, s, c, newAgent)
	if c, _ = s.store.Client(ctx, c.ID); !c.RotateToken || resp.Config == nil || resp.Config.Target.Secret != "tok" {
		t.Fatalf("failed rotation: %+v", c)
	}
	if s.tokenRotationDue(c) {
		t.Fatal("retried at once")
	}
	s.rotateFailed[c.ID] = time.Now().Add(-rotateRetry)
	if !s.tokenRotationDue(c) {
		t.Fatal("not retried after the wait")
	}
}

func TestBulkRotation(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "a", "b", "c")
	s.store.TouchClient(ctx, cs[1].ID, oldAgent)
	for _, tc := range []struct {
		body string
		want []bool
	}{
		{`{"exposed":true}`, []bool{false, true, false}},
		{`{"client_ids":[` + strconv.FormatInt(cs[2].ID, 10) + `]}`, []bool{false, true, true}},
	} {
		rec := httptest.NewRecorder()
		s.handleRotateCredentialsBulk(rec, asAdmin(httptest.NewRequest("POST", "/api/clients/rotate-credentials", strings.NewReader(tc.body))))
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", tc.body, rec.Code, rec.Body)
		}
		for i, want := range tc.want {
			if c, _ := s.store.Client(ctx, cs[i].ID); c.RotateToken != want || c.CertRenew != want {
				t.Errorf("%s: client %s rotate=%v renew=%v, want %v", tc.body, c.Name, c.RotateToken, c.CertRenew, want)
			}
		}
	}
}

func TestCertRenewal(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := groupTestClients(t, s, "pc-1")[0]
	_, csrPEM := testCSR(t)
	oldPEM, oldSerial, _ := s.pki.SignClientCSR(csrPEM, c.Name)
	s.store.db.Exec(`UPDATE clients SET cert_serial=? WHERE id=?`, oldSerial, c.ID)
	oldCert := parseCertPEM(t, oldPEM)

	call := func(cert *x509.Certificate, h agentHandler, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/agent/v1/cert", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
		s.requireAgent(h).ServeHTTP(rec, req)
		return rec
	}
	csrBody := func(csr []byte) string {
		b, _ := json.Marshal(api.RenewCertRequest{CSR: string(csr)})
		return string(b)
	}
	_, newCSR := testCSR(t)
	if rec := call(oldCert, s.handleRenewCert, csrBody(newCSR)); rec.Code != http.StatusConflict {
		t.Fatalf("renewal without a request: %d %s", rec.Code, rec.Body)
	}
	s.store.RequestRotation(ctx, c.ID)
	if rec := call(oldCert, s.handleRenewCert, csrBody(csrPEM)); rec.Code != http.StatusBadRequest {
		t.Fatalf("renewal with the old key: %d %s", rec.Code, rec.Body)
	}
	rec := call(oldCert, s.handleRenewCert, csrBody(newCSR))
	if rec.Code != 200 {
		t.Fatalf("renewal: %d %s", rec.Code, rec.Body)
	}
	var resp api.RenewCertResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	newCert := parseCertPEM(t, []byte(resp.CertPEM))

	ok := func(w http.ResponseWriter, r *http.Request, c *Client) { w.WriteHeader(204) }
	// Both certificates work until the new one is used.
	if rec := call(oldCert, ok, ""); rec.Code != 204 {
		t.Fatalf("old certificate before the switch: %d", rec.Code)
	}
	if rec := call(newCert, ok, ""); rec.Code != 204 {
		t.Fatalf("new certificate: %d", rec.Code)
	}
	if rec := call(oldCert, ok, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("old certificate after the switch: %d", rec.Code)
	}
	c, _ = s.store.Client(ctx, c.ID)
	if c.CertRenew || c.CertRenewedAt == 0 || c.CertSerial != newCert.SerialNumber.Text(16) {
		t.Fatalf("client after renewal = %+v", c)
	}
	// Revoking keeps the new serial for un-revoking.
	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if rec := call(newCert, ok, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked: %d", rec.Code)
	}
}

func testCSR(t *testing.T) (key *ecdsa.PrivateKey, csrPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pc"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func parseCertPEM(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("no PEM certificate")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
