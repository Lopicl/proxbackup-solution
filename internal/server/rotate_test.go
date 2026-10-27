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
	if err := s.store.SaveTarget(ctx, tg, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// agentCert issues c a certificate and makes it the client's current one.
func agentCert(t *testing.T, s *Server, c *Client) *x509.Certificate {
	t.Helper()
	_, csrPEM := testCSR(t)
	certPEM, serial, err := s.pki.SignClientCSR(csrPEM, c.Name)
	if err != nil {
		t.Fatal(err)
	}
	s.store.db.Exec(`UPDATE clients SET cert_serial=? WHERE id=?`, serial, c.ID)
	return parseCertPEM(t, certPEM)
}

// agentCall sends a request with the client certificate cert through requireAgent.
func agentCall(s *Server, cert *x509.Certificate, h agentHandler, target, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", target, strings.NewReader(body))
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
	s.requireAgent(h).ServeHTTP(rec, req)
	return rec
}

// testPoll runs one poll with cert and req (wait=0) and returns the response.
func testPoll(t *testing.T, s *Server, cert *x509.Certificate, req api.PollRequest) api.PollResponse {
	t.Helper()
	b, _ := json.Marshal(req)
	rec := agentCall(s, cert, s.handlePoll, "/agent/v1/poll?wait=0", string(b))
	if rec.Code != 200 {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	var resp api.PollResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp
}

func csrBody(csr []byte) string {
	b, _ := json.Marshal(api.RenewCertRequest{CSR: string(csr)})
	return string(b)
}

// renewCert has the console sign csr for the holder of cert.
func renewCert(s *Server, cert *x509.Certificate, csr []byte) *httptest.ResponseRecorder {
	return agentCall(s, cert, s.handleRenewCert, "/agent/v1/cert", csrBody(csr))
}

// renewedCert renews cert with a new key and returns the new certificate.
func renewedCert(t *testing.T, s *Server, cert *x509.Certificate) *x509.Certificate {
	t.Helper()
	_, csr := testCSR(t)
	rec := renewCert(s, cert, csr)
	if rec.Code != 200 {
		t.Fatalf("renewal: %d %s", rec.Code, rec.Body)
	}
	var resp api.RenewCertResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return parseCertPEM(t, []byte(resp.CertPEM))
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
	cert := agentCert(t, s, c)

	// An old Windows agent marks its credentials exposed but can't fix them.
	resp := testPoll(t, s, cert, oldAgent)
	c, _ = s.store.Client(ctx, c.ID)
	if !c.CredsExposed || c.TokenRotatedAt != 0 || resp.RenewCert || len(f.calls) != 0 {
		t.Fatalf("after old agent: exposed=%v rotated=%d renew=%v calls=%v", c.CredsExposed, c.TokenRotatedAt, resp.RenewCert, f.calls)
	}

	// The updated agent is asked for a new certificate first; its token stays
	// until it uses it, so whoever else holds the old certificate can't get the new one.
	resp = testPoll(t, s, cert, newAgent)
	c, _ = s.store.Client(ctx, c.ID)
	if !c.CredsExposed || !c.RotateToken || !c.CertRenew || !resp.RenewCert || len(f.calls) != 0 {
		t.Fatalf("after new agent: %+v, renew=%v, calls=%v", c, resp.RenewCert, f.calls)
	}
	if resp = testPoll(t, s, cert, newAgent); len(f.calls) != 0 || !resp.RenewCert {
		t.Fatalf("token rotated before the certificate: %v", f.calls)
	}

	// The first poll with the new certificate gets the new token secret.
	newCert := renewedCert(t, s, cert)
	resp = testPoll(t, s, newCert, newAgent)
	c, _ = s.store.Client(ctx, c.ID)
	if c.CredsExposed || c.TokenRotatedAt == 0 || c.CertRenew || c.RotateToken || resp.RenewCert {
		t.Fatalf("after renewal: %+v, renew=%v", c, resp.RenewCert)
	}
	if resp.Config == nil || resp.Config.Target.Secret != f.secret || !strings.HasPrefix(f.secret, "regenerated-") ||
		resp.Config.Target.AuthID != "proxbackup@pbs!pc-1" {
		t.Fatalf("config target = %+v, PBS secret %q", resp.Config, f.secret)
	}
	if rec := agentCall(s, cert, s.handlePoll, "/agent/v1/poll?wait=0", "{}"); rec.Code != http.StatusForbidden {
		t.Fatalf("old certificate after the renewal: %d", rec.Code)
	}

	// Later polls don't rotate again.
	n := len(f.calls)
	testPoll(t, s, newCert, newAgent)
	if len(f.calls) != n {
		t.Fatalf("rotated again: %v", f.calls[n:])
	}
	// A Linux agent never counts as exposed.
	s.store.TouchClient(ctx, c.ID, api.PollRequest{OS: "linux/amd64"}, true)
	if c, _ = s.store.Client(ctx, c.ID); c.CredsExposed {
		t.Fatal("linux agent marked exposed")
	}
}

func TestManualRotationWaitsForCertificate(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	f := &fakeTokenPBS{noRegenerate: true}
	c := rotationTestClient(t, s, f)
	cert := agentCert(t, s, c)
	testPoll(t, s, cert, oldAgent)

	rec := httptest.NewRecorder()
	req := asAdmin(httptest.NewRequest("POST", "/api/clients/1/rotate-credentials", nil))
	req.SetPathValue("id", strconv.FormatInt(c.ID, 10))
	s.handleRotateCredentials(rec, req)
	if rec.Code != 200 {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}
	// An old agent can't renew its certificate, so it keeps its token too.
	resp := testPoll(t, s, cert, oldAgent)
	c, _ = s.store.Client(ctx, c.ID)
	if len(f.calls) != 0 || !c.CredsExposed || !c.RotateToken || !c.CertRenew || !resp.RenewCert {
		t.Fatalf("client = %+v, renew=%v, calls %v", c, resp.RenewCert, f.calls)
	}
	// What a poll with the certificate being replaced reports isn't taken.
	testPoll(t, s, cert, newAgent)
	if c, _ = s.store.Client(ctx, c.ID); len(c.Features) != 0 {
		t.Fatalf("features taken from the old certificate: %v", c.Features)
	}
	// Once updated, it renews the certificate and gets the new token with it.
	resp = testPoll(t, s, renewedCert(t, s, cert), newAgent)
	c, _ = s.store.Client(ctx, c.ID)
	// PBS without regenerate: the token was replaced under the same id.
	if !strings.HasPrefix(f.secret, "created-") || resp.Config == nil || resp.Config.Target.Secret != f.secret {
		t.Fatalf("secret %q, config %+v, calls %v", f.secret, resp.Config, f.calls)
	}
	if c.CredsExposed || c.RotateToken || c.CertRenew {
		t.Fatalf("client after rotation = %+v", c)
	}
}

func TestRotationRetriesAfterPBSFailure(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := rotationTestClient(t, s, http.NotFoundHandler())
	cert := agentCert(t, s, c)
	s.store.RequestRotation(ctx, c.ID)
	resp := testPoll(t, s, renewedCert(t, s, cert), newAgent)
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
	s.store.TouchClient(ctx, cs[1].ID, oldAgent, true)
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

	_, newCSR := testCSR(t)
	if rec := renewCert(s, oldCert, newCSR); rec.Code != http.StatusConflict {
		t.Fatalf("renewal without a request: %d %s", rec.Code, rec.Body)
	}
	s.store.RequestRotation(ctx, c.ID)
	if rec := renewCert(s, oldCert, csrPEM); rec.Code != http.StatusBadRequest {
		t.Fatalf("renewal with the old key: %d %s", rec.Code, rec.Body)
	}
	rec := renewCert(s, oldCert, newCSR)
	if rec.Code != 200 {
		t.Fatalf("renewal: %d %s", rec.Code, rec.Body)
	}
	// The agent retrying after a lost reply (same key) gets a certificate again.
	if rec = renewCert(s, oldCert, newCSR); rec.Code != 200 {
		t.Fatalf("repeated renewal: %d %s", rec.Code, rec.Body)
	}
	var resp api.RenewCertResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	newCert := parseCertPEM(t, []byte(resp.CertPEM))

	ok := func(w http.ResponseWriter, r *http.Request, c *Client) { w.WriteHeader(204) }
	// Both certificates work until the new one is used.
	if rec := agentCall(s, oldCert, ok, "/", ""); rec.Code != 204 {
		t.Fatalf("old certificate before the switch: %d", rec.Code)
	}
	if rec := agentCall(s, newCert, ok, "/", ""); rec.Code != 204 {
		t.Fatalf("new certificate: %d", rec.Code)
	}
	if rec := agentCall(s, oldCert, ok, "/", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("old certificate after the switch: %d", rec.Code)
	}
	c, _ = s.store.Client(ctx, c.ID)
	if c.CertRenew || c.CertRenewedAt == 0 || c.CertSerial != newCert.SerialNumber.Text(16) || c.Revoked {
		t.Fatalf("client after renewal = %+v", c)
	}
	// Revoking keeps the new serial for un-revoking.
	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if rec := agentCall(s, newCert, ok, "/", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("revoked: %d", rec.Code)
	}
	if c, _ = s.store.Client(ctx, c.ID); !c.Restorable || c.RevokedReason != "" {
		t.Fatalf("revoked client = %+v", c)
	}
}

// Two parties with the same certificate: the second CSR of a renewal, before
// or after the first party switched, revokes the client for good.
func TestCertRenewalIsOneShot(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request, c *Client) { w.WriteHeader(204) }
	for _, tc := range []struct {
		name      string
		switched  bool // the first party used its new certificate before the second CSR
		ago       time.Duration
		wantRevok bool
	}{
		{"pending", false, 0, true},
		{"switched", true, 0, true},
		{"switched long ago", true, renewalRaceWindow + time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t, "")
			ctx := context.Background()
			f := &fakeTokenPBS{}
			c := rotationTestClient(t, s, f)
			cert := agentCert(t, s, c)
			s.store.RequestRotation(ctx, c.ID)
			first := renewedCert(t, s, cert)
			if tc.switched {
				if rec := agentCall(s, first, ok, "/", ""); rec.Code != 204 {
					t.Fatalf("first party's certificate: %d", rec.Code)
				}
				s.store.db.Exec(`UPDATE clients SET cert_renewed_at=? WHERE id=?`, time.Now().Add(-tc.ago).Unix(), c.ID)
			}
			_, csr := testCSR(t)
			if rec := renewCert(s, cert, csr); rec.Code != http.StatusForbidden {
				t.Fatalf("second CSR: %d %s", rec.Code, rec.Body)
			}
			c, _ = s.store.Client(ctx, c.ID)
			if !tc.wantRevok {
				if c.Revoked || agentCall(s, first, ok, "/", "").Code != 204 {
					t.Fatalf("revoked by a late CSR with the replaced certificate: %+v", c)
				}
				return
			}
			if !c.Revoked || c.Restorable || !strings.Contains(c.RevokedReason, "possible credential theft") {
				t.Fatalf("client = %+v", c)
			}
			for _, crt := range []*x509.Certificate{cert, first} {
				if rec := agentCall(s, crt, ok, "/", ""); rec.Code != http.StatusForbidden {
					t.Fatalf("certificate still accepted: %d", rec.Code)
				}
			}
			if !strings.Contains(strings.Join(f.calls, " "), "DELETE access/users/proxbackup@pbs/token/pc-1") {
				t.Fatalf("PBS token not deleted: %v", f.calls)
			}
			rec := httptest.NewRecorder()
			req := asAdmin(httptest.NewRequest("POST", "/", nil))
			req.SetPathValue("id", strconv.FormatInt(c.ID, 10))
			s.handleUnrevokeClient(rec, req)
			if rec.Code != http.StatusConflict {
				t.Fatalf("un-revoke: %d %s", rec.Code, rec.Body)
			}
		})
	}
}

// A poll waiting with the old certificate while the renewal completes ends
// without config: the new token only goes to the new certificate.
func TestWaitingPollEndsWhenCertificateRenewed(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := rotationTestClient(t, s, &fakeTokenPBS{})
	cert := agentCert(t, s, c)
	s.store.RequestRotation(ctx, c.ID)
	cfg, _ := s.agentConfig(ctx, c)
	body, _ := json.Marshal(api.PollRequest{OS: "windows/amd64", ConfigRev: cfg.Rev})
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- agentCall(s, cert, s.handlePoll, "/agent/v1/poll?wait=30", string(body)) }()
	time.Sleep(200 * time.Millisecond)
	testPoll(t, s, renewedCert(t, s, cert), newAgent)
	s.wakeClient(c.ID)
	select {
	case rec := <-done:
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "regenerated") {
			t.Fatalf("waiting poll: %d %s", rec.Code, rec.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting poll didn't end")
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
