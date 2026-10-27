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
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proxbackup/pkg/pbs"
)

// fakePBS answers the calls the target test makes and records the tokens it
// was sent. Each one has its own certificate (httptest shares one).
func fakePBS(t *testing.T) (*httptest.Server, string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var auths []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/version") {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "4.0", "release": "1"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"store": "ds"}}})
	}))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	fp := pbs.FormatFingerprint(sha256.Sum256(der))
	return srv, fp, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), auths...) }
}

func TestTargetSecretsStayWithTheirPBS(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	local, localFP, localAuths := fakePBS(t)
	evil, evilFP, evilAuths := fakePBS(t)
	localHost, evilHost := local.Listener.Addr().String(), evil.Listener.Addr().String()
	secretFile := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secretFile, []byte("local-root-secret\n"), 0o600)
	const localID = "root@pam!proxbackup-console"
	s.cfg.LocalPBS = &LocalPBS{APIAddr: localHost, PublicHost: localHost, AuthID: localID, SecretFile: secretFile}

	stored := &Target{Name: "remote", Host: localHost, Fingerprint: localFP, Datastore: "ds", AdminAuthID: "admin@pbs!t",
		PBSUser: "proxbackup@pbs"}
	if err := s.store.SaveTarget(ctx, stored, s.sealer.sealFor("stored-secret", colTargetSecret)); err != nil {
		t.Fatal(err)
	}

	test := func(body map[string]any) int {
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		s.handleTestTarget(rec, asAdmin(httptest.NewRequest("POST", "/api/targets/test", strings.NewReader(string(b)))))
		return rec.Code
	}
	save := func(id int64, body map[string]any) int {
		b, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		r := asAdmin(httptest.NewRequest("PUT", "/api/targets/x", strings.NewReader(string(b))))
		if id != 0 {
			r.SetPathValue("id", strconv.FormatInt(id, 10))
		}
		s.handleSaveTarget(rec, r)
		return rec.Code
	}

	// Pointing an existing target or the local token id elsewhere sends nothing.
	if c := test(map[string]any{"id": stored.ID, "host": evilHost, "fingerprint": evilFP, "admin_auth_id": "admin@pbs!t"}); c != 400 {
		t.Fatalf("stored secret to another host: %d", c)
	}
	if c := test(map[string]any{"host": evilHost, "fingerprint": evilFP, "admin_auth_id": localID}); c != 400 {
		t.Fatalf("local secret to another host: %d", c)
	}
	if c := test(map[string]any{"host": localHost, "fingerprint": evilFP, "admin_auth_id": localID}); c != 400 {
		t.Fatalf("local secret with another fingerprint: %d", c)
	}
	if a := evilAuths(); len(a) != 0 {
		t.Fatalf("other host received %q", a)
	}

	// Unchanged targets and the local PBS still work without a secret.
	if c := test(map[string]any{"id": stored.ID, "host": localHost, "fingerprint": strings.ReplaceAll(localFP, ":", ""), "admin_auth_id": "admin@pbs!t", "created_at": 1}); c != 200 {
		t.Fatalf("stored target test: %d", c)
	}
	if c := test(map[string]any{"host": localHost, "admin_auth_id": localID}); c != 200 {
		t.Fatalf("local target test: %d", c)
	}
	a := localAuths()
	if len(a) != 4 || !strings.HasSuffix(a[0], ":stored-secret") || !strings.HasSuffix(a[2], ":local-root-secret") {
		t.Fatalf("local PBS received %q", a)
	}

	// Saving with another host keeps the stored secret only if it is entered again.
	form := map[string]any{"name": "remote", "host": evilHost, "fingerprint": evilFP, "datastore": "ds", "admin_auth_id": "admin@pbs!t"}
	if c := save(stored.ID, form); c != 400 {
		t.Fatalf("save with new host and no secret: %d", c)
	}
	form["admin_secret"] = "new-secret"
	if c := save(stored.ID, form); c != 200 {
		t.Fatalf("save with new host and secret: %d", c)
	}
	got, _ := s.store.Target(ctx, stored.ID)
	if sec, _ := s.sealer.Open(got.adminSecretEnc, colTargetSecret, got.ID); sec != "new-secret" || got.Host != evilHost {
		t.Fatalf("saved target %+v secret %q", got, sec)
	}
	delete(form, "admin_secret")
	form["name"] = "renamed"
	if c := save(stored.ID, form); c != 200 {
		t.Fatalf("save without changing the endpoint: %d", c)
	}

	// New targets get the local secret only for the local PBS.
	if c := save(0, map[string]any{"name": "l", "host": evilHost, "datastore": "ds", "admin_auth_id": localID}); c != 400 {
		t.Fatalf("new target with local token id on another host: %d", c)
	}
	if c := save(0, map[string]any{"name": "l", "host": localHost, "datastore": "ds", "admin_auth_id": localID}); c != 200 {
		t.Fatalf("new local target: %d", c)
	}
}

func TestTargetRepointNeedsRestore(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	used := &Target{Name: "used", Host: "pbs:8007", Fingerprint: "aa", Datastore: "ds", AdminAuthID: "admin@pbs!t", PBSUser: "proxbackup@pbs"}
	empty := &Target{Name: "empty", Host: "pbs:8007", Fingerprint: "aa", Datastore: "ds", AdminAuthID: "admin@pbs!t", PBSUser: "proxbackup@pbs"}
	for _, tg := range []*Target{used, empty} {
		if err := s.store.SaveTarget(ctx, tg, s.sealer.sealFor("x", colTargetSecret)); err != nil {
			t.Fatal(err)
		}
	}
	c := &Client{Name: "pc-1", TargetID: used.ID, CertSerial: "01", Namespace: "pcs/pc-1", TokenID: "proxbackup@pbs!pc-1"}
	if err := s.store.CreateClient(ctx, c, s.sealer.sealFor("tok", colClientToken)); err != nil {
		t.Fatal(err)
	}
	as := func(r *http.Request, ras []RoleAssignment) *http.Request {
		a := newAccess(ras, map[int64][]Perm{1: {PermTargets}, 2: {PermRestore}})
		return r.WithContext(context.WithValue(r.Context(), sessionUserKey, &SessionUser{ID: 2, Name: "u", Access: a}))
	}
	targetsOnly := []RoleAssignment{{RoleID: 1, AllClients: true}}
	someRestore := append(targetsOnly, RoleAssignment{RoleID: 2, Clients: []int64{c.ID}})
	allRestore := append(targetsOnly, RoleAssignment{RoleID: 2, AllClients: true})
	save := func(tg *Target, ras []RoleAssignment, host, fp string) int {
		b, _ := json.Marshal(map[string]any{"name": tg.Name, "host": host, "fingerprint": fp, "datastore": "ds",
			"admin_auth_id": "admin@pbs!t", "admin_secret": "made-up"})
		r := as(httptest.NewRequest("PUT", "/api/targets/x", strings.NewReader(string(b))), ras)
		r.SetPathValue("id", strconv.FormatInt(tg.ID, 10))
		rec := httptest.NewRecorder()
		s.handleSaveTarget(rec, r)
		return rec.Code
	}

	if c := save(used, targetsOnly, "evil:8007", "aa"); c != 403 {
		t.Fatalf("new host without restore: %d", c)
	}
	if c := save(used, targetsOnly, "pbs", "bb"); c != 403 {
		t.Fatalf("new fingerprint without restore: %d", c)
	}
	if c := save(used, someRestore, "evil:8007", "aa"); c != 403 {
		t.Fatalf("new host with restore for some clients: %d", c)
	}
	if got, _ := s.store.Target(ctx, used.ID); got.Host != "pbs:8007" || got.Fingerprint != "aa" {
		t.Fatalf("target changed: %+v", got)
	}
	if c := save(used, targetsOnly, "PBS", "AA"); c != 200 {
		t.Fatalf("same endpoint without restore: %d", c)
	}
	if c := save(empty, targetsOnly, "other:8007", "bb"); c != 200 {
		t.Fatalf("target without clients: %d", c)
	}
	if c := save(used, allRestore, "other:8007", "bb"); c != 200 {
		t.Fatalf("new host with restore for all clients: %d", c)
	}
}
