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
	"maps"
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

// fakePBS answers the calls the target test makes and records the credentials
// it was sent: token headers, and "password:<pw>" for sign-ins. Each one has
// its own certificate (httptest shares one).
func fakePBS(t *testing.T) (*httptest.Server, string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var auths []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/access/ticket") {
			var in struct{ Password string }
			json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			auths = append(auths, "password:"+in.Password)
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ticket": "PBS:t", "CSRFPreventionToken": "c"}})
			return
		}
		if r.Header.Get("Authorization") != "" {
			mu.Lock()
			auths = append(auths, r.Header.Get("Authorization"))
			mu.Unlock()
		} else if r.Header.Get("Cookie") == "" {
			http.Error(w, "no credentials", http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/version") {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "4.0", "release": "1"}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/access/permissions") {
			path := r.URL.Query().Get("path")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{path: map[string]bool{"Datastore.Modify": true}}})
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
	os.WriteFile(secretFile, []byte("local-password\n"), 0o600)
	const localID = "proxbackup@pbs"
	s.cfg.LocalPBS = &LocalPBS{APIAddr: localHost, PublicHost: localHost, AuthID: localID, SecretFile: secretFile}
	root := newFakePBSRoot("ds")
	root.proxyFP = localFP
	s.grantHelper = func() {
		if err := grantLocalPBS(ctx, s.cfg.DataDir, localID, root, s.log); err != nil {
			t.Errorf("grant helper: %v", err)
		}
	}

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
	if len(a) != 3 || !strings.HasSuffix(a[0], ":stored-secret") || a[2] != "password:local-password" {
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
	if c := save(0, map[string]any{"name": "l", "host": localHost, "datastore": "ds", "admin_auth_id": localID}); c != 400 {
		t.Fatalf("new local target without a root namespace: %d", c)
	}
	if c := save(0, map[string]any{"name": "l", "host": localHost, "datastore": "ds", "root_ns": "pcs", "admin_auth_id": localID}); c != 200 {
		t.Fatalf("new local target: %d", c)
	}
	if !root.has(pbsACL{"/datastore/ds/pcs", true, "DatastoreAdmin", localID}) || !root.ns["ds"]["pcs"] {
		t.Fatalf("local target got no rights: %+v %v", root.acls, root.ns)
	}
	ts, _ := s.store.Targets(ctx)
	for _, tg := range ts {
		if tg.Local != (tg.Name == "l") {
			t.Fatalf("target %s local=%v", tg.Name, tg.Local)
		}
	}

	// A remote PBS with a user of the same name gets neither the local
	// fingerprint nor its password.
	remote := map[string]any{"name": "r", "host": evilHost, "datastore": "ds", "admin_auth_id": localID, "pbs_user": localID}
	if c := save(0, remote); c != 400 {
		t.Fatalf("remote target with the local user and no password: %d", c)
	}
	remote["admin_secret"] = "remote-password"
	if c := save(0, remote); c != 200 {
		t.Fatalf("remote target with the local user's name: %d", c)
	}
	if a := evilAuths(); len(a) != 0 {
		t.Fatalf("other host received %q", a)
	}
	ts, _ = s.store.Targets(ctx)
	for _, tg := range ts {
		if tg.Name == "r" && (tg.Local || tg.Fingerprint != "") {
			t.Fatalf("remote target %+v", tg)
		}
	}
	// A user admin must own the agent tokens.
	if c := save(0, map[string]any{"name": "u", "host": evilHost, "datastore": "ds", "admin_auth_id": "admin@pbs",
		"pbs_user": "proxbackup@pbs", "admin_secret": "x"}); c != 400 {
		t.Fatalf("user admin other than the agent user: %d", c)
	}
}

// TestLocalTargetsLeaveRootToken checks that local targets of the package's
// old root token move to its PBS user, and that remote ones stay as they are.
func TestLocalTargetsLeaveRootToken(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	local, localFP, _ := fakePBS(t)
	localHost := local.Listener.Addr().String()
	secretFile := filepath.Join(t.TempDir(), "pbs-password")
	os.WriteFile(secretFile, []byte("local-password\n"), 0o600)
	s.cfg.LocalPBS = &LocalPBS{APIAddr: localHost, PublicHost: localHost, AuthID: "proxbackup@pbs", SecretFile: secretFile}
	localHelper(t, s, localFP)

	// Saved by an older console: no local column yet.
	if _, err := s.store.db.Exec(`ALTER TABLE targets DROP COLUMN local`); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][]string{
		{"ds", legacyLocalAuthID, "proxbackup@pbs"},
		{"other-user", legacyLocalAuthID, "pbtest@pbs"},
		{"remote", "proxbackup@pbs", "proxbackup@pbs"},
	} {
		if _, err := s.store.db.Exec(`INSERT INTO targets(name, host, fingerprint, datastore, admin_auth_id, admin_secret_enc, pbs_user, created_at)
			VALUES(?, 'remote.example:8007', 'aa', 'ds', ?, X'', ?, 1)`, row[0], row[1], row[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.migrate(); err != nil {
		t.Fatal(err)
	}
	s.store.SetSetting(ctx, unusedLocalTargetsKey, true) // see TestUnusedLocalTargetsRemoved
	if err := s.syncLocalTargets(ctx); err != nil {
		t.Fatal(err)
	}
	ts, _ := s.store.Targets(ctx)
	got := map[string]*Target{}
	for _, tg := range ts {
		got[tg.Name] = tg
	}
	if tg := got["ds"]; !tg.Local || tg.AdminAuthID != "proxbackup@pbs" || tg.Host != localHost || tg.Fingerprint != localFP {
		t.Fatalf("migrated target %+v", tg)
	} else if sec, _ := s.sealer.Open(tg.adminSecretEnc, colTargetSecret, tg.ID); sec != "local-password" {
		t.Fatalf("migrated target secret %q", sec)
	}
	if tg := got["other-user"]; !tg.Local || tg.AdminAuthID != legacyLocalAuthID {
		t.Fatalf("target of another agent user %+v", tg)
	}
	if tg := got["remote"]; tg.Local || tg.Host != "remote.example:8007" || len(tg.adminSecretEnc) != 0 {
		t.Fatalf("remote target %+v", tg)
	}
}

// localHelper runs the root helper on each request, on a PBS with datastore
// "ds" whose proxy.pem has fingerprint proxyFP.
func localHelper(t *testing.T, s *Server, proxyFP string) *fakePBSRoot {
	root := newFakePBSRoot("ds")
	root.proxyFP = proxyFP
	s.grantHelper = func() {
		if err := grantLocalPBS(context.Background(), s.cfg.DataDir, s.cfg.LocalPBS.AuthID, root, s.log); err != nil {
			t.Errorf("grant helper: %v", err)
		}
	}
	return root
}

// TestLocalPBSCertificatePinned checks that the console sends its PBS
// password only to the certificate in PBS's proxy.pem, as the root helper
// reports it, and follows a renewal.
func TestLocalPBSCertificatePinned(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	real, realFP, realAuths := fakePBS(t)
	impostor, _, impostorAuths := fakePBS(t)
	renewed, renewedFP, renewedAuths := fakePBS(t)
	secretFile := filepath.Join(t.TempDir(), "pbs-password")
	os.WriteFile(secretFile, []byte("local-password\n"), 0o600)
	l := &LocalPBS{APIAddr: real.Listener.Addr().String(), PublicHost: "pbs.example:8007", AuthID: "proxbackup@pbs", SecretFile: secretFile}
	s.cfg.LocalPBS = l
	root := localHelper(t, s, realFP)
	s.proxyCertEvery = 0
	login := func() error {
		pc, _, _, err := s.localClient(ctx)
		if err == nil {
			_, err = pc.Version(ctx)
		}
		return err
	}

	if err := login(); err != nil {
		t.Fatalf("local PBS: %v", err)
	}
	if a := realAuths(); len(a) != 1 || a[0] != "password:local-password" {
		t.Fatalf("local PBS received %q", a)
	}
	// Something else listening on the port while PBS is down gets nothing.
	l.APIAddr = impostor.Listener.Addr().String()
	if err := login(); err == nil || !strings.Contains(err.Error(), "isn't the one in") {
		t.Fatalf("impostor: %v", err)
	}
	if a := impostorAuths(); len(a) != 0 {
		t.Fatalf("impostor received %q", a)
	}
	// A renewed certificate is trusted once the helper reports it.
	root.proxyFP = renewedFP
	l.APIAddr = renewed.Listener.Addr().String()
	if err := login(); err != nil {
		t.Fatalf("renewed certificate: %v", err)
	}
	if a := renewedAuths(); len(a) != 1 {
		t.Fatalf("renewed PBS received %q", a)
	}
	if fp, err := s.localFingerprint(ctx); err != nil || fp != renewedFP {
		t.Fatalf("fingerprint %q %v", fp, err)
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
	saveWith := func(tg *Target, ras []RoleAssignment, host, fp, pbsUser string, extra map[string]any) int {
		req := map[string]any{"name": tg.Name, "host": host, "fingerprint": fp, "datastore": "ds",
			"admin_auth_id": "admin@pbs!t", "admin_secret": "made-up", "pbs_user": pbsUser}
		maps.Copy(req, extra)
		b, _ := json.Marshal(req)
		r := as(httptest.NewRequest("PUT", "/api/targets/x", strings.NewReader(string(b))), ras)
		r.SetPathValue("id", strconv.FormatInt(tg.ID, 10))
		rec := httptest.NewRecorder()
		s.handleSaveTarget(rec, r)
		return rec.Code
	}
	saveAs := func(tg *Target, ras []RoleAssignment, host, fp, pbsUser string) int {
		return saveWith(tg, ras, host, fp, pbsUser, nil)
	}
	save := func(tg *Target, ras []RoleAssignment, host, fp string) int {
		return saveAs(tg, ras, host, fp, "proxbackup@pbs")
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
	// The agent user owns the tokens of clients enrolled from now on.
	if c := saveAs(used, targetsOnly, "pbs:8007", "aa", "evil@pbs"); c != 403 {
		t.Fatalf("new agent user without restore: %d", c)
	}
	// A new datastore or root namespace sends backups and client tokens elsewhere.
	if c := saveWith(used, targetsOnly, "pbs:8007", "aa", "proxbackup@pbs", map[string]any{"datastore": "other"}); c != 403 {
		t.Fatalf("new datastore without restore: %d", c)
	}
	if c := saveWith(used, targetsOnly, "pbs:8007", "aa", "proxbackup@pbs", map[string]any{"root_ns": "elsewhere"}); c != 403 {
		t.Fatalf("new root namespace without restore: %d", c)
	}
	// Auth ids go into request headers.
	if c := saveWith(empty, allRestore, "pbs:8007", "aa", "proxbackup@pbs", map[string]any{"admin_auth_id": "admin@pbs!t\r\nX-Evil: 1"}); c != 400 {
		t.Fatalf("auth id with CR/LF: %d", c)
	}
	if c := saveAs(empty, allRestore, "pbs:8007", "aa", "proxbackup@pbs!tok"); c != 400 {
		t.Fatalf("token as agent user: %d", c)
	}
	if got, _ := s.store.Target(ctx, used.ID); got.Host != "pbs:8007" || got.Fingerprint != "aa" || got.PBSUser != "proxbackup@pbs" || got.Datastore != "ds" || got.RootNS != "" {
		t.Fatalf("target changed: %+v", got)
	}
	if c := save(used, targetsOnly, "PBS", "AA"); c != 200 {
		t.Fatalf("same endpoint without restore: %d", c)
	}
	if c := save(empty, targetsOnly, "other:8007", "bb"); c != 200 {
		t.Fatalf("target without clients: %d", c)
	}
	if c := saveAs(empty, targetsOnly, "other:8007", "bb", "other@pbs"); c != 200 {
		t.Fatalf("new agent user of a target without clients: %d", c)
	}
	if c := saveAs(used, allRestore, "pbs:8007", "aa", "other@pbs"); c != 200 {
		t.Fatalf("new agent user with restore for all clients: %d", c)
	}
	if c := save(used, allRestore, "other:8007", "bb"); c != 200 {
		t.Fatalf("new host with restore for all clients: %d", c)
	}
}

// The console reaches this PBS on loopback even when agents get a reverse
// proxy that refuses password sign-ins (docs/network.md).
func TestLocalTargetsUseLoopbackAPI(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	api, fp, auths := fakePBS(t)
	secretFile := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secretFile, []byte("local-password\n"), 0o600)
	const proxy = "pbs.invalid:8443" // must never be dialed
	s.cfg.LocalPBS = &LocalPBS{APIAddr: api.Listener.Addr().String(), PublicHost: proxy, AuthID: "proxbackup@pbs", SecretFile: secretFile}
	tg := &Target{Name: "local", Host: proxy, Fingerprint: fp, Datastore: "ds", AdminAuthID: "proxbackup@pbs", PBSUser: "proxbackup@pbs", Local: true}
	if err := s.store.SaveTarget(ctx, tg, s.sealer.sealFor("local-password", colTargetSecret)); err != nil {
		t.Fatal(err)
	}
	pc, err := s.adminClient(tg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.Version(ctx); err != nil {
		t.Fatalf("local target via loopback: %v", err)
	}
	if a := auths(); len(a) != 1 || a[0] != "password:local-password" {
		t.Fatalf("loopback API received %q", a)
	}
	if h := s.pbsAPIHost("other.example:8007"); h != "other.example:8007" {
		t.Fatalf("remote PBS rerouted to %s", h)
	}
}
