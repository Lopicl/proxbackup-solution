// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"proxbackup/internal/api"
)

// fakeProvisionPBS answers the calls of enrollment and re-enrollment: tokens
// get the name they are created with.
type fakeProvisionPBS struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeProvisionPBS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
	f.calls = append(f.calls, r.Method+" "+path)
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	switch {
	case strings.HasPrefix(path, "access/users/") && strings.Contains(path, "/token/"):
		user, name, _ := strings.Cut(strings.TrimPrefix(path, "access/users/"), "/token/")
		if r.Method == http.MethodPost {
			reply(map[string]any{"tokenid": user + "!" + name, "value": "secret-" + name})
			return
		}
		reply(nil)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/namespace"):
		reply([]map[string]any{})
	default:
		reply(nil) // namespace creation, ACLs
	}
}

func (f *fakeProvisionPBS) called(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// reenrollTestClient creates pc-1 with a job on a target served by a fake PBS,
// and revokes it.
func reenrollTestClient(t *testing.T, s *Server) (*Client, *Job, *fakeProvisionPBS) {
	t.Helper()
	ctx := context.Background()
	f := &fakeProvisionPBS{}
	c := rotationTestClient(t, s, f)
	g := &GroupJob{Name: "Users", Kind: api.KindFiles, Sources: []string{`C:\Users`}, Schedule: "0 21 * * *",
		Enabled: true, CatchUp: true, WindowMinutes: 60, ChangeDetection: "metadata", Clients: []int64{c.ID}}
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}
	jobs, _ := s.store.Jobs(ctx, c.ID)
	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	s.cfg.PublicURL = "https://console.example:8077"
	return c, jobs[0], f
}

// adminCall runs h as an administrator, with {id} set to id when not 0.
func adminCall(h http.HandlerFunc, method string, id int64, body string) *httptest.ResponseRecorder {
	return callWith(asAdmin, h, method, id, body)
}

func callWith(as func(*http.Request) *http.Request, h http.HandlerFunc, method string, id int64, body string) *httptest.ResponseRecorder {
	req := as(httptest.NewRequest(method, "/api/x", strings.NewReader(body)))
	if id != 0 {
		req.SetPathValue("id", strconv.FormatInt(id, 10))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// enrollWith enrolls a PC with the code in an enrollment command.
func enrollWith(t *testing.T, s *Server, command, hostname string) (*httptest.ResponseRecorder, api.EnrollResponse) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(command, "proxbackup-agent.exe enroll "))
	if err != nil {
		t.Fatal(err)
	}
	var tok api.EnrollmentToken
	json.Unmarshal(b, &tok)
	_, csrPEM := testCSR(t)
	body, _ := json.Marshal(api.EnrollRequest{Code: tok.Code, CSR: string(csrPEM), Hostname: hostname, OS: "windows/amd64"})
	rec := httptest.NewRecorder()
	s.handleEnroll(rec, httptest.NewRequest("POST", "/agent/v1/enroll", strings.NewReader(string(body))))
	var resp api.EnrollResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

func TestReenrollRevokedClient(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c, job, f := reenrollTestClient(t, s)

	var list []*Client
	json.Unmarshal(adminCall(s.handleRevokedClients, "GET", 0, "").Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != c.ID || list[0].Reenroll != nil || list[0].NameInUse {
		t.Fatalf("revoked list = %+v", list)
	}

	rec := adminCall(s.handleCreateReenrollment, "POST", c.ID, `{"ttl_hours":2}`)
	if rec.Code != 200 {
		t.Fatalf("create re-enrollment: %d %s", rec.Code, rec.Body)
	}
	var created struct{ Command string }
	json.Unmarshal(rec.Body.Bytes(), &created)
	if rec := adminCall(s.handleCreateReenrollment, "POST", c.ID, `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("second re-enrollment: %d", rec.Code)
	}
	// The name is reserved meanwhile.
	if rec := adminCall(s.handleCreateEnrollment, "POST", 0, `{"client_name":"pc-1","target_id":1,"new_client":true}`); rec.Code != 400 {
		t.Fatalf("enrollment under a reserved name: %d %s", rec.Code, rec.Body)
	}
	json.Unmarshal(adminCall(s.handleRevokedClients, "GET", 0, "").Body.Bytes(), &list)
	if list[0].Reenroll == nil {
		t.Fatal("pending re-enrollment not listed")
	}
	var shown struct{ Command string }
	json.Unmarshal(adminCall(s.handleReenrollmentCommand, "GET", c.ID, "").Body.Bytes(), &shown)
	if shown.Command != created.Command {
		t.Fatal("shown command differs")
	}
	// Managing clients isn't enough to read it from the enrollments list.
	es, _ := s.store.Enrollments(ctx)
	manager := func(r *http.Request) *http.Request {
		a := newAccess([]RoleAssignment{{RoleID: 1, AllClients: true}}, map[int64][]Perm{1: {PermViewClients, PermManageClients}})
		return r.WithContext(context.WithValue(r.Context(), sessionUserKey, &SessionUser{ID: 2, Name: "op", Access: a}))
	}
	if rec := callWith(manager, s.handleEnrollmentCommand, "GET", es[0].ID, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("re-enrollment command for clients.manage: %d", rec.Code)
	}
	if rec := adminCall(s.handleEnrollmentCommand, "GET", es[0].ID, ""); rec.Code != 200 {
		t.Fatalf("re-enrollment command for an admin: %d", rec.Code)
	}
	// Nor to cancel it there.
	if rec := callWith(manager, s.handleDeleteEnrollment, "DELETE", es[0].ID, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("re-enrollment canceled with clients.manage: %d", rec.Code)
	}

	rec, resp := enrollWith(t, s, created.Command, "NEW-PC")
	if rec.Code != 200 || resp.ClientID != c.ID || resp.ClientName != "pc-1" {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	rc, _ := s.store.Client(ctx, c.ID)
	if rc.Revoked || rc.Name != "pc-1" || rc.Hostname != "NEW-PC" || rc.Namespace != c.Namespace || rc.TokenID != "proxbackup@pbs!pc-1" || rc.CertSerial == "" {
		t.Fatalf("re-enrolled client = %+v", rc)
	}
	if j, _ := s.store.Job(ctx, job.ID); !j.Enabled {
		t.Fatal("job not re-enabled")
	}
	if cfg, err := s.agentConfig(ctx, rc); err != nil || cfg.Target.Secret != "secret-pc-1" {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	if got := f.called("POST access/users/proxbackup@pbs/token/"); len(got) != 1 || !strings.HasSuffix(got[0], "/token/pc-1") {
		t.Fatalf("token creations = %q", got)
	}
	if got := f.called("PUT access/acl"); len(got) == 0 {
		t.Fatal("no ACL granted")
	}
	// The code is used up, and nothing is left to list.
	if rec, _ := enrollWith(t, s, created.Command, "OTHER"); rec.Code != http.StatusForbidden {
		t.Fatalf("second use: %d", rec.Code)
	}
	json.Unmarshal(adminCall(s.handleRevokedClients, "GET", 0, "").Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("revoked list after re-enrollment = %+v", list)
	}
}

func TestReenrollmentCanceledOrOutdated(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c, _, _ := reenrollTestClient(t, s)
	var created struct{ Command string }
	json.Unmarshal(adminCall(s.handleCreateReenrollment, "POST", c.ID, `{}`).Body.Bytes(), &created)
	if rec := adminCall(s.handleDeleteReenrollment, "DELETE", c.ID, ""); rec.Code != 200 {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	if rec, _ := enrollWith(t, s, created.Command, "PC"); rec.Code != http.StatusForbidden {
		t.Fatalf("canceled re-enrollment used: %d", rec.Code)
	}

	// The client comes back another way before the PC enrolls.
	json.Unmarshal(adminCall(s.handleCreateReenrollment, "POST", c.ID, `{}`).Body.Bytes(), &created)
	rc, _ := s.store.Client(ctx, c.ID)
	s.store.UnrevokeClient(ctx, rc, "pc-1", rc.TokenID, nil)
	if rec, _ := enrollWith(t, s, created.Command, "PC"); rec.Code != http.StatusInternalServerError {
		t.Fatalf("re-enrollment of an active client: %d", rec.Code)
	}
	if rec := adminCall(s.handleCreateReenrollment, "POST", c.ID, `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("re-enrollment of an active client: %d", rec.Code)
	}
}

func TestNewClientUnderRevokedName(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c, _, f := reenrollTestClient(t, s)
	body := `{"client_name":"pc-1","target_id":` + strconv.FormatInt(c.TargetID, 10)
	if rec := adminCall(s.handleCreateEnrollment, "POST", 0, body+`}`); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "Revoked clients") {
		t.Fatalf("revoked name without confirmation: %d %s", rec.Code, rec.Body)
	}
	rec := adminCall(s.handleCreateEnrollment, "POST", 0, body+`,"new_client":true}`)
	if rec.Code != 200 {
		t.Fatalf("new client: %d %s", rec.Code, rec.Body)
	}
	var created struct{ Command string }
	json.Unmarshal(rec.Body.Bytes(), &created)
	rec, resp := enrollWith(t, s, created.Command, "PC2")
	if rec.Code != 200 || resp.ClientID == c.ID || resp.ClientName != "pc-1" {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	nc, _ := s.store.Client(ctx, resp.ClientID)
	if nc.Namespace != "pc-1.2" || nc.TokenID != "proxbackup@pbs!pc-1.2" {
		t.Fatalf("new client storage = %s, %s", nc.Namespace, nc.TokenID)
	}
	if got := f.called("POST access/users/proxbackup@pbs/token/"); len(got) != 1 || !strings.HasSuffix(got[0], "/token/pc-1.2") {
		t.Fatalf("token creations = %q", got)
	}

	// The revoked client can't come back under the name meanwhile.
	var list []*Client
	json.Unmarshal(adminCall(s.handleRevokedClients, "GET", 0, "").Body.Bytes(), &list)
	if len(list) != 1 || !list[0].NameInUse {
		t.Fatalf("revoked list = %+v", list)
	}
	if rec := adminCall(s.handleCreateReenrollment, "POST", c.ID, `{}`); rec.Code != http.StatusConflict {
		t.Fatalf("re-enrollment while the name is used: %d", rec.Code)
	}

	// Revoked in turn, the next client under the name gets pc-1.3.
	s.store.RevokeClient(ctx, nc.ID)
	tg, _ := s.store.Target(ctx, c.TargetID)
	if got := s.freeStorageName(ctx, tg, "pc-1"); got != "pc-1.3" {
		t.Fatalf("next storage name = %s", got)
	}
	if got := s.freeStorageName(ctx, tg, "pc-9"); got != "pc-9" {
		t.Fatalf("fresh name's storage = %s", got)
	}
	// A root namespace move keeps the storage name.
	nc, _ = s.store.Client(ctx, nc.ID)
	if tokenName(nc) != "pc-1.2" || nc.baseName() != "pc-1" {
		t.Fatalf("token name %s, base name %s", tokenName(nc), nc.baseName())
	}
}

// The un-revoke of a client enrolled under a revoked name keeps its own token name.
func TestUnrevokeKeepsTokenName(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	f := &fakeProvisionPBS{}
	c := rotationTestClient(t, s, f)
	s.store.db.Exec(`UPDATE clients SET token_id='proxbackup@pbs!pc-1.2', namespace='pcs/pc-1.2' WHERE id=?`, c.ID)
	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if rec := adminCall(s.handleUnrevokeClient, "POST", c.ID, ""); rec.Code != 200 {
		t.Fatalf("un-revoke: %d %s", rec.Code, rec.Body)
	}
	rc, _ := s.store.Client(ctx, c.ID)
	if rc.Name != "pc-1" || rc.TokenID != "proxbackup@pbs!pc-1.2" {
		t.Fatalf("un-revoked client = %s, %s", rc.Name, rc.TokenID)
	}
}

// The old PC has the client's encryption key, so a re-enrolled client backs
// up with a new one unless asked to keep it; old keys stay escrowed.
func TestReenrollNewEncryptionKey(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c, _, _ := reenrollTestClient(t, s)
	if err := s.ensureClientKey(ctx, c); err != nil {
		t.Fatal(err)
	}
	c, _ = s.store.Client(ctx, c.ID)
	oldKey, _ := s.clientKey(ctx, c)

	reenroll := func(body string) *Client {
		t.Helper()
		rec := adminCall(s.handleCreateReenrollment, "POST", c.ID, body)
		if rec.Code != 200 {
			t.Fatalf("create re-enrollment: %d %s", rec.Code, rec.Body)
		}
		var created struct{ Command string }
		json.Unmarshal(rec.Body.Bytes(), &created)
		if rec, _ := enrollWith(t, s, created.Command, "NEW-PC"); rec.Code != 200 {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
		}
		rc, _ := s.store.Client(ctx, c.ID)
		return rc
	}
	download := func(fp string) int {
		req := asAdmin(httptest.NewRequest("GET", "/api/clients/x/encryption-key?fingerprint="+fp, nil))
		req.SetPathValue("id", strconv.FormatInt(c.ID, 10))
		rec := httptest.NewRecorder()
		s.handleClientKey(rec, req)
		return rec.Code
	}

	rc := reenroll(`{"ttl_hours":1}`)
	if rc.EncryptionFingerprint == "" || rc.EncryptionFingerprint == oldKey.Fingerprint {
		t.Fatalf("key not replaced: %q", rc.EncryptionFingerprint)
	}
	if cfg, err := s.agentConfig(ctx, rc); err != nil || cfg.Crypt.Fingerprint != rc.EncryptionFingerprint || cfg.Crypt.Key == oldKey.Key {
		t.Fatalf("config key = %+v, %v", cfg.Crypt, err)
	}
	olds, _ := s.store.OldClientKeys(ctx, c.ID)
	if len(olds) != 1 || olds[0].Fingerprint != oldKey.Fingerprint || olds[0].Created != oldKey.Created || olds[0].RetiredAt == 0 {
		t.Fatalf("old keys = %+v", olds)
	}
	if k, err := s.keyFor(ctx, rc, oldKey.Fingerprint); err != nil || k.Key != oldKey.Key {
		t.Fatalf("old key = %+v, %v", k, err)
	}
	if _, err := s.keyFor(ctx, rc, "00:11"); err == nil {
		t.Fatal("unknown fingerprint found")
	}
	if code := download(oldKey.Fingerprint); code != 200 {
		t.Fatalf("download old key: %d", code)
	}
	if code := download("00:11"); code != 404 {
		t.Fatalf("download unknown key: %d", code)
	}

	// Kept on request.
	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	kept := reenroll(`{"ttl_hours":1,"new_key":false}`)
	if kept.EncryptionFingerprint != rc.EncryptionFingerprint {
		t.Fatalf("key replaced although kept: %q", kept.EncryptionFingerprint)
	}
	if olds, _ := s.store.OldClientKeys(ctx, c.ID); len(olds) != 1 {
		t.Fatalf("old keys after keeping = %d", len(olds))
	}
}
