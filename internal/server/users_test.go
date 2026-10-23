// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// asAdmin signs r in as an administrator (for tests calling handlers directly).
func asAdmin(r *http.Request) *http.Request {
	var all []Perm
	for _, p := range permissions {
		all = append(all, p.ID)
	}
	a := newAccess([]RoleAssignment{{RoleID: 1, AllClients: true}}, map[int64][]Perm{1: all})
	return r.WithContext(context.WithValue(r.Context(), sessionUserKey, &SessionUser{ID: 1, Name: "admin", Access: a}))
}

func TestMigrateAdmins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxbackup.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, expires INTEGER NOT NULL)`,
		`INSERT INTO admins VALUES (1, 'admin', 'argon2id$x$y', 1), (2, 'root@pam', 'external:pbs', 2)`,
		`INSERT INTO sessions VALUES ('a', 1, 9999999999), ('b', 2, 9999999999)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	us, err := st.Users(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 || us[0].Username != "admin" || !us[0].MustChange || len(us[0].Roles) != 1 || !us[0].Roles[0].AllClients {
		t.Fatalf("users = %+v", us)
	}
	if u, err := st.SessionUser(ctx, "a"); err != nil || !u.Access.Global(PermUsers) {
		t.Fatalf("admin session: %+v %v", u, err)
	}
	if _, err := st.SessionUser(ctx, "b"); !errors.Is(err, errNotFound) {
		t.Fatalf("PBS realm session kept: %v", err)
	}
	if ok, _ := st.tableExists("admins"); ok {
		t.Fatal("admins table kept")
	}
	// Opening again is a no-op.
	st.Close()
	if st, err = OpenStore(path); err != nil {
		t.Fatal(err)
	}
	if rs, _ := st.Roles(ctx); len(rs) != len(builtinRoles) {
		t.Fatalf("roles = %d", len(rs))
	}
}

func TestAccessScopes(t *testing.T) {
	roles := map[int64][]Perm{1: {PermRestore, PermUsers}, 2: {PermViewClients}}
	a := newAccess([]RoleAssignment{
		{RoleID: 1, Clients: []int64{5}, Tags: []string{"office"}},
		{RoleID: 2, AllClients: true},
	}, roles)
	c5, c6, office := &Client{ID: 5}, &Client{ID: 6}, &Client{ID: 7, Tags: []string{"office"}}
	switch {
	case !a.Client(PermRestore, c5) || a.Client(PermRestore, c6) || !a.Client(PermRestore, office):
		t.Fatal("restore scope")
	case a.Global(PermRestore) || !a.Has(PermRestore):
		t.Fatal("restore is scoped")
	case a.Has(PermUsers):
		t.Fatal("a scoped assignment granted a console permission")
	case !a.Global(PermViewClients):
		t.Fatal("view for all clients")
	}
	// Acting on a client includes seeing it.
	b := newAccess([]RoleAssignment{{RoleID: 1, Clients: []int64{5}}}, roles)
	if !b.Client(PermViewClients, c5) || b.Client(PermViewClients, c6) {
		t.Fatal("implied view")
	}
}

// session is a signed-in browser for the UI routes.
type session struct {
	t      *testing.T
	ui     http.Handler
	cookie string
}

func (c *session) call(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set(csrfHeader, "1")
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
	}
	w := httptest.NewRecorder()
	c.ui.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, ui http.Handler, user, pw string) (*session, int) {
	t.Helper()
	c := &session{t: t, ui: ui}
	w := c.call("POST", "/api/login", map[string]string{"username": user, "password": pw})
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck.Value
		}
	}
	return c, w.Code
}

func TestUsersAndPermissions(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin-password"); err != nil {
		t.Fatal(err)
	}
	cs := groupTestClients(t, s, "pc1", "pc2", "pc3")
	if _, err := s.store.SetClientTags(ctx, cs[2].ID, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	ui := s.uiRoutes()
	admin, code := login(t, ui, "admin", "admin-password")
	if code != 200 {
		t.Fatalf("admin login: %d", code)
	}
	if _, code := login(t, ui, "admin", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}

	var roles []*Role
	json.NewDecoder(admin.call("GET", "/api/roles", nil).Body).Decode(&roles)
	roleID := map[string]int64{}
	for _, r := range roles {
		roleID[r.Builtin] = r.ID
	}
	if len(roles) != 4 || roleID["restore"] == 0 {
		t.Fatalf("roles = %+v", roles)
	}

	// A restore-only user for pc1 and the "office" tag.
	w := admin.call("POST", "/api/users", map[string]any{"username": "helpdesk", "password": "helpdesk-pw", "enabled": true,
		"roles": []RoleAssignment{{RoleID: roleID["restore"], Clients: []int64{cs[0].ID}, Tags: []string{"office"}}}})
	if w.Code != 200 {
		t.Fatalf("create user: %d %s", w.Code, w.Body)
	}
	var hd User
	json.NewDecoder(w.Body).Decode(&hd)
	if w := admin.call("POST", "/api/users", map[string]any{"username": "HelpDesk", "password": "helpdesk-pw", "enabled": true}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate name: %d", w.Code)
	}

	user, code := login(t, ui, "helpdesk", "helpdesk-pw")
	if code != 200 {
		t.Fatalf("user login: %d", code)
	}
	var clients []*Client
	json.NewDecoder(user.call("GET", "/api/clients", nil).Body).Decode(&clients)
	if len(clients) != 2 || clients[0].Name != "pc1" || clients[1].Name != "pc3" {
		t.Fatalf("visible clients = %+v", clients)
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/api/clients/" + jsonNum(cs[1].ID), http.StatusForbidden},
		{"GET", "/api/clients/" + jsonNum(cs[0].ID), 200},
		{"GET", "/api/users", http.StatusForbidden},
		{"GET", "/api/settings/notifications", http.StatusForbidden},
		{"POST", "/api/targets", http.StatusForbidden},
		{"GET", "/api/enrollments", http.StatusForbidden},
		{"DELETE", "/api/clients/" + jsonNum(cs[0].ID), http.StatusForbidden},
		{"POST", "/api/clients/" + jsonNum(cs[1].ID) + "/restore", http.StatusForbidden},
		{"PUT", "/api/clients/" + jsonNum(cs[2].ID) + "/tags", http.StatusForbidden},
		{"GET", "/api/audit", http.StatusForbidden},
	} {
		var body any
		if c.method != "GET" && c.method != "DELETE" {
			body = map[string]any{}
		}
		if w := user.call(c.method, c.path, body); w.Code != c.want {
			t.Errorf("%s %s: %d %s, want %d", c.method, c.path, w.Code, w.Body, c.want)
		}
	}
	var me struct {
		Permissions map[Perm]scopeView `json:"permissions"`
	}
	json.NewDecoder(user.call("GET", "/api/me", nil).Body).Decode(&me)
	if sc := me.Permissions[PermRestore]; sc.All || len(sc.Clients) != 1 || len(sc.Tags) != 1 || len(me.Permissions) != 2 {
		t.Fatalf("me permissions = %+v", me.Permissions)
	}

	// The last administrator can't be removed or disabled.
	adminID := int64(1)
	if w := admin.call("PUT", "/api/users/"+jsonNum(adminID), map[string]any{"enabled": true, "roles": []RoleAssignment{}}); w.Code != http.StatusConflict {
		t.Fatalf("demote last admin: %d %s", w.Code, w.Body)
	}
	if w := admin.call("DELETE", "/api/users/"+jsonNum(adminID), nil); w.Code != http.StatusBadRequest {
		t.Fatalf("delete self: %d", w.Code)
	}

	// Disabling a user ends its sessions; a reset password must be changed.
	if w := admin.call("PUT", "/api/users/"+jsonNum(hd.ID), map[string]any{"enabled": false, "roles": hd.Roles}); w.Code != 200 {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	if w := user.call("GET", "/api/me", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled session: %d", w.Code)
	}
	if _, code := login(t, ui, "helpdesk", "helpdesk-pw"); code != http.StatusUnauthorized {
		t.Fatalf("disabled login: %d", code)
	}
	admin.call("PUT", "/api/users/"+jsonNum(hd.ID), map[string]any{"enabled": true, "roles": hd.Roles})
	if w := admin.call("POST", "/api/users/"+jsonNum(hd.ID)+"/password", map[string]any{"password": "new-password-1", "must_change_password": true}); w.Code != 200 {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	user, _ = login(t, ui, "helpdesk", "new-password-1")
	if w := user.call("GET", "/api/clients", nil); w.Code != http.StatusForbidden {
		t.Fatalf("must change first: %d", w.Code)
	}
	if w := user.call("POST", "/api/password", map[string]string{"current_password": "new-password-1", "new_password": "own-password-2"}); w.Code != 200 {
		t.Fatalf("change own password: %d %s", w.Code, w.Body)
	}

	// Custom roles: in use ones can't be deleted, built-in ones not changed.
	w = admin.call("POST", "/api/roles", map[string]any{"name": "Runner", "permissions": []Perm{PermRunBackups}})
	var runner Role
	json.NewDecoder(w.Body).Decode(&runner)
	if w.Code != 200 || len(runner.Permissions) != 1 {
		t.Fatalf("create role: %d %+v", w.Code, runner)
	}
	if w := admin.call("PUT", "/api/roles/"+jsonNum(roleID["admin"]), map[string]any{"name": "x"}); w.Code != http.StatusBadRequest {
		t.Fatalf("change built-in: %d", w.Code)
	}
	if w := admin.call("DELETE", "/api/roles/"+jsonNum(runner.ID), nil); w.Code != 200 {
		t.Fatalf("delete role: %d %s", w.Code, w.Body)
	}

	var log []*AuditEntry
	json.NewDecoder(admin.call("GET", "/api/audit", nil).Body).Decode(&log)
	var actions []string
	for _, e := range log {
		actions = append(actions, e.Username+":"+e.Action)
	}
	all := strings.Join(actions, ",")
	for _, want := range []string{"admin:sign-in", "admin:create user", "admin:reset user password", "helpdesk:change own password", "admin:delete role"} {
		if !strings.Contains(all, want) {
			t.Errorf("audit log lacks %q: %s", want, all)
		}
	}
}
