// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"proxbackup/internal/api"
)

// A user manager can't grant what they don't have, or take over an account
// that has more.
func TestUserManagerCantEscalate(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin-password"); err != nil {
		t.Fatal(err)
	}
	cs := groupTestClients(t, s, "pc1", "pc2")
	ui := s.uiRoutes()
	admin, _ := login(t, ui, "admin", "admin-password")
	var roles []*Role
	json.NewDecoder(admin.call("GET", "/api/roles", nil).Body).Decode(&roles)
	roleID := map[string]int64{}
	for _, r := range roles {
		roleID[r.Builtin] = r.ID
	}
	w := admin.call("POST", "/api/roles", map[string]any{"name": "User manager", "permissions": []Perm{PermUsers, PermRestore}})
	var mgrRole Role
	json.NewDecoder(w.Body).Decode(&mgrRole)
	if w.Code != 200 {
		t.Fatalf("create role: %d %s", w.Code, w.Body)
	}
	if w := admin.call("POST", "/api/users", map[string]any{"username": "mgr", "password": "manager-pw", "enabled": true,
		"roles": []RoleAssignment{{RoleID: mgrRole.ID, AllClients: true}}}); w.Code != 200 {
		t.Fatalf("create mgr: %d %s", w.Code, w.Body)
	}
	mgr, _ := login(t, ui, "mgr", "manager-pw")
	adminID := int64(1)
	for _, c := range []struct {
		name, method, path string
		body               any
		want               int
	}{
		{"grant Administrator", "POST", "/api/users", map[string]any{"username": "evil", "password": "evil-password", "enabled": true,
			"roles": []RoleAssignment{{RoleID: roleID["admin"], AllClients: true}}}, http.StatusForbidden},
		{"grant own permissions", "POST", "/api/users", map[string]any{"username": "helper", "password": "helper-password", "enabled": true,
			"roles": []RoleAssignment{{RoleID: roleID["restore"], Clients: []int64{cs[0].ID}}}}, 200},
		{"reset the admin's password", "POST", "/api/users/" + jsonNum(adminID) + "/password", map[string]any{"password": "taken-over-1"}, http.StatusForbidden},
		{"change the admin", "PUT", "/api/users/" + jsonNum(adminID), map[string]any{"enabled": false, "roles": []RoleAssignment{}}, http.StatusForbidden},
		{"delete the admin", "DELETE", "/api/users/" + jsonNum(adminID), nil, http.StatusForbidden},
		{"widen own role", "PUT", "/api/roles/" + jsonNum(mgrRole.ID), map[string]any{"name": "User manager",
			"permissions": []Perm{PermUsers, PermRestore, PermRestoreSystem}}, http.StatusForbidden},
		{"create a wider role", "POST", "/api/roles", map[string]any{"name": "Wide", "permissions": []Perm{PermTargets}}, http.StatusForbidden},
		{"create a narrower role", "POST", "/api/roles", map[string]any{"name": "Narrow", "permissions": []Perm{PermRestore}}, 200},
	} {
		if w := mgr.call(c.method, c.path, c.body); w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body, c.want)
		}
	}
	// The admin may still do all of it.
	if w := admin.call("POST", "/api/users", map[string]any{"username": "second-admin", "password": "second-admin-pw", "enabled": true,
		"roles": []RoleAssignment{{RoleID: roleID["admin"], AllClients: true}}}); w.Code != 200 {
		t.Fatalf("admin grants Administrator: %d %s", w.Code, w.Body)
	}
}

func TestAccessGrantsScopes(t *testing.T) {
	roles := map[int64][]Perm{1: {PermRestore}}
	all := newAccess([]RoleAssignment{{RoleID: 1, AllClients: true}}, roles)
	pc5 := newAccess([]RoleAssignment{{RoleID: 1, Clients: []int64{5}}}, roles)
	pc6 := newAccess([]RoleAssignment{{RoleID: 1, Clients: []int64{6}}}, roles)
	office := newAccess([]RoleAssignment{{RoleID: 1, Tags: []string{"office"}}}, roles)
	switch {
	case all.Grants(pc5) != nil || all.Grants(office) != nil || pc5.Grants(pc5) != nil:
		t.Fatal("covered grant refused")
	case pc5.Grants(all) == nil || pc5.Grants(pc6) == nil || pc5.Grants(office) == nil:
		t.Fatal("wider grant allowed")
	case !errors.Is(pc5.Grants(all), errBeyondOwnAccess):
		t.Fatal("error kind")
	}
}

// A setup token enrolls at most its limit of PCs.
func TestSetupTokenUseLimit(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "pc1")
	id, err := s.store.CreateSetupToken(ctx, "hash", cs[0].TargetID, time.Now().Add(time.Hour).Unix(), 2, s.sealer.sealFor("tok", colSetupToken))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := s.store.TakeSetupTokenUse(ctx, id); err != nil {
			t.Fatalf("use %d: %v", i, err)
		}
	}
	if err := s.store.TakeSetupTokenUse(ctx, id); !errors.Is(err, errSetupUsedUp) {
		t.Fatalf("third use: %v", err)
	}
	s.store.ReleaseSetupTokenUse(ctx, id) // a failed enrollment gives its use back
	if err := s.store.TakeSetupTokenUse(ctx, id); err != nil {
		t.Fatalf("after release: %v", err)
	}
	if st, err := s.store.SetupTokenByCode(ctx, "hash"); err != nil || st.Uses != 2 || st.MaxUses != 2 {
		t.Fatalf("token = %+v, %v", st, err)
	}
	unlimited, _ := s.store.CreateSetupToken(ctx, "hash2", cs[0].TargetID, time.Now().Add(time.Hour).Unix(), 0, s.sealer.sealFor("tok", colSetupToken))
	for range 5 {
		if err := s.store.TakeSetupTokenUse(ctx, unlimited); err != nil {
			t.Fatal(err)
		}
	}
	l := rateLimiter[int64]{perHour: setupEnrollsPerHour, burst: setupEnrollsBurst}
	now := time.Now()
	for range setupEnrollsBurst {
		if !l.allow(id, now) {
			t.Fatal("burst refused")
		}
	}
	if l.allow(id, now) || !l.allow(unlimited, now) {
		t.Fatal("rate limit is per token")
	}
}

// A PC whose administrators don't allow console restores into system
// folders gets none, whatever the console user may do.
func TestRestoreSystemRefusedByPC(t *testing.T) {
	c := &Client{OS: "windows/amd64", Features: []string{api.FeatureProtectedRestore, api.FeatureNoConsoleSystemRestores}}
	req := &api.RestoreSpec{TargetDir: `C:\Windows\System32`}
	if err := restoreSystemAllowed(req, c, true); err == nil || !strings.Contains(err.Error(), "doesn't allow") {
		t.Fatalf("system target: %v", err)
	}
	req = &api.RestoreSpec{TargetDir: `C:\Restore`}
	if err := restoreSystemAllowed(req, c, true); err != nil || req.SystemFolders {
		t.Fatalf("other target: %v, system_folders=%v", err, req.SystemFolders)
	}
}

func TestWebhookAddrAllowed(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8007": false, "[::1]:443": false, "169.254.169.254:80": false, "[fe80::1]:80": false,
		"0.0.0.0:80": false, "[::ffff:127.0.0.1]:80": false,
		"10.0.0.5:443": true, "192.168.1.10:8080": true, "203.0.113.7:443": true, "[2001:db8::1]:443": true,
	} {
		if err := webhookAddrAllowed(addr); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}
