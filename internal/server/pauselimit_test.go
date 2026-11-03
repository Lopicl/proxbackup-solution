// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPauseLimit checks the console's limit on paused days in a row: a
// default of 1 day, the console-wide setting, and per-client overrides.
func TestPauseLimit(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	tg := &Target{Name: "pbs", Host: "pbs:8007", Datastore: "ds", AdminAuthID: "root@pam!x", PBSUser: "proxbackup@pbs"}
	if err := s.store.SaveTarget(ctx, tg, s.sealer.sealFor("x", colTargetSecret)); err != nil {
		t.Fatal(err)
	}
	c := &Client{Name: "pc-1", TargetID: tg.ID, CertSerial: "01", Namespace: "pcs/pc-1", TokenID: "proxbackup@pbs!pc-1"}
	if err := s.store.CreateClient(ctx, c, s.sealer.sealFor("tok", colClientToken)); err != nil {
		t.Fatal(err)
	}
	pushed := func() *int {
		t.Helper()
		c, err := s.store.Client(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := s.agentConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.PauseDays
	}
	if d := pushed(); d == nil || *d != 1 {
		t.Fatalf("default limit %v", d)
	}
	saveDefault := func(as func(*http.Request) *http.Request, body string) int {
		rec := httptest.NewRecorder()
		s.handleSaveAgentSettings(rec, as(httptest.NewRequest("PUT", "/api/settings/agents", strings.NewReader(body))))
		return rec.Code
	}
	if c := saveDefault(asAdmin, `{"pause_days":3}`); c != 200 {
		t.Fatalf("save default: %d", c)
	}
	if d := pushed(); d == nil || *d != 3 {
		t.Fatalf("console default %v", d)
	}
	if c := saveDefault(asAdmin, `{"pause_days":-2}`); c != 400 {
		t.Fatalf("invalid default: %d", c)
	}
	if c := saveDefault(asAdmin, `{"pause_days":-1}`); c != 200 || pushed() != nil {
		t.Fatalf("no limit: %d %v", c, pushed())
	}

	// A client's own limit wins; null follows the default again.
	viewer := func(r *http.Request) *http.Request {
		a := newAccess([]RoleAssignment{{RoleID: 1, AllClients: true}}, map[int64][]Perm{1: {PermViewClients}})
		return r.WithContext(context.WithValue(r.Context(), sessionUserKey, &SessionUser{ID: 2, Name: "v", Access: a}))
	}
	if rec := callWith(viewer, s.handleClientPauseLimit, "PUT", c.ID, `{"days":0}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d", rec.Code)
	}
	if rec := adminCall(s.handleClientPauseLimit, "PUT", c.ID, `{"days":0}`); rec.Code != 200 {
		t.Fatalf("set: %d %s", rec.Code, rec.Body)
	}
	if d := pushed(); d == nil || *d != 0 {
		t.Fatalf("client limit %v", d)
	}
	if rec := adminCall(s.handleClientPauseLimit, "PUT", c.ID, `{"days":400}`); rec.Code != 400 {
		t.Fatalf("too many days: %d", rec.Code)
	}
	adminCall(s.handleClientPauseLimit, "PUT", c.ID, `{"days":null}`)
	if got, _ := s.store.Client(ctx, c.ID); got.PauseDays != nil || pushed() != nil {
		t.Fatalf("back to the default: %v %v", got.PauseDays, pushed())
	}
}
