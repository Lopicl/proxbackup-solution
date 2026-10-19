// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxbackup/internal/api"
)

func TestSelfRestore(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := groupTestClients(t, s, "pc-1")[0]
	g := &GroupJob{Name: "Users", Kind: api.KindFiles, Sources: []string{`C:\Users`}, Schedule: "0 21 * * *", Enabled: true,
		WindowMinutes: 60, ChangeDetection: "metadata", Clients: []int64{c.ID}}
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}

	open := func(req api.RestoreSessionRequest) (string, int) {
		b, _ := json.Marshal(req)
		r := httptest.NewRequest("POST", "https://console:8077/agent/v1/restore-sessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		s.handleCreateRestoreSession(w, r, c)
		var resp api.RestoreSessionResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		token, _ := strings.CutPrefix(resp.URL, "https://console:8077/#/restore/")
		return token, w.Code
	}
	if _, code := open(api.RestoreSessionRequest{Ref: "0123456789abcdef", User: `PC\bob`}); code != 400 {
		t.Fatalf("a non-admin session without a scope must be rejected, got %d", code)
	}
	token, code := open(api.RestoreSessionRequest{Ref: "0123456789abcdef", User: `PC\alice`, SID: "S-1-5-21-1", Scope: `C:\Users\Alice`, TTL: 3600})
	if code != 200 || token == "" {
		t.Fatalf("create session: %d", code)
	}

	ui := s.uiRoutes()
	call := func(method, path, tok string, body any) *httptest.ResponseRecorder {
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		r := httptest.NewRequest(method, path, rd)
		if tok != "" {
			r.Header.Set(restoreSessionHeader, tok)
		}
		w := httptest.NewRecorder()
		ui.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/self-restore/session", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := call("GET", "/api/self-restore/session", "wrong", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", w.Code)
	}
	w := call("GET", "/api/self-restore/session", token, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"scope":"C:\\Users\\Alice"`) {
		t.Fatalf("session: %d %s", w.Code, w.Body)
	}
	// The session doesn't open the admin API.
	if w := call("GET", "/api/clients", token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin API with a restore token: %d", w.Code)
	}

	spec := func(paths []string, target string) api.RestoreSpec {
		return api.RestoreSpec{BackupID: "pc-1", BackupTime: 1700000000, Archive: "c-users.mpxar.didx", Paths: paths, TargetDir: target,
			Session: "forged", RequestedBy: "forged"}
	}
	for _, bad := range []api.RestoreSpec{
		spec([]string{"Bob/Documents"}, `C:\Users`),
		spec(nil, `C:\Users`),
		spec([]string{"Alice/Documents"}, `C:\Windows`),
	} {
		if w := call("POST", "/api/self-restore/restore", token, bad); w.Code != http.StatusForbidden {
			t.Errorf("restore %v → %s: %d %s", bad.Paths, bad.TargetDir, w.Code, w.Body)
		}
	}
	w = call("POST", "/api/self-restore/restore", token, spec([]string{"Alice/Documents"}, `C:\Users`))
	if w.Code != 200 {
		t.Fatalf("allowed restore: %d %s", w.Code, w.Body)
	}
	var queued struct {
		RunID int64 `json:"run_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &queued)
	run, err := s.store.Run(ctx, queued.RunID)
	if err != nil || run.Restore.Session != "0123456789abcdef" || run.Restore.RequestedBy != `PC\alice` {
		t.Fatalf("queued run: %+v %v", run, err)
	}
	w = call("GET", "/api/self-restore/runs", token, nil)
	var runs []selfRun
	json.Unmarshal(w.Body.Bytes(), &runs)
	if len(runs) != 1 || runs[0].ID != queued.RunID {
		t.Fatalf("runs = %s", w.Body)
	}

	// A console admin's restore can't carry a session (the agent would treat it as the user's).
	req := spec([]string{"x"}, `D:\x`)
	if err := validateRestore(&req, c); err != nil || req.Session != "" || req.RequestedBy != "" {
		t.Fatalf("validateRestore kept the session: %+v %v", req, err)
	}

	// Expired sessions stop working.
	s.store.db.Exec(`UPDATE restore_sessions SET expires=1`)
	if w := call("GET", "/api/self-restore/runs", token, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired session: %d", w.Code)
	}
}
