// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A cross-site form can post text/plain JSON but can't set the CSRF header:
// sign-in and sign-out must not work without it.
func TestLoginLogoutNeedCSRFHeader(t *testing.T) {
	s := newTestServer(t, "")
	if _, err := s.EnsureAdmin(context.Background(), "admin-password"); err != nil {
		t.Fatal(err)
	}
	ui := securityHeaders(s.uiRoutes())
	post := func(path, ctype string, csrf bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"username":"admin","password":"admin-password"}`))
		r.Header.Set("Content-Type", ctype)
		if csrf {
			r.Header.Set(csrfHeader, "1")
		}
		w := httptest.NewRecorder()
		ui.ServeHTTP(w, r)
		return w
	}
	if w := post("/api/login", "text/plain", false); w.Code != http.StatusForbidden || len(w.Result().Cookies()) > 0 {
		t.Fatalf("form sign-in: %d %v", w.Code, w.Result().Cookies())
	}
	if w := post("/api/logout", "text/plain", false); w.Code != http.StatusForbidden {
		t.Fatalf("form sign-out: %d", w.Code)
	}
	if w := post("/api/login", "text/plain", true); w.Code != http.StatusBadRequest {
		t.Fatalf("text/plain sign-in with header: %d", w.Code)
	}
	w := post("/api/login", "application/json; charset=utf-8", true)
	if w.Code != http.StatusOK {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
		t.Fatalf("HSTS = %q", got)
	}
	if csp := w.Header().Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP = %q", csp)
	}
}

func TestSealerBindsRowAndColumn(t *testing.T) {
	sl, err := LoadOrCreateSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v := sl.Seal("secret", colClientToken, 7)
	if got, err := sl.Open(v, colClientToken, 7); err != nil || got != "secret" {
		t.Fatalf("open = %q, %v", got, err)
	}
	if _, err := sl.Open(v, colClientToken, 8); err == nil {
		t.Fatal("opened in another row")
	}
	if _, err := sl.Open(v, colClientKey, 7); err == nil {
		t.Fatal("opened in another column")
	}
	if _, err := sl.Open(sl.seal("secret", nil), colClientToken, 7); err == nil {
		t.Fatal("opened an unbound value")
	}
}

// Values sealed before binding are re-sealed once, at startup; unbound
// values written afterwards stay unreadable.
func TestBindSealedValues(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := groupTestClients(t, s, "pc-1")[0]
	db := s.store.db
	legacy := func(plain string) []byte { return s.sealer.seal(plain, nil) }
	if _, err := db.Exec(`UPDATE clients SET token_secret_enc=?, crypt_key_enc=? WHERE id=?`, legacy("tok"), legacy("key"), c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE targets SET admin_secret_enc=? WHERE id=?`, legacy("admin"), c.TargetID); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(ctx, "notifications", NotifySettings{SMTPHost: "mail", SMTPPassEnc: legacy("smtp")}); err != nil {
		t.Fatal(err)
	}
	db.Exec(`DELETE FROM settings WHERE key=?`, sealedBoundKey)
	n, err := s.store.BindSealedValues(ctx, s.sealer)
	if err != nil || n != 4 {
		t.Fatalf("re-sealed %d, %v", n, err)
	}
	c, _ = s.store.Client(ctx, c.ID)
	tg, _ := s.store.Target(ctx, c.TargetID)
	var ns NotifySettings
	s.store.Setting(ctx, "notifications", &ns)
	for want, got := range map[string]string{
		"tok":   must(s.sealer.Open(c.tokenSecretEnc, colClientToken, c.ID)),
		"key":   must(s.sealer.Open(c.cryptKeyEnc, colClientKey, c.ID)),
		"admin": must(s.sealer.Open(tg.adminSecretEnc, colTargetSecret, tg.ID)),
		"smtp":  must(s.sealer.Open(ns.SMTPPassEnc, colSMTPPass, 0)),
	} {
		if got != want {
			t.Errorf("%s: got %q", want, got)
		}
	}
	var raw string
	db.QueryRow(`SELECT value FROM settings WHERE key='notifications'`).Scan(&raw)
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m); m["smtp_host"] != "mail" {
		t.Errorf("notification settings lost fields: %s", raw)
	}

	// Once bound, a legacy value swapped in is not re-sealed.
	db.Exec(`UPDATE clients SET token_secret_enc=? WHERE id=?`, legacy("other"), c.ID)
	if n, err := s.store.BindSealedValues(ctx, s.sealer); err != nil || n != 0 {
		t.Fatalf("second run re-sealed %d, %v", n, err)
	}
	c, _ = s.store.Client(ctx, c.ID)
	if _, err := s.sealer.Open(c.tokenSecretEnc, colClientToken, c.ID); err == nil {
		t.Fatal("unbound value opened after binding")
	}
}

func must(s string, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return s
}

// Failed sign-ins are recorded without signing in, so the audit log must not
// store large usernames or keep an unbounded number of them.
func TestAuditSignInSizeLimits(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin-password"); err != nil {
		t.Fatal(err)
	}
	ui := s.uiRoutes()
	login := func(user string) int {
		body, _ := json.Marshal(map[string]string{"username": user, "password": "wrong"})
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		ui.ServeHTTP(w, r)
		return w.Code
	}
	if code := login(strings.Repeat("a", 3<<20)); code != http.StatusBadRequest {
		t.Fatalf("huge username: %d", code)
	}
	if code := login("nobody"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	es, err := s.store.AuditLog(ctx, AuditFilter{Limit: 500})
	if err != nil || len(es) != 1 || es[0].Username != "nobody" {
		t.Fatalf("audit after sign-ins: %v %+v", err, es)
	}

	// AddAudit clips every caller's fields.
	big := strings.Repeat("é", 1<<20)
	s.store.AddAudit(ctx, &AuditEntry{Username: big, Action: big, Target: big, Detail: big, IP: big})
	es, _ = s.store.AuditLog(ctx, AuditFilter{Limit: 1})
	e := es[0]
	for _, f := range []struct {
		v string
		n int
	}{{e.Username, maxAuditName}, {e.Action, maxAuditName}, {e.IP, maxAuditName}, {e.Target, maxAuditText}, {e.Detail, maxAuditText}} {
		if len(f.v) > f.n+len("…") || !strings.HasSuffix(f.v, "é…") {
			t.Fatalf("field not clipped on a rune boundary: %d bytes", len(f.v))
		}
	}

	// Rows stored before the clipping are cut on upgrade.
	if _, err := s.store.db.Exec(`INSERT INTO audit_log(ts, username, action, detail) VALUES(1, ?, 'sign-in', ?)`, big, big); err != nil {
		t.Fatal(err)
	}
	if err := s.store.migrate(); err != nil {
		t.Fatal(err)
	}
	var n int
	s.store.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE length(username)>? OR length(detail)>?`, maxAuditName, maxAuditText).Scan(&n)
	if n != 0 {
		t.Fatalf("%d oversized rows left after migrate", n)
	}

	// Only failed sign-ins are capped, oldest first.
	s.store.db.Exec(`DELETE FROM audit_log`)
	for i := range 10 {
		s.store.AddAudit(ctx, &AuditEntry{Username: "x" + jsonNum(int64(i)), Action: "sign-in", Status: http.StatusUnauthorized})
		s.store.AddAudit(ctx, &AuditEntry{Username: "admin", Action: "create user", Status: http.StatusOK})
	}
	s.store.AddAudit(ctx, &AuditEntry{Username: "admin", Action: "sign-in", Status: http.StatusOK})
	if got, err := s.store.TrimFailedSignIns(ctx, 3); err != nil || got != 7 {
		t.Fatalf("trim: %d %v", got, err)
	}
	if got, err := s.store.TrimFailedSignIns(ctx, 3); err != nil || got != 0 {
		t.Fatalf("second trim: %d %v", got, err)
	}
	es, _ = s.store.AuditLog(ctx, AuditFilter{Limit: 500})
	var failed []string
	for _, e := range es {
		if e.Action == "sign-in" && e.Status != http.StatusOK {
			failed = append(failed, e.Username)
		}
	}
	if len(es) != 14 || strings.Join(failed, ",") != "x9,x8,x7" {
		t.Fatalf("after trim: %d entries, failed %v", len(es), failed)
	}
}
