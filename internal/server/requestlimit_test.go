// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"proxbackup/internal/api"
)

// Bodies with more array elements than any real request are refused before
// they are decoded: decoded, a few bytes each become a run event of about a
// hundred.
func TestRequestBodyItemLimit(t *testing.T) {
	s := newTestServer(t, "")
	c := floodTestClient(t, s, "pc-items")
	_, run := registerRun(t, s, c, "items-0000-0000-0000")
	post := func(body string) int {
		req := httptest.NewRequest("POST", fmt.Sprintf("/agent/v1/runs/%d/events", run), strings.NewReader(body))
		req.SetPathValue("id", fmt.Sprint(run))
		rec := httptest.NewRecorder()
		s.handleEvents(rec, req, c)
		return rec.Code
	}
	events := func(n int) string {
		return "[" + strings.TrimSuffix(strings.Repeat(`{"type":"log","message":"x"},`, n), ",") + "]"
	}
	// The most an agent sends: its full buffer and the result.
	if code := post(events(20001)); code != http.StatusNoContent {
		t.Fatalf("agent's largest batch: %d", code)
	}
	if code := post(events(maxJSONItems + 1)); code != http.StatusBadRequest {
		t.Fatalf("too many events: %d", code)
	}
	n := (4<<20 - 2) / 3
	if code := post("[" + strings.Repeat("{},", n-1) + "{}]"); code != http.StatusBadRequest {
		t.Fatalf("4 MiB of empty events: %d", code)
	}

	ones := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat("1,", n), ",") + "]" }
	for _, tc := range []struct {
		body string
		ok   bool
	}{
		{ones(maxJSONItems), true},
		{`{"a":` + ones(maxJSONItems/2) + `,"b":` + ones(maxJSONItems/2) + `}`, true},
		// Nested arrays count together, and the inner arrays themselves.
		{"[" + ones(maxJSONItems/2) + "," + ones(maxJSONItems/2) + "]", false},
		{`{"a":` + ones(maxJSONItems/2) + `,"b":` + ones(maxJSONItems/2+1) + `}`, false},
		// Brackets and commas inside strings are no elements.
		{`["` + strings.Repeat("[1,", maxJSONItems) + `"]`, true},
		// Only the value decodeJSON reads counts.
		{`[1] ` + ones(maxJSONItems+1), true},
	} {
		if err := checkJSONItems([]byte(tc.body)); (err == nil) != tc.ok {
			t.Errorf("checkJSONItems(%.40q…) = %v, want ok=%t", tc.body, err, tc.ok)
		}
	}
}

// Sign-in and enrollment bodies are refused past maxPublicBody before they
// are decoded: anyone can send them, and the sign-in throttling comes after.
func TestPublicBodyLimit(t *testing.T) {
	s := newTestServer(t, "")
	if _, err := s.EnsureAdmin(context.Background(), "admin-password"); err != nil {
		t.Fatal(err)
	}
	send := func(h http.Handler, path string, body map[string]string) int {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	big := strings.Repeat("x", maxPublicBody)
	ui, agents := s.uiRoutes(), s.agentRoutes()
	if code := send(ui, "/api/login", map[string]string{"username": "admin", "password": big}); code != http.StatusBadRequest {
		t.Fatalf("huge password: %d", code)
	}
	if code := send(ui, "/api/login", map[string]string{"username": "admin", "password": "wrong-password"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if code := send(agents, "/agent/v1/enroll", map[string]string{"code": "x", "csr": big}); code != http.StatusBadRequest {
		t.Fatalf("huge enrollment: %d", code)
	}
	if code := send(agents, "/agent/v1/enroll", map[string]string{"code": "x"}); code != http.StatusForbidden {
		t.Fatalf("unknown code: %d", code)
	}
}

// holdRequests starts n requests that stay open until release is closed, and
// returns once all of them run.
func holdRequests(n int, call func(hold func())) (release func()) {
	started, done := make(chan struct{}, n), make(chan struct{})
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			call(func() { started <- struct{}{}; <-done })
		}()
	}
	for range n {
		<-started
	}
	return func() { close(done); wg.Wait() }
}

// One client's agent may hold maxAgentRequests requests; other clients aren't
// held back, and a renewed certificate still takes over meanwhile.
func TestAgentRequestLimit(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "pc-1", "pc-2")
	cert, otherCert := agentCert(t, s, cs[0]), agentCert(t, s, cs[1])
	s.store.RequestRotation(ctx, cs[0].ID)
	newCert := renewedCert(t, s, cert)

	release := holdRequests(maxAgentRequests, func(hold func()) {
		agentCall(s, cert, func(w http.ResponseWriter, r *http.Request, c *Client) { hold() }, "/agent/v1/runs", "")
	})
	ok := func(w http.ResponseWriter, r *http.Request, c *Client) { w.WriteHeader(http.StatusNoContent) }
	if rec := agentCall(s, cert, ok, "/agent/v1/runs", ""); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("request past the limit: %d %v", rec.Code, rec.Header())
	}
	if rec := agentCall(s, otherCert, ok, "/agent/v1/runs", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("other client: %d", rec.Code)
	}
	// The renewed certificate is refused for now, but it replaced the old one.
	if rec := agentCall(s, newCert, ok, "/agent/v1/runs", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("renewed certificate while the old one holds every request: %d", rec.Code)
	}
	if rec := agentCall(s, cert, ok, "/agent/v1/runs", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("replaced certificate: %d", rec.Code)
	}
	release()
	if rec := agentCall(s, newCert, ok, "/agent/v1/runs", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("after the requests ended: %d", rec.Code)
	}
	if n := len(s.agentReqs.clients); n != 0 {
		t.Fatalf("%d clients still counted", n)
	}
}

// A new poll ends the client's oldest one past maxWaitingPolls, so an agent
// that lost its connection isn't held back by its own stale polls.
func TestNewPollEndsOldestWaiting(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := rotationTestClient(t, s, &fakeTokenPBS{})
	cert := agentCert(t, s, c)
	cfg, _ := s.agentConfig(ctx, c)
	body, _ := json.Marshal(api.PollRequest{OS: "windows/amd64", ConfigRev: cfg.Rev})
	type result struct{ poll, code int }
	results := make(chan result, maxWaitingPolls+1)
	for i := range maxWaitingPolls + 1 {
		go func() {
			rec := agentCall(s, cert, s.handlePoll, "/agent/v1/poll?wait=30", string(body))
			results <- result{i, rec.Code}
		}()
		time.Sleep(200 * time.Millisecond) // in this order
	}
	select {
	case r := <-results:
		if r.poll != 0 || r.code != http.StatusOK {
			t.Fatalf("first poll to end: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the oldest poll still waits")
	}
	select {
	case r := <-results:
		t.Fatalf("poll %d ended too: %d", r.poll, r.code)
	case <-time.After(300 * time.Millisecond):
	}
	// End the others: revoked clients' polls answer at once.
	s.store.RevokeClient(ctx, c.ID)
	s.wakeClient(c.ID)
	for range maxWaitingPolls {
		select {
		case <-results:
		case <-time.After(5 * time.Second):
			t.Fatal("polls didn't end")
		}
	}
	if n := len(s.agentReqs.clients); n != 0 {
		t.Fatalf("%d clients still counted", n)
	}
}

// A PC's restore pages share maxRestorePageRequests, apart from its agent,
// and their restore requests are small.
func TestRestorePageRequestLimit(t *testing.T) {
	s := newTestServer(t, "")
	c := groupTestClients(t, s, "pc-1")[0]
	cert := agentCert(t, s, c)
	b, _ := json.Marshal(api.RestoreSessionRequest{Ref: "0123456789abcdef", User: `PC\alice`, SID: "S-1-5-21-1", Scope: `C:\Users\Alice`})
	rec := agentCall(s, cert, s.handleCreateRestoreSession, "https://console:8077/agent/v1/restore-sessions", string(b))
	var resp api.RestoreSessionResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	token, _ := strings.CutPrefix(resp.URL, "https://console:8077/#/restore/")
	page := func(h selfRestoreHandler, body string) int {
		r := httptest.NewRequest("POST", "/api/self-restore/restore", strings.NewReader(body))
		r.Header.Set(restoreSessionHeader, token)
		w := httptest.NewRecorder()
		s.requireRestoreSession(h).ServeHTTP(w, r)
		return w.Code
	}
	release := holdRequests(maxRestorePageRequests, func(hold func()) {
		page(func(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) { hold() }, "")
	})
	ok := func(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) {
		w.WriteHeader(http.StatusNoContent)
	}
	if code := page(ok, ""); code != http.StatusTooManyRequests {
		t.Fatalf("restore page request past the limit: %d", code)
	}
	agentOK := func(w http.ResponseWriter, r *http.Request, c *Client) { w.WriteHeader(http.StatusNoContent) }
	if rec := agentCall(s, cert, agentOK, "/agent/v1/runs", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("agent while its restore pages are busy: %d", rec.Code)
	}
	release()
	big, _ := json.Marshal(api.RestoreSpec{BackupID: "pc-1", BackupTime: 1, Archive: "c.pxar.didx", TargetDir: `C:\Users\Alice`,
		Paths: []string{strings.Repeat("x", maxRestorePageBody)}})
	if code := page(s.handleSelfRestore, string(big)); code != http.StatusBadRequest {
		t.Fatalf("huge restore request: %d", code)
	}
}
