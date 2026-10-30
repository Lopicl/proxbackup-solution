// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"proxbackup/internal/api"
)

func TestClip(t *testing.T) {
	if clip("abc", 3) != "abc" || clip("abcd", 3) != "abc…" {
		t.Fatal("clip ascii")
	}
	// "é" is two bytes: never cut inside it.
	if got := clip("aéé", 2); got != "a…" || !utf8.ValidString(got) {
		t.Fatalf("clip utf-8: %q", got)
	}
	for _, l := range []string{"info", "warn", "error"} {
		if logLevel(l) != l {
			t.Fatal(l)
		}
	}
	if logLevel(strings.Repeat("x", 1<<20)) != "info" || logLevel("") != "info" {
		t.Fatal("unknown level kept")
	}
}

// The 2026-10-29 re-audit PoC: big log levels, run messages and restore
// session fields grew the data directory by 136 MiB without counting
// against any quota.
func TestAgentFieldsCapped(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := floodTestClient(t, s, "pc-1")
	huge := strings.Repeat("A", 3<<20)
	dbSize := func() int64 {
		var n int64
		filepath.Walk(s.cfg.DataDir, func(_ string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				n += fi.Size()
			}
			return nil
		})
		return n
	}
	before := dbSize()

	// Log levels.
	_, run := registerRun(t, s, c, "0123456789abcdef-log")
	for range 20 {
		if code := postEvents(t, s, c, run, []api.Event{{Time: time.Now(), Type: "log", Level: huge, Message: huge[:512<<10]}}); code != http.StatusNoContent {
			t.Fatalf("events: %d", code)
		}
	}
	_, ls := logCount(t, s, run)
	for _, l := range ls {
		if l.Level != "info" || len(l.Msg) > maxAgentText+len("…") {
			t.Fatalf("stored level %d bytes, message %d bytes", len(l.Level), len(l.Msg))
		}
	}

	// Run registrations: a long UUID is refused, the rest is cut.
	b, _ := json.Marshal(api.RunRegister{UUID: huge, State: api.RunMissed})
	w := httptest.NewRecorder()
	s.handleRegisterRun(w, httptest.NewRequest("POST", "/agent/v1/runs", bytes.NewReader(b)), c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("huge uuid: %d", w.Code)
	}
	var missed []int64
	for i := range 10 {
		b, _ := json.Marshal(api.RunRegister{UUID: fmt.Sprintf("0123456789abcdef-m%d", i), State: api.RunMissed, Kind: huge[:1<<20], Trigger: huge[:1<<20],
			Message: huge[:1<<20], StartedAt: time.Now().Unix()})
		w := httptest.NewRecorder()
		s.handleRegisterRun(w, httptest.NewRequest("POST", "/agent/v1/runs", bytes.NewReader(b)), c)
		var resp api.RunRegisterResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		if w.Code != http.StatusOK {
			t.Fatalf("missed run: %d", w.Code)
		}
		missed = append(missed, resp.RunID)
	}
	r, err := s.store.Run(ctx, missed[0])
	if err != nil || len(r.Error) > maxAgentText+len("…") || len(r.Kind) > maxAgentToken+len("…") || len(r.Trigger) > maxAgentToken+len("…") {
		t.Fatalf("missed run stored: %v error %d kind %d trigger %d", err, len(r.Error), len(r.Kind), len(r.Trigger))
	}

	// Results.
	res := &api.Result{State: api.RunFailed, Error: huge, Snapshot: huge}
	postEvents(t, s, c, run, []api.Event{{Time: time.Now(), Type: "result", Result: res}})
	if r, _ := s.store.Run(ctx, run); len(r.Error) > maxAgentText+len("…") || len(r.Snapshot) > maxAgentName+len("…") || r.Result.Error != r.Error {
		t.Fatalf("result stored: error %d snapshot %d", len(r.Error), len(r.Snapshot))
	}

	// Restore sessions: too long is refused; the rest is rate limited.
	open := func(req api.RestoreSessionRequest) int {
		b, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		s.handleCreateRestoreSession(w, httptest.NewRequest("POST", "https://console:8077/agent/v1/restore-sessions", bytes.NewReader(b)), c)
		return w.Code
	}
	for _, req := range []api.RestoreSessionRequest{
		{Ref: "0123456789abcdef", User: huge, Admin: true},
		{Ref: huge, User: `PC\bob`, Admin: true},
		{Ref: "0123456789abcdef", User: `PC\bob`, SID: huge, Admin: true},
		{Ref: "0123456789abcdef", User: `PC\bob`, Scope: `C:\Users\` + huge},
	} {
		if code := open(req); code != http.StatusBadRequest {
			t.Fatalf("huge restore session field: %d", code)
		}
	}

	// Everything the agent stored counts against its quota.
	var counted int64
	s.store.db.QueryRow(`SELECT SUM(log_bytes) FROM runs WHERE client_id=?`, c.ID).Scan(&counted)
	if grown := dbSize() - before; grown > 8<<20 || counted < 20*maxAgentText+10*(maxAgentText+2*maxAgentToken) {
		t.Fatalf("data directory grew %d MiB, %d bytes counted", grown>>20, counted)
	}
}

func TestRestoreSessionLimits(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := floodTestClient(t, s, "pc-1")
	open := func() int {
		b, _ := json.Marshal(api.RestoreSessionRequest{Ref: "0123456789abcdef", User: `PC\alice`, Admin: true})
		w := httptest.NewRecorder()
		s.handleCreateRestoreSession(w, httptest.NewRequest("POST", "https://console:8077/agent/v1/restore-sessions", bytes.NewReader(b)), c)
		return w.Code
	}
	live := func() (n int) {
		s.store.db.QueryRow(`SELECT COUNT(*) FROM restore_sessions WHERE client_id=?`, c.ID).Scan(&n)
		return n
	}
	for i := range restoreSessionsBurst {
		if code := open(); code != http.StatusOK {
			t.Fatalf("session %d: %d", i, code)
		}
	}
	if code := open(); code != http.StatusTooManyRequests {
		t.Fatalf("session over the limit: %d", code)
	}

	// The newest sessions stay; older ones beyond the cap end.
	s.restores = clientLimiter{perHour: 1e6, burst: 1e6}
	var tokens []string
	for i := range maxLiveRestoreSessions + 5 {
		tok := fmt.Sprintf("tok-%d", i)
		if _, err := s.store.CreateRestoreSession(ctx, hashToken(tok), c.ID, api.RestoreSessionRequest{User: "u", Admin: true}, time.Hour); err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, tok)
	}
	if n := live(); n != maxLiveRestoreSessions {
		t.Fatalf("%d live sessions", n)
	}
	if _, err := s.store.RestoreSession(ctx, hashToken(tokens[len(tokens)-1])); err != nil {
		t.Fatal("newest session ended")
	}
	if _, err := s.store.RestoreSession(ctx, hashToken(tokens[0])); err == nil {
		t.Fatal("oldest session still live")
	}
	// Other clients keep theirs.
	other := floodTestClient(t, s, "pc-2")
	s.store.CreateRestoreSession(ctx, hashToken("other"), other.ID, api.RestoreSessionRequest{User: "u", Admin: true}, time.Hour)
	if _, err := s.store.RestoreSession(ctx, hashToken(tokens[len(tokens)-1])); err != nil || live() != maxLiveRestoreSessions {
		t.Fatal("another client's session ended this client's")
	}
}

func TestTrimShortensErrors(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := floodTestClient(t, s, "pc-1")
	var runs []int64
	for i := range 3 {
		b, _ := json.Marshal(api.RunRegister{UUID: fmt.Sprintf("0123456789abcdef-%d", i), State: api.RunMissed, Message: strings.Repeat("e", 4000)})
		w := httptest.NewRecorder()
		s.handleRegisterRun(w, httptest.NewRequest("POST", "/agent/v1/runs", bytes.NewReader(b)), c)
		var resp api.RunRegisterResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		runs = append(runs, resp.RunID)
	}
	if n, err := s.store.TrimClientLogs(ctx, 9000); err != nil || n != 1 {
		t.Fatalf("trimmed %d, %v", n, err)
	}
	if r, _ := s.store.Run(ctx, runs[0]); len(r.Error) > 210 {
		t.Fatalf("trimmed run keeps a %d byte error", len(r.Error))
	}
	if r, _ := s.store.Run(ctx, runs[2]); len(r.Error) != 4000 {
		t.Fatalf("newest run's error cut to %d", len(r.Error))
	}
}

func TestClipPoll(t *testing.T) {
	huge := strings.Repeat("A", 1<<20)
	req := api.PollRequest{Hostname: huge, OS: huge, AgentVersion: huge, ConfigRev: huge, TimeZone: huge, PausedBy: huge, TrayError: huge,
		Features: make([]string, 1000), Schedule: make([]api.JobState, 5000)}
	for i := range req.Features {
		req.Features[i] = huge
	}
	req.Schedule[0].Waiting = huge
	clipPoll(&req)
	b, _ := json.Marshal(req)
	if len(b) > 64<<10 {
		t.Fatalf("clipped poll is %d bytes", len(b))
	}
}
