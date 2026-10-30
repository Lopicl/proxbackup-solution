// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxbackup/internal/api"
)

func floodTestClient(t *testing.T, s *Server, name string) *Client {
	t.Helper()
	ctx := context.Background()
	tg := &Target{Name: "pbs-" + name, Host: "pbs:8007", Datastore: "ds", AdminAuthID: "root@pam!x", PBSUser: "proxbackup@pbs"}
	if err := s.store.SaveTarget(ctx, tg, s.sealer.sealFor("x", colTargetSecret)); err != nil {
		t.Fatal(err)
	}
	c := &Client{Name: name, TargetID: tg.ID, CertSerial: "serial-" + name, Namespace: "pcs/" + name, TokenID: "proxbackup@pbs!" + name}
	if err := s.store.CreateClient(ctx, c, s.sealer.sealFor("tok", colClientToken)); err != nil {
		t.Fatal(err)
	}
	return c
}

func registerRun(t *testing.T, s *Server, c *Client, uuid string) (int, int64) {
	t.Helper()
	b, _ := json.Marshal(api.RunRegister{UUID: uuid, State: api.RunRunning, Kind: api.KindFiles, StartedAt: time.Now().Unix()})
	req := httptest.NewRequest("POST", "/agent/v1/runs", strings.NewReader(string(b)))
	rec := httptest.NewRecorder()
	s.handleRegisterRun(rec, req, c)
	var resp api.RunRegisterResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp.RunID
}

func postEvents(t *testing.T, s *Server, c *Client, run int64, events []api.Event) int {
	t.Helper()
	b, _ := json.Marshal(events)
	req := httptest.NewRequest("POST", fmt.Sprintf("/agent/v1/runs/%d/events", run), strings.NewReader(string(b)))
	req.SetPathValue("id", fmt.Sprint(run))
	rec := httptest.NewRecorder()
	s.handleEvents(rec, req, c)
	return rec.Code
}

func logCount(t *testing.T, s *Server, run int64) (int, []LogLine) {
	t.Helper()
	var all []LogLine
	for after := int64(0); ; {
		ls, err := s.store.Logs(context.Background(), run, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(ls) == 0 {
			return len(all), all
		}
		all = append(all, ls...)
		after = ls[len(ls)-1].ID
	}
}

func TestRunLogCaps(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := floodTestClient(t, s, "pc-1")
	_, run := registerRun(t, s, c, "0123456789abcdef-1")

	// Lines: the cap, then one note; later lines are dropped.
	lines := make([]LogLine, maxRunLogLines+10)
	for i := range lines {
		lines[i] = LogLine{Time: 1, Level: "info", Msg: "x"}
	}
	if err := s.store.AddLogs(ctx, run, lines); err != nil {
		t.Fatal(err)
	}
	s.store.AddLogs(ctx, run, lines[:5])
	n, all := logCount(t, s, run)
	if n != maxRunLogLines+1 || !strings.HasPrefix(all[n-1].Msg, "log truncated") {
		t.Fatalf("%d lines, last %q", n, all[n-1].Msg)
	}

	// Bytes.
	_, run2 := registerRun(t, s, c, "0123456789abcdef-2")
	big := strings.Repeat("y", 4000)
	for range maxRunLogBytes/4000/100 + 2 {
		batch := make([]LogLine, 100)
		for i := range batch {
			batch[i] = LogLine{Time: 1, Level: "info", Msg: big}
		}
		s.store.AddLogs(ctx, run2, batch)
	}
	n, all = logCount(t, s, run2)
	size := 0
	for _, l := range all[:n-1] {
		size += len(l.Level) + len(l.Msg)
	}
	if size > maxRunLogBytes || size < maxRunLogBytes-4100 || !strings.HasPrefix(all[n-1].Msg, "log truncated") {
		t.Fatalf("%d bytes in %d lines, last %.40q", size, n, all[n-1].Msg)
	}
}

func TestEventsForFinishedRun(t *testing.T) {
	s := newTestServer(t, "")
	c := floodTestClient(t, s, "pc-1")
	_, run := registerRun(t, s, c, "0123456789abcdef-1")
	now := time.Now()
	logEv := api.Event{Time: now, Type: "log", Level: "info", Message: "hello"}
	res := api.Event{Time: now, Type: "result", Result: &api.Result{State: api.RunSuccess}}
	if code := postEvents(t, s, c, run, []api.Event{logEv, res}); code != http.StatusNoContent {
		t.Fatalf("events: %d", code)
	}
	// A resent batch and later events are accepted but not stored.
	for range 3 {
		if code := postEvents(t, s, c, run, []api.Event{logEv, logEv, res}); code != http.StatusNoContent {
			t.Fatalf("events after finish: %d", code)
		}
	}
	if n, _ := logCount(t, s, run); n != 1 {
		t.Fatalf("finished run has %d log lines", n)
	}

	// A lost run still takes its (spooled) report.
	_, run2 := registerRun(t, s, c, "0123456789abcdef-2")
	s.store.db.Exec(`UPDATE runs SET state='lost' WHERE id=?`, run2)
	postEvents(t, s, c, run2, []api.Event{logEv, res})
	if r, _ := s.store.Run(context.Background(), run2); r.State != api.RunSuccess {
		t.Fatalf("lost run state after its report = %s", r.State)
	}
	if n, _ := logCount(t, s, run2); n != 1 {
		t.Fatalf("lost run has %d log lines", n)
	}

	// Another client's run is not found.
	other := floodTestClient(t, s, "pc-2")
	if code := postEvents(t, s, other, run2, []api.Event{logEv}); code != http.StatusNotFound {
		t.Fatalf("other client's run: %d", code)
	}
}

func TestRunRegistrationLimit(t *testing.T) {
	s := newTestServer(t, "")
	c := floodTestClient(t, s, "pc-1")
	for i := range runRegsBurst {
		if code, _ := registerRun(t, s, c, fmt.Sprintf("0123456789abcdef-%d", i)); code != http.StatusOK {
			t.Fatalf("registration %d: %d", i, code)
		}
	}
	if code, _ := registerRun(t, s, c, "0123456789abcdef-new"); code != http.StatusTooManyRequests {
		t.Fatalf("registration over the limit: %d", code)
	}
	// Retries of known runs still get their id.
	if code, id := registerRun(t, s, c, "0123456789abcdef-3"); code != http.StatusOK || id == 0 {
		t.Fatalf("retry: %d %d", code, id)
	}
	// Other clients have their own budget.
	if code, _ := registerRun(t, s, floodTestClient(t, s, "pc-2"), "0123456789abcdef-x"); code != http.StatusOK {
		t.Fatalf("other client: %d", code)
	}
	// The budget refills over time.
	l := clientLimiter{perHour: runRegsPerHour, burst: runRegsBurst}
	t0 := time.Now()
	for range runRegsBurst {
		l.allow(1, t0)
	}
	if l.allow(1, t0) || !l.allow(1, t0.Add(time.Hour/runRegsPerHour+time.Second)) {
		t.Fatal("bucket doesn't refill")
	}
	l.prune(t0.Add(2 * time.Hour))
	if len(l.buckets) != 0 {
		t.Fatal("full bucket not pruned")
	}
}

func TestTrimClientLogs(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	a, b := floodTestClient(t, s, "pc-1"), floodTestClient(t, s, "pc-2")
	msg := strings.Repeat("z", 1000)
	var runs []int64
	for i := range 4 {
		_, id := registerRun(t, s, a, fmt.Sprintf("0123456789abcdef-%d", i))
		s.store.AddLogs(ctx, id, []LogLine{{Time: 1, Level: "info", Msg: msg}, {Time: 1, Level: "info", Msg: msg}})
		runs = append(runs, id)
	}
	_, idB := registerRun(t, s, b, "0123456789abcdef-b")
	s.store.AddLogs(ctx, idB, []LogLine{{Time: 1, Level: "info", Msg: msg}})

	// pc-1 has 8000 bytes; keep 5000: the two oldest runs go.
	n, err := s.store.TrimClientLogs(ctx, 5000)
	if err != nil || n != 2 {
		t.Fatalf("trimmed %d, %v", n, err)
	}
	for i, id := range runs {
		_, ls := logCount(t, s, id)
		trimmed := len(ls) == 1 && strings.HasPrefix(ls[0].Msg, "log removed")
		if trimmed != (i < 2) {
			t.Fatalf("run %d: %+v", i, ls)
		}
	}
	// A trimmed log takes no new lines.
	s.store.AddLogs(ctx, runs[0], []LogLine{{Time: 1, Level: "info", Msg: "more"}})
	if c, _ := logCount(t, s, runs[0]); c != 1 {
		t.Fatalf("trimmed run has %d lines", c)
	}
	if c, _ := logCount(t, s, idB); c != 1 {
		t.Fatal("other client's log trimmed")
	}
	if n, _ := s.store.TrimClientLogs(ctx, 5000); n != 0 {
		t.Fatalf("second trim cleared %d", n)
	}
}
