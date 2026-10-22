// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxbackup/internal/api"
)

func consoleAt(announce *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.PollResponse{ServerURL: *announce})
	}))
}

func testRunner(t *testing.T, url string) *Runner {
	dir := t.TempDir()
	cfg := &Config{ServerURL: url, ClientID: 1, ClientName: "pc", dir: dir}
	r := &Runner{cfg: cfg, hc: http.DefaultClient, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		running: map[int64]context.CancelFunc{}, inflight: map[int64]bool{}, queue: make(chan task, 4)}
	r.sched = NewScheduler(dir)
	return r
}

func TestFollowServerURL(t *testing.T) {
	var announce string
	oldSrv, newSrv := consoleAt(&announce), consoleAt(&announce)
	defer oldSrv.Close()
	announce = newSrv.URL + "/"
	r := testRunner(t, oldSrv.URL)
	ctx := context.Background()

	if err := r.pollOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if r.serverURL() != newSrv.URL || r.fallbackURL() != oldSrv.URL {
		t.Fatalf("after move: url %q fallback %q", r.serverURL(), r.fallbackURL())
	}
	saved, err := LoadConfig(r.cfg.dir)
	if err != nil || saved.ServerURL != newSrv.URL || saved.FallbackURL != oldSrv.URL {
		t.Fatalf("saved config %+v, %v", saved, err)
	}

	// The new address goes away: the agent returns to the old one and doesn't
	// immediately retry the new one.
	newSrv.Close()
	if err := r.pollOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if r.serverURL() != oldSrv.URL {
		t.Fatalf("after fallback: url %q", r.serverURL())
	}
	if err := r.pollOnce(ctx, 0); err != nil || r.serverURL() != oldSrv.URL {
		t.Fatalf("second poll: url %q, %v", r.serverURL(), err)
	}
}

func TestFollowServerURLUnreachable(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	announce := dead.URL
	srv := consoleAt(&announce)
	defer srv.Close()
	r := testRunner(t, srv.URL)
	if err := r.pollOnce(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if r.serverURL() != srv.URL || r.fallbackURL() != "" {
		t.Fatalf("url %q fallback %q", r.serverURL(), r.fallbackURL())
	}
}
