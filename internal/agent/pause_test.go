// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/ipc"
)

func pauseTestRunner(t *testing.T, dir string) *Runner {
	r := &Runner{cfg: &Config{dir: dir}, sched: NewScheduler(dir), log: slog.New(slog.NewTextHandler(io.Discard, nil)), queue: make(chan task, 8),
		inflight: map[int64]bool{}}
	r.loadLocal()
	r.applyPausePolicy(r.sched.Config())
	return r
}

func setPauseDays(t *testing.T, r *Runner, rev string, days *int) {
	t.Helper()
	cfg := &api.AgentConfig{Rev: rev, PauseDays: days}
	if err := r.sched.Update(cfg); err != nil {
		t.Fatal(err)
	}
	r.applyPausePolicy(cfg)
}

// TestTrayPauseLimit checks the console's limit on paused days in a row:
// pauses stop once it is used up, resuming early doesn't reset it, and a
// scheduled backup does.
func TestTrayPauseLimit(t *testing.T) {
	dir := t.TempDir()
	r := pauseTestRunner(t, dir)
	peer := &ipc.Peer{User: `PC\alice`}
	ctx := context.Background()
	pause := func(r *Runner, minutes int) ipc.Response {
		return r.handleLocal(ctx, peer, ipc.Request{Op: ipc.OpPause, Minutes: minutes})
	}
	one := 1
	setPauseDays(t, r, "r1", &one)

	if resp := pause(r, 24*60); resp.Error != "" || r.pausedBy() != `PC\alice` {
		t.Fatalf("pause: %+v", resp)
	}
	r.handleLocal(ctx, peer, ipc.Request{Op: ipc.OpResume})
	// The day counts from the first pause: a new one ends with it.
	if resp := pause(r, 60); resp.Error != "" {
		t.Fatalf("second pause within the day: %+v", resp)
	}

	// A day after the first pause, no more until a scheduled backup ran.
	r.local.mu.Lock()
	r.local.pause.Since = time.Now().Add(-25 * time.Hour).Unix()
	r.local.pause.Until = time.Now().Add(-time.Minute).Unix()
	r.local.mu.Unlock()
	if resp := pause(r, 60); !strings.Contains(resp.Error, "1 day in a row") || r.pausedBy() != "" {
		t.Fatalf("pause past the limit: %+v", resp)
	}
	if st := r.localStatus(peer); !st.PauseOff {
		t.Fatal("tray not told")
	}
	// Also after a restart.
	r.setPause(r.local.pause)
	if resp := pause(pauseTestRunner(t, dir), 60); resp.Error == "" {
		t.Fatal("pause allowed after restart")
	}
	r.startLocal(api.JobSpec{}, api.JobConfig{ID: 1}, api.TriggerSchedule, time.Now())
	if resp := pause(r, 60); resp.Error != "" {
		t.Fatalf("pause after a scheduled backup: %+v", resp)
	}

	// Pauses can go up to the end of the allowance only.
	r.local.mu.Lock()
	r.local.pause.Since = time.Now().Add(-23 * time.Hour).Unix()
	r.local.mu.Unlock()
	r.handleLocal(ctx, peer, ipc.Request{Op: ipc.OpResume})
	pause(r, 24*60)
	if until, _ := r.pauseInfo(); until > time.Now().Add(61*time.Minute).Unix() {
		t.Fatalf("pause past the allowance: until %s", time.Unix(until, 0))
	}

	// A stricter limit shortens a pause in effect; 0 ends it and allows none.
	setPauseDays(t, r, "r2", nil)
	r.local.mu.Lock()
	r.local.pause.Since = time.Now().Unix()
	r.local.mu.Unlock()
	pause(r, 24*60)
	zero := 0
	setPauseDays(t, r, "r3", &zero)
	if r.pausedBy() != "" {
		t.Fatal("pause kept with pauses off")
	}
	if resp := pause(r, 60); !strings.Contains(resp.Error, "turned off") {
		t.Fatalf("pause with pauses off: %+v", resp)
	}

	// Without a limit, pauses go on as before.
	setPauseDays(t, r, "r4", nil)
	if resp := pause(r, 24*60); resp.Error != "" {
		t.Fatalf("pause without a limit: %+v", resp)
	}
}
