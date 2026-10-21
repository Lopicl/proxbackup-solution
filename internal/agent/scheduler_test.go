// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"strings"
	"testing"
	"time"

	"proxbackup/internal/api"
)

type schedHarness struct {
	s       *Scheduler
	now     time.Time
	busy    map[int64]bool
	started []string
	missed  []string
	since   time.Time // zero = offline
	drops   int
}

func newHarness(t *testing.T, jobs ...api.JobConfig) *schedHarness {
	h := &schedHarness{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.Local), busy: map[int64]bool{}}
	h.s = NewScheduler(t.TempDir())
	h.s.now = func() time.Time { return h.now }
	h.s.start = func(_ api.JobSpec, j api.JobConfig, trigger string, slot time.Time) bool {
		if h.busy[j.ID] {
			return false
		}
		h.busy[j.ID] = true
		h.started = append(h.started, trigger+"@"+slot.Format("02 15:04"))
		return true
	}
	h.s.busy = func(id int64) bool { return h.busy[id] }
	h.s.missed = func(_ api.JobConfig, slot time.Time, reason string) {
		h.missed = append(h.missed, slot.Format("02 15:04")+" "+reason)
	}
	h.s.conn = func() (time.Time, int) { return h.since, h.drops }
	h.s.logf = func(string, string, ...any) {}
	if err := h.s.Update(&api.AgentConfig{Rev: "r1", Jobs: jobs}); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *schedHarness) at(d, hh, mm int) { h.now = time.Date(2026, 10, d, hh, mm, 0, 0, time.Local) }

func daily(catchUp bool) api.JobConfig {
	return api.JobConfig{ID: 1, Name: "files", Kind: api.KindFiles, Schedule: "0 21 * * *", WindowMinutes: 60, CatchUp: catchUp}
}

func TestSchedulerOnTime(t *testing.T) {
	h := newHarness(t, daily(true))
	h.at(12, 20, 59)
	h.s.Tick()
	h.at(12, 21, 0)
	h.s.Tick()
	h.s.Tick() // same slot must not start twice
	if strings.Join(h.started, ",") != "schedule@12 21:00" {
		t.Fatalf("started %v", h.started)
	}
}

func TestSchedulerCatchUpAfterOffline(t *testing.T) {
	h := newHarness(t, daily(true))
	h.at(15, 8, 30) // PC was off for three evenings
	h.s.Tick()
	if strings.Join(h.started, ",") != "catch-up@14 21:00" || len(h.missed) != 0 {
		t.Fatalf("started %v missed %v", h.started, h.missed)
	}
}

func TestSchedulerMissedWithoutCatchUp(t *testing.T) {
	h := newHarness(t, daily(false))
	h.at(12, 22, 30) // asleep at 21:00, woke up after the 60 min window
	h.s.Tick()
	if len(h.started) != 0 || len(h.missed) != 1 || !strings.Contains(h.missed[0], "off, asleep") {
		t.Fatalf("started %v missed %v", h.started, h.missed)
	}
}

func TestSchedulerBusyDefersCatchUp(t *testing.T) {
	j := daily(true)
	j.Schedule = "0 * * * *" // hourly
	h := newHarness(t, j)
	h.at(12, 10, 0)
	h.s.Tick() // starts 10:00
	h.at(12, 11, 0)
	h.s.Tick() // 10:00 run still going → defer
	if len(h.started) != 1 {
		t.Fatalf("started %v", h.started)
	}
	if st := h.s.States(); !st[0].CatchUpPending {
		t.Fatal("catch-up should be pending")
	}
	h.busy[1] = false // run finished
	h.at(12, 11, 20)
	h.s.Tick()
	if strings.Join(h.started, ",") != "schedule@12 10:00,catch-up@12 11:00" {
		t.Fatalf("started %v", h.started)
	}
}

func TestSchedulerBusyWithoutCatchUpIsMissed(t *testing.T) {
	j := daily(false)
	j.Schedule = "0 * * * *"
	h := newHarness(t, j)
	h.at(12, 10, 0)
	h.s.Tick()
	h.at(12, 11, 0)
	h.s.Tick()
	if len(h.missed) != 1 || !strings.Contains(h.missed[0], "still in progress") {
		t.Fatalf("missed %v", h.missed)
	}
}

func TestSchedulerNewJobDoesNotCatchUpHistory(t *testing.T) {
	h := newHarness(t) // no jobs yet
	h.at(12, 23, 0)
	h.s.Update(&api.AgentConfig{Rev: "r2", Jobs: []api.JobConfig{daily(true)}}) // added after today's 21:00
	h.s.Tick()
	if len(h.started) != 0 {
		t.Fatalf("new job must not catch up on slots before it existed: %v", h.started)
	}
}

func TestSchedulerStatePersists(t *testing.T) {
	h := newHarness(t, daily(true))
	h.at(12, 21, 0)
	h.s.Tick()
	s2 := NewScheduler(h.s.dir) // agent restart
	s2.now, s2.start, s2.busy, s2.missed, s2.logf = h.s.now, h.s.start, func(int64) bool { return false }, h.s.missed, h.s.logf
	h.at(12, 21, 30)
	s2.Tick()
	if len(h.started) != 1 {
		t.Fatalf("restart re-ran an already handled slot: %v", h.started)
	}
	if s2.Rev() != "r1" {
		t.Fatal("config not persisted")
	}
}

func TestLateStart(t *testing.T) {
	j := daily(false)
	slot := time.Date(2026, 10, 12, 21, 0, 0, 0, time.Local)
	if tr, err := lateStart(j, api.TriggerSchedule, slot, slot.Add(30*time.Minute)); err != nil || tr != api.TriggerSchedule {
		t.Fatal("within window should stay scheduled")
	}
	if _, err := lateStart(j, api.TriggerSchedule, slot, slot.Add(2*time.Hour)); err == nil {
		t.Fatal("late start without catch-up must be missed")
	}
	j.CatchUp = true
	if tr, _ := lateStart(j, api.TriggerSchedule, slot, slot.Add(2*time.Hour)); tr != api.TriggerCatchUp {
		t.Fatal("late start with catch-up must become catch-up")
	}
}

func TestSchedulerStartDelay(t *testing.T) {
	j := daily(true)
	j.StartDelay = 10 * 60
	h := newHarness(t, j)
	h.at(12, 21, 5)
	h.s.Tick()
	if len(h.started) != 0 {
		t.Fatalf("started before its delay: %v", h.started)
	}
	if st := h.s.States(); st[0].NextRun != time.Date(2026, 10, 12, 21, 10, 0, 0, time.Local).Unix() {
		t.Fatalf("next run %v", time.Unix(st[0].NextRun, 0))
	}
	h.at(12, 21, 10)
	h.s.Tick()
	h.s.Tick()
	if strings.Join(h.started, ",") != "schedule@12 21:10" {
		t.Fatalf("started %v", h.started)
	}
}

// A job pushed between the schedule time and its delayed start still runs.
func TestSchedulerStartDelayNewJob(t *testing.T) {
	j := daily(true)
	j.StartDelay = 30 * 60
	h := newHarness(t)
	h.at(12, 21, 5)
	if err := h.s.Update(&api.AgentConfig{Rev: "r2", Jobs: []api.JobConfig{j}}); err != nil {
		t.Fatal(err)
	}
	h.at(12, 21, 30)
	h.s.Tick()
	if strings.Join(h.started, ",") != "schedule@12 21:30" {
		t.Fatalf("started %v", h.started)
	}
}

func TestSchedulerPause(t *testing.T) {
	h := newHarness(t, daily(true), api.JobConfig{ID: 2, Name: "img", Kind: api.KindImage, Schedule: "0 21 * * *", WindowMinutes: 60})
	by := `PC\alice`
	h.s.pausedBy = func() string { return by }
	h.at(12, 21, 0)
	h.s.Tick()
	if len(h.started) != 0 || len(h.missed) != 1 || !strings.Contains(h.missed[0], `paused on the PC by PC\alice`) {
		t.Fatalf("while paused: started %v missed %v", h.started, h.missed)
	}
	h.at(12, 21, 30)
	h.s.Tick()
	if len(h.started) != 0 {
		t.Fatalf("catch-up started while paused: %v", h.started)
	}
	by = "" // resumed
	h.s.Tick()
	if strings.Join(h.started, ",") != "catch-up@12 21:00" || len(h.missed) != 1 {
		t.Fatalf("after resume: started %v missed %v", h.started, h.missed)
	}
}

func TestSchedulerNextWake(t *testing.T) {
	late := daily(true)
	late.WakeToRun = true
	early := api.JobConfig{ID: 2, Name: "image", Schedule: "0 3 * * *", StartDelay: 600, WakeToRun: true}
	noWake := api.JobConfig{ID: 3, Name: "other", Schedule: "0 12 * * *"}
	h := newHarness(t, late, early, noWake)
	from := time.Date(2026, 10, 12, 9, 0, 0, 0, time.Local)
	if got, want := h.s.NextWake(from), time.Date(2026, 10, 12, 21, 0, 0, 0, time.Local); !got.Equal(want) {
		t.Fatalf("NextWake = %v, want %v (jobs that don't wake are skipped)", got, want)
	}
	// After 21:00 the earliest is the 03:00 job, shifted by its start delay.
	if got, want := h.s.NextWake(from.Add(13*time.Hour)), time.Date(2026, 10, 13, 3, 10, 0, 0, time.Local); !got.Equal(want) {
		t.Fatalf("NextWake = %v, want %v", got, want)
	}
	h2 := newHarness(t, noWake)
	if got := h2.s.NextWake(from); !got.IsZero() {
		t.Fatalf("NextWake without waking jobs = %v", got)
	}
}

// finish ends the job's run (as the runner does after it executed).
func (h *schedHarness) finish(failed bool) {
	h.busy[1] = false
	h.s.RunEnded(1, failed)
}

func TestSchedulerRetriesRunCutOffByGoingOffline(t *testing.T) {
	h := newHarness(t, daily(true))
	h.since = time.Date(2026, 10, 12, 8, 0, 0, 0, time.Local)
	h.at(12, 21, 0)
	h.s.Tick()
	h.s.RunStarted(1, h.now)
	h.at(12, 21, 20)
	h.finish(true) // network gone: the run fails before the poll notices
	h.s.Tick()
	h.at(12, 21, 22)
	h.since, h.drops = time.Time{}, 1 // now the agent is offline
	h.s.Tick()
	if st := h.s.States(); !st[0].CatchUpPending {
		t.Fatal("catch-up should be pending")
	}
	h.at(12, 23, 0)
	h.since = h.now // back online
	h.s.Tick()
	h.at(12, 23, 29)
	h.s.Tick()
	if len(h.started) != 1 {
		t.Fatalf("catch-up must wait 30 minutes after coming back online: %v", h.started)
	}
	h.at(12, 23, 30)
	h.s.Tick()
	if strings.Join(h.started, ",") != "schedule@12 21:00,catch-up@12 21:00" {
		t.Fatalf("started %v", h.started)
	}
}

func TestSchedulerFailureWhileOnlineIsNotRetried(t *testing.T) {
	h := newHarness(t, daily(true))
	h.since = time.Date(2026, 10, 12, 8, 0, 0, 0, time.Local)
	h.at(12, 21, 0)
	h.s.Tick()
	h.s.RunStarted(1, h.now)
	h.at(12, 21, 20)
	h.finish(true)
	h.at(12, 23, 0)
	h.s.Tick()
	h.drops = 1 // a later connection loss is unrelated
	h.s.Tick()
	if st := h.s.States(); st[0].CatchUpPending || len(h.started) != 1 {
		t.Fatalf("plain failure must not be retried: %v", h.started)
	}
}

func TestSchedulerNoRetryWithoutCatchUp(t *testing.T) {
	h := newHarness(t, daily(false))
	h.since = time.Date(2026, 10, 12, 8, 0, 0, 0, time.Local)
	h.at(12, 21, 0)
	h.s.Tick()
	h.s.RunStarted(1, h.now)
	h.drops = 1
	h.finish(true)
	h.at(13, 9, 0)
	h.s.Tick()
	if len(h.started) != 1 {
		t.Fatalf("started %v", h.started)
	}
}

func TestSchedulerRetriesRunCutOffByAgentStop(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, daily(true))
	h.s.dir = dir
	h.s.Update(&api.AgentConfig{Rev: "r1", Jobs: []api.JobConfig{daily(true)}})
	h.at(12, 21, 0)
	h.s.Tick()
	h.s.RunStarted(1, h.now) // PC shuts down mid-run

	h2 := &schedHarness{busy: map[int64]bool{}}
	h2.at(13, 8, 0)
	s := NewScheduler(dir)
	s.now = func() time.Time { return h2.now }
	s.start = func(_ api.JobSpec, j api.JobConfig, trigger string, slot time.Time) bool {
		h2.started = append(h2.started, trigger+"@"+slot.Format("02 15:04"))
		return true
	}
	s.busy = func(int64) bool { return false }
	s.conn = func() (time.Time, int) { return h2.since, 0 }
	s.logf = func(string, string, ...any) {}
	s.Tick()
	h2.since = h2.now.Add(time.Minute) // server reachable a minute after boot
	h2.at(13, 8, 30)
	s.Tick()
	if len(h2.started) != 0 {
		t.Fatalf("started too early: %v", h2.started)
	}
	h2.at(13, 8, 31)
	s.Tick()
	if strings.Join(h2.started, ",") != "catch-up@12 21:00" {
		t.Fatalf("started %v", h2.started)
	}
}

func TestSchedulerNewRunReplacesOfflineRetry(t *testing.T) {
	h := newHarness(t, daily(true))
	h.at(12, 21, 0)
	h.s.Tick()
	h.s.RunStarted(1, h.now)
	h.drops = 1
	h.finish(true)
	h.s.Tick() // pending, offline
	h.at(13, 21, 0)
	h.since = h.now.Add(-time.Minute)
	h.s.Tick() // next slot starts on time
	h.s.RunStarted(1, h.now)
	h.finish(false)
	h.at(13, 23, 0)
	h.s.Tick()
	if strings.Join(h.started, ",") != "schedule@12 21:00,schedule@13 21:00" {
		t.Fatalf("started %v", h.started)
	}
}
