package agent

import (
	"strings"
	"testing"
	"time"

	"pbspc/internal/api"
)

type schedHarness struct {
	s       *Scheduler
	now     time.Time
	busy    map[int64]bool
	started []string
	missed  []string
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
