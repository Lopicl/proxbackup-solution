// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/schedule"
)

// Scheduler decides when scheduled backups start. The server only pushes the
// configuration; the agent evaluates schedules on its own clock (in the PC's
// local time zone), so backups also run while the server is unreachable.
//
// For every job it remembers the last scheduled slot it handled. When a slot
// comes due:
//   - within the job's start window   → start it (trigger "schedule")
//   - window passed (PC off/asleep)   → catch-up on: start now (trigger "catch-up")
//     catch-up off: record the run as "missed"
//   - same job still running (busy)   → catch-up on: start it once the current run ends
//     catch-up off: record as "missed"
//   - backups paused from the tray     → catch-up on: start it once the pause ends
//     catch-up off: record as "missed"
//
// Several missed slots are coalesced into a single catch-up run.
type Scheduler struct {
	dir string
	now func() time.Time

	// start queues a job; it returns false if the job is already queued or running.
	start func(spec api.JobSpec, job api.JobConfig, trigger string, slot time.Time) bool
	// busy reports whether the job is queued or running.
	busy func(jobID int64) bool
	// missed records a skipped scheduled run.
	missed func(job api.JobConfig, slot time.Time, reason string)
	// pausedBy reports who paused scheduled backups ("" = not paused).
	pausedBy func() string
	logf     func(level, format string, args ...any)

	mu    sync.Mutex
	cfg   *api.AgentConfig
	state map[int64]*jobState
}

type jobState struct {
	Schedule       string `json:"schedule"`
	LastSlot       int64  `json:"last_slot"` // newest slot already handled (unix seconds)
	CatchUpPending bool   `json:"catch_up_pending"`
	PendingSlot    int64  `json:"pending_slot,omitempty"`
}

const (
	configFile        = "jobs.json"     // pushed config incl. PBS token: written 0600
	scheduleStateFile = "schedule.json" // per-job scheduling state
	defaultWindow     = 60 * time.Minute
)

// NewScheduler loads the persisted configuration and state from dir.
func NewScheduler(dir string) *Scheduler {
	s := &Scheduler{dir: dir, now: time.Now, state: map[int64]*jobState{}}
	if b, err := os.ReadFile(filepath.Join(dir, configFile)); err == nil {
		var c api.AgentConfig
		if json.Unmarshal(b, &c) == nil {
			s.cfg = &c
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, scheduleStateFile)); err == nil {
		json.Unmarshal(b, &s.state)
	}
	return s
}

// Rev returns the revision of the current configuration ("" if none).
func (s *Scheduler) Rev() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return ""
	}
	return s.cfg.Rev
}

// Config returns the current configuration (nil before the first sync).
func (s *Scheduler) Config() *api.AgentConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Job returns a job of the current configuration.
func (s *Scheduler) Job(id int64) (api.JobConfig, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg != nil {
		for _, j := range s.cfg.Jobs {
			if j.ID == id {
				return j, true
			}
		}
	}
	return api.JobConfig{}, false
}

// Update installs a new configuration pushed by the server.
func (s *Scheduler) Update(c *api.AgentConfig) error {
	for _, j := range c.Jobs {
		if j.Schedule != "" {
			if err := schedule.Validate(j.Schedule); err != nil {
				return fmt.Errorf("job %d: %w", j.ID, err)
			}
		}
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := writeSecret(filepath.Join(s.dir, configFile), b); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
	now := s.now()
	keep := map[int64]*jobState{}
	for _, j := range c.Jobs {
		st := s.state[j.ID]
		if st == nil || st.Schedule != j.Schedule {
			// New job or changed schedule: start counting from now, don't
			// catch up on slots that belonged to a different schedule.
			st = &jobState{Schedule: j.Schedule, LastSlot: now.Add(-delay(j)).Unix()}
		}
		if !j.CatchUp {
			st.CatchUpPending = false
		}
		keep[j.ID] = st
	}
	s.state = keep
	return s.saveLocked()
}

func (s *Scheduler) saveLocked() error {
	b, _ := json.MarshalIndent(s.state, "", "  ")
	return writeSecret(filepath.Join(s.dir, scheduleStateFile), b)
}

// delay is the job's start offset: slots are evaluated on a clock that runs
// this much behind, so a 21:00 schedule with a 10 minute delay starts at 21:10.
// LastSlot keeps the unshifted schedule time.
func delay(j api.JobConfig) time.Duration {
	return time.Duration(max(j.StartDelay, 0)) * time.Second
}

func window(j api.JobConfig) time.Duration {
	if j.WindowMinutes <= 0 {
		return defaultWindow
	}
	return time.Duration(j.WindowMinutes) * time.Minute
}

// Tick evaluates all schedules once; call it periodically and after wake-up.
// The callbacks (start, busy, missed) must not call back into the Scheduler.
func (s *Scheduler) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return
	}
	jobs := s.cfg.Jobs
	now := s.now()
	changed := false
	paused := ""
	if s.pausedBy != nil {
		paused = s.pausedBy()
	}
	for _, j := range jobs {
		if j.Schedule == "" {
			continue
		}
		sched, err := schedule.Parse(j.Schedule)
		if err != nil {
			continue
		}
		off := delay(j)
		st := s.state[j.ID]
		if st == nil {
			st = &jobState{Schedule: j.Schedule, LastSlot: now.Add(-off).Unix()}
			s.state[j.ID] = st
			changed = true
		}

		// A catch-up deferred because the job was busy: start it once it's free.
		if st.CatchUpPending && paused == "" && !s.busy(j.ID) {
			if s.start(s.cfg.Spec(j), j, api.TriggerCatchUp, time.Unix(st.PendingSlot, 0)) {
				s.logf("info", "%s: starting deferred catch-up run", j.Name)
				st.CatchUpPending, changed = false, true
			}
		}

		due := schedule.Check(sched, time.Unix(st.LastSlot, 0), now.Add(-off), window(j))
		if due.Count == 0 {
			continue
		}
		st.LastSlot, changed = due.Slot.Unix(), true
		due.Slot = due.Slot.Add(off) // when this member's run is due
		skipped := ""
		if due.Count > 1 {
			skipped = fmt.Sprintf(" (%d scheduled runs were missed)", due.Count)
		}
		switch {
		case paused != "":
			if j.CatchUp {
				st.CatchUpPending, st.PendingSlot = true, due.Slot.Unix()
				s.logf("info", "%s: backups are paused, will catch up when the pause ends", j.Name)
			} else {
				s.missed(j, due.Slot, "scheduled backups were paused on the PC by "+paused)
			}
		case s.busy(j.ID):
			if j.CatchUp {
				st.CatchUpPending, st.PendingSlot = true, due.Slot.Unix()
				s.logf("info", "%s: previous run still in progress, will catch up when it finishes", j.Name)
			} else {
				s.missed(j, due.Slot, "the previous run of this job was still in progress")
			}
		case due.OnTime:
			s.start(s.cfg.Spec(j), j, api.TriggerSchedule, due.Slot)
		case j.CatchUp:
			s.logf("info", "%s: scheduled time %s was missed%s, catching up now", j.Name, due.Slot.Format(time.RFC1123), skipped)
			s.start(s.cfg.Spec(j), j, api.TriggerCatchUp, due.Slot)
		default:
			s.missed(j, due.Slot, "the PC was off, asleep or the agent was not running at the scheduled time"+skipped)
		}
	}
	if changed {
		if err := s.saveLocked(); err != nil {
			s.logf("warn", "saving schedule state: %v", err)
		}
	}
}

// States reports the scheduling view of every job to the server.
func (s *Scheduler) States() []api.JobState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return nil
	}
	now := s.now()
	out := make([]api.JobState, 0, len(s.cfg.Jobs))
	for _, j := range s.cfg.Jobs {
		js := api.JobState{JobID: j.ID, Running: s.busy(j.ID)}
		if st := s.state[j.ID]; st != nil {
			js.LastSlot, js.CatchUpPending = st.LastSlot, st.CatchUpPending
		}
		if j.Schedule != "" {
			if sched, err := schedule.Parse(j.Schedule); err == nil {
				js.NextRun = sched.Next(now.Add(-delay(j))).Add(delay(j)).Unix()
			}
		}
		out = append(out, js)
	}
	return out
}

// lateStart decides what to do when a queued scheduled run finally gets its
// turn: if it waited past its window (agent busy with another job), it becomes
// a catch-up run or is recorded as missed.
func lateStart(j api.JobConfig, trigger string, slot, now time.Time) (string, error) {
	if trigger != api.TriggerSchedule || now.Sub(slot) <= window(j) {
		return trigger, nil
	}
	if j.CatchUp {
		return api.TriggerCatchUp, nil
	}
	return "", errors.New("the agent was busy with another job during the start window")
}
