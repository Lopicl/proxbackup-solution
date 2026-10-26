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
//   - PC on battery / metered network  → (job policy "defer" or "stop") wait: start
//     it once the condition ends, as a scheduled run within the start window,
//     later as a catch-up run; catch-up off: "missed" once the window has passed
//
// A job with policy "stop" also has its scheduled run stopped when the
// condition sets in mid-run (Runner.enforceConditions); the run then waits
// like a deferred one (Defer).
//
// With catch-up on, a scheduled run that fails because the agent went offline
// meanwhile (lost contact with the server, or the agent stopped mid-run: PC
// shut down, power loss) is caught up once the agent has been back online
// for offlineRetryDelay.
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
	// conn reports since when the agent has been connected to the server (zero
	// while offline) and how often it lost the connection so far.
	conn func() (onlineSince time.Time, drops int)
	// cond reports the PC's power and network state (nil = mains, unmetered).
	cond func() conditions
	logf func(level, format string, args ...any)

	mu     sync.Mutex
	cfg    *api.AgentConfig
	state  map[int64]*jobState
	drops  map[int64]int       // connection drops when a job's run started
	failed map[int64]failedRun // failed runs that may have been cut off by going offline
}

// failedRun is a failed scheduled run waiting to see whether the agent went
// offline during it (the connection loss may be noticed after the run failed).
type failedRun struct {
	slot  time.Time
	drops int
	at    time.Time
}

type jobState struct {
	Schedule       string `json:"schedule"`
	LastSlot       int64  `json:"last_slot"` // newest slot already handled (unix seconds)
	CatchUpPending bool   `json:"catch_up_pending"`
	PendingSlot    int64  `json:"pending_slot,omitempty"`
	// The pending catch-up repeats a run cut off by the agent going offline:
	// it waits until the agent has been online for offlineRetryDelay after RetryFrom.
	RetryOnline bool  `json:"retry_online,omitempty"`
	RetryFrom   int64 `json:"retry_from,omitempty"`
	Running     int64 `json:"running,omitempty"` // slot of the scheduled run in progress
	// Deferred: the run of PendingSlot waits for the PC to leave battery
	// power or a metered network (Reason, for a "missed" record).
	Deferred bool   `json:"deferred,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

const (
	configFile        = "jobs.json"     // pushed config incl. PBS token: written 0600
	scheduleStateFile = "schedule.json" // per-job scheduling state
	defaultWindow     = 60 * time.Minute
	// offlineRetryDelay: a run cut off by the agent going offline is repeated
	// once the agent has been back online this long.
	offlineRetryDelay = 30 * time.Minute
	// offlineGrace: how long after a failed run a connection loss still counts
	// as its cause (the poll notices a dead network only after its timeout).
	offlineGrace = 5 * time.Minute
)

// NewScheduler loads the persisted configuration and state from dir.
func NewScheduler(dir string) *Scheduler {
	s := &Scheduler{dir: dir, now: time.Now, state: map[int64]*jobState{}, drops: map[int64]int{}, failed: map[int64]failedRun{}}
	if b, err := os.ReadFile(filepath.Join(dir, configFile)); err == nil {
		var c api.AgentConfig
		if json.Unmarshal(b, &c) == nil {
			s.cfg = &c
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, scheduleStateFile)); err == nil {
		json.Unmarshal(b, &s.state)
	}
	// A run still marked as in progress was cut off by the agent stopping; it
	// is repeated once this agent process has been online long enough.
	for id, st := range s.state {
		if st.Running == 0 {
			continue
		}
		if j, ok := s.jobLocked(id); ok && j.CatchUp {
			st.CatchUpPending, st.PendingSlot = true, st.Running
			st.RetryOnline, st.RetryFrom = true, 0
		}
		st.Running = 0
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
	return s.jobLocked(id)
}

func (s *Scheduler) jobLocked(id int64) (api.JobConfig, bool) {
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
			st.CatchUpPending, st.RetryOnline = false, false
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
	cond := s.conditions()
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

		// A failed run turns out to have been cut off by the agent going offline.
		if f, ok := s.failed[j.ID]; ok {
			if _, drops := s.connection(); drops > f.drops && j.CatchUp {
				s.logf("info", "%s: the run failed while the agent was offline, will catch up %s after it is back online",
					j.Name, offlineRetryDelay)
				st.CatchUpPending, st.PendingSlot = true, f.slot.Unix()
				st.RetryOnline, st.RetryFrom = true, f.at.Unix()
				changed = true
				delete(s.failed, j.ID)
			} else if !j.CatchUp || now.Sub(f.at) > offlineGrace {
				delete(s.failed, j.ID)
			}
		}

		blocked, _ := cond.blockedBy(j)

		// A run waiting for the PC to leave battery power or a metered
		// network: on time within its window, a catch-up after it.
		if st.Deferred {
			slot := time.Unix(st.PendingSlot, 0)
			late := now.Sub(slot) > window(j)
			switch {
			case blocked == "" && paused == "" && !s.busy(j.ID) && (!late || j.CatchUp):
				trigger, msg := api.TriggerSchedule, "starting the run that waited"
				if late {
					trigger, msg = api.TriggerCatchUp, "starting catch-up of the run that waited"
				}
				if s.start(s.cfg.Spec(j), j, trigger, slot) {
					s.logf("info", "%s: no longer %s, %s", j.Name, st.Reason, msg)
					st.Deferred, st.Reason, changed = false, "", true
				}
			case late && !j.CatchUp:
				s.missed(j, slot, "the PC was "+st.Reason+" during the start window")
				st.Deferred, st.Reason, changed = false, "", true
			}
		}

		// A catch-up deferred because the job was busy (or a run cut off by
		// going offline): start it once it's free.
		if st.CatchUpPending && paused == "" && blocked == "" && !s.busy(j.ID) && s.retryDue(st, now) {
			msg := "starting deferred catch-up run"
			if st.RetryOnline {
				msg = "starting catch-up of the run cut off by the agent going offline"
			}
			if s.start(s.cfg.Spec(j), j, api.TriggerCatchUp, time.Unix(st.PendingSlot, 0)) {
				s.logf("info", "%s: %s", j.Name, msg)
				st.CatchUpPending, st.RetryOnline, changed = false, false, true
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
				st.CatchUpPending, st.PendingSlot, st.RetryOnline = true, due.Slot.Unix(), false
				st.Deferred = false // coalesced into this catch-up
				s.logf("info", "%s: backups are paused, will catch up when the pause ends", j.Name)
			} else {
				s.missed(j, due.Slot, "scheduled backups were paused on the PC by "+paused)
			}
		case blocked != "" && (due.OnTime || j.CatchUp):
			st.Deferred, st.PendingSlot, st.Reason = true, due.Slot.Unix(), blocked
			st.CatchUpPending, st.RetryOnline = false, false // coalesced into this run
			s.logf("info", "%s: the PC is %s, the scheduled run waits until it no longer is", j.Name, blocked)
		case s.busy(j.ID):
			if j.CatchUp {
				st.CatchUpPending, st.PendingSlot, st.RetryOnline = true, due.Slot.Unix(), false
				st.Deferred = false // coalesced into this catch-up
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

// conditions reports the PC's power and network state.
func (s *Scheduler) conditions() conditions {
	if s.cond == nil {
		return conditions{}
	}
	return s.cond()
}

// Defer makes a scheduled run that was stopped because the PC went on battery
// power or a metered network wait until it no longer is (see Tick).
func (s *Scheduler) Defer(jobID int64, slot time.Time, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[jobID]
	if st == nil {
		return
	}
	st.Deferred, st.PendingSlot, st.Reason = true, slot.Unix(), reason
	st.CatchUpPending, st.RetryOnline = false, false
	s.saveLocked()
}

// connection reports the agent's connection to the server.
func (s *Scheduler) connection() (time.Time, int) {
	if s.conn == nil {
		return time.Time{}, 0
	}
	return s.conn()
}

// retryDue reports whether a pending catch-up may start: a run cut off by
// going offline waits until the agent has been online for offlineRetryDelay.
func (s *Scheduler) retryDue(st *jobState, now time.Time) bool {
	if !st.RetryOnline {
		return true
	}
	since, _ := s.connection()
	if since.IsZero() {
		return false
	}
	if from := time.Unix(st.RetryFrom, 0); from.After(since) {
		since = from
	}
	return !now.Before(since.Add(offlineRetryDelay))
}

// RunStarted marks a scheduled or catch-up run as in progress, so a run cut
// off by the agent stopping is caught up after a restart. It replaces a
// pending catch-up of a run cut off by going offline.
func (s *Scheduler) RunStarted(jobID int64, slot time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[jobID]
	if st == nil {
		return
	}
	_, s.drops[jobID] = s.connection()
	delete(s.failed, jobID)
	st.Running = slot.Unix()
	if st.RetryOnline {
		st.CatchUpPending, st.RetryOnline = false, false
	}
	s.saveLocked()
}

// RunEnded clears the in-progress mark. A failed run is caught up if the
// agent turns out to have gone offline during it (checked by Tick).
func (s *Scheduler) RunEnded(jobID int64, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[jobID]
	if st == nil || st.Running == 0 {
		return
	}
	if failed {
		s.failed[jobID] = failedRun{slot: time.Unix(st.Running, 0), drops: s.drops[jobID], at: s.now()}
	}
	st.Running = 0
	s.saveLocked()
}

// States reports the scheduling view of every job to the server.
func (s *Scheduler) States() []api.JobState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		return nil
	}
	now := s.now()
	cond := s.conditions()
	out := make([]api.JobState, 0, len(s.cfg.Jobs))
	for _, j := range s.cfg.Jobs {
		js := api.JobState{JobID: j.ID, Running: s.busy(j.ID)}
		if st := s.state[j.ID]; st != nil {
			js.LastSlot, js.CatchUpPending = st.LastSlot, st.CatchUpPending
			if st.Deferred || st.CatchUpPending {
				js.Waiting, _ = cond.blockedBy(j)
			}
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

// NextWake is the earliest scheduled start after t of a job that may wake
// the PC from sleep (zero if there is none).
func (s *Scheduler) NextWake(t time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	var next time.Time
	if s.cfg == nil {
		return next
	}
	for _, j := range s.cfg.Jobs {
		if !j.WakeToRun || j.Schedule == "" {
			continue
		}
		sched, err := schedule.Parse(j.Schedule)
		if err != nil {
			continue
		}
		if n := sched.Next(t.Add(-delay(j))); !n.IsZero() {
			if n = n.Add(delay(j)); next.IsZero() || n.Before(next) {
				next = n
			}
		}
	}
	return next
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
