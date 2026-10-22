// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/ipc"
)

// Runner connects the agent to the management server and executes jobs.
//
// Scheduled backups are started by the agent's own Scheduler from the
// configuration the server pushes; the server only dispatches on-demand work
// ("Run now", restores). Jobs run one at a time.
type Runner struct {
	cfg     *Config
	hc      *http.Client
	version string
	log     *slog.Logger
	sched   *Scheduler
	spool   *spool

	mu         sync.Mutex
	running    map[int64]context.CancelFunc // by server run id
	inflight   map[int64]bool               // job ids queued or running
	queue      chan task
	wakeAt     time.Time // armed wake time (scheduleLoop only)
	wakeWarned bool

	updating       bool // self-update in progress (selfupdate.go)
	updateFailed   string
	updateFailedAt time.Time

	local localState // tray app view (local.go)

	trayErrs map[uint32]string // tray app launch failures by user session

	urlMu     sync.Mutex // guards cfg.ServerURL/FallbackURL
	moveTried map[string]time.Time
}

// task is one unit of work for the worker.
type task struct {
	spec    api.JobSpec // RunID > 0 for server-dispatched runs
	job     api.JobConfig
	local   bool // started by the agent's scheduler
	trigger string
	slot    time.Time
	by      string // user who started it from the tray
}

// NewRunner creates a runner from an enrolled configuration.
func NewRunner(cfg *Config, version string, log *slog.Logger) (*Runner, error) {
	tc, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}
	r := &Runner{
		cfg:      cfg,
		hc:       &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, IdleConnTimeout: 2 * time.Minute}},
		version:  version,
		log:      log,
		spool:    &spool{dir: filepath.Join(cfg.dir, "spool")},
		running:  map[int64]context.CancelFunc{},
		inflight: map[int64]bool{},
		queue:    make(chan task, 64),
	}
	r.sched = NewScheduler(cfg.dir)
	r.sched.start = r.startLocal
	r.sched.busy = r.busy
	r.sched.missed = r.reportMissed
	r.sched.pausedBy = r.pausedBy
	r.sched.conn = r.connection
	r.loadLocal()
	r.sched.logf = func(level, format string, args ...any) { r.log.Info(fmt.Sprintf(format, args...), "level", level) }
	return r, nil
}

// Run blocks until ctx is canceled.
func (r *Runner) Run(ctx context.Context) error {
	cleanupUpdate()
	go r.worker(ctx)
	// Fetch the latest configuration before evaluating schedules, so changes made
	// while the PC was off apply to the first check. Fall back to the cached config.
	syncCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if err := r.pollOnce(syncCtx, 0); err != nil {
		r.log.Warn("server unreachable at startup; using the cached configuration", "err", err)
	}
	cancel()
	go r.scheduleLoop(ctx)
	go r.spoolLoop(ctx)
	go r.serveLocal(ctx)
	go launchTrays(ctx, r.log, r.setTrayError)
	r.pollLoop(ctx)
	return ctx.Err()
}

// scheduleLoop evaluates schedules every 20s. It runs from the persisted
// configuration, so backups happen even when the server is down.
func (r *Runner) scheduleLoop(ctx context.Context) {
	if r.sched.Config() == nil {
		r.log.Info("no job configuration yet; waiting for the server")
	}
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		r.sched.Tick()
		r.armWake()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// errNoWake: the PC has no sleep state it can wake from on a timer.
var errNoWake = errors.New("this PC can't wake up on a timer (no supported sleep state, or wake timers are off)")

// wakeLead is how long before a scheduled run the PC is woken, so the
// schedule check (every 20s) sees the run on time.
const wakeLead = 30 * time.Second

// armWake sets the wake timer to the next scheduled run that may wake the PC,
// skipping runs while scheduled backups are paused from the tray.
func (r *Runner) armWake() {
	now := time.Now()
	from := now
	if until, _ := r.pauseInfo(); until > 0 {
		from = time.Unix(until, 0)
	}
	at := r.sched.NextWake(from)
	if !at.IsZero() {
		at = at.Add(-wakeLead)
		if !at.After(now) {
			return // due now: the PC is awake and keeps the armed time
		}
	}
	if at.Equal(r.wakeAt) {
		return
	}
	if err := setWakeTimer(at); err != nil {
		if !r.wakeWarned {
			r.log.Warn("can't set the wake timer for scheduled backups", "err", err)
		}
		r.wakeWarned = true
	} else if !at.IsZero() {
		r.log.Info("PC will wake up for the next scheduled backup", "at", at.Format(time.RFC3339))
	}
	r.wakeAt = at
}

func (r *Runner) spoolLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		r.spool.drain(ctx, r)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Runner) pollLoop(ctx context.Context) {
	backoff := time.Second
	online := true
	for ctx.Err() == nil {
		if err := r.pollOnce(ctx, 30); err != nil {
			if ctx.Err() != nil {
				break
			}
			r.setOnline(false)
			if online {
				r.log.Warn("server unreachable; scheduled backups continue from the cached configuration", "err", err)
				online = false
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		if !online {
			r.log.Info("server reachable again")
			online = true
			go r.spool.drain(ctx, r)
		}
		backoff = time.Second
	}
}

// pollOnce sends a heartbeat (long-polling up to wait seconds) and applies the
// response: configuration updates, cancellations and on-demand jobs. If the
// console is unreachable it tries the previous console URL, and it follows the
// console to a new URL once that answers.
func (r *Runner) pollOnce(ctx context.Context, wait int) error {
	resp, err := r.poll(ctx, r.serverURL(), wait)
	if err != nil {
		if fb := r.fallbackURL(); fb != "" && ctx.Err() == nil {
			fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			resp, ferr := r.poll(fctx, fb, 0)
			cancel()
			if ferr == nil {
				r.log.Warn("console unreachable; using its previous address", "url", fb, "err", err)
				r.swapServer(fb)
				r.followServer(ctx, resp.ServerURL)
				return nil
			}
		}
		return err
	}
	r.followServer(ctx, resp.ServerURL)
	return nil
}

// followServer switches to the console URL the server announced once a poll
// through it succeeds; the old URL stays as the fallback. Failed attempts are
// retried every 10 minutes, so the old address must stay reachable meanwhile.
func (r *Runner) followServer(ctx context.Context, to string) {
	to = strings.TrimRight(to, "/")
	if to == "" || to == r.serverURL() {
		return
	}
	r.urlMu.Lock()
	if t, ok := r.moveTried[to]; ok && time.Since(t) < 10*time.Minute {
		r.urlMu.Unlock()
		return
	}
	if r.moveTried == nil {
		r.moveTried = map[string]time.Time{}
	}
	r.moveTried[to] = time.Now()
	r.urlMu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := r.poll(pctx, to, 0); err != nil {
		r.log.Warn("console moved, but its new address is unreachable; staying on the current one", "current", r.serverURL(), "new", to, "err", err)
		return
	}
	r.log.Info("console moved; switching to its new address", "old", r.serverURL(), "new", to)
	r.swapServer(to)
}

func (r *Runner) serverURL() string {
	r.urlMu.Lock()
	defer r.urlMu.Unlock()
	return r.cfg.ServerURL
}

func (r *Runner) fallbackURL() string {
	r.urlMu.Lock()
	defer r.urlMu.Unlock()
	if r.cfg.FallbackURL == r.cfg.ServerURL {
		return ""
	}
	return r.cfg.FallbackURL
}

// swapServer makes to the active console URL and the current one the fallback.
func (r *Runner) swapServer(to string) {
	r.urlMu.Lock()
	defer r.urlMu.Unlock()
	if to == r.cfg.ServerURL {
		return
	}
	r.cfg.ServerURL, r.cfg.FallbackURL = to, r.cfg.ServerURL
	if err := r.cfg.save(); err != nil {
		r.log.Error("saving the new console address", "err", err)
	}
}

// poll does one poll against base and applies the response.
func (r *Runner) poll(ctx context.Context, base string, wait int) (*api.PollResponse, error) {
	hostname, _ := os.Hostname()
	req := api.PollRequest{
		Hostname: hostname, OS: osDescription(), AgentVersion: r.version, RunningRuns: r.runningIDs(),
		ConfigRev: r.sched.Rev(), Schedule: r.sched.States(), TimeZone: time.Now().Format("MST -07:00"),
	}
	req.PausedUntil, req.PausedBy = r.pauseInfo()
	req.TrayError = r.trayError()
	var resp api.PollResponse
	if err := postJSON(ctx, r.hc, fmt.Sprintf("%s/agent/v1/poll?wait=%d", base, wait), req, &resp); err != nil {
		return nil, err
	}
	r.setOnline(true)
	if resp.Config != nil {
		if err := r.sched.Update(resp.Config); err != nil {
			r.log.Error("rejecting configuration", "err", err)
		} else {
			r.log.Info("configuration updated", "rev", resp.Config.Rev[:12], "jobs", len(resp.Config.Jobs))
			r.sched.Tick()
		}
	}
	for _, id := range resp.Cancel {
		r.mu.Lock()
		if cancel := r.running[id]; cancel != nil {
			r.log.Info("canceling run", "run", id)
			cancel()
		}
		r.mu.Unlock()
	}
	for _, j := range resp.Jobs {
		r.log.Info("received on-demand job", "run", j.RunID, "kind", j.Kind)
		r.mu.Lock()
		r.running[j.RunID] = func() {} // placeholder until it starts
		if j.JobID > 0 {
			r.inflight[j.JobID] = true
		}
		r.mu.Unlock()
		r.queue <- task{spec: j, trigger: api.TriggerManual}
	}
	if resp.Update != nil {
		r.maybeUpdate(ctx, resp.Update)
	}
	return &resp, nil
}

// setTrayError records (msg != "") or clears a tray app launch failure.
func (r *Runner) setTrayError(session uint32, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if msg == "" {
		delete(r.trayErrs, session)
		return
	}
	if r.trayErrs == nil {
		r.trayErrs = map[uint32]string{}
	}
	r.trayErrs[session] = msg
}

// trayError is the tray app launch failures for the poll ("" = none).
func (r *Runner) trayError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	msgs := make([]string, 0, len(r.trayErrs))
	for _, m := range r.trayErrs {
		msgs = append(msgs, m)
	}
	sort.Strings(msgs)
	return strings.Join(msgs, "; ")
}

func (r *Runner) runningIDs() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]int64, 0, len(r.running))
	for id := range r.running {
		ids = append(ids, id)
	}
	return ids
}

func (r *Runner) busy(jobID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inflight[jobID]
}

// startLocal queues a scheduled or catch-up run (called by the Scheduler).
func (r *Runner) startLocal(spec api.JobSpec, job api.JobConfig, trigger string, slot time.Time) bool {
	return r.queueLocal(task{spec: spec, job: job, local: true, trigger: trigger, slot: slot})
}

// queueLocal queues a run the agent starts itself, unless its job is queued or running.
func (r *Runner) queueLocal(t task) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight[t.job.ID] {
		return false
	}
	select {
	case r.queue <- t:
		r.inflight[t.job.ID] = true
		r.log.Info("job queued", "job", t.job.Name, "trigger", t.trigger, "slot", t.slot.Format(time.RFC3339))
		return true
	default:
		return false
	}
}

// reportMissed records a scheduled run that was not started.
func (r *Runner) reportMissed(job api.JobConfig, slot time.Time, reason string) {
	r.log.Warn("scheduled run missed", "job", job.Name, "slot", slot.Format(time.RFC3339), "reason", reason)
	r.spool.put(spoolEntry{Reg: &api.RunRegister{
		UUID: newUUID(), JobID: job.ID, Kind: job.Kind, Trigger: api.TriggerSchedule, State: api.RunMissed,
		ScheduledFor: slot.Unix(), StartedAt: time.Now().Unix(), Message: reason,
	}})
	r.recordRun(ipc.RunInfo{JobID: job.ID, JobName: job.Name, Kind: job.Kind, Trigger: api.TriggerSchedule, State: api.RunMissed,
		Error: reason, Finished: time.Now().Unix()})
	go r.spool.drain(context.Background(), r)
}

// worker executes queued tasks sequentially (VSS and disk I/O don't benefit from parallel runs).
func (r *Runner) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-r.queue:
			r.execute(ctx, t)
			r.mu.Lock()
			delete(r.inflight, t.spec.JobID)
			r.mu.Unlock()
			r.sched.Tick() // start a deferred catch-up right away
		}
	}
}

func (r *Runner) execute(parent context.Context, t task) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var rep *reporter
	if t.local {
		trigger, err := lateStart(t.job, t.trigger, t.slot, time.Now())
		if err != nil {
			r.reportMissed(t.job, t.slot, err.Error())
			return
		}
		t.trigger = trigger
		reg := &api.RunRegister{UUID: newUUID(), JobID: t.job.ID, Kind: t.job.Kind, Trigger: t.trigger,
			State: api.RunRunning, ScheduledFor: t.slot.Unix(), StartedAt: time.Now().Unix()}
		rep = newReporter(r, reg, 0, func(id int64) {
			r.mu.Lock()
			r.running[id] = cancel
			r.mu.Unlock()
		})
		if t.by != "" {
			rep.Log("info", fmt.Sprintf("run of job %q started from the tray app by %s (agent %s)", t.job.Name, t.by, r.version))
		} else {
			rep.Log("info", fmt.Sprintf("%s run of job %q started by the agent (scheduled for %s, agent %s)",
				t.trigger, t.job.Name, t.slot.Format("2006-01-02 15:04 MST"), r.version))
		}
	} else {
		r.mu.Lock()
		r.running[t.spec.RunID] = cancel
		r.mu.Unlock()
		rep = newReporter(r, nil, t.spec.RunID, nil)
		rep.Log("info", fmt.Sprintf("starting %s job requested from the server (agent %s)", t.spec.Kind, r.version))
	}
	name := r.jobName(t.spec.JobID, t.spec.Kind)
	// A run the PC woke up for also needs it, or Windows sleeps again after 2 minutes.
	if t.spec.PreventSleep || t.spec.Restore != nil || (t.local && t.job.WakeToRun) {
		if release, err := keepAwake(fmt.Sprintf("ProxBackup: %q in progress", name)); err != nil {
			rep.Log("warn", "can't keep the PC awake during the run: "+err.Error())
		} else {
			defer release()
		}
	}
	r.runStarted(name, t.spec.Kind, t.trigger)
	scheduled := t.local && t.by == ""
	if scheduled {
		r.sched.RunStarted(t.job.ID, t.slot)
	}
	started := time.Now()
	var res api.Result
	if rs := t.spec.Restore; rs != nil && rs.Session != "" {
		res = r.restoreAs(ctx, t.spec, tapReporter{rep, r})
	} else {
		res = Run(ctx, t.spec, tapReporter{rep, r})
	}
	r.runEnded()
	if scheduled && parent.Err() == nil { // agent stopping: the restart catches it up
		r.sched.RunEnded(t.job.ID, res.State == api.RunFailed)
	}
	r.log.Info("run finished", "job", t.spec.JobID, "trigger", t.trigger, "state", res.State, "err", res.Error)
	rep.finish(res)
	r.recordRun(ipc.RunInfo{JobID: t.spec.JobID, JobName: name, Kind: t.spec.Kind, Trigger: t.trigger, State: res.State, Error: res.Error,
		Started: started.Unix(), Finished: time.Now().Unix(), Files: res.Files, Bytes: res.BytesTotal})

	r.mu.Lock()
	delete(r.running, rep.runID)
	delete(r.running, t.spec.RunID)
	r.mu.Unlock()
}

func (r *Runner) register(ctx context.Context, reg *api.RunRegister) (int64, error) {
	var resp api.RunRegisterResponse
	if err := postJSON(ctx, r.hc, r.serverURL()+"/agent/v1/runs", reg, &resp); err != nil {
		return 0, err
	}
	return resp.RunID, nil
}

func (r *Runner) postEvents(ctx context.Context, runID int64, events []api.Event) error {
	return postJSON(ctx, r.hc, fmt.Sprintf("%s/agent/v1/runs/%d/events", r.serverURL(), runID), events, nil)
}
