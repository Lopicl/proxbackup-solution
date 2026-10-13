package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"proxbackup/internal/api"
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

	mu       sync.Mutex
	running  map[int64]context.CancelFunc // by server run id
	inflight map[int64]bool               // job ids queued or running
	queue    chan task

	updating       bool // self-update in progress (selfupdate.go)
	updateFailed   string
	updateFailedAt time.Time
}

// task is one unit of work for the worker.
type task struct {
	spec    api.JobSpec // RunID > 0 for server-dispatched runs
	job     api.JobConfig
	local   bool // started by the agent's scheduler
	trigger string
	slot    time.Time
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
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
// response: configuration updates, cancellations and on-demand jobs.
func (r *Runner) pollOnce(ctx context.Context, wait int) error {
	hostname, _ := os.Hostname()
	req := api.PollRequest{
		Hostname: hostname, OS: osDescription(), AgentVersion: r.version, RunningRuns: r.runningIDs(),
		ConfigRev: r.sched.Rev(), Schedule: r.sched.States(), TimeZone: time.Now().Format("MST -07:00"),
	}
	var resp api.PollResponse
	if err := postJSON(ctx, r.hc, fmt.Sprintf("%s/agent/v1/poll?wait=%d", r.cfg.ServerURL, wait), req, &resp); err != nil {
		return err
	}
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
	return nil
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight[job.ID] {
		return false
	}
	select {
	case r.queue <- task{spec: spec, job: job, local: true, trigger: trigger, slot: slot}:
		r.inflight[job.ID] = true
		r.log.Info("scheduled job queued", "job", job.Name, "trigger", trigger, "slot", slot.Format(time.RFC3339))
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
		rep.Log("info", fmt.Sprintf("%s run of job %q started by the agent (scheduled for %s, agent %s)",
			t.trigger, t.job.Name, t.slot.Format("2006-01-02 15:04 MST"), r.version))
	} else {
		r.mu.Lock()
		r.running[t.spec.RunID] = cancel
		r.mu.Unlock()
		rep = newReporter(r, nil, t.spec.RunID, nil)
		rep.Log("info", fmt.Sprintf("starting %s job requested from the server (agent %s)", t.spec.Kind, r.version))
	}
	res := Run(ctx, t.spec, rep)
	r.log.Info("run finished", "job", t.spec.JobID, "trigger", t.trigger, "state", res.State, "err", res.Error)
	rep.finish(res)

	r.mu.Lock()
	delete(r.running, rep.runID)
	delete(r.running, t.spec.RunID)
	r.mu.Unlock()
}

func (r *Runner) register(ctx context.Context, reg *api.RunRegister) (int64, error) {
	var resp api.RunRegisterResponse
	if err := postJSON(ctx, r.hc, r.cfg.ServerURL+"/agent/v1/runs", reg, &resp); err != nil {
		return 0, err
	}
	return resp.RunID, nil
}

func (r *Runner) postEvents(ctx context.Context, runID int64, events []api.Event) error {
	return postJSON(ctx, r.hc, fmt.Sprintf("%s/agent/v1/runs/%d/events", r.cfg.ServerURL, runID), events, nil)
}
