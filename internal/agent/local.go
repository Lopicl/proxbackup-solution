// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/ipc"
)

// Local control for the tray app (internal/ipc): status, recent runs,
// "Back up now", pausing scheduled backups and "Restore files…" sessions.

const (
	historyFile    = "history.json" // recent runs shown in the tray
	pauseFile      = "pause.json"
	historyKeep    = 20
	maxPause       = 24 * time.Hour
	restoreSessTTL = 8 * time.Hour // how long a "Restore files…" page works
)

// localState is the part of the runner the tray reads.
type localState struct {
	mu       sync.Mutex
	online   bool
	since    time.Time // when the connection to the server was (re)established
	drops    int       // how often the connection to the server was lost
	contact  time.Time // when a request to the server last succeeded
	current  *ipc.RunningRun
	history  []ipc.RunInfo // newest first
	pause    pauseState
	sessions map[string]*restoreSession

	// pauseDays is the console's limit on paused days in a row (nil = none,
	// 0 = no pauses; applyPausePolicy).
	pauseDays *int
}

type pauseState struct {
	Until int64  `json:"until"`
	By    string `json:"by"`
	// Since is when the current run of pauses began: the console's limit
	// counts from it until a scheduled backup has started again (0 = none
	// since then). Resuming early doesn't reset it.
	Since int64 `json:"since,omitempty"`
}

type restoreSession struct {
	peer    *ipc.Peer // kept to write files as the user
	scope   string    // "" = everything (administrators)
	expires time.Time
}

func (r *Runner) loadLocal() {
	r.local.sessions = map[string]*restoreSession{}
	if b, err := readSecret(filepath.Join(r.cfg.dir, historyFile)); err == nil {
		json.Unmarshal(b, &r.local.history)
	}
	if b, err := readSecret(filepath.Join(r.cfg.dir, pauseFile)); err == nil {
		json.Unmarshal(b, &r.local.pause)
	}
}

// pausedBy is the Scheduler's pause hook.
func (r *Runner) pausedBy() string {
	_, by := r.pauseInfo()
	return by
}

func (r *Runner) pauseInfo() (until int64, by string) {
	r.local.mu.Lock()
	defer r.local.mu.Unlock()
	if p := r.local.pause; p.Until > time.Now().Unix() {
		return p.Until, p.By
	}
	return 0, ""
}

// pauseAllowed returns when the run of pauses a pause starting at now
// belongs to began, and until when the console's limit lets it last (zero =
// no limit), or why no pause is allowed. Caller holds r.local.mu.
func (r *Runner) pauseAllowed(now time.Time) (since int64, end time.Time, err error) {
	since = r.local.pause.Since
	if since == 0 {
		since = now.Unix()
	}
	switch days := r.local.pauseDays; {
	case days == nil:
		return since, time.Time{}, nil
	case *days <= 0:
		return 0, time.Time{}, errors.New("Your administrator has turned off pausing backups on this PC")
	default:
		end = time.Unix(since, 0).Add(time.Duration(*days) * 24 * time.Hour)
		if !now.Before(end) {
			return 0, time.Time{}, fmt.Errorf("Backups were paused for %s in a row, the most your administrator allows. "+
				"You can pause them again after the next scheduled backup", daysText(*days))
		}
		return since, end, nil
	}
}

func daysText(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

// pause pauses scheduled backups for d, within the console's limit, and
// returns until when.
func (r *Runner) pause(by string, d time.Duration) (time.Time, error) {
	now := time.Now()
	r.local.mu.Lock()
	since, end, err := r.pauseAllowed(now)
	r.local.mu.Unlock()
	if err != nil {
		return time.Time{}, err
	}
	until := now.Add(d)
	if !end.IsZero() && until.After(end) {
		until = end
	}
	return until, r.setPause(pauseState{Until: until.Unix(), By: by, Since: since})
}

// applyPausePolicy follows the console's limit on paused days in a row: a
// pause in effect is cut to what the limit allows (or ends at once with
// pauses off).
func (r *Runner) applyPausePolicy(cfg *api.AgentConfig) {
	var days *int
	if cfg != nil && cfg.PauseDays != nil {
		d := *cfg.PauseDays
		days = &d
	}
	now := time.Now()
	r.local.mu.Lock()
	r.local.pauseDays = days
	p := r.local.pause
	var cut int64
	if p.Until > now.Unix() && days != nil {
		cut = now.Unix()
		if _, end, err := r.pauseAllowed(now); err == nil && !end.IsZero() {
			cut = end.Unix()
		}
	}
	r.local.mu.Unlock()
	if cut > 0 && cut < p.Until {
		p.Until = cut
		if err := r.setPause(p); err != nil {
			r.log.Warn("cannot shorten the tray pause", "err", err)
		}
		r.log.Info("tray pause shortened to the console's limit", "until", time.Unix(cut, 0).Format(time.RFC3339))
	}
}

// pauseStreakOver is called when a scheduled backup starts: pauses after it
// count anew against the console's limit.
func (r *Runner) pauseStreakOver() {
	r.local.mu.Lock()
	p := r.local.pause
	r.local.mu.Unlock()
	if p.Since != 0 && p.Until <= time.Now().Unix() {
		if err := r.setPause(pauseState{}); err != nil {
			r.log.Warn("cannot reset the tray pause count", "err", err)
		}
	}
}

func (r *Runner) setPause(p pauseState) error {
	b, _ := json.Marshal(p)
	r.local.mu.Lock()
	r.local.pause = p
	r.local.mu.Unlock()
	return writeSecret(filepath.Join(r.cfg.dir, pauseFile), b)
}

func (r *Runner) setOnline(v bool) {
	r.local.mu.Lock()
	switch {
	case v && !r.local.online:
		r.local.since = time.Now()
	case !v && r.local.online:
		r.local.drops++
	}
	r.local.online = v
	if v {
		r.local.contact = time.Now()
	}
	r.local.mu.Unlock()
}

// lastContact is the Scheduler's network hook: unlike connection, it can't be
// stale after the PC slept, as only a request that succeeded since sets it.
func (r *Runner) lastContact() time.Time {
	r.local.mu.Lock()
	defer r.local.mu.Unlock()
	return r.local.contact
}

// connection is the Scheduler's connectivity hook.
func (r *Runner) connection() (onlineSince time.Time, drops int) {
	r.local.mu.Lock()
	defer r.local.mu.Unlock()
	if !r.local.online {
		return time.Time{}, r.local.drops
	}
	return r.local.since, r.local.drops
}

// runStarted and runFinished track the run in progress and the history.
func (r *Runner) runStarted(name, kind, trigger string) {
	r.local.mu.Lock()
	r.local.current = &ipc.RunningRun{JobName: name, Kind: kind, Trigger: trigger, Started: time.Now().Unix()}
	r.local.mu.Unlock()
}

func (r *Runner) runEnded() {
	r.local.mu.Lock()
	r.local.current = nil
	r.local.mu.Unlock()
}

func (r *Runner) runProgress(p api.Progress) {
	r.local.mu.Lock()
	if r.local.current != nil {
		r.local.current.Progress = p
	}
	r.local.mu.Unlock()
}

func (r *Runner) recordRun(ri ipc.RunInfo) {
	r.local.mu.Lock()
	r.local.history = append([]ipc.RunInfo{ri}, r.local.history...)
	if len(r.local.history) > historyKeep {
		r.local.history = r.local.history[:historyKeep]
	}
	b, _ := json.Marshal(r.local.history)
	r.local.mu.Unlock()
	if err := writeSecret(filepath.Join(r.cfg.dir, historyFile), b); err != nil {
		r.log.Warn("saving run history", "err", err)
	}
}

// tapReporter shows a run's progress in the tray as well.
type tapReporter struct {
	Reporter
	r *Runner
}

func (t tapReporter) Progress(p api.Progress) {
	t.r.runProgress(p)
	t.Reporter.Progress(p)
}

func (r *Runner) jobName(id int64, kind string) string {
	if j, ok := r.sched.Job(id); ok {
		return j.Name
	}
	if kind == api.KindRestore {
		return "Restore"
	}
	return kind
}

// serveLocal answers the tray app until ctx ends.
func (r *Runner) serveLocal(ctx context.Context) {
	l, err := ipc.Listen(r.cfg.dir)
	if err != nil {
		r.log.Error("tray app channel unavailable", "err", err)
		return
	}
	ipc.Serve(ctx, l, r.handleLocal)
}

func (r *Runner) handleLocal(ctx context.Context, peer *ipc.Peer, req ipc.Request) ipc.Response {
	switch req.Op {
	case ipc.OpStatus:
		return ipc.Response{Status: r.localStatus(peer)}
	case ipc.OpBackupNow:
		n, err := r.backupNow(peer.User)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		return ipc.Response{Message: fmt.Sprintf("%d backup job(s) started", n), Status: r.localStatus(peer)}
	case ipc.OpPause:
		d := time.Duration(req.Minutes) * time.Minute
		if d <= 0 || d > maxPause {
			return ipc.Response{Error: fmt.Sprintf("backups can be paused for up to %s", maxPause)}
		}
		until, err := r.pause(peer.User, d)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		r.log.Info("scheduled backups paused from the tray", "by", peer.User, "until", until.Format(time.RFC3339))
		return ipc.Response{Message: "Scheduled backups are paused until " + until.Format("Mon 15:04"), Status: r.localStatus(peer)}
	case ipc.OpResume:
		r.local.mu.Lock()
		since := r.local.pause.Since // resuming early doesn't reset the limit's count
		r.local.mu.Unlock()
		if err := r.setPause(pauseState{Since: since}); err != nil {
			return ipc.Response{Error: err.Error()}
		}
		r.log.Info("scheduled backups resumed from the tray", "by", peer.User)
		r.sched.Tick() // start catch-ups that waited for the pause
		return ipc.Response{Message: "Scheduled backups resumed", Status: r.localStatus(peer)}
	case ipc.OpRestoreLink:
		u, err := r.restoreLink(ctx, peer)
		if err != nil {
			return ipc.Response{Error: err.Error()}
		}
		return ipc.Response{URL: u}
	}
	return ipc.Response{Error: "unknown operation " + req.Op}
}

func (r *Runner) localStatus(peer *ipc.Peer) *ipc.Status {
	st := &ipc.Status{Version: r.version, Client: r.cfg.ClientName, Server: r.serverURL(), User: peer.User, Admin: peer.Admin,
		Jobs: []ipc.Job{}, Recent: []ipc.RunInfo{}}
	st.Exe, _ = os.Executable()
	st.PausedUntil, st.PausedBy = r.pauseInfo()
	r.local.mu.Lock()
	_, _, perr := r.pauseAllowed(time.Now())
	r.local.mu.Unlock()
	st.PauseOff = perr != nil
	cfg := r.sched.Config()
	next := map[int64]int64{}
	for _, js := range r.sched.States() {
		next[js.JobID] = js.NextRun
		if st.Waiting == "" {
			st.Waiting = js.Waiting
		}
	}
	r.local.mu.Lock()
	defer r.local.mu.Unlock()
	st.Online = r.local.online
	if r.local.current != nil {
		cur := *r.local.current
		st.Running = &cur
	}
	st.Recent = append(st.Recent, r.local.history...)
	if cfg != nil {
		st.Configured = true
		for _, j := range cfg.Jobs {
			lj := ipc.Job{ID: j.ID, Name: j.Name, Kind: j.Kind, NextRun: next[j.ID]}
			for i := range r.local.history {
				if h := r.local.history[i]; h.JobID == j.ID && h.State != api.RunMissed {
					lj.LastRun = &h
					break
				}
			}
			st.Jobs = append(st.Jobs, lj)
		}
	}
	return st
}

// backupNow queues every backup job of this PC (pausing doesn't apply).
func (r *Runner) backupNow(by string) (int, error) {
	cfg := r.sched.Config()
	if cfg == nil || len(cfg.Jobs) == 0 {
		return 0, errors.New("this PC has no backup jobs yet")
	}
	n := 0
	for _, j := range cfg.Jobs {
		if r.queueLocal(task{spec: cfg.Spec(j), job: j, local: true, trigger: api.TriggerManual, slot: time.Now(), by: by}) {
			n++
		}
	}
	if n == 0 {
		return 0, errors.New("the backups are already running")
	}
	r.log.Info("backup started from the tray", "by", by, "jobs", n)
	return n, nil
}

// restoreLink creates a self-service restore page on the console for peer.
// Administrators may restore everything; other users only their profile
// folder, and the agent writes their files with their own rights.
func (r *Runner) restoreLink(ctx context.Context, peer *ipc.Peer) (string, error) {
	kept, err := peer.Keep()
	if err != nil {
		return "", err
	}
	sess := &restoreSession{peer: kept, expires: time.Now().Add(restoreSessTTL)}
	if !peer.Admin {
		if peer.Profile == "" {
			kept.Close()
			return "", errors.New("your profile folder is unknown")
		}
		sess.scope = peer.Profile
	}
	ref := newUUID()
	req := api.RestoreSessionRequest{Ref: ref, User: peer.User, SID: peer.SID, Admin: peer.Admin, Scope: sess.scope, TTL: int64(restoreSessTTL / time.Second)}
	var resp api.RestoreSessionResponse
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	server := r.serverURL()
	if err := postJSON(ctx, r.client(), server+"/agent/v1/restore-sessions", req, &resp); err != nil {
		kept.Close()
		if HTTPStatus(err) != 0 {
			return "", fmt.Errorf("the ProxBackup Console refused the restore page: %w", err)
		}
		return "", fmt.Errorf("the ProxBackup Console is unreachable: %w", err)
	}
	link, err := ipc.CheckRestoreURL(resp.URL, server)
	if err != nil {
		kept.Close()
		return "", err
	}
	r.local.mu.Lock()
	for k, s := range r.local.sessions {
		if time.Now().After(s.expires) {
			s.peer.Close()
			delete(r.local.sessions, k)
		}
	}
	r.local.sessions[ref] = sess
	r.local.mu.Unlock()
	r.log.Info("restore page opened from the tray", "user", peer.User, "admin", peer.Admin)
	return link, nil
}

// restoreAs runs a restore a PC user requested on their restore page. It
// re-checks the request against the user's scope (the agent doesn't rely on
// the console for that) and writes as the user unless they are an administrator.
func (r *Runner) restoreAs(ctx context.Context, spec api.JobSpec, rep Reporter) api.Result {
	rs := spec.Restore
	r.local.mu.Lock()
	sess := r.local.sessions[rs.Session]
	r.local.mu.Unlock()
	if sess == nil || time.Now().After(sess.expires) {
		return api.Result{State: api.RunFailed, Error: `this restore page has expired or the agent restarted since it was opened; choose "Restore files…" in the tray again`}
	}
	origin := r.archiveOrigin(rs.BackupID, rs.Archive)
	if err := api.RestoreAllowed(sess.scope, origin, rs.Paths, rs.TargetDir, strings.HasSuffix(rs.Archive, ".img.fidx")); err != nil {
		return api.Result{State: api.RunFailed, Error: err.Error()}
	}
	// PC administrators may restore into system folders; other users write
	// with their own rights anyway.
	own := *rs
	own.SystemFolders = sess.peer.Admin
	spec.Restore = &own
	if sess.peer.Admin {
		rep.Log("info", fmt.Sprintf("restore requested on the PC by administrator %s", sess.peer.User))
		return Run(ctx, spec, rep)
	}
	rep.Log("info", fmt.Sprintf("restore requested on the PC by %s; files are written with their rights", sess.peer.User))
	var res api.Result
	if err := sess.peer.RunAs(func() error { res = Run(ctx, spec, rep); return nil }); err != nil {
		return api.Result{State: api.RunFailed, Error: err.Error()}
	}
	return res
}

// archiveOrigin is the path on the PC that archive of backupID was backed up
// from, per the current jobs ("" if no job writes it).
func (r *Runner) archiveOrigin(backupID, archive string) string {
	cfg := r.sched.Config()
	if cfg == nil {
		return ""
	}
	if label, ok := strings.CutSuffix(archive, ".ppxar.didx"); ok {
		archive = label + ".mpxar.didx"
	}
	for _, j := range cfg.Jobs {
		if j.BackupID != backupID {
			continue
		}
		switch j.Kind {
		case api.KindFiles:
			if src, ok := api.SourceArchives(j.Sources)[archive]; ok {
				return src
			}
		case api.KindImage:
			for _, v := range j.Volumes {
				if api.VolumeArchive(v) == archive {
					return api.OriginPath(v, "")
				}
			}
		}
	}
	return ""
}
