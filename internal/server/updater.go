// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/update"
)

// Automatic updates. The server checks GitHub for new releases every few hours
// and installs the newest one during the update window chosen in the UI. Agents
// follow the server: once the console runs version X, every Windows agent older
// than X is offered X (downloaded from the same release and cached here) and
// replaces itself when idle.
//
// How the console installs itself depends on how it was installed:
//   - deb: the service runs unprivileged, so it only writes a request file; the
//     root unit proxbackup-server-update.service (started by a .path unit)
//     downloads the package from GitHub itself, verifies it and runs dpkg. See
//     ApplyUpdate.
//   - binary: the new binary is downloaded next to the running one, swapped in
//     and the process re-executes itself.

const checkInterval = 6 * time.Hour

// ErrRestart is returned by Run when the server replaced its own binary and
// should be re-executed.
var ErrRestart = errors.New("restart requested after update")

// UpdateSettings are stored under "updates".
type UpdateSettings struct {
	AutoInstall bool          `json:"auto_install"`
	Window      update.Window `json:"window"`
	Prerelease  bool          `json:"prerelease"`
	Agents      bool          `json:"agents"` // offer the console's version to older agents
}

func defaultUpdateSettings() UpdateSettings {
	return UpdateSettings{AutoInstall: true, Agents: true,
		Window: update.Window{Days: []time.Weekday{time.Sunday}, Time: "03:00", Minutes: 60}}
}

// UpdateResult is the outcome of the last install, written by whoever
// installed it (the root helper for deb installs) to updates/result.json.
type UpdateResult struct {
	State string `json:"state"` // "installing" | "success" | "failed"
	From  string `json:"from"`
	To    string `json:"to"`
	Time  int64  `json:"time"`
	Error string `json:"error,omitempty"`
}

// UpdateStatus is shown in the UI.
type UpdateStatus struct {
	Current       string        `json:"current"`
	Mode          string        `json:"mode"` // "deb" | "binary" | "" (can't self-update)
	ModeNote      string        `json:"mode_note,omitempty"`
	Repo          string        `json:"repo"`
	LastCheck     int64         `json:"last_check"`
	CheckError    string        `json:"check_error,omitempty"`
	Latest        string        `json:"latest,omitempty"`
	LatestURL     string        `json:"latest_url,omitempty"`
	LatestNotes   string        `json:"latest_notes,omitempty"`
	PublishedAt   int64         `json:"published_at,omitempty"`
	Available     bool          `json:"available"`
	NextInstall   int64         `json:"next_install,omitempty"`
	Installing    bool          `json:"installing"`
	LastResult    *UpdateResult `json:"last_result,omitempty"`
	AgentVersion  string        `json:"agent_version,omitempty"` // version offered to agents
	AgentArchs    []string      `json:"agent_archs,omitempty"`
	AgentCacheErr string        `json:"agent_cache_error,omitempty"`
}

type agentBinary struct {
	path, sha256 string
	size         int64
}

// updater holds the update state; methods are safe for concurrent use.
type updater struct {
	s      *Server
	gh     *update.Client
	dir    string // <data dir>/updates
	mode   string
	note   string
	mu     sync.Mutex
	status UpdateStatus
	latest *update.Release
	agents map[string]agentBinary // by arch, for s.cfg.Version
	busy   sync.Mutex             // one check/install at a time

	resultMod time.Time
	restart   func()
}

func newUpdater(s *Server) *updater {
	u := &updater{s: s, gh: &update.Client{Repo: s.cfg.UpdateRepo}, dir: filepath.Join(s.cfg.DataDir, "updates"),
		agents: map[string]agentBinary{}}
	switch {
	case !isVersion(s.cfg.Version):
		u.note = "development build: updates are shown but not installed"
	case s.cfg.UpdateMode == "deb":
		u.mode = "deb"
	case runtime.GOOS == "linux":
		u.mode = "binary"
	default:
		u.note = fmt.Sprintf("no release builds for %s/%s; install updates manually", runtime.GOOS, runtime.GOARCH)
	}
	repo := s.cfg.UpdateRepo
	if repo == "" {
		repo = update.DefaultRepo
	}
	u.status = UpdateStatus{Current: s.cfg.Version, Mode: u.mode, ModeNote: u.note, Repo: repo}
	u.readResult()
	return u
}

func isVersion(v string) bool { _, ok := update.ParseVersion(v); return ok }

func (u *updater) settings(ctx context.Context) UpdateSettings {
	us := defaultUpdateSettings()
	u.s.store.Setting(ctx, "updates", &us)
	return us
}

// Status returns a snapshot for the UI.
func (u *updater) Status(ctx context.Context) UpdateStatus {
	us := u.settings(ctx)
	u.readResult()
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.status
	st.Available = update.Newer(st.Latest, st.Current)
	if st.Available && us.AutoInstall && u.mode != "" {
		if slot, ok := us.Window.Slot(time.Now()); ok && slot.Unix() != u.lastSlot(ctx) {
			st.NextInstall = time.Now().Unix()
		} else if n := us.Window.Next(time.Now()); !n.IsZero() {
			st.NextInstall = n.Unix()
		}
	}
	for a := range u.agents {
		st.AgentArchs = append(st.AgentArchs, a)
	}
	if len(st.AgentArchs) > 0 {
		st.AgentVersion = u.s.cfg.Version
	}
	return st
}

func (u *updater) lastSlot(ctx context.Context) int64 {
	var st struct {
		LastSlot int64 `json:"last_slot"`
	}
	u.s.store.Setting(ctx, "update_state", &st)
	return st.LastSlot
}

// loop checks for releases periodically and installs during the window.
func (u *updater) loop(ctx context.Context) {
	select {
	case <-time.After(30 * time.Second): // let the server settle first
	case <-ctx.Done():
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		u.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (u *updater) tick(ctx context.Context) {
	u.readResult()
	u.mu.Lock()
	stale := time.Since(time.Unix(u.status.LastCheck, 0)) > checkInterval
	u.mu.Unlock()
	if stale {
		u.Check(ctx)
	}
	us := u.settings(ctx)
	if !us.AutoInstall || u.mode == "" {
		return
	}
	slot, ok := us.Window.Slot(time.Now())
	if !ok || slot.Unix() == u.lastSlot(ctx) {
		return
	}
	u.mu.Lock()
	latest, avail := u.status.Latest, update.Newer(u.status.Latest, u.status.Current)
	u.mu.Unlock()
	if !avail {
		return
	}
	// One attempt per window: a failed install is retried in the next window
	// (or with "Install now"), not every minute.
	u.s.store.SetSetting(ctx, "update_state", map[string]int64{"last_slot": slot.Unix()})
	u.s.log.Info("update window open, installing", "from", u.s.cfg.Version, "to", latest)
	if err := u.Install(ctx); err != nil {
		u.s.log.Error("automatic update failed", "err", err)
	}
}

// Check looks for the newest release and refreshes the agent binary cache.
func (u *updater) Check(ctx context.Context) error {
	u.busy.Lock()
	defer u.busy.Unlock()
	us := u.settings(ctx)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	r, err := u.gh.Latest(ctx, us.Prerelease)
	u.mu.Lock()
	u.status.LastCheck = time.Now().Unix()
	u.status.CheckError = ""
	if err != nil {
		u.status.CheckError = err.Error()
	} else if r != nil {
		v, _ := r.Version()
		u.latest = r
		u.status.Latest, u.status.LatestURL, u.status.PublishedAt = v, r.HTMLURL, r.PublishedAt.Unix()
		u.status.LatestNotes = r.Body
		if len(u.status.LatestNotes) > 4000 {
			u.status.LatestNotes = u.status.LatestNotes[:4000] + "…"
		}
	} else {
		u.latest = nil
		u.status.Latest, u.status.LatestURL, u.status.LatestNotes, u.status.PublishedAt = "", "", "", 0
	}
	u.mu.Unlock()
	if err != nil {
		u.s.log.Warn("update check failed", "err", err)
		return err
	}
	if us.Agents {
		u.cacheAgents(ctx)
	}
	return nil
}

// cacheAgents downloads the Windows agents of the console's own release, so
// agents can be brought to the console's version.
func (u *updater) cacheAgents(ctx context.Context) {
	v := u.s.cfg.Version
	if !isVersion(v) {
		return
	}
	u.mu.Lock()
	have := len(u.agents) == 2
	u.mu.Unlock()
	if have {
		return
	}
	err := func() error {
		r, err := u.gh.ByVersion(ctx, v)
		if err != nil {
			return err
		}
		sums, err := u.gh.Sums(ctx, r)
		if err != nil {
			return err
		}
		dir := filepath.Join(u.dir, "agent", v)
		var errs []error
		for _, arch := range []string{"amd64", "arm64"} {
			p, sum, err := u.gh.Download(ctx, r, sums, update.AgentAsset(arch), dir)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			fi, err := os.Stat(p)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			u.mu.Lock()
			u.agents[arch] = agentBinary{path: p, sha256: sum, size: fi.Size()}
			u.mu.Unlock()
		}
		// Drop agents cached for other versions.
		if entries, err := os.ReadDir(filepath.Join(u.dir, "agent")); err == nil {
			for _, e := range entries {
				if e.Name() != v {
					os.RemoveAll(filepath.Join(u.dir, "agent", e.Name()))
				}
			}
		}
		return errors.Join(errs...)
	}()
	u.mu.Lock()
	u.status.AgentCacheErr = ""
	if err != nil {
		u.status.AgentCacheErr = err.Error()
	}
	u.mu.Unlock()
	if err != nil {
		u.s.log.Warn("could not cache agent binaries for automatic agent updates", "version", v, "err", err)
	}
}

// agentOffer returns the update to offer an agent that reported os ("windows/amd64")
// and version, or nil.
func (u *updater) agentOffer(ctx context.Context, osArch, version string) *api.AgentUpdate {
	goos, arch, _ := strings.Cut(osArch, "/")
	if goos != "windows" || !update.Newer(u.s.cfg.Version, version) || !u.settings(ctx).Agents {
		return nil
	}
	u.mu.Lock()
	b, ok := u.agents[arch]
	u.mu.Unlock()
	if !ok {
		return nil
	}
	return &api.AgentUpdate{Version: u.s.cfg.Version, URL: "/agent/v1/update/windows-" + arch, SHA256: b.sha256, Size: b.size}
}

func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request, c *Client) {
	goos, arch, _ := strings.Cut(r.PathValue("platform"), "-")
	s.updater.mu.Lock()
	b, ok := s.updater.agents[arch]
	s.updater.mu.Unlock()
	if goos != "windows" || !ok {
		httpError(w, http.StatusNotFound, errors.New("no agent update available"))
		return
	}
	f, err := os.Open(b.path)
	if err != nil {
		httpError(w, http.StatusNotFound, err)
		return
	}
	defer f.Close()
	s.log.Info("agent downloading update", "client", c.Name, "version", s.cfg.Version, "arch", arch)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Checksum-Sha256", b.sha256)
	http.ServeContent(w, r, "", time.Time{}, f)
}

// Install installs the newest release found by the last check.
func (u *updater) Install(ctx context.Context) error {
	u.busy.Lock()
	defer u.busy.Unlock()
	u.mu.Lock()
	r, latest, installing := u.latest, u.status.Latest, u.status.Installing
	u.mu.Unlock()
	switch {
	case u.mode == "":
		return errors.New(u.note)
	case r == nil || !update.Newer(latest, u.s.cfg.Version):
		return errors.New("no newer release available")
	case installing:
		return errors.New("an update is already being installed")
	}
	if err := os.MkdirAll(u.dir, 0o700); err != nil {
		return err
	}
	var err error
	if u.mode == "deb" {
		err = u.requestDebInstall(latest)
	} else {
		err = u.installBinary(ctx, r, latest)
	}
	if err != nil {
		u.writeResult(UpdateResult{State: "failed", From: u.s.cfg.Version, To: latest, Time: now(), Error: err.Error()})
		u.s.notify.Update(ctx, u.s.cfg.Version, latest, err)
	}
	return err
}

// requestDebInstall hands the install to the root helper (see ApplyUpdate).
func (u *updater) requestDebInstall(version string) error {
	b, _ := json.Marshal(updateRequest{Version: version})
	tmp := filepath.Join(u.dir, "request.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(u.dir, updateRequestFile)); err != nil {
		return err
	}
	u.writeResult(UpdateResult{State: "installing", From: u.s.cfg.Version, To: version, Time: now()})
	u.s.log.Info("update requested from the system updater", "version", version)
	return nil
}

// installBinary replaces the running binary and asks Run to re-execute.
func (u *updater) installBinary(ctx context.Context, r *update.Release, version string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	u.writeResult(UpdateResult{State: "installing", From: u.s.cfg.Version, To: version, Time: now()})
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	sums, err := u.gh.Sums(ctx, r)
	if err != nil {
		return err
	}
	p, _, err := u.gh.Download(ctx, r, sums, update.ServerAsset(runtime.GOOS, runtime.GOARCH), u.dir)
	if err != nil {
		return err
	}
	if err := os.Chmod(p, 0o755); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, p, "version").Output()
	if got := strings.TrimSpace(string(out)); err != nil || got != version {
		return fmt.Errorf("downloaded binary reports version %q (%v), want %s", got, err, version)
	}
	// Rename within the executable's directory so the swap is atomic.
	next := exe + ".new"
	if err := copyFile(p, next, 0o755); err != nil {
		return fmt.Errorf("cannot write next to %s (install updates manually or use the .deb): %w", exe, err)
	}
	if err := os.Rename(next, exe); err != nil {
		os.Remove(next)
		return err
	}
	os.Remove(p)
	u.writeResult(UpdateResult{State: "success", From: u.s.cfg.Version, To: version, Time: now()})
	u.s.log.Info("server binary updated, restarting", "from", u.s.cfg.Version, "to", version)
	u.s.notify.Update(ctx, u.s.cfg.Version, version, nil)
	if u.restart != nil {
		u.restart()
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

func (u *updater) writeResult(res UpdateResult) {
	b, _ := json.Marshal(res)
	os.MkdirAll(u.dir, 0o700)
	os.WriteFile(filepath.Join(u.dir, updateResultFile), b, 0o600)
	u.readResult()
}

// readResult picks up result.json when it changed (it is also written by the
// root helper, possibly while this process runs).
func (u *updater) readResult() {
	p := filepath.Join(u.dir, updateResultFile)
	fi, err := os.Stat(p)
	if err != nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if fi.ModTime().Equal(u.resultMod) {
		return
	}
	var res UpdateResult
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &res) != nil {
		return
	}
	first := u.resultMod.IsZero()
	u.resultMod = fi.ModTime()
	// An "installing" result from a helper that died long ago isn't news.
	if res.State == "installing" && time.Since(time.Unix(res.Time, 0)) > time.Hour {
		res.State, res.Error = "failed", "the update did not complete (see journalctl -u proxbackup-server-update)"
	}
	// We are running the version that was being installed: it worked, whatever
	// the helper managed to write before dpkg restarted us.
	if res.State == "installing" && res.To == u.s.cfg.Version {
		res.State = "success"
	}
	u.status.LastResult = &res
	u.status.Installing = res.State == "installing"
	if !first && res.State != "installing" {
		go u.s.notify.Update(context.Background(), res.From, res.To, resultErr(res))
	}
}

func resultErr(r UpdateResult) error {
	if r.State == "failed" {
		return errors.New(r.Error)
	}
	return nil
}

// ---- admin API ----

type updatesView struct {
	Settings UpdateSettings `json:"settings"`
	Status   UpdateStatus   `json:"status"`
}

func (s *Server) handleGetUpdates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, updatesView{Settings: s.updater.settings(r.Context()), Status: s.updater.Status(r.Context())})
}

func (s *Server) handleSaveUpdates(w http.ResponseWriter, r *http.Request) {
	var us UpdateSettings
	if err := decodeJSON(r, &us); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if us.Window.Days == nil {
		us.Window.Days = []time.Weekday{}
	}
	if us.Window.Minutes == 0 {
		us.Window.Minutes = 60
	}
	if err := us.Window.Validate(); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	old := s.updater.settings(r.Context())
	if err := s.store.SetSetting(r.Context(), "updates", us); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if us.Prerelease != old.Prerelease || (us.Agents && !old.Agents) {
		s.updater.Check(r.Context())
	}
	s.handleGetUpdates(w, r)
}

func (s *Server) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	if err := s.updater.Check(r.Context()); err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	s.handleGetUpdates(w, r)
}

func (s *Server) handleInstallUpdate(w http.ResponseWriter, r *http.Request) {
	if err := s.updater.Install(context.WithoutCancel(r.Context())); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	s.handleGetUpdates(w, r)
}
