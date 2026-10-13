package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxbackup/internal/api"
)

// Self-update: the server offers a newer agent in the poll response (see
// api.AgentUpdate). When no job is running, the agent downloads it over the
// mTLS connection, verifies size, SHA-256 and the version the binary reports,
// swaps it in next to the running executable and exits; the service manager
// restarts it (recovery action "restart", plus an explicit start on Windows).

// maybeUpdate starts installing an offered update unless one is in progress,
// recently failed, or the agent is busy.
func (r *Runner) maybeUpdate(ctx context.Context, u *api.AgentUpdate) {
	if u.Version == r.version || runtime.GOOS != "windows" {
		return
	}
	r.mu.Lock()
	if r.updating || (r.updateFailed == u.Version && time.Since(r.updateFailedAt) < time.Hour) || r.busyLocked() {
		r.mu.Unlock()
		return
	}
	r.updating = true
	r.mu.Unlock()
	ctx = context.WithoutCancel(ctx) // the poll's context ends long before a download does
	go func() {
		err := r.selfUpdate(ctx, u)
		r.mu.Lock()
		r.updating = false
		if err != nil {
			r.updateFailed, r.updateFailedAt = u.Version, time.Now()
		}
		r.mu.Unlock()
		if err != nil {
			r.log.Error("agent update failed; retrying in an hour", "version", u.Version, "err", err)
		}
	}()
}

func (r *Runner) busyLocked() bool {
	return len(r.running) > 0 || len(r.inflight) > 0 || len(r.queue) > 0
}

func (r *Runner) selfUpdate(ctx context.Context, u *api.AgentUpdate) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	r.log.Info("updating agent", "from", r.version, "to", u.Version)
	// Download next to the executable so the final rename stays on one volume.
	next := exe + ".new"
	if err := r.download(ctx, u, next); err != nil {
		os.Remove(next)
		return err
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	out, err := exec.CommandContext(vctx, next, "version").Output()
	cancel()
	if got := strings.TrimSpace(string(out)); err != nil || got != u.Version {
		os.Remove(next)
		return fmt.Errorf("downloaded agent reports version %q (%v), want %s", got, err, u.Version)
	}
	// A running .exe can be renamed but not overwritten on Windows.
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		os.Rename(old, exe)
		os.Remove(next)
		return err
	}
	// Let a job that started meanwhile finish before restarting.
	for {
		r.mu.Lock()
		busy := r.busyLocked()
		r.mu.Unlock()
		if !busy {
			break
		}
		time.Sleep(10 * time.Second)
	}
	r.log.Info("agent updated, restarting", "version", u.Version)
	restartService()
	os.Exit(3) // non-zero: the service manager's recovery action restarts us
	return nil
}

func (r *Runner) download(ctx context.Context, u *api.AgentUpdate, dst string) error {
	if !strings.HasPrefix(u.URL, "/agent/") {
		return fmt.Errorf("unexpected update URL %q", u.URL)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.ServerURL+u.URL, nil)
	if err != nil {
		return err
	}
	// The poll client's timeout is too short for a download.
	hc := &http.Client{Transport: r.hc.Transport}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, u.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != u.Size {
		return fmt.Errorf("download: got %d bytes, want %d", n, u.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, u.SHA256) {
		return fmt.Errorf("download: checksum mismatch (got %s, want %s)", got, u.SHA256)
	}
	return nil
}

// cleanupUpdate removes the previous binary left behind by an update.
func cleanupUpdate() {
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
		os.Remove(exe + ".new")
	}
}
