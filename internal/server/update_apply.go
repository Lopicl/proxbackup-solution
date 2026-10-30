// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"proxbackup/internal/update"
)

const (
	updateRequestFile = "request"
	updateResultFile  = "result.json"
)

type updateRequest struct {
	Version string `json:"version"`
}

// ApplyUpdate is the root side of deb updates (proxbackup-server apply-update,
// run by proxbackup-server-update.service when the console writes a request).
//
// It trusts the unprivileged console only to name a version: the package is
// downloaded from the configured GitHub repository into a root-owned cache,
// checked against the release's SHA256SUMS and must be newer than the
// installed version, so a compromised console cannot get arbitrary code run
// as root or force a downgrade.
func ApplyUpdate(ctx context.Context, installed, dataDir, cacheDir, repo string, log *slog.Logger) error {
	dir, err := openHelperDir(dataDir, "updates")
	if err != nil {
		return err
	}
	if dir == nil {
		log.Info("no update requested")
		return nil
	}
	defer dir.Close()
	b, found, err := readHelperRequest(dir)
	if !found && err == nil {
		log.Info("no update requested")
		return nil
	}
	var req updateRequest
	if err != nil || json.Unmarshal(b, &req) != nil || !isVersion(req.Version) {
		return errors.New("invalid update request")
	}
	res := UpdateResult{State: "installing", From: installed, To: req.Version, Time: time.Now().Unix()}
	writeHelperResult(dir, res, log)
	err = applyDeb(ctx, installed, req.Version, cacheDir, repo, log)
	res.Time = time.Now().Unix()
	if err != nil {
		res.State, res.Error = "failed", err.Error()
		log.Error("update failed", "version", req.Version, "err", err)
	} else {
		res.State = "success"
		log.Info("update installed", "from", installed, "to", req.Version)
	}
	writeHelperResult(dir, res, log)
	return err
}

// openHelperDir opens dataDir/sub, nil if it doesn't exist. Both belong to
// the service user and the root helpers run as root, so every file operation
// goes through the returned root: the service user can't redirect them
// elsewhere by swapping in a symlink, not even between a check and the use.
func openHelperDir(dataDir, sub string) (*os.Root, error) {
	data, err := os.OpenRoot(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer data.Close()
	name := filepath.Join(dataDir, sub)
	fi, err := data.Lstat(sub)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (%s); refusing to use it", name, fi.Mode().Type())
	}
	// A symlink swapped in now can only point within dataDir, and is caught
	// here: the directory we opened must be the one checked above.
	dir, err := data.OpenRoot(sub)
	if err != nil {
		return nil, err
	}
	if opened, err := dir.Stat("."); err != nil || !os.SameFile(fi, opened) {
		dir.Close()
		return nil, fmt.Errorf("%s changed while it was opened; refusing to use it", name)
	}
	return dir, nil
}

func applyDeb(ctx context.Context, installed, version, cacheDir, repo string, log *slog.Logger) error {
	if !update.Newer(version, installed) {
		return fmt.Errorf("refusing to install %q: not newer than the installed %s", version, installed)
	}
	gh := &update.Client{Repo: repo}
	dlCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	r, err := gh.ByVersion(dlCtx, version)
	if err != nil {
		return err
	}
	sums, err := gh.Sums(dlCtx, r)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	log.Info("downloading update", "version", version, "repo", gh.Repo)
	deb, _, err := gh.Download(dlCtx, r, sums, update.DebAsset(version, runtime.GOARCH), cacheDir)
	if err != nil {
		return err
	}
	defer os.Remove(deb)
	// dpkg restarts proxbackup-server from the package's postinst. Retry while
	// another package manager holds the dpkg lock.
	for attempt := 1; ; attempt++ {
		cmd := exec.CommandContext(ctx, "dpkg", "--force-confold", "-i", deb)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		out, err := cmd.CombinedOutput()
		if err == nil {
			log.Info("dpkg finished", "output", strings.TrimSpace(string(out)))
			return nil
		}
		msg := strings.TrimSpace(string(out))
		if !strings.Contains(msg, "lock") || attempt >= 10 {
			return fmt.Errorf("dpkg -i %s: %v: %s", filepath.Base(deb), err, msg)
		}
		log.Warn("dpkg is locked, retrying", "attempt", attempt)
		select {
		case <-time.After(30 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func writeHelperResult(dir *os.Root, res UpdateResult, log *slog.Logger) {
	b, _ := json.Marshal(res)
	if err := writeHelperFile(dir, updateResultFile, b); err != nil {
		log.Warn("cannot write update result", "err", err)
	}
}

// readHelperRequest reads and removes the console's request in dir: one
// attempt per request, as the .path unit would retrigger otherwise. found is
// false when there is none; b is nil for anything but a small regular file.
func readHelperRequest(dir *os.Root) (b []byte, found bool, err error) {
	fi, err := dir.Lstat(updateRequestFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if fi.Mode().IsRegular() && fi.Size() < 1<<20 {
		b, err = dir.ReadFile(updateRequestFile)
	}
	dir.Remove(updateRequestFile)
	return b, true, err
}

// writeHelperFile writes name owned by the service user, so the console can
// read it. We run as root in a directory the service user owns, so never
// follow a planted symlink: create the file exclusively and chown the open
// descriptor.
func writeHelperFile(dir *os.Root, name string, b []byte) error {
	tmp := name + ".tmp"
	dir.Remove(tmp)
	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if u, err := user.Lookup("proxbackup"); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		f.Chown(uid, gid)
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return dir.Rename(tmp, name)
}
