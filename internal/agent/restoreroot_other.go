// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// restoreRoot is the target folder of a restore. Like on Windows, symbolic
// links below it are not followed; development builds check each folder
// with Lstat, which unlike the Windows handles is open to races.
type restoreRoot struct{ path string }

// restoreEntry is a file or folder below a restoreRoot. Entries from Create
// are new files under a temporary name until Commit.
type restoreEntry struct {
	f         *os.File
	path, tmp string
}

func openRestoreRoot(dir string) (*restoreRoot, error) {
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(dir); err != nil {
		return nil, err
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("target folder: %s is a symbolic link or not a folder", dir)
	}
	return &restoreRoot{dir}, nil
}

func (r *restoreRoot) Close() error { return nil }

// dir returns the path of the folder rel, creating missing folders with create.
func (r *restoreRoot) dir(rel string, create bool) (string, error) {
	p := r.path
	if rel == "" {
		return p, nil
	}
	done := ""
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		done = filepath.Join(done, name)
		if name == "" || name == "." || name == ".." {
			return "", fmt.Errorf("%s: %w", done, errBadName)
		}
		p = filepath.Join(p, name)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) && create {
			if err = os.Mkdir(p, 0o755); err == nil || errors.Is(err, fs.ErrExist) {
				fi, err = os.Lstat(p)
			}
		}
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("%s: %w", done, errNotFollowed)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("%s: not a folder", done)
		}
	}
	return p, nil
}

func (r *restoreRoot) MkdirAll(rel string) error {
	_, err := r.dir(rel, true)
	return err
}

func (r *restoreRoot) entry(rel string, create bool) (string, error) {
	parent, name := filepath.Split(rel)
	d, err := r.dir(strings.TrimSuffix(parent, string(filepath.Separator)), create)
	return filepath.Join(d, name), err
}

func (r *restoreRoot) Lstat(rel string) (time.Time, error) {
	p, err := r.entry(rel, false)
	if err != nil {
		return time.Time{}, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

func (r *restoreRoot) Open(rel string) (*restoreEntry, error) {
	p, err := r.entry(rel, false)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(p); err != nil {
		return nil, err
	}
	return &restoreEntry{path: p}, nil
}

func (r *restoreRoot) Create(rel string) (*restoreEntry, error) {
	p, err := r.entry(rel, true)
	if err != nil {
		return nil, err
	}
	tmp := fmt.Sprintf("%s.proxbackup-restore-%08x", p, rand.Uint32())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	return &restoreEntry{f: f, path: p, tmp: tmp}, nil
}

func (r *restoreRoot) Symlink(rel, target string) error {
	p, err := r.entry(rel, true)
	if err != nil {
		return err
	}
	return os.Symlink(target, p)
}

func (e *restoreEntry) Write(b []byte) (int, error) { return e.f.Write(b) }

func (e *restoreEntry) Close() error {
	if e.f == nil {
		return nil
	}
	return e.f.Close()
}

func (e *restoreEntry) Commit() error {
	err := e.f.Close()
	if err == nil {
		err = os.Rename(e.tmp, e.path)
	}
	if err != nil {
		os.Remove(e.tmp)
	}
	return err
}

func (e *restoreEntry) Discard() {
	e.f.Close()
	os.Remove(e.tmp)
}

// Development builds don't restore NTFS security descriptors or streams.
func (e *restoreEntry) WriteStreams(ntExtras) error { return nil }
func (e *restoreEntry) SetSecurity(ntExtras) error  { return nil }

func (e *restoreEntry) SetMeta(mtime time.Time, attrs uint32, hasAttrs bool, ctime time.Time) error {
	p := e.path
	if e.tmp != "" {
		p = e.tmp
	}
	return applyMeta(p, mtime, attrs, hasAttrs, ctime)
}
