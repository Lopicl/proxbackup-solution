// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SecureDataDir creates dir accessible to its owner only, or restricts an
// existing one. A symlink is refused. start (the service starting) also
// deletes leftover temporary files.
func SecureDataDir(dir string, start bool) (removed []RemovedEntry, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("refusing to use %s as the data directory: it is a link or not a directory", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if start {
		filepath.WalkDir(dir, func(p string, de fs.DirEntry, err error) error {
			if err == nil && de.Type().IsRegular() && isTempName(de.Name()) && os.Remove(p) == nil {
				removed = append(removed, RemovedEntry{p, removedTemp})
			}
			return nil
		})
	}
	return removed, nil
}

// PrepareDataDir does nothing here: only root can create the data dir.
func PrepareDataDir(dir string) (aside, why string, err error) {
	return "", "", nil
}

// programData is only used on Windows.
func programData() string { return "" }

func readSecret(p string) ([]byte, error) {
	return os.ReadFile(p)
}
