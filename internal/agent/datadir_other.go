// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import (
	"fmt"
	"os"
)

// SecureDataDir creates dir accessible to its owner only, or restricts an
// existing one. A symlink is refused.
func SecureDataDir(dir string) (removed []string, err error) {
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
	return nil, os.Chmod(dir, 0o700)
}
