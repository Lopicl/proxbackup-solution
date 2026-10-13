// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import (
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Non-Windows builds exist for development and CI; they map dot-files to HIDDEN.
func statMeta(fi fs.FileInfo) winMeta {
	m := winMeta{mtime: fi.ModTime()}
	if strings.HasPrefix(fi.Name(), ".") {
		m.attrs |= attrHidden
	}
	if !fi.IsDir() && fi.Mode().Perm()&0o222 == 0 {
		m.attrs |= attrReadonly
	}
	return m
}

func applyMeta(p string, mtime time.Time, attrs uint32, _ bool, _ time.Time) error {
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		// Set the link's own times; Chtimes would follow it to the target.
		ts := []unix.Timespec{unix.NsecToTimespec(mtime.UnixNano()), unix.NsecToTimespec(mtime.UnixNano())}
		return unix.UtimesNanoAt(unix.AT_FDCWD, p, ts, unix.AT_SYMLINK_NOFOLLOW)
	}
	if attrs&attrReadonly != 0 {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
			os.Chmod(p, fi.Mode().Perm()&^0o222)
		}
	}
	return os.Chtimes(p, mtime, mtime)
}
