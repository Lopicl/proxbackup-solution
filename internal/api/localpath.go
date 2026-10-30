// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The agent runs as SYSTEM, so opening a UNC path (\\server\share) makes it
// authenticate to that server as the PC's machine account (NTLM relay) and a
// restore there sends the data off the PC. Device paths (\\?\, \\.\) can name
// UNC shares too. Backup sources, volumes and restore targets must therefore
// be absolute paths on a local drive.
var (
	localPathRe   = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	localVolumeRe = regexp.MustCompile(`^[A-Za-z]:[\\/]?$`)
)

// LocalPath reports whether p is an absolute path on a drive: `C:\Users` or `C:/Users`.
func LocalPath(p string) bool { return localPathRe.MatchString(p) }

// LocalVolume reports whether v names a drive: "C:" or `C:\`.
func LocalVolume(v string) bool { return localVolumeRe.MatchString(v) }

// CheckLocalPaths returns an error for the first of paths that isn't a
// LocalPath; what names them in the message ("source", "target folder").
func CheckLocalPaths(what string, paths ...string) error {
	for _, p := range paths {
		if !LocalPath(p) {
			return fmt.Errorf(`%s %s must be a full path on a local drive, like C:\Folder (network paths are not allowed)`, what, QuotePath(p))
		}
	}
	return nil
}

// CheckUnixPaths returns an error for the first of paths that isn't an
// absolute macOS or Linux path.
func CheckUnixPaths(what string, paths ...string) error {
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
			return fmt.Errorf(`%s %s must be a full path, like /Users/alice`, what, QuotePath(p))
		}
	}
	return nil
}

// CheckLocalVolumes returns an error for the first of vols that isn't a
// LocalVolume.
func CheckLocalVolumes(vols ...string) error {
	for _, v := range vols {
		if !LocalVolume(v) {
			return fmt.Errorf(`volume %s must be a drive letter, like C:`, QuotePath(v))
		}
	}
	return nil
}

// QuotePath quotes a Windows path for a message. Unlike %q it leaves
// backslashes alone, so `\\server\share` doesn't read as
// `\\\\server\\share`. Paths with quotes, invalid UTF-8 or unprintable
// characters (such as text direction overrides) are still escaped.
func QuotePath(p string) string {
	if !utf8.ValidString(p) || strings.ContainsFunc(p, func(r rune) bool { return !strconv.IsPrint(r) || r == '"' }) {
		return strconv.Quote(p)
	}
	return `"` + p + `"`
}
