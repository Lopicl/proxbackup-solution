// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"fmt"
	"regexp"
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
			return fmt.Errorf(`%s %q must be a full path on a local drive, like C:\Folder (network paths are not allowed)`, what, p)
		}
	}
	return nil
}

// CheckLocalVolumes returns an error for the first of vols that isn't a
// LocalVolume.
func CheckLocalVolumes(vols ...string) error {
	for _, v := range vols {
		if !LocalVolume(v) {
			return fmt.Errorf(`volume %q must be a drive letter, like C:`, v)
		}
	}
	return nil
}
