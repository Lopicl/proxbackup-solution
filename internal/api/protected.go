// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "strings"

// Restores run as SYSTEM and apply the archive's owners and permissions, so
// a restore into a system folder can replace what the PC runs. Console users
// without the "Restore to system folders" permission can't: the console
// refuses targets in the usual locations of these folders, and the agent,
// which knows where they really are, refuses those targets and skips what a
// restore would put in them (RestoreSpec.SystemFolders).

// protectedFolders are the usual locations of the protected folders, below
// any drive letter; "*" matches any folder name. Files in the Default user
// profile are copied into every new account; those in Startup folders run
// when their user signs in.
var protectedFolders = [][]string{
	{"Windows"},
	{"Program Files"},
	{"Program Files (x86)"},
	{"Program Files (Arm)"},
	{"ProgramData"},
	{"Users", "Default"},
	{"Users", "*", "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"},
}

// ProtectedFolder returns the protected system folder the Windows path p is
// in or is, like `C:\Windows`, or "" if none. Folders above one (C:\) aren't
// protected themselves.
func ProtectedFolder(p string) string {
	if !LocalPath(p) {
		return ""
	}
	// Resolve the path like Windows does: "." and ".." segments, and
	// trailing dots and spaces dropped from names.
	var segs []string
	for _, s := range strings.FieldsFunc(p[3:], func(r rune) bool { return r == '\\' || r == '/' }) {
		switch {
		case s == "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
		case strings.TrimRight(s, ". ") != "":
			segs = append(segs, strings.TrimRight(s, ". "))
		}
	}
	for _, f := range protectedFolders {
		if len(segs) < len(f) {
			continue
		}
		match := true
		for i, name := range f {
			match = match && (name == "*" || strings.EqualFold(segs[i], name))
		}
		if match {
			return p[:2] + `\` + strings.Join(segs[:len(f)], `\`)
		}
	}
	return ""
}
