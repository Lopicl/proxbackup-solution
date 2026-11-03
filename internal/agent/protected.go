// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"strings"

	"proxbackup/internal/api"
)

// agentDataDir is the agent's data directory (set by NewRunner). Restores
// keep out of it like they keep out of the system folders.
var agentDataDir string

// errProtected makes a restore skip what would land in a protected system
// folder: restores run as SYSTEM, so writing there could replace what the PC
// runs. Only console users with the "Restore to system folders" permission
// and PC administrators may (api.RestoreSpec.SystemFolders).
var errProtected = errors.New("protected system folder")

// restoreProtection returns the folders a restore of spec must keep out of.
func restoreProtection(spec *api.RestoreSpec) (protectedFolders, error) {
	if spec.SystemFolders {
		return nil, nil
	}
	return loadProtected()
}

// belowAny reports whether the archive path p is below one of the folders dirs.
func belowAny(dirs []string, p string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}
