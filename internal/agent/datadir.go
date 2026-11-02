// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "strings"

// A RemovedEntry is something SecureDataDir deleted from the data dir.
type RemovedEntry struct {
	Path string
	Why  string // removedLink, removedForeign or removedTemp
}

const (
	removedLink    = "a link"
	removedForeign = "not created by the agent"
	removedTemp    = "a leftover temporary file"
)

// isTempName reports whether name is a temporary file of writeSecret (or of
// older agents, which reused <name>.tmp).
func isTempName(name string) bool {
	return len(name) > 4 && strings.EqualFold(name[len(name)-4:], ".tmp")
}
