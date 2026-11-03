// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

// protectedFolders is empty here: other platforms only run tests and
// development builds.
type protectedFolders map[string]string

func loadProtected() (protectedFolders, error) { return nil, nil }
