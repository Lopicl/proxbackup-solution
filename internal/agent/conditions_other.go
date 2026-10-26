// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

// readConditions is a stub on non-Windows platforms: always on mains power
// and an unmetered network.
func readConditions() (conditions, error) { return conditions{}, nil }
