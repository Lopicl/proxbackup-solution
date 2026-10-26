// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import "log/slog"

// elevate is a no-op: run the setup as root.
func elevate() (bool, error) { return false, nil }

// installService installs and starts the service from this executable.
func installService(dataDir string) error {
	log := slog.Default()
	if err := serviceCommand("install", dataDir, log, nil); err != nil {
		return err
	}
	return serviceCommand("start", dataDir, log, nil)
}
