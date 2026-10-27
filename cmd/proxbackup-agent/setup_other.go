// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import "log/slog"

// elevate is a no-op: run the setup as root.
func elevate() (bool, error) { return false, nil }

// installAgent installs the service from this executable.
func installAgent(dataDir string) error {
	return serviceCommand("install", dataDir, slog.Default(), nil)
}

// installService installs and starts the service from this executable.
func installService(dataDir string) error {
	if err := installAgent(dataDir); err != nil {
		return err
	}
	return serviceCommand("start", dataDir, slog.Default(), nil)
}
