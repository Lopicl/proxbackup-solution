// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

// restartService relies on the service manager (systemd Restart=, launchd KeepAlive).
func restartService() {}
