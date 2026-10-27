// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

// RestartService relies on the service manager (systemd Restart=, launchd KeepAlive).
func RestartService() {}
