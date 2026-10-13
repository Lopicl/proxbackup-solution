//go:build !windows

package agent

// restartService relies on the service manager (systemd Restart=, launchd KeepAlive).
func restartService() {}
