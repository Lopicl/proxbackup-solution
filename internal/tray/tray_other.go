// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package tray

import (
	"fmt"
	"os"

	"proxbackup/internal/ipc"
)

// Run: the tray app is Windows-only.
func Run(string, string, bool) int {
	fmt.Fprintln(os.Stderr, "the tray app runs on Windows only")
	return ipc.TrayExitQuit
}
