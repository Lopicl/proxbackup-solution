// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os/exec"
	"syscall"
)

// RestartService starts the agent service again a few seconds after this
// process exits, in case the service's recovery actions are not configured.
// If recovery already restarted it, the extra start fails harmlessly.
func RestartService() {
	cmd := exec.Command("cmd.exe", "/c", "ping -n 6 127.0.0.1 >nul & sc.exe start proxbackup-agent")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	cmd.Start()
}
