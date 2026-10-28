// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// RestartService starts the agent service again a few seconds after this
// process exits, in case the service's recovery actions are not configured.
// If recovery already restarted it, the extra start fails harmlessly.
// Programs are run by full path, never looked up in PATH.
func RestartService() {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return
	}
	cmdExe := filepath.Join(sys, "cmd.exe")
	cmd := exec.Command(cmdExe)
	// /s: cmd.exe drops the outer quotes and runs the rest as written.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CmdLine: fmt.Sprintf(`"%s" /s /c ""%s" -n 6 127.0.0.1 >nul & "%s" start proxbackup-agent"`,
			cmdExe, filepath.Join(sys, "PING.EXE"), filepath.Join(sys, "sc.exe")),
		CreationFlags: 0x00000008 | 0x00000200} // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
	cmd.Start()
}
