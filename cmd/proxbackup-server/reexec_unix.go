//go:build unix

package main

import (
	"os"
	"syscall"
)

// reexec replaces the process with the (updated) executable, keeping the PID
// so service managers don't notice.
func reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
