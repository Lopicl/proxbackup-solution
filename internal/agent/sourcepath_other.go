// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import "os"

// sourceGuard checks nothing outside Windows (see sourcepath_windows.go and
// the phase-3 hardening of the macOS and Linux agents).
type sourceGuard struct{}

func (g *sourceGuard) live() bool { return false }

func (g *sourceGuard) checkFile(*os.File, string) error { return nil }
