// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

import "time"

// keepAwake is a no-op on non-Windows platforms.
func keepAwake(reason string) (release func(), err error) { return func() {}, nil }

// setWakeTimer is a no-op on non-Windows platforms.
func setWakeTimer(t time.Time) error { return nil }
