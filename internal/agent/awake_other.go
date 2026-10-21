// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package agent

// keepAwake is a no-op on non-Windows platforms.
func keepAwake(reason string) (release func(), err error) { return func() {}, nil }
