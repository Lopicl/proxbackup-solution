// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "proxbackup/internal/api"

// conditions are the PC's power and network state that jobs can wait for
// (api.JobConfig.OnBattery, OnMetered).
type conditions struct {
	Battery bool // running on battery power
	Metered bool // the internet connection is metered (or roaming, over its data limit)
}

// Reasons a scheduled run waits, as shown in logs, the tray and the console.
const (
	reasonBattery = "on battery power"
	reasonMetered = "on a metered network"
)

// blockedBy reports why job j may not run under c ("" = it may), and whether
// a run in progress has to stop as well.
func (c conditions) blockedBy(j api.JobConfig) (reason string, stop bool) {
	if c.Battery && j.OnBattery != api.PolicyRun {
		reason, stop = reasonBattery, j.OnBattery == api.PolicyStop
	}
	if c.Metered && j.OnMetered != api.PolicyRun {
		if reason == "" {
			reason = reasonMetered
		}
		stop = stop || j.OnMetered == api.PolicyStop
	}
	return reason, stop
}
