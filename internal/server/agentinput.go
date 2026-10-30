// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"unicode/utf8"

	"proxbackup/internal/api"
)

// Agents send strings up to the 4 MiB body limit. Everything the console
// stores from them is cut to these lengths (or refused, where a cut string
// would mean something else), so a compromised PC can't fill the console's
// disk through fields the log caps don't count.
const (
	maxAgentText  = 4000 // a log line, a run's error, the tray app's error
	maxAgentToken = 64   // run UUID, kind, trigger, OS, version, time zone, feature
	maxAgentName  = 256  // host and user names, SIDs, snapshot names, archives
	maxAgentPath  = 1024 // a restore session's profile folder

	maxAgentFeatures = 32   // PollRequest.Features entries
	maxAgentJobState = 1000 // PollRequest.Schedule entries
)

// clip cuts s to at most n bytes (plus "…"), on a UTF-8 boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// logLevel maps an agent's log level to one the console knows; agents only
// send these three.
func logLevel(l string) string {
	switch l {
	case "warn", "error":
		return l
	}
	return "info"
}

// clipPoll cuts the agent's heartbeat to what the console stores of it.
func clipPoll(req *api.PollRequest) {
	req.Hostname, req.OS = clip(req.Hostname, maxAgentName), clip(req.OS, maxAgentToken)
	req.AgentVersion, req.ConfigRev = clip(req.AgentVersion, maxAgentToken), clip(req.ConfigRev, maxAgentToken)
	req.TimeZone, req.PausedBy = clip(req.TimeZone, maxAgentToken), clip(req.PausedBy, maxAgentName)
	req.TrayError = clip(req.TrayError, maxAgentText)
	req.Features = req.Features[:min(len(req.Features), maxAgentFeatures)]
	for i, f := range req.Features {
		req.Features[i] = clip(f, maxAgentToken)
	}
	req.Schedule = req.Schedule[:min(len(req.Schedule), maxAgentJobState)]
	for i := range req.Schedule {
		req.Schedule[i].Waiting = clip(req.Schedule[i].Waiting, maxAgentName)
	}
}

func clipProgress(p *api.Progress) {
	p.Phase, p.CurrentArchive = clip(p.Phase, maxAgentToken), clip(p.CurrentArchive, maxAgentName)
}

func clipResult(r *api.Result) {
	r.Error, r.Snapshot = clip(r.Error, maxAgentText), clip(r.Snapshot, maxAgentName)
}
