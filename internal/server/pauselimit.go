// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"fmt"
	"net/http"
)

// Any interactive user on a PC can pause its scheduled backups from the tray
// app, for up to 24 hours at a time. So the console limits how many days in
// a row pauses may cover, counted from the first one until a scheduled backup
// has started again (the agent enforces it, see api.AgentConfig.PauseDays).
// The limit is a console-wide default that each client can override.

const (
	agentSettingsKey    = "agents"
	defaultPauseDays    = 1
	maxPauseDays        = 365
	noPauseLimit        = -1
	pauseDaysOutOfRange = "the pause limit must be -1 (no limit), 0 (no pauses) or up to 365 days"
)

// AgentSettings are console-wide settings for the agents.
type AgentSettings struct {
	// PauseDays: how many days in a row PC users may pause scheduled backups
	// (-1 = no limit, 0 = no pauses).
	PauseDays int `json:"pause_days"`
}

func validPauseDays(d int) bool { return d >= noPauseLimit && d <= maxPauseDays }

func (s *Server) agentSettings(ctx context.Context) AgentSettings {
	as := AgentSettings{PauseDays: defaultPauseDays}
	if err := s.store.Setting(ctx, agentSettingsKey, &as); err != nil || !validPauseDays(as.PauseDays) {
		as.PauseDays = defaultPauseDays
	}
	return as
}

// pauseDays is the limit pushed to client c's agent (nil = none).
func (s *Server) pauseDays(ctx context.Context, c *Client) *int {
	d := s.agentSettings(ctx).PauseDays
	if c.PauseDays != nil && validPauseDays(*c.PauseDays) {
		d = *c.PauseDays
	}
	if d == noPauseLimit {
		return nil
	}
	return &d
}

func describePauseDays(d int) string {
	switch d {
	case noPauseLimit:
		return "no limit"
	case 0:
		return "no pauses"
	case 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", d)
}

func (s *Server) handleGetAgentSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.agentSettings(r.Context()))
}

func (s *Server) handleSaveAgentSettings(w http.ResponseWriter, r *http.Request) {
	var as AgentSettings
	if err := decodeJSON(r, &as); err != nil {
		httpError(w, 400, err)
		return
	}
	if !validPauseDays(as.PauseDays) {
		httpError(w, 400, fmt.Errorf("%s", pauseDaysOutOfRange))
		return
	}
	ctx := r.Context()
	auditDetail(r, "tray pause limit: %s", describePauseDays(as.PauseDays))
	if err := s.store.SetSetting(ctx, agentSettingsKey, as); err != nil {
		httpError(w, 500, err)
		return
	}
	if cs, err := s.store.Clients(ctx); err == nil {
		for _, c := range cs {
			if c.PauseDays == nil {
				s.wakeClient(c.ID)
			}
		}
	}
	writeJSON(w, as)
}

// handleClientPauseLimit sets client c's own pause limit, or (null) makes it
// follow the console's default.
func (s *Server) handleClientPauseLimit(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermManageClients)
	if !ok {
		return
	}
	var req struct {
		Days *int `json:"days"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	if req.Days != nil && !validPauseDays(*req.Days) {
		httpError(w, 400, fmt.Errorf("%s", pauseDaysOutOfRange))
		return
	}
	auditTarget(r, "client "+c.Name)
	if req.Days == nil {
		auditDetail(r, "tray pause limit: console default")
	} else {
		auditDetail(r, "tray pause limit: %s", describePauseDays(*req.Days))
	}
	if err := s.store.SetClientPauseDays(r.Context(), c.ID, req.Days); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	s.wakeClient(c.ID)
	writeJSON(w, map[string]*int{"days": req.Days})
}

// SetClientPauseDays sets Client.PauseDays (nil = the console's default).
func (s *Store) SetClientPauseDays(ctx context.Context, clientID int64, days *int) error {
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET pause_days=? WHERE id=? AND revoked=0`, days, clientID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}
