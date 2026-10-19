// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"proxbackup/internal/api"
	"proxbackup/internal/schedule"
)

// groupJobView is a group job with its resolved members, for the UI.
type groupJobView struct {
	*GroupJob
	Members []memberView `json:"members"`
}

type memberView struct {
	*Job
	ClientName string `json:"client_name"`
	Online     bool   `json:"online"`
	// Explicit: chosen by name; otherwise only through Tags.
	Explicit bool     `json:"explicit"`
	ViaTags  []string `json:"via_tags"`
	LastRun  *Run     `json:"last_run,omitempty"`
}

func (s *Server) groupViews(ctx context.Context, groups []*GroupJob) ([]groupJobView, error) {
	clients, err := s.store.Clients(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]*Client{}
	for _, c := range clients {
		byID[c.ID] = c
	}
	last, err := s.store.LastRuns(ctx)
	if err != nil {
		return nil, err
	}
	out := []groupJobView{}
	for _, g := range groups {
		jobs, err := s.store.GroupMembers(ctx, g.ID)
		if err != nil {
			return nil, err
		}
		v := groupJobView{GroupJob: g, Members: []memberView{}}
		for _, j := range jobs {
			c := byID[j.ClientID]
			if c == nil {
				continue // revoked
			}
			applyAgentState(c, []*Job{j})
			m := memberView{Job: j, ClientName: c.Name, Online: c.Online, Explicit: slices.Contains(g.Clients, c.ID),
				ViaTags: []string{}, LastRun: last[j.ID]}
			for _, t := range g.Tags {
				if t == AllClientsTag || slices.Contains(c.Tags, t) {
					m.ViaTags = append(m.ViaTags, t)
				}
			}
			v.Members = append(v.Members, m)
		}
		slices.SortFunc(v.Members, func(a, b memberView) int { return cmp.Compare(a.ClientName, b.ClientName) })
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) handleGroupJobs(w http.ResponseWriter, r *http.Request) {
	groups, err := s.store.GroupJobs(r.Context())
	if err != nil {
		httpError(w, 500, err)
		return
	}
	views, err := s.groupViews(r.Context(), groups)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, views)
}

func (s *Server) handleGroupJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	g, err := s.store.GroupJob(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	views, err := s.groupViews(ctx, []*GroupJob{g})
	if err != nil {
		httpError(w, 500, err)
		return
	}
	runs, _ := s.store.Runs(ctx, RunFilter{GroupID: id, Limit: 100})
	writeJSON(w, map[string]any{"job": views[0], "runs": orEmpty(runs)})
}

var backupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// validateGroupJob normalizes g and checks it.
func validateGroupJob(g *GroupJob) error {
	g.Sources, g.Excludes, g.Volumes = cleanList(g.Sources), cleanList(g.Excludes), cleanList(g.Volumes)
	tags := []string{}
	for _, t := range cleanList(g.Tags) {
		if t != AllClientsTag && !tagRe.MatchString(t) {
			return fmt.Errorf("invalid tag %q: use lowercase letters, digits, '.', '_' and '-'", t)
		}
		if !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	g.Tags = tags
	clients := []int64{}
	for _, c := range g.Clients {
		if c > 0 && !slices.Contains(clients, c) {
			clients = append(clients, c)
		}
	}
	g.Clients = clients
	if g.WindowMinutes <= 0 {
		g.WindowMinutes = 60
	}
	switch {
	case g.Name == "":
		return errors.New("name is required")
	case g.Kind != api.KindFiles && g.Kind != api.KindImage:
		return errors.New("kind must be files or image")
	case g.Kind == api.KindFiles && len(g.Sources) == 0:
		return errors.New("at least one source path is required")
	case g.Kind == api.KindImage && len(g.Volumes) == 0:
		return errors.New("at least one volume is required")
	case g.BackupID != "" && !backupIDRe.MatchString(g.BackupID):
		return errors.New("invalid backup id")
	case g.WindowMinutes > 7*24*60:
		return errors.New("start window must be at most 7 days")
	case g.LockDays < 0 || g.LockDays > maxLockDays:
		return fmt.Errorf("lock period must be between 0 and %d days", maxLockDays)
	case g.DailyCap < 0 || g.DailyCap > maxDailyCap:
		return fmt.Errorf("backups per day must be between 0 and %d", maxDailyCap)
	case g.SpreadMinutes < 0 || g.SpreadMinutes > maxSpreadMinutes:
		return fmt.Errorf("start spread must be between 0 and %d minutes", maxSpreadMinutes)
	}
	if g.Schedule != "" {
		if err := schedule.Validate(g.Schedule); err != nil {
			return err
		}
	}
	switch g.ChangeDetection {
	case "":
		g.ChangeDetection = "metadata"
	case "metadata", "data", "legacy":
	default:
		return errors.New("change_detection must be metadata, data or legacy")
	}
	return nil
}

func (s *Server) handleSaveGroupJob(w http.ResponseWriter, r *http.Request) {
	var g GroupJob
	if err := decodeJSON(r, &g); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	g.ID = 0
	if r.PathValue("id") != "" {
		id, err := pathID(r)
		if err != nil {
			httpError(w, 400, err)
			return
		}
		old, err := s.store.GroupJob(ctx, id)
		if err != nil {
			httpError(w, statusFor(err), err)
			return
		}
		if g.Kind != old.Kind {
			httpError(w, 400, errors.New("the type of a job can't be changed"))
			return
		}
		g.ID, g.CreatedAt = id, old.CreatedAt
	}
	if err := validateGroupJob(&g); err != nil {
		httpError(w, 400, err)
		return
	}
	for _, id := range g.Clients {
		if c, err := s.store.Client(ctx, id); err != nil || c.Revoked {
			httpError(w, 400, fmt.Errorf("unknown client %d", id))
			return
		}
	}
	affected, err := s.store.SaveGroupJob(ctx, &g)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	if err := s.membersChanged(ctx, affected); err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, g)
}

// membersChanged creates encryption keys members now need and pushes the new
// configuration to the clients.
func (s *Server) membersChanged(ctx context.Context, clientIDs []int64) error {
	var firstErr error
	for _, id := range clientIDs {
		jobs, err := s.store.Jobs(ctx, id)
		if err == nil && slices.ContainsFunc(jobs, func(j *Job) bool { return j.Encrypt }) {
			var c *Client
			if c, err = s.store.Client(ctx, id); err == nil {
				err = s.ensureClientKey(ctx, c)
			}
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("create encryption key: %w", err)
		}
		s.wakeClient(id)
	}
	return firstErr
}

func (s *Server) handleDeleteGroupJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	affected, err := s.store.DeleteGroupJob(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	for _, c := range affected {
		s.wakeClient(c)
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleRunGroupJob queues a run on every enabled member. Members with a run
// already in progress are skipped.
func (s *Server) handleRunGroupJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	if _, err := s.store.GroupJob(ctx, id); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	jobs, err := s.store.GroupMembers(ctx, id)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	queued, skipped := []int64{}, 0
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		if c, err := s.store.Client(ctx, j.ClientID); err != nil || c.Revoked {
			continue
		}
		runID, err := s.queueJob(ctx, j.ID, api.TriggerManual)
		if err != nil {
			skipped++
			continue
		}
		queued = append(queued, runID)
	}
	if len(queued) == 0 && skipped == 0 {
		httpError(w, 400, errors.New("the job has no enabled members"))
		return
	}
	writeJSON(w, map[string]any{"run_ids": queued, "skipped": skipped})
}

func (s *Server) handleClientTags(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	var req struct {
		Tags []string `json:"tags"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	tags := []string{}
	for _, t := range cleanList(req.Tags) {
		if !tagRe.MatchString(t) {
			httpError(w, 400, fmt.Errorf("invalid tag %q: use lowercase letters, digits, '.', '_' and '-'", t))
			return
		}
		if !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}
	ctx := r.Context()
	affected, err := s.store.SetClientTags(ctx, id, tags)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	if err := s.membersChanged(ctx, appendNew(affected, id)); err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"tags": tags})
}
