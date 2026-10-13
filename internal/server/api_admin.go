// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/schedule"
	"proxbackup/pkg/pbs"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clients, err := s.store.Clients(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	runs, _ := s.store.Runs(ctx, RunFilter{Limit: 20})
	active, _ := s.store.Runs(ctx, RunFilter{Active: true, Limit: 100})
	last := s.store.LastSuccess(ctx)
	var online, stale, failedRecent int
	for _, c := range clients {
		if c.Online {
			online++
		}
		if t := last[c.ID]; t == 0 || time.Since(time.Unix(t, 0)) > 3*24*time.Hour {
			stale++
		}
	}
	for _, rn := range runs {
		if rn.State == api.RunFailed || rn.State == api.RunLost {
			failedRecent++
		}
	}
	writeJSON(w, map[string]any{
		"clients": len(clients), "online": online, "stale": stale, "active_runs": len(active),
		"failed_recent": failedRecent, "recent_runs": orEmpty(runs), "active": orEmpty(active),
	})
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ---- targets ----

type targetReq struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
	Datastore   string `json:"datastore"`
	RootNS      string `json:"root_ns"`
	AdminAuthID string `json:"admin_auth_id"`
	AdminSecret string `json:"admin_secret"` // empty on update = keep
	PBSUser     string `json:"pbs_user"`
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.Targets(r.Context())
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, orEmpty(ts))
}

var nsRe = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9._-]*)(/[A-Za-z0-9_][A-Za-z0-9._-]*){0,6}$`)

func (s *Server) handleSaveTarget(w http.ResponseWriter, r *http.Request) {
	var req targetReq
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	t := &Target{}
	if r.PathValue("id") != "" {
		id, err := pathID(r)
		if err != nil {
			httpError(w, 400, err)
			return
		}
		if t, err = s.store.Target(ctx, id); err != nil {
			httpError(w, statusFor(err), err)
			return
		}
	}
	req.RootNS = strings.Trim(req.RootNS, "/")
	if req.PBSUser == "" {
		req.PBSUser = "proxbackup@pbs"
	}
	switch {
	case req.Name == "" || req.Host == "" || req.Datastore == "" || req.AdminAuthID == "":
		httpError(w, 400, errors.New("name, host, datastore and admin token id are required"))
		return
	case !strings.Contains(req.AdminAuthID, "!"):
		httpError(w, 400, errors.New("admin token id must look like user@realm!token"))
		return
	case req.RootNS != "" && !nsRe.MatchString(req.RootNS):
		httpError(w, 400, errors.New("invalid namespace"))
		return
	case t.ID == 0 && req.AdminSecret == "" && s.localSecretFor(req.AdminAuthID) == "":
		httpError(w, 400, errors.New("admin token secret is required"))
		return
	}
	t.Name, t.Host, t.Fingerprint, t.Datastore, t.RootNS, t.AdminAuthID, t.PBSUser =
		req.Name, req.Host, strings.TrimSpace(req.Fingerprint), req.Datastore, req.RootNS, req.AdminAuthID, req.PBSUser
	if req.AdminSecret == "" && t.ID == 0 {
		req.AdminSecret = s.localSecretFor(req.AdminAuthID)
	}
	if t.Fingerprint == "" {
		t.Fingerprint = s.localFingerprintFor(ctx, req.AdminAuthID)
	}
	if req.AdminSecret != "" {
		t.adminSecretEnc = s.sealer.Seal(req.AdminSecret)
	}
	if err := s.store.SaveTarget(ctx, t); err != nil {
		httpError(w, 500, err)
		return
	}
	// Host or fingerprint changes are part of every client's config: push them.
	if cs, err := s.store.Clients(ctx); err == nil {
		for _, c := range cs {
			if c.TargetID == t.ID {
				s.wakeClient(c.ID)
			}
		}
	}
	writeJSON(w, t)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err == nil {
		err = s.store.DeleteTarget(r.Context(), id)
	}
	if err != nil {
		httpError(w, 400, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleTestTarget checks connectivity, credentials and datastore access.
func (s *Server) handleTestTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		targetReq
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if req.AdminSecret == "" && req.ID > 0 {
		if t, err := s.store.Target(ctx, req.ID); err == nil {
			req.AdminSecret, _ = s.sealer.Open(t.adminSecretEnc)
		}
	}
	if req.AdminSecret == "" {
		req.AdminSecret = s.localSecretFor(req.AdminAuthID)
	}
	if strings.TrimSpace(req.Fingerprint) == "" {
		req.Fingerprint = s.localFingerprintFor(ctx, req.AdminAuthID)
	}
	pc, err := pbs.NewClient(pbs.Config{Host: req.Host, Fingerprint: req.Fingerprint, AuthID: req.AdminAuthID, Secret: req.AdminSecret})
	if err != nil {
		httpError(w, 400, err)
		return
	}
	v, err := pc.Version(ctx)
	if err != nil {
		httpError(w, 502, fmt.Errorf("connect: %w", err))
		return
	}
	var stores []struct {
		Store string `json:"store"`
	}
	if err := pc.Call(ctx, http.MethodGet, "admin/datastore", nil, &stores); err != nil {
		httpError(w, 502, fmt.Errorf("list datastores: %w", err))
		return
	}
	found := false
	names := []string{}
	for _, st := range stores {
		names = append(names, st.Store)
		found = found || st.Store == req.Datastore
	}
	writeJSON(w, map[string]any{"version": v["version"], "release": v["release"], "datastores": names, "datastore_found": found})
}

// ---- clients ----

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cs, err := s.store.Clients(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	last := s.store.LastSuccess(ctx)
	for _, c := range cs {
		c.LastSuccess = last[c.ID]
		if cfg, err := s.agentConfig(ctx, c); err == nil {
			c.ConfigSynced = cfg.Rev == c.ConfigRev
		}
		if runs, _ := s.store.Runs(ctx, RunFilter{ClientID: c.ID, Limit: 1}); len(runs) > 0 {
			c.LastRun = runs[0]
		}
	}
	writeJSON(w, orEmpty(cs))
}

func (s *Server) handleClient(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	c, err := s.store.Client(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	c.LastSuccess = s.store.LastSuccess(ctx)[c.ID]
	jobs, _ := s.store.Jobs(ctx, c.ID)
	applyAgentState(c, jobs)
	if cfg, err := s.agentConfig(ctx, c); err == nil {
		c.ConfigSynced = cfg.Rev == c.ConfigRev
	}
	runs, _ := s.store.Runs(ctx, RunFilter{ClientID: c.ID, Limit: 50})
	writeJSON(w, map[string]any{"client": c, "jobs": orEmpty(jobs), "runs": orEmpty(runs)})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	c, err := s.store.Client(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	// Remove the PBS token so the agent can no longer write; existing snapshots stay.
	if t, err := s.store.Target(ctx, c.TargetID); err == nil {
		if pc, err := s.adminClient(t); err == nil {
			if user, name, ok := strings.Cut(c.TokenID, "!"); ok {
				if err := pc.DeleteToken(ctx, user, name); err != nil {
					s.log.Warn("could not delete PBS token", "token", c.TokenID, "err", err)
				}
			}
		}
	}
	if err := s.store.RevokeClient(ctx, id); err != nil {
		httpError(w, 500, err)
		return
	}
	s.wakeClient(id)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	c, err := s.store.Client(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	pc, err := s.adminClient(t)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	snaps, err := pc.ListSnapshots(ctx, t.Datastore, c.Namespace, "", "")
	if err != nil {
		httpError(w, 502, err)
		return
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].BackupTime > snaps[j].BackupTime })
	writeJSON(w, orEmpty(snaps))
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	var req api.RestoreSpec
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	if req.BackupID == "" || req.BackupTime == 0 || req.Archive == "" || req.TargetDir == "" {
		httpError(w, 400, errors.New("backup_id, backup_time, archive and target_dir are required"))
		return
	}
	if !pbs.ValidArchiveName(req.Archive) || strings.HasSuffix(req.Archive, ".blob") {
		httpError(w, 400, errors.New("archive must be a .pxar.didx or .img.fidx archive"))
		return
	}
	switch req.Overwrite {
	case "":
		req.Overwrite = "skip"
	case "skip", "overwrite", "if-newer":
	default:
		httpError(w, 400, errors.New("overwrite must be skip, overwrite or if-newer"))
		return
	}
	ctx := r.Context()
	if _, err := s.store.Client(ctx, id); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	runID, err := s.store.QueueRun(ctx, 0, id, api.KindRestore, "manual", &req)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	s.wakeClient(id)
	writeJSON(w, map[string]int64{"run_id": runID})
}

// ---- enrollments ----

func (s *Server) handleEnrollments(w http.ResponseWriter, r *http.Request) {
	es, err := s.store.Enrollments(r.Context())
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, orEmpty(es))
}

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientName string `json:"client_name"`
		TargetID   int64  `json:"target_id"`
		TTLHours   int    `json:"ttl_hours"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	name := sanitizeClientName(req.ClientName)
	if !clientNameRe.MatchString(name) {
		httpError(w, 400, errors.New("client name must contain letters or digits"))
		return
	}
	if s.store.ClientNameTaken(ctx, name) {
		httpError(w, 400, fmt.Errorf("client %q already exists or is waiting to enroll", name))
		return
	}
	if _, err := s.store.Target(ctx, req.TargetID); err != nil {
		httpError(w, 400, errors.New("unknown target"))
		return
	}
	if req.TTLHours <= 0 || req.TTLHours > 24*30 {
		req.TTLHours = 24
	}
	if s.cfg.PublicURL == "" {
		httpError(w, 400, errors.New("server has no -public-url configured"))
		return
	}
	code := randToken(24)
	tok, _ := json.Marshal(api.EnrollmentToken{URL: s.cfg.PublicURL, Code: code, CAFingerprint: s.pki.CAFingerprint()})
	enc := base64.RawURLEncoding.EncodeToString(tok)
	command := `proxbackup-agent.exe enroll ` + enc + ` && proxbackup-agent.exe install && proxbackup-agent.exe start`
	if err := s.store.CreateEnrollment(ctx, hashToken(code), name, req.TargetID, time.Duration(req.TTLHours)*time.Hour, s.sealer.Seal(command)); err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, map[string]string{"client_name": name, "token": enc, "command": command})
}

// handleEnrollmentCommand shows the command of a pending enrollment again.
func (s *Server) handleEnrollmentCommand(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	enc, err := s.store.PendingEnrollmentCommand(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), errors.New("enrollment not pending (used, expired or created before this was stored)"))
		return
	}
	command, err := s.sealer.Open(enc)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, map[string]string{"command": command})
}

// handleDeleteEnrollment cancels an enrollment no PC has completed yet.
func (s *Server) handleDeleteEnrollment(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	if err := s.store.DeleteEnrollment(r.Context(), id); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ---- jobs ----

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	cid, _ := strconv.ParseInt(r.URL.Query().Get("client_id"), 10, 64)
	jobs, err := s.store.Jobs(r.Context(), cid)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	clients := map[int64]*Client{}
	for _, j := range jobs {
		c := clients[j.ClientID]
		if c == nil {
			if c, err = s.store.Client(r.Context(), j.ClientID); err != nil {
				continue
			}
			clients[j.ClientID] = c
		}
		applyAgentState(c, []*Job{j})
	}
	writeJSON(w, orEmpty(jobs))
}

var backupIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

func (s *Server) handleSaveJob(w http.ResponseWriter, r *http.Request) {
	var j Job
	if err := decodeJSON(r, &j); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	if r.PathValue("id") != "" {
		id, err := pathID(r)
		if err != nil {
			httpError(w, 400, err)
			return
		}
		old, err := s.store.Job(ctx, id)
		if err != nil {
			httpError(w, statusFor(err), err)
			return
		}
		j.ID, j.ClientID = id, old.ClientID
	}
	c, err := s.store.Client(ctx, j.ClientID)
	if err != nil || c.Revoked {
		httpError(w, 400, errors.New("unknown client"))
		return
	}
	j.Sources, j.Excludes, j.Volumes = cleanList(j.Sources), cleanList(j.Excludes), cleanList(j.Volumes)
	if j.BackupID == "" {
		j.BackupID = c.Name
		if j.Kind == api.KindImage {
			j.BackupID = c.Name + "-image"
		}
	}
	switch {
	case j.Name == "":
		err = errors.New("name is required")
	case j.Kind != api.KindFiles && j.Kind != api.KindImage:
		err = errors.New("kind must be files or image")
	case j.Kind == api.KindFiles && len(j.Sources) == 0:
		err = errors.New("at least one source path is required")
	case j.Kind == api.KindImage && len(j.Volumes) == 0:
		err = errors.New("at least one volume is required")
	case !backupIDRe.MatchString(j.BackupID):
		err = errors.New("invalid backup id")
	case j.Schedule != "":
		err = schedule.Validate(j.Schedule)
	}
	if j.WindowMinutes <= 0 {
		j.WindowMinutes = 60
	}
	if err == nil && j.WindowMinutes > 7*24*60 {
		err = errors.New("start window must be at most 7 days")
	}
	if err != nil {
		httpError(w, 400, err)
		return
	}
	if err := s.store.SaveJob(ctx, &j); err != nil {
		httpError(w, 500, err)
		return
	}
	s.wakeClient(j.ClientID) // push the new configuration right away
	writeJSON(w, j)
}

func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	j, err := s.store.Job(r.Context(), id)
	if err == nil {
		err = s.store.DeleteJob(r.Context(), id)
	}
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	s.wakeClient(j.ClientID)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRunJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	runID, err := s.queueJob(r.Context(), id, "manual")
	if err != nil {
		httpError(w, 400, err)
		return
	}
	writeJSON(w, map[string]int64{"run_id": runID})
}

func (s *Server) queueJob(ctx context.Context, jobID int64, trigger string) (int64, error) {
	j, err := s.store.Job(ctx, jobID)
	if err != nil {
		return 0, err
	}
	runID, err := s.store.QueueRun(ctx, j.ID, j.ClientID, j.Kind, trigger, nil)
	if err != nil {
		return 0, err
	}
	s.wakeClient(j.ClientID)
	return runID, nil
}

// ---- runs ----

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := RunFilter{Active: q.Get("active") == "1"}
	f.ClientID, _ = strconv.ParseInt(q.Get("client_id"), 10, 64)
	f.JobID, _ = strconv.ParseInt(q.Get("job_id"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	runs, err := s.store.Runs(r.Context(), f)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, orEmpty(runs))
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	run, err := s.store.Run(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, run)
}

func (s *Server) handleRunLogs(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	logs, err := s.store.Logs(r.Context(), id, after)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, orEmpty(logs))
}

func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	run, err := s.store.Run(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	if err := s.store.RequestCancel(ctx, id); err != nil {
		httpError(w, 500, err)
		return
	}
	s.wakeClient(run.ClientID)
	writeJSON(w, map[string]bool{"ok": true})
}
