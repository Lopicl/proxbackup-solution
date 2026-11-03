// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

func (s *Server) caPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.pki.CA)
	return p
}

func (s *Server) agentRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/enroll", s.handleEnroll)
	mux.Handle("POST /agent/v1/poll", s.requireAgent(s.handlePoll))
	mux.Handle("POST /agent/v1/runs", s.requireAgent(s.handleRegisterRun))
	mux.Handle("POST /agent/v1/runs/{id}/events", s.requireAgent(s.handleEvents))
	mux.Handle("GET /agent/v1/update/{platform}", s.requireAgent(s.handleAgentBinary))
	mux.Handle("POST /agent/v1/restore-sessions", s.requireAgent(s.handleCreateRestoreSession))
	mux.Handle("POST /agent/v1/cert", s.requireAgent(s.handleRenewCert))
	return mux
}

type agentHandler func(w http.ResponseWriter, r *http.Request, c *Client)

// requireAgent authenticates the client certificate (verified by TLS against our CA)
// and resolves it to a non-revoked client. The first request with a renewed
// certificate revokes the previous one.
func (s *Server) requireAgent(h agentHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			httpError(w, http.StatusUnauthorized, errors.New("client certificate required"))
			return
		}
		serial := connSerial(r)
		c, err := s.store.ClientBySerial(r.Context(), serial)
		if err != nil {
			s.replacedCertUsed(r, serial)
			httpError(w, http.StatusForbidden, errors.New("unknown or revoked client"))
			return
		}
		if serial == c.pendingSerial {
			if err := s.store.PromoteSerial(r.Context(), c.ID, serial); err != nil {
				httpError(w, http.StatusInternalServerError, err)
				return
			}
			s.log.Info("client certificate renewed; the old one is no longer accepted", "client", c.Name, "id", c.ID, "old_serial", c.CertSerial)
			s.wakeClient(c.ID) // a poll waiting with the old certificate ends at once
			c.CertSerial, c.pendingSerial, c.CertRenew = serial, "", false
		}
		h(w, r, c)
	})
}

// connSerial is the serial of the client certificate r came with.
func connSerial(r *http.Request) string {
	return r.TLS.VerifiedChains[0][0].SerialNumber.Text(16)
}

var clientNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// sanitizeClientName produces a name usable as PBS namespace, backup-id and token name.
func sanitizeClientName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = regexp.MustCompile(`[^a-z0-9_-]+`).ReplaceAllString(n, "-")
	n = strings.Trim(n, "-_")
	if len(n) > 63 {
		n = n[:63]
	}
	return n
}

var (
	errClientNameTaken   = errors.New("client name already exists")
	errClientNameInvalid = errors.New("invalid client name")
)

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	req.Hostname, req.OS = clip(req.Hostname, maxAgentName), clip(req.OS, maxAgentToken)
	ctx := r.Context()
	if st, err := s.store.SetupTokenByCode(ctx, hashToken(req.Code)); err == nil {
		s.enrollWithSetupToken(w, r, st, req)
		return
	}
	e, err := s.store.ClaimEnrollment(ctx, hashToken(req.Code))
	if err != nil {
		s.log.Warn("enrollment rejected", "remote", r.RemoteAddr, "err", err)
		httpError(w, http.StatusForbidden, err)
		return
	}
	c, certPEM, err := s.enrollClient(ctx, e, req, false)
	if err != nil {
		s.store.ReleaseEnrollment(ctx, e.ID)
		s.log.Error("enrollment failed", "client", e.ClientName, "err", err)
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	s.store.CompleteEnrollment(ctx, e.ID, c.ID)
	s.log.Info("client enrolled", "client", c.Name, "id", c.ID, "hostname", req.Hostname, "remote", r.RemoteAddr)
	writeJSON(w, api.EnrollResponse{ClientID: c.ID, ClientName: c.Name, CertPEM: string(certPEM), CAPEM: string(s.pki.CAPEM)})
}

// enrollWithSetupToken enrolls a PC under the name it chose (its hostname if
// none). A taken name is a 409 so the setup can ask for another one. Names of
// revoked clients count as taken: whoever runs the setup chooses the name, and
// the new client would inherit the revoked PC's PBS token id and namespace,
// and with them its snapshots.
func (s *Server) enrollWithSetupToken(w http.ResponseWriter, r *http.Request, st *SetupToken, req api.EnrollRequest) {
	ctx := r.Context()
	e := &Enrollment{ClientName: cmp.Or(strings.TrimSpace(req.ClientName), req.Hostname), TargetID: st.TargetID}
	c, certPEM, err := s.enrollClient(ctx, e, req, true)
	if err != nil {
		s.log.Warn("setup enrollment failed", "client", e.ClientName, "setup_token", st.ID, "remote", r.RemoteAddr, "err", err)
		code := http.StatusInternalServerError
		switch {
		case errors.Is(err, errClientNameTaken):
			code = http.StatusConflict
		case errors.Is(err, errClientNameInvalid):
			code = http.StatusBadRequest
		}
		httpError(w, code, err)
		return
	}
	s.store.CountSetupTokenUse(ctx, st.ID)
	s.log.Info("client enrolled", "client", c.Name, "id", c.ID, "hostname", req.Hostname, "setup_token", st.ID, "remote", r.RemoteAddr)
	writeJSON(w, api.EnrollResponse{ClientID: c.ID, ClientName: c.Name, CertPEM: string(certPEM), CAPEM: string(s.pki.CAPEM)})
}

// enrollClient creates the client, or for a re-enrollment hands the PC the
// revoked client (reenroll.go). An admin-issued enrollment may use a revoked
// client's name, but gets PBS storage of its own; with a setup token
// (setup=true) such names are refused.
func (s *Server) enrollClient(ctx context.Context, e *Enrollment, req api.EnrollRequest, setup bool) (*Client, []byte, error) {
	if e.ReenrollID > 0 {
		return s.reenrollClient(ctx, e, req)
	}
	name := sanitizeClientName(e.ClientName)
	if name == "" {
		name = sanitizeClientName(req.Hostname)
	}
	if !clientNameRe.MatchString(name) {
		return nil, nil, fmt.Errorf("%w %q", errClientNameInvalid, name)
	}
	// Setup tokens let several PCs enroll at once: hold the name from the check
	// until the client row exists (provisioning replaces a same-named PBS token).
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	if s.store.ClientNameTaken(ctx, name) {
		return nil, nil, fmt.Errorf("%w: %q", errClientNameTaken, name)
	}
	if setup && s.store.RevokedClientNamed(ctx, name) {
		return nil, nil, fmt.Errorf("%w: %q belonged to a revoked client", errClientNameTaken, name)
	}
	t, err := s.store.Target(ctx, e.TargetID)
	if err != nil {
		return nil, nil, fmt.Errorf("target: %w", err)
	}
	certPEM, serial, err := s.pki.SignClientCSR([]byte(req.CSR), name)
	if err != nil {
		return nil, nil, err
	}
	ns, tokenID, secret, err := s.provisionClient(ctx, t, s.freeStorageName(ctx, t, name))
	if err != nil {
		return nil, nil, fmt.Errorf("PBS provisioning: %w", err)
	}
	c := &Client{Name: name, Hostname: req.Hostname, OS: req.OS, CertSerial: serial, TargetID: t.ID,
		Namespace: ns, TokenID: tokenID}
	if err := s.store.CreateClient(ctx, c, s.sealer.sealFor(secret, colClientToken)); err != nil {
		return nil, nil, err
	}
	// Group jobs for all clients pick up the new one.
	if affected, err := s.store.SyncAllGroups(ctx); err != nil {
		s.log.Error("attach group jobs", "client", c.Name, "err", err)
	} else if err := s.membersChanged(ctx, affected); err != nil {
		s.log.Error("attach group jobs", "client", c.Name, "err", err)
	}
	return c, certPEM, nil
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request, c *Client) {
	var req api.PollRequest
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	clipPoll(&req)
	ctx := r.Context()
	serial := connSerial(r)
	// A certificate due for renewal may be a stolen copy: what its polls report
	// about the agent (features) isn't taken.
	s.store.TouchClient(ctx, c.ID, req, !c.CertRenew)
	s.store.MarkMissingLost(ctx, c.ID, req.RunningRuns)
	agentRev := req.ConfigRev
	renewing := c.CertRenew

	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	wait = min(max(wait, 0), 55)
	deadline := time.After(time.Duration(wait) * time.Second)
	for {
		wake := s.wakeChan(c.ID)
		if fresh, err := s.store.Client(ctx, c.ID); err == nil {
			c = fresh // e.g. moved to another namespace while this poll waited
		}
		// The certificate was renewed (or the client revoked) while this poll
		// waited: config and a new token go only to the current certificate.
		if c.Revoked || c.CertSerial != serial {
			httpError(w, http.StatusForbidden, errors.New("client certificate replaced or revoked"))
			return
		}
		if s.tokenRotationDue(c) {
			if err := s.rotateClientToken(ctx, c); err != nil {
				s.log.Warn("could not rotate the client's PBS token; retrying later", "client", c.Name, "err", err)
			} else if fresh, err := s.store.Client(ctx, c.ID); err == nil {
				c = fresh
			}
		}
		offer := s.updater.agentOffer(ctx, c.ID, req.OS, req.AgentVersion)
		resp := api.PollResponse{Jobs: []api.JobSpec{}, Cancel: s.store.CancelRequestedFor(ctx, c.ID), Update: offer,
			ServerURL: strings.TrimRight(s.cfg.PublicURL, "/"),
			RenewCert: c.CertRenew}
		cfg, err := s.agentConfig(ctx, c)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		if cfg.Rev != agentRev {
			resp.Config = cfg
		}
		runs, err := s.store.DispatchQueued(ctx, c.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		for _, run := range runs {
			spec, err := s.buildSpec(ctx, c, run)
			if err != nil {
				s.store.FinishRun(ctx, run.ID, api.Result{State: api.RunFailed, Error: err.Error()}, now())
				continue
			}
			resp.Jobs = append(resp.Jobs, *spec)
		}
		// A renewal requested meanwhile is answered at once (agents that can't
		// renew ignore RenewCert; they'd poll again right away if every reply did).
		if len(resp.Jobs) > 0 || len(resp.Cancel) > 0 || resp.Config != nil || offer != nil && offer.Force || resp.RenewCert && !renewing {
			writeJSON(w, resp)
			return
		}
		select {
		case <-wake:
		case <-deadline:
			writeJSON(w, resp)
			return
		case <-ctx.Done():
			return
		}
	}
}

// agentConfig builds the configuration pushed to an agent: the PBS target
// (with the client's scoped token) and its enabled jobs. Rev is a content hash.
func (s *Server) agentConfig(ctx context.Context, c *Client) (*api.AgentConfig, error) {
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return nil, err
	}
	secret, err := s.sealer.Open(c.tokenSecretEnc, colClientToken, c.ID)
	if err != nil {
		return nil, fmt.Errorf("decrypt client token: %w", err)
	}
	jobs, err := s.store.Jobs(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	key, err := s.clientKey(ctx, c)
	if err != nil {
		return nil, err
	}
	cfg := &api.AgentConfig{
		Crypt:     key,
		Bandwidth: c.Bandwidth,
		Target: api.PBSTarget{Host: t.Host, Fingerprint: t.Fingerprint, Datastore: t.Datastore, Namespace: c.Namespace,
			AuthID: c.TokenID, Secret: secret},
		Jobs: []api.JobConfig{},
	}
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		cfg.Jobs = append(cfg.Jobs, api.JobConfig{ID: j.ID, Name: j.Name, Kind: j.Kind, BackupID: j.BackupID,
			Sources: j.Sources, Excludes: j.AllExcludes(), Volumes: j.Volumes, UseVSS: j.UseVSS,
			ChangeDetection: s.changeDetection(ctx, t, j),
			Schedule:        j.Schedule, WindowMinutes: j.WindowMinutes, CatchUp: j.CatchUp, Encrypt: j.Encrypt,
			StartDelay: j.StartDelay, PreventSleep: j.PreventSleep,
			WakeToRun: j.WakeToRun, Bandwidth: j.Bandwidth, OnBattery: j.OnBattery, OnMetered: j.OnMetered})
	}
	b, _ := json.Marshal(cfg)
	sum := sha256.Sum256(b)
	cfg.Rev = hex.EncodeToString(sum[:])
	return cfg, nil
}

// applyAgentState copies the agent-reported schedule view (next run, pending
// catch-up) onto jobs for display.
func applyAgentState(c *Client, jobs []*Job) {
	for _, j := range jobs {
		for _, st := range c.ScheduleState {
			if st.JobID == j.ID {
				j.NextRun, j.CatchUpPending, j.Waiting = st.NextRun, st.CatchUpPending, st.Waiting
			}
		}
	}
}

// handleRegisterRun records a run the agent started on its own schedule (or a
// scheduled run it had to skip). Idempotent on the run UUID.
func (s *Server) handleRegisterRun(w http.ResponseWriter, r *http.Request, c *Client) {
	var reg api.RunRegister
	if err := decodeJSON(r, &reg); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(reg.UUID) < 16 || len(reg.UUID) > maxAgentToken || (reg.State != api.RunRunning && reg.State != api.RunMissed) {
		httpError(w, http.StatusBadRequest, errors.New("invalid run registration"))
		return
	}
	reg.Kind, reg.Trigger, reg.Message = clip(reg.Kind, maxAgentToken), clip(reg.Trigger, maxAgentToken), clip(reg.Message, maxAgentText)
	ctx := r.Context()
	if id, ok := s.store.RegisteredRun(ctx, c.ID, reg.UUID); ok { // a retry
		writeJSON(w, api.RunRegisterResponse{RunID: id})
		return
	}
	if !s.runRegs.allow(c.ID, time.Now()) {
		// Agents retry a 429 later (spooled runs stay spooled).
		w.Header().Set("Retry-After", "60")
		httpError(w, http.StatusTooManyRequests, errors.New("too many run registrations; try again later"))
		return
	}
	if reg.JobID > 0 {
		if j, err := s.store.Job(ctx, reg.JobID); err != nil || j.ClientID != c.ID {
			reg.JobID = 0 // job deleted meanwhile; keep the run for the record
		}
	}
	id, created, err := s.store.RegisterRun(ctx, c.ID, reg)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if created {
		s.log.Info("agent started run", "run", id, "client", c.Name, "job", reg.JobID, "trigger", reg.Trigger, "state", reg.State)
		if reg.State == api.RunMissed {
			go s.afterRun(context.WithoutCancel(ctx), id)
		}
	}
	writeJSON(w, api.RunRegisterResponse{RunID: id})
}

// restoreKey returns the key of the snapshot a restore spec reads. If PBS
// can't say which one that is, the current key is sent: the agent then
// reports a snapshot encrypted with another key.
func (s *Server) restoreKey(ctx context.Context, t *Target, c *Client, spec *api.JobSpec) (*api.CryptKey, error) {
	pc, err := s.adminClient(t)
	if err == nil {
		ref := pbs.SnapshotRef{Store: t.Datastore, NS: spec.Target.Namespace, Type: "host", ID: spec.Restore.BackupID, Time: spec.Restore.BackupTime}
		var k *api.CryptKey
		if k, err = s.snapshotKey(ctx, pc, c, ref); err == nil {
			return k, nil
		}
	}
	s.log.Warn("restore: can't tell which encryption key the snapshot needs, sending the current one", "client", c.Name, "err", err)
	return s.clientKey(ctx, c)
}

// buildSpec turns a run into the self-contained job description sent to the agent.
func (s *Server) buildSpec(ctx context.Context, c *Client, run *Run) (*api.JobSpec, error) {
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return nil, err
	}
	secret, err := s.sealer.Open(c.tokenSecretEnc, colClientToken, c.ID)
	if err != nil {
		return nil, fmt.Errorf("decrypt client token: %w", err)
	}
	spec := &api.JobSpec{
		RunID: run.ID, JobID: run.JobID, Kind: run.Kind,
		Target: api.PBSTarget{Host: t.Host, Fingerprint: t.Fingerprint, Datastore: t.Datastore, Namespace: c.Namespace,
			AuthID: c.TokenID, Secret: secret},
		BackupID: c.Name,
		Restore:  run.Restore,
	}
	if run.Restore != nil && run.Restore.Namespace != "" {
		spec.Target.Namespace = run.Restore.Namespace // snapshot from before a namespace move
	}
	// Restores need the key too, for snapshots encrypted earlier: the one of
	// the snapshot, which may be an old key of the client.
	if run.Restore != nil {
		spec.Crypt, err = s.restoreKey(ctx, t, c, spec)
	} else {
		spec.Crypt, err = s.clientKey(ctx, c)
	}
	if err != nil {
		return nil, err
	}
	if run.JobID > 0 {
		j, err := s.store.Job(ctx, run.JobID)
		if err != nil {
			return nil, fmt.Errorf("job %d: %w", run.JobID, err)
		}
		spec.BackupID, spec.Sources, spec.Excludes, spec.Volumes, spec.UseVSS = j.BackupID, j.Sources, j.AllExcludes(), j.Volumes, j.UseVSS
		spec.ChangeDetection = s.changeDetection(ctx, t, j)
		spec.Encrypt, spec.PreventSleep = j.Encrypt, j.PreventSleep
		spec.Bandwidth, spec.ClientBandwidth = j.Bandwidth, c.Bandwidth
	}
	return spec, nil
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, c *Client) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	run, err := s.store.Run(ctx, id)
	if err != nil || run.ClientID != c.ID {
		httpError(w, http.StatusNotFound, errors.New("no such run"))
		return
	}
	var events []api.Event
	if err := decodeJSON(r, &events); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// A finished run takes no more events. Lost runs still do: their report
	// may have been spooled while the console was unreachable. The agent
	// resends a batch whose answer it missed, so this isn't an error.
	if api.Terminal(run.State) && run.State != api.RunLost {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var logs []LogLine
	var result *api.Result
	var resultAt int64
	var lastProgress *api.Progress
	var lastTime int64
	for _, e := range events {
		ts := e.Time.Unix()
		lastTime = max(lastTime, ts)
		switch e.Type {
		case "log":
			logs = append(logs, LogLine{Time: ts, Level: logLevel(e.Level), Msg: clip(e.Message, maxAgentText)})
		case "progress":
			if e.Progress != nil {
				lastProgress = e.Progress
				clipProgress(lastProgress)
			}
		case "result":
			if e.Result != nil {
				result, resultAt = e.Result, ts
				clipResult(result)
			}
		}
	}
	if len(logs) > 0 {
		s.store.AddLogs(ctx, id, logs)
	}
	if lastProgress != nil {
		s.store.RunProgress(ctx, id, *lastProgress, now())
	} else if len(events) > 0 {
		s.store.RunStarted(ctx, id, now())
	}
	if result != nil {
		if !api.Terminal(result.State) {
			result.State = api.RunFailed
		}
		if s.store.FinishRun(ctx, id, *result, resultAt) {
			s.log.Info("run finished", "run", id, "client", c.Name, "state", result.State, "snapshot", result.Snapshot)
			go s.afterRun(context.WithoutCancel(ctx), id)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// afterRun locks the new snapshot and sends notifications. Retention runs on
// the console's own schedule (see retention.go), never because of a run.
func (s *Server) afterRun(ctx context.Context, runID int64) {
	run, err := s.store.Run(ctx, runID)
	if err != nil {
		return
	}
	if (run.State == api.RunSuccess || run.State == api.RunWarning) && run.JobID > 0 && run.Kind != api.KindRestore {
		s.afterBackup(ctx, run)
	}
	s.notify.RunFinished(ctx, run)
}

// afterBackup protects the new snapshot (see locks.go), unless the
// job already had its daily cap of backups that day.
func (s *Server) afterBackup(ctx context.Context, run *Run) {
	j, err := s.store.Job(ctx, run.JobID)
	if err != nil || j.LockDays <= 0 || run.Result.BackupTime <= 0 {
		return
	}
	logErr := func(what string, err error) {
		s.log.Error(what+" failed", "run", run.ID, "err", err)
		s.store.AddLogs(ctx, run.ID, []LogLine{{Time: now(), Level: "error", Msg: "server: " + what + " failed: " + err.Error()}})
	}
	c, err := s.store.Client(ctx, run.ClientID)
	if err != nil {
		logErr("lock", err)
		return
	}
	bt := run.Result.BackupTime
	day := time.Unix(bt, 0)
	dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.Local).Unix()
	successes, err := s.store.SuccessfulBackupTimes(ctx, j.ID, dayStart)
	if err != nil {
		logErr("lock", err)
		return
	}
	if limit := dailyCap(j, time.Now()); overDailyCap(bt, successes, limit, time.Local) {
		s.store.AddLogs(ctx, run.ID, []LogLine{{Time: now(), Level: "warn",
			Msg: fmt.Sprintf("server: more than %d backups of this job today: snapshot not protected, retention removes it", limit)}})
		s.dailyCapHit(ctx, c, j, dayKey(bt, time.Local), limit, 1, "the latest ones are not protected and retention removes them")
		return
	}
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		logErr("lock", err)
		return
	}
	pc, err := s.adminClient(t)
	if err != nil {
		logErr("lock", err)
		return
	}
	if err := s.lockSnapshot(ctx, pc, t, c, j, bt); err != nil {
		logErr("lock", err)
	} else {
		s.store.AddLogs(ctx, run.ID, []LogLine{{Time: now(), Level: "info",
			Msg: fmt.Sprintf("server: snapshot protected for at least %d day(s), then while retention keeps it", j.LockDays)}})
	}
}

func (s *Server) adminClient(t *Target) (*pbs.Client, error) {
	secret, err := s.sealer.Open(t.adminSecretEnc, colTargetSecret, t.ID)
	if err != nil {
		return nil, fmt.Errorf("decrypt admin token: %w", err)
	}
	return pbs.NewClient(pbs.Config{Host: s.pbsAPIHost(t.Host), Fingerprint: t.Fingerprint, AuthID: t.AdminAuthID, Secret: secret})
}

// clientNamespace is the PBS namespace a client named name gets on t.
func clientNamespace(t *Target, name string) string {
	if root := strings.Trim(t.RootNS, "/"); root != "" {
		return root + "/" + name
	}
	return name
}

// prepareRootNamespace creates t's root namespace and lets the agents' PBS
// user back up below it. Token privileges are intersected with the owning
// user's, so the user needs DatastoreBackup on the root namespace and each
// token on its own namespace. When the console signs in as that user, it has
// DatastoreAdmin already (and can't change its own ACLs).
func prepareRootNamespace(ctx context.Context, pc *pbs.Client, t *Target) error {
	root := strings.Trim(t.RootNS, "/")
	if err := pc.EnsureNamespace(ctx, t.Datastore, root); err != nil {
		return fmt.Errorf("namespace %s: %w", root, err)
	}
	if t.AdminAuthID == t.PBSUser {
		return nil
	}
	if err := pc.EnsureUser(ctx, t.PBSUser, "proxbackup managed agents"); err != nil {
		return fmt.Errorf("user %s: %w", t.PBSUser, err)
	}
	if err := pc.GrantACL(ctx, pbs.DatastoreACLPath(t.Datastore, root), "DatastoreBackup", t.PBSUser); err != nil {
		return fmt.Errorf("user ACL: %w", err)
	}
	return nil
}

// prepareClientNamespace creates ns and grants the agent token backup rights on it.
func prepareClientNamespace(ctx context.Context, pc *pbs.Client, t *Target, ns, tokenID string) error {
	if err := pc.EnsureNamespace(ctx, t.Datastore, ns); err != nil {
		return fmt.Errorf("namespace %s: %w", ns, err)
	}
	path := pbs.DatastoreACLPath(t.Datastore, ns)
	// Tokens created before the target's PBS user changed belong to the old user,
	// which has no rights below the new root namespace.
	if user, _, _ := strings.Cut(tokenID, "!"); user != t.PBSUser {
		if err := pc.GrantACL(ctx, path, "DatastoreBackup", user); err != nil {
			return fmt.Errorf("user ACL: %w", err)
		}
	}
	if err := pc.GrantACL(ctx, path, "DatastoreBackup", tokenID); err != nil {
		return fmt.Errorf("token ACL: %w", err)
	}
	return nil
}

// provisionClient creates the namespace, API token and ACL for a new client;
// name is its storage name (see freeStorageName). The token gets
// DatastoreBackup only: it can create snapshots in its own namespace but
// cannot read other clients' data, delete or prune.
func (s *Server) provisionClient(ctx context.Context, t *Target, name string) (ns, tokenID, secret string, err error) {
	pc, err := s.adminClient(t)
	if err != nil {
		return "", "", "", err
	}
	if err = prepareRootNamespace(ctx, pc, t); err != nil {
		return "", "", "", err
	}
	ns = clientNamespace(t, name)
	pc.DeleteToken(ctx, t.PBSUser, name) // stale token from a previous enrollment of the same name
	tokenID, secret, err = pc.CreateToken(ctx, t.PBSUser, name, "proxbackup agent "+name)
	if err != nil {
		return "", "", "", fmt.Errorf("token: %w", err)
	}
	if err = prepareClientNamespace(ctx, pc, t, ns, tokenID); err != nil {
		pc.DeleteToken(ctx, t.PBSUser, name)
		return "", "", "", err
	}
	return ns, tokenID, secret, nil
}

// moveTargetClients points the clients of t at their namespace below t's
// current root namespace, creating it and its ACLs on PBS. Earlier snapshots
// stay in the old namespace, where the token keeps its rights.
func (s *Server) moveTargetClients(ctx context.Context, pc *pbs.Client, t *Target) error {
	cs, err := s.store.Clients(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		ns := clientNamespace(t, tokenName(c))
		if c.TargetID != t.ID || c.Namespace == ns {
			continue
		}
		if err := prepareClientNamespace(ctx, pc, t, ns, c.TokenID); err != nil {
			return fmt.Errorf("client %s: %w", c.Name, err)
		}
		old := c.Namespace
		if err := s.store.MoveClientNamespace(ctx, c, ns); err != nil {
			return err
		}
		s.log.Info("client moved to new namespace", "client", c.Name, "from", old, "to", ns)
		s.wakeClient(c.ID)
	}
	return nil
}
