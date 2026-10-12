package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"pbspc/internal/api"
	"pbspc/pkg/pbs"
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
	mux.Handle("POST /agent/v1/runs/{id}/events", s.requireAgent(s.handleEvents))
	return mux
}

type agentHandler func(w http.ResponseWriter, r *http.Request, c *Client)

// requireAgent authenticates the client certificate (verified by TLS against our CA)
// and resolves it to a non-revoked client.
func (s *Server) requireAgent(h agentHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			httpError(w, http.StatusUnauthorized, errors.New("client certificate required"))
			return
		}
		serial := r.TLS.VerifiedChains[0][0].SerialNumber.Text(16)
		c, err := s.store.ClientBySerial(r.Context(), serial)
		if err != nil {
			httpError(w, http.StatusForbidden, errors.New("unknown or revoked client"))
			return
		}
		h(w, r, c)
	})
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

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req api.EnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	e, err := s.store.ClaimEnrollment(ctx, hashToken(req.Code))
	if err != nil {
		s.log.Warn("enrollment rejected", "remote", r.RemoteAddr, "err", err)
		httpError(w, http.StatusForbidden, err)
		return
	}
	c, certPEM, err := s.enrollClient(ctx, e, req)
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

func (s *Server) enrollClient(ctx context.Context, e *Enrollment, req api.EnrollRequest) (*Client, []byte, error) {
	name := sanitizeClientName(e.ClientName)
	if name == "" {
		name = sanitizeClientName(req.Hostname)
	}
	if !clientNameRe.MatchString(name) {
		return nil, nil, fmt.Errorf("invalid client name %q", name)
	}
	if s.store.ClientNameTaken(ctx, name) {
		return nil, nil, fmt.Errorf("client name %q already exists", name)
	}
	t, err := s.store.Target(ctx, e.TargetID)
	if err != nil {
		return nil, nil, fmt.Errorf("target: %w", err)
	}
	certPEM, serial, err := s.pki.SignClientCSR([]byte(req.CSR), name)
	if err != nil {
		return nil, nil, err
	}
	ns, tokenID, secret, err := s.provisionClient(ctx, t, name)
	if err != nil {
		return nil, nil, fmt.Errorf("PBS provisioning: %w", err)
	}
	c := &Client{Name: name, Hostname: req.Hostname, OS: req.OS, CertSerial: serial, TargetID: t.ID,
		Namespace: ns, TokenID: tokenID, tokenSecretEnc: s.sealer.Seal(secret)}
	if err := s.store.CreateClient(ctx, c); err != nil {
		return nil, nil, err
	}
	return c, certPEM, nil
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request, c *Client) {
	var req api.PollRequest
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	s.store.TouchClient(ctx, c.ID, req.Hostname, req.OS, req.AgentVersion)
	s.store.MarkMissingLost(ctx, c.ID, req.RunningRuns)

	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	wait = min(max(wait, 0), 55)
	deadline := time.After(time.Duration(wait) * time.Second)
	for {
		wake := s.wakeChan(c.ID)
		resp := api.PollResponse{Jobs: []api.JobSpec{}, Cancel: s.store.CancelRequestedFor(ctx, c.ID)}
		runs, err := s.store.DispatchQueued(ctx, c.ID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		for _, run := range runs {
			spec, err := s.buildSpec(ctx, c, run)
			if err != nil {
				s.store.FinishRun(ctx, run.ID, api.Result{State: api.RunFailed, Error: err.Error()})
				continue
			}
			resp.Jobs = append(resp.Jobs, *spec)
		}
		if len(resp.Jobs) > 0 || len(resp.Cancel) > 0 {
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

// buildSpec turns a run into the self-contained job description sent to the agent.
func (s *Server) buildSpec(ctx context.Context, c *Client, run *Run) (*api.JobSpec, error) {
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return nil, err
	}
	secret, err := s.sealer.Open(c.tokenSecretEnc)
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
	if run.JobID > 0 {
		j, err := s.store.Job(ctx, run.JobID)
		if err != nil {
			return nil, fmt.Errorf("job %d: %w", run.JobID, err)
		}
		spec.BackupID, spec.Sources, spec.Excludes, spec.Volumes, spec.UseVSS = j.BackupID, j.Sources, j.Excludes, j.Volumes, j.UseVSS
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
	var logs []LogLine
	var result *api.Result
	var lastProgress *api.Progress
	var lastTime int64
	for _, e := range events {
		ts := e.Time.Unix()
		lastTime = max(lastTime, ts)
		switch e.Type {
		case "log":
			msg := e.Message
			if len(msg) > 4000 {
				msg = msg[:4000] + "…"
			}
			logs = append(logs, LogLine{Time: ts, Level: e.Level, Msg: msg})
		case "progress":
			lastProgress = e.Progress
		case "result":
			result = e.Result
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
		if s.store.FinishRun(ctx, id, *result) {
			s.log.Info("run finished", "run", id, "client", c.Name, "state", result.State, "snapshot", result.Snapshot)
			go s.afterRun(context.WithoutCancel(ctx), id)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// afterRun applies retention and sends notifications.
func (s *Server) afterRun(ctx context.Context, runID int64) {
	run, err := s.store.Run(ctx, runID)
	if err != nil {
		return
	}
	if (run.State == api.RunSuccess || run.State == api.RunWarning) && run.JobID > 0 && run.Kind != api.KindRestore {
		if err := s.applyRetention(ctx, run); err != nil {
			s.log.Error("retention failed", "run", runID, "err", err)
			s.store.AddLogs(ctx, runID, []LogLine{{Time: now(), Level: "error", Msg: "server: prune failed: " + err.Error()}})
		}
	}
	s.notify.RunFinished(ctx, run)
}

func (s *Server) applyRetention(ctx context.Context, run *Run) error {
	j, err := s.store.Job(ctx, run.JobID)
	if err != nil || j.Retention.IsZero() {
		return nil
	}
	c, err := s.store.Client(ctx, run.ClientID)
	if err != nil {
		return err
	}
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return err
	}
	pc, err := s.adminClient(t)
	if err != nil {
		return err
	}
	res, err := pc.PruneGroup(ctx, t.Datastore, c.Namespace, "host", j.BackupID, j.Retention, false)
	if err != nil {
		return err
	}
	removed := 0
	for _, p := range res {
		if !p.Keep {
			removed++
		}
	}
	s.store.AddLogs(ctx, run.ID, []LogLine{{Time: now(), Level: "info",
		Msg: fmt.Sprintf("server: retention applied, %d snapshot(s) kept, %d pruned", len(res)-removed, removed)}})
	return nil
}

func (s *Server) adminClient(t *Target) (*pbs.Client, error) {
	secret, err := s.sealer.Open(t.adminSecretEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt admin token: %w", err)
	}
	return pbs.NewClient(pbs.Config{Host: t.Host, Fingerprint: t.Fingerprint, AuthID: t.AdminAuthID, Secret: secret})
}

// provisionClient creates the namespace, API token and ACL for a new client.
// The token gets DatastoreBackup only: it can create snapshots in its own
// namespace but cannot read other clients' data, delete or prune.
func (s *Server) provisionClient(ctx context.Context, t *Target, name string) (ns, tokenID, secret string, err error) {
	pc, err := s.adminClient(t)
	if err != nil {
		return "", "", "", err
	}
	ns = name
	if t.RootNS != "" {
		ns = strings.Trim(t.RootNS, "/") + "/" + name
	}
	if err = pc.EnsureNamespace(ctx, t.Datastore, ns); err != nil {
		return "", "", "", fmt.Errorf("namespace: %w", err)
	}
	user := t.PBSUser
	if err = pc.EnsureUser(ctx, user, "pbspc managed agents"); err != nil {
		return "", "", "", fmt.Errorf("user %s: %w", user, err)
	}
	// Token privileges are intersected with the owning user's, so the user needs
	// DatastoreBackup on the root namespace and each token on its own namespace.
	if err = pc.GrantACL(ctx, pbs.DatastoreACLPath(t.Datastore, strings.Trim(t.RootNS, "/")), "DatastoreBackup", user); err != nil {
		return "", "", "", fmt.Errorf("user ACL: %w", err)
	}
	pc.DeleteToken(ctx, user, name) // stale token from a previous enrollment of the same name
	tokenID, secret, err = pc.CreateToken(ctx, user, name, "pbspc agent "+name)
	if err != nil {
		return "", "", "", fmt.Errorf("token: %w", err)
	}
	if err = pc.GrantACL(ctx, pbs.DatastoreACLPath(t.Datastore, ns), "DatastoreBackup", tokenID); err != nil {
		pc.DeleteToken(ctx, user, name)
		return "", "", "", fmt.Errorf("token ACL: %w", err)
	}
	return ns, tokenID, secret, nil
}
