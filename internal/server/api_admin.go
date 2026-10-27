// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a := access(r)
	clients, err := s.store.Clients(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	clients = slices.DeleteFunc(clients, func(c *Client) bool { return !a.Client(PermViewClients, c) })
	recent, current := RunFilter{Limit: 20}, RunFilter{Active: true, Limit: 100}
	s.scopeRuns(ctx, a, &recent)
	s.scopeRuns(ctx, a, &current)
	runs, _ := s.store.Runs(ctx, recent)
	active, _ := s.store.Runs(ctx, current)
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
	auditTarget(r, "PBS server "+req.Name)
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
	}
	fp := strings.TrimSpace(req.Fingerprint)
	if fp == "" {
		fp = s.localFingerprintFor(ctx, req.AdminAuthID)
	}
	// The stored secret only stays with the PBS and token it was entered for.
	if req.AdminSecret == "" && (t.ID == 0 || !t.sameEndpoint(req.Host, fp, req.AdminAuthID)) {
		if req.AdminSecret = s.localSecretFor(ctx, req.AdminAuthID, req.Host, fp); req.AdminSecret == "" {
			httpError(w, 400, errors.New("admin token secret is required (enter it again when host, fingerprint or token id change)"))
			return
		}
	}
	// A new root namespace must exist on PBS before agents are pointed at it.
	nsChanged := t.ID != 0 && t.RootNS != req.RootNS
	t.Name, t.Host, t.Fingerprint, t.Datastore, t.RootNS, t.AdminAuthID, t.PBSUser =
		req.Name, req.Host, fp, req.Datastore, req.RootNS, req.AdminAuthID, req.PBSUser
	if req.AdminSecret != "" {
		t.adminSecretEnc = s.sealer.Seal(req.AdminSecret)
	}
	var pc *pbs.Client
	if nsChanged {
		var err error
		if pc, err = s.adminClient(t); err == nil {
			err = prepareRootNamespace(ctx, pc, t)
		}
		if err != nil {
			httpError(w, 502, fmt.Errorf("PBS: %w", err))
			return
		}
	}
	if err := s.store.SaveTarget(ctx, t); err != nil {
		httpError(w, 500, err)
		return
	}
	if nsChanged {
		if err := s.moveTargetClients(ctx, pc, t); err != nil {
			httpError(w, 502, fmt.Errorf("saved, but moving clients to the new namespace failed: %w", err))
			return
		}
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
	if t, terr := s.store.Target(r.Context(), id); err == nil && terr == nil {
		auditTarget(r, "PBS server "+t.Name)
	}
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
	// The form sends the whole target, so unknown fields are allowed here.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if req.Fingerprint = strings.TrimSpace(req.Fingerprint); req.Fingerprint == "" {
		req.Fingerprint = s.localFingerprintFor(ctx, req.AdminAuthID)
	}
	// Stored and local secrets are only sent to the PBS they belong to.
	if req.AdminSecret == "" && req.ID > 0 {
		if t, err := s.store.Target(ctx, req.ID); err == nil && t.sameEndpoint(req.Host, req.Fingerprint, req.AdminAuthID) {
			req.AdminSecret, _ = s.sealer.Open(t.adminSecretEnc)
		}
	}
	if req.AdminSecret == "" {
		req.AdminSecret = s.localSecretFor(ctx, req.AdminAuthID, req.Host, req.Fingerprint)
	}
	if req.AdminSecret == "" {
		httpError(w, 400, errors.New("admin token secret is required (enter it again when host, fingerprint or token id change)"))
		return
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
	a := access(r)
	cs = slices.DeleteFunc(cs, func(c *Client) bool { return !a.Client(PermViewClients, c) })
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
	c, ok := s.pathClient(w, r, PermViewClients)
	if !ok {
		return
	}
	ctx := r.Context()
	c.LastSuccess = s.store.LastSuccess(ctx)[c.ID]
	jobs, _ := s.store.Jobs(ctx, c.ID)
	applyAgentState(c, jobs)
	if cfg, err := s.agentConfig(ctx, c); err == nil {
		c.ConfigSynced = cfg.Rev == c.ConfigRev
	}
	c.AgentUpdate, c.AgentUpdatePushed = s.updater.agentUpdate(c)
	runs, _ := s.store.Runs(ctx, RunFilter{ClientID: c.ID, Limit: 50})
	writeJSON(w, map[string]any{"client": c, "jobs": orEmpty(jobs), "runs": orEmpty(runs)})
}

func (s *Server) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermManageClients)
	if !ok {
		return
	}
	ctx, id := r.Context(), c.ID
	if c.Revoked {
		httpError(w, http.StatusConflict, errors.New("client is already revoked"))
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
		if errors.Is(err, errNotFound) {
			httpError(w, http.StatusConflict, errors.New("client is already revoked"))
			return
		}
		httpError(w, 500, err)
		return
	}
	s.wakeClient(id)
	writeJSON(w, map[string]bool{"ok": true})
}

// revokedListDays is how long revoked clients are listed (and can be
// un-revoked from the list; their detail page keeps the button).
const revokedListDays = 30

func (s *Server) handleRevokedClients(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.RevokedClients(r.Context(), now()-revokedListDays*86400)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	a := access(r)
	cs = slices.DeleteFunc(cs, func(c *Client) bool { return !a.Client(PermViewClients, c) })
	writeJSON(w, orEmpty(cs))
}

// handleUnrevokeClient reactivates a revoked client under its old name: a new
// PBS token is created and its agent, which still holds its certificate,
// reconnects with its jobs and history.
func (s *Server) handleUnrevokeClient(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermManageClients)
	if !ok {
		return
	}
	ctx, id := r.Context(), c.ID
	if !c.Revoked {
		httpError(w, http.StatusConflict, errors.New("client is not revoked"))
		return
	}
	if !c.Restorable {
		httpError(w, http.StatusConflict, errors.New("this client was revoked by an older console version and cannot be restored; enroll the PC again"))
		return
	}
	name := strings.TrimSuffix(c.Name, fmt.Sprintf("#revoked-%d", c.ID))
	// Hold the name like an enrollment does until the client row has it.
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	if s.store.ClientNameTaken(ctx, name) {
		httpError(w, http.StatusConflict, fmt.Errorf("%w: %q is used by another client meanwhile", errClientNameTaken, name))
		return
	}
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		httpError(w, statusFor(err), fmt.Errorf("target: %w", err))
		return
	}
	pc, err := s.adminClient(t)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	pc.DeleteToken(ctx, t.PBSUser, name) // stale token of the same name
	tokenID, secret, err := pc.CreateToken(ctx, t.PBSUser, name, "proxbackup agent "+name)
	if err != nil {
		httpError(w, http.StatusBadGateway, fmt.Errorf("PBS token: %w", err))
		return
	}
	for _, ns := range append([]string{c.Namespace}, c.OldNamespaces...) {
		if err := prepareClientNamespace(ctx, pc, t, ns, tokenID); err != nil {
			pc.DeleteToken(ctx, t.PBSUser, name)
			httpError(w, http.StatusBadGateway, err)
			return
		}
	}
	if err := s.store.UnrevokeClient(ctx, c, name, tokenID, s.sealer.Seal(secret)); err != nil {
		pc.DeleteToken(ctx, t.PBSUser, name)
		httpError(w, statusFor(err), err)
		return
	}
	// Group jobs selecting it by tag (or all clients) pick it up again.
	if affected, err := s.store.SyncAllGroups(ctx); err != nil {
		s.log.Error("attach group jobs", "client", name, "err", err)
	} else if err := s.membersChanged(ctx, affected); err != nil {
		s.log.Error("attach group jobs", "client", name, "err", err)
	}
	s.log.Info("client un-revoked", "client", name, "id", c.ID)
	s.wakeClient(id)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermRestore)
	if !ok {
		return
	}
	snaps, code, err := s.clientSnapshots(r.Context(), c)
	if err != nil {
		httpError(w, code, err)
		return
	}
	writeJSON(w, orEmpty(snaps))
}

type clientSnapshot struct {
	pbs.SnapshotInfo
	NS  string `json:"ns"`
	Old bool   `json:"old,omitempty"` // in a namespace the client used before
}

// clientSnapshots lists the client's snapshots, newest first, including
// those in namespaces it used before. On error it also returns an HTTP status.
func (s *Server) clientSnapshots(ctx context.Context, c *Client) ([]clientSnapshot, int, error) {
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return nil, 500, err
	}
	pc, err := s.adminClient(t)
	if err != nil {
		return nil, 500, err
	}
	var snaps []clientSnapshot
	for i, ns := range append([]string{c.Namespace}, c.OldNamespaces...) {
		list, err := pc.ListSnapshots(ctx, t.Datastore, ns, "", "")
		if err != nil {
			if i == 0 {
				return nil, 502, err
			}
			s.log.Warn("list snapshots in old namespace", "client", c.Name, "ns", ns, "err", err)
			continue
		}
		for _, sn := range list {
			snaps = append(snaps, clientSnapshot{sn, ns, i > 0})
		}
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].BackupTime > snaps[j].BackupTime })
	return snaps, 0, nil
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
	ctx := r.Context()
	c, ok := s.allowClient(w, r, PermRestore, id)
	if !ok {
		return
	}
	auditDetail(r, "%s from %s/%d to %s", req.Archive, req.BackupID, req.BackupTime, req.TargetDir)
	if err := validateRestore(&req, c); err != nil {
		httpError(w, 400, err)
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
	auditTarget(r, "client "+name)
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
	command := `proxbackup-agent.exe enroll ` + enc + ` && proxbackup-agent.exe install`
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

// ---- setup tokens ----

// defaultSetupTTL is how long a setup token stays valid unless the admin picks another time.
const defaultSetupTTL = 4 * time.Hour

func setupCommand(token string) string {
	return `proxbackup-agent.exe setup ` + token
}

func (s *Server) handleSetupTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.SetupTokens(r.Context())
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, orEmpty(ts))
}

// handleCreateSetupToken creates a token that enrolls any number of PCs until
// it expires. Each PC's setup asks for its client name and the console address.
func (s *Server) handleCreateSetupToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetID int64 `json:"target_id"`
		TTLHours int   `json:"ttl_hours"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	if _, err := s.store.Target(ctx, req.TargetID); err != nil {
		httpError(w, 400, errors.New("unknown target"))
		return
	}
	ttl := defaultSetupTTL
	if req.TTLHours > 0 && req.TTLHours <= 24*30 {
		ttl = time.Duration(req.TTLHours) * time.Hour
	}
	if s.cfg.PublicURL == "" {
		httpError(w, 400, errors.New("server has no -public-url configured"))
		return
	}
	code := randToken(24)
	expires := time.Now().Add(ttl).Unix()
	tok, _ := json.Marshal(api.EnrollmentToken{URL: s.cfg.PublicURL, Code: code, CAFingerprint: s.pki.CAFingerprint(),
		Multi: true, Expires: expires, Host: s.agentFacingIP(ctx)})
	enc := base64.RawURLEncoding.EncodeToString(tok)
	id, err := s.store.CreateSetupToken(ctx, hashToken(code), req.TargetID, expires, s.sealer.Seal(enc))
	if err != nil {
		httpError(w, 500, err)
		return
	}
	s.log.Info("setup token created", "id", id, "target", req.TargetID, "expires", time.Unix(expires, 0))
	writeJSON(w, map[string]any{"id": id, "expires": expires, "token": enc, "command": setupCommand(enc)})
}

// agentFacingIP is the console address a setup offers by default: the IP of
// the -public-url host (resolved if it is a name), else the name itself.
func (s *Server) agentFacingIP(ctx context.Context) string {
	u, err := url.Parse(s.cfg.PublicURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	h := u.Hostname()
	if net.ParseIP(h) != nil {
		return h
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	if err != nil || len(addrs) == 0 {
		return h
	}
	for _, a := range addrs {
		if a.Unmap().Is4() && !a.IsLoopback() {
			return a.Unmap().String()
		}
	}
	if !addrs[0].IsLoopback() {
		return addrs[0].String()
	}
	return h
}

// handleSetupToken shows a setup token's command again.
func (s *Server) handleSetupToken(w http.ResponseWriter, r *http.Request) {
	enc, err := s.setupTokenString(r)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]string{"token": enc, "command": setupCommand(enc)})
}

func (s *Server) setupTokenString(r *http.Request) (string, error) {
	id, err := pathID(r)
	if err != nil {
		return "", err
	}
	sealed, err := s.store.SetupTokenSealed(r.Context(), id)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return "", fmt.Errorf("setup token expired or revoked: %w", errNotFound)
		}
		return "", err
	}
	return s.sealer.Open(sealed)
}

// handleSetupDownload serves the console's Windows agent with the setup token
// appended (see api.SetupTrailer): double-clicking it runs the setup.
func (s *Server) handleSetupDownload(w http.ResponseWriter, r *http.Request) {
	arch := r.PathValue("arch")
	if arch != "amd64" && arch != "arm64" {
		httpError(w, 400, errors.New("arch must be amd64 or arm64"))
		return
	}
	enc, err := s.setupTokenString(r)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	b, err := s.updater.agentBinary(r.Context(), arch)
	if err != nil {
		httpError(w, http.StatusServiceUnavailable, err)
		return
	}
	f, err := os.Open(b.path)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	defer f.Close()
	trailer := api.SetupTrailer(enc)
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", `attachment; filename="proxbackup-agent-setup-`+arch+`.exe"`)
	w.Header().Set("Content-Length", strconv.FormatInt(b.size+int64(len(trailer)), 10))
	w.Header().Set("Cache-Control", "no-store")
	if _, err := io.Copy(w, f); err != nil {
		return
	}
	w.Write(trailer)
}

// handleDeleteSetupToken revokes a setup token. PCs it already enrolled stay.
func (s *Server) handleDeleteSetupToken(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	if err := s.store.DeleteSetupToken(r.Context(), id); err != nil {
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
	visible := s.clientFilter(r.Context(), access(r), PermViewClients)
	jobs = slices.DeleteFunc(jobs, func(j *Job) bool { return !visible(j.ClientID) })
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

// memberReq holds a member's own settings; the definition belongs to its group job.
type memberReq struct {
	Enabled       bool     `json:"enabled"`
	ExtraExcludes []string `json:"extra_excludes"`
}

// handleSaveMember changes a member job's overrides.
func (s *Server) handleSaveMember(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	var req memberReq
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	j, err := s.store.Job(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	if _, ok := s.allowClient(w, r, PermManageJobs, j.ClientID); !ok {
		return
	}
	auditDetail(r, "job %s: enabled=%t", j.Name, req.Enabled)
	if err := s.store.SetMemberOverrides(ctx, id, req.Enabled, cleanList(req.ExtraExcludes)); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	s.wakeClient(j.ClientID)
	j, err = s.store.Job(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
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

// handleDeleteJob detaches a client from the job's group. Clients selected by
// one of the group's tags can only be disabled, not detached.
func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	ctx := r.Context()
	j, err := s.store.Job(ctx, id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	if _, ok := s.allowClient(w, r, PermManageJobs, j.ClientID); !ok {
		return
	}
	auditDetail(r, "job %s", j.Name)
	if j.GroupID == 0 {
		err = s.store.DeleteJob(ctx, id)
	} else {
		_, err = s.store.RemoveGroupClient(ctx, j.GroupID, j.ClientID)
	}
	if err != nil {
		httpError(w, 500, err)
		return
	}
	s.wakeClient(j.ClientID)
	if _, err := s.store.Job(ctx, id); err == nil {
		httpError(w, http.StatusConflict, errors.New("the client is selected by a tag of this group job: disable it here, or change its tags"))
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRunJob(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	j, err := s.store.Job(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	if _, ok := s.allowClient(w, r, PermRunBackups, j.ClientID); !ok {
		return
	}
	auditDetail(r, "job %s", j.Name)
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
	s.scopeRuns(r.Context(), access(r), &f)
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
	if !s.clientFilter(r.Context(), access(r), PermViewClients)(run.ClientID) {
		httpError(w, http.StatusForbidden, errClientDenied)
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
	run, err := s.store.Run(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	if !s.clientFilter(r.Context(), access(r), PermViewClients)(run.ClientID) {
		httpError(w, http.StatusForbidden, errClientDenied)
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
	// Restores are canceled with the restore permission, backups with backups.run.
	p := PermRunBackups
	if run.Kind == api.KindRestore {
		p = PermRestore
	}
	if !s.clientFilter(ctx, access(r), p)(run.ClientID) {
		httpError(w, http.StatusForbidden, errClientDenied)
		return
	}
	auditTarget(r, fmt.Sprintf("run %d of %s", run.ID, run.ClientName))
	if err := s.store.RequestCancel(ctx, id); err != nil {
		httpError(w, 500, err)
		return
	}
	s.wakeClient(run.ClientID)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handlePushAgentUpdate(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermManageClients)
	if !ok {
		return
	}
	if c.Revoked {
		httpError(w, http.StatusConflict, errors.New("client is revoked"))
		return
	}
	if err := s.updater.PushAgent(r.Context(), c); err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	writeJSON(w, map[string]string{"version": s.cfg.Version})
}
