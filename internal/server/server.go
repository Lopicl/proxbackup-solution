// SPDX-License-Identifier: AGPL-3.0-or-later

// Package server implements proxbackup-server: the management API, web UI and the
// control-plane endpoint agents connect to. Agents own their schedules: the
// server pushes job configuration and records what the agents report.
package server

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config configures the management server.
type Config struct {
	DataDir   string
	UIAddr    string   // admin UI + API, e.g. ":8077"; comma separated for several
	AgentAddr string   // separate agent mTLS endpoint(s); empty = served on UIAddr
	PublicURL string   // URL agents use to reach the agent API, e.g. "https://backup.example.com:8077"
	Hostnames []string // extra SANs for the server certificate
	Version   string
	LocalPBS  *LocalPBS // set when installed on the PBS host itself (see localpbs.go)
	// UpdateRepo is the GitHub repository (owner/name) releases come from; empty = update.DefaultRepo.
	UpdateRepo string
	// UpdateMode is "deb" when installed from the package (see updater.go).
	UpdateMode string
	// PrereleaseDefault turns pre-release updates on until the admin saves the
	// update settings (builds from the alpha branch).
	PrereleaseDefault bool
}

// Server is the management server.
type Server struct {
	cfg     Config
	store   *Store
	pki     *PKI
	sealer  *Sealer
	log     *slog.Logger
	notify  *Notifier
	updater *updater

	enrollMu sync.Mutex // serializes client creation (see enrollClient)

	wakeMu sync.Mutex
	wake   map[int64]chan struct{} // per-client long-poll wakeups

	capMu       sync.Mutex
	capNotified map[string]bool // "<job>/<day>" daily cap alerts already sent

	versions pbsVersions
	catalogs catalogCache // snapshot catalogs open in the restore browser
	storage  storageCache // datastore usage shown on the dashboard
}

// New opens the data directory and prepares the server.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	store, err := OpenStore(filepath.Join(cfg.DataDir, "proxbackup.db"))
	if err != nil {
		return nil, err
	}
	pki, err := LoadOrCreatePKI(cfg.DataDir, cfg.Hostnames)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	sealer, err := LoadOrCreateSealer(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: store, pki: pki, sealer: sealer, log: log, wake: map[int64]chan struct{}{}}
	s.notify = &Notifier{s: s}
	s.updater = newUpdater(s)
	return s, nil
}

// Store exposes the database (used by CLI commands).
func (s *Server) Store() *Store { return s.store }

// Run serves until ctx is canceled. It returns ErrRestart after the server
// replaced its own binary.
func (s *Server) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	s.updater.restart = func() { cancel(ErrRestart) }
	go s.housekeeping(ctx)
	go s.updater.loop(ctx)
	if s.cfg.LocalPBS != nil {
		go s.localPBSLoop(ctx)
	}

	// Agents present a client certificate, browsers don't: one TLS config that
	// asks for (but doesn't require) a certificate serves both.
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{s.pki.Server},
		ClientCAs:    s.caPool(),
		ClientAuth:   tls.VerifyClientCertIfGiven, // enrollment and the UI work without one
		MinVersion:   tls.VersionTLS12,
	}
	ui, agent := securityHeaders(s.uiRoutes()), s.agentRoutes()
	var servers []*http.Server
	if s.cfg.AgentAddr == "" || s.cfg.AgentAddr == s.cfg.UIAddr {
		mux := http.NewServeMux()
		mux.Handle("/agent/", agent)
		mux.Handle("/", ui)
		for _, a := range splitAddrs(s.cfg.UIAddr) {
			servers = append(servers, &http.Server{Addr: a, Handler: mux})
		}
	} else {
		for _, a := range splitAddrs(s.cfg.UIAddr) {
			servers = append(servers, &http.Server{Addr: a, Handler: ui})
		}
		for _, a := range splitAddrs(s.cfg.AgentAddr) {
			servers = append(servers, &http.Server{Addr: a, Handler: agent})
		}
	}
	errc := make(chan error, len(servers))
	for _, hs := range servers {
		hs.TLSConfig, hs.ReadHeaderTimeout = tlsConf, 10*time.Second
		go func() { errc <- hs.ListenAndServeTLS("", "") }()
	}
	s.log.Info("proxbackup-server listening", "ui", "https://"+displayAddr(s.cfg.UIAddr), "agents", cmp.Or(s.cfg.AgentAddr, s.cfg.UIAddr), "public_url", s.cfg.PublicURL)
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	for _, hs := range servers {
		hs.Shutdown(shutdown)
	}
	if err := s.store.Close(); err != nil {
		return err
	}
	if errors.Is(context.Cause(ctx), ErrRestart) {
		return ErrRestart
	}
	return nil
}

// splitAddrs splits a comma separated listen address list, e.g. to keep the
// old address up while agents move to a new PROXBACKUP_PUBLIC_URL.
func splitAddrs(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return []string{s}
	}
	return out
}

func displayAddr(a string) string {
	a, _, _ = strings.Cut(a, ",")
	if len(a) > 0 && a[0] == ':' {
		return "localhost" + a
	}
	return a
}

func (s *Server) uiRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// Every route states the permission it needs (see users.go). Client-level
	// handlers also check the client they act on, list handlers filter.
	view, manage, jobs, run, restore := PermViewClients, PermManageClients, PermManageJobs, PermRunBackups, PermRestore
	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", signedIn(s.handleMe))
	api.HandleFunc("POST /api/password", signedIn(s.handleChangePassword))
	api.HandleFunc("GET /api/dashboard", s.need(view, s.handleDashboard))
	api.HandleFunc("GET /api/storage", s.need(view, s.handleStorage))
	api.HandleFunc("GET /api/targets", s.needAny(s.handleTargets, view, PermTargets))
	api.HandleFunc("POST /api/targets", s.need(PermTargets, s.handleSaveTarget))
	api.HandleFunc("PUT /api/targets/{id}", s.need(PermTargets, s.handleSaveTarget))
	api.HandleFunc("DELETE /api/targets/{id}", s.need(PermTargets, s.handleDeleteTarget))
	api.HandleFunc("POST /api/targets/test", s.need(PermTargets, s.handleTestTarget))
	api.HandleFunc("GET /api/clients", s.need(view, s.handleClients))
	api.HandleFunc("GET /api/clients/{id}", s.need(view, s.handleClient))
	api.HandleFunc("DELETE /api/clients/{id}", s.need(manage, s.handleRevokeClient))
	api.HandleFunc("GET /api/clients/revoked", s.need(view, s.handleRevokedClients))
	api.HandleFunc("POST /api/clients/{id}/unrevoke", s.need(manage, s.handleUnrevokeClient))
	api.HandleFunc("POST /api/clients/{id}/agent-update", s.need(manage, s.handlePushAgentUpdate))
	api.HandleFunc("GET /api/clients/{id}/snapshots", s.need(restore, s.handleSnapshots))
	api.HandleFunc("GET /api/clients/{id}/catalog", s.need(restore, s.handleCatalog))
	api.HandleFunc("POST /api/clients/{id}/restore", s.need(restore, s.handleRestore))
	api.HandleFunc("GET /api/clients/{id}/encryption-key", s.need(restore, s.handleClientKey))
	// Tags decide which clients scoped roles cover: only for all clients.
	api.HandleFunc("PUT /api/clients/{id}/tags", s.needGlobal(manage, s.handleClientTags))
	api.HandleFunc("PUT /api/clients/{id}/bandwidth", s.need(manage, s.handleClientBandwidth))
	// New clients aren't in anyone's scope yet: enrolling needs all clients.
	api.HandleFunc("GET /api/enrollments", s.needGlobal(manage, s.handleEnrollments))
	api.HandleFunc("POST /api/enrollments", s.needGlobal(manage, s.handleCreateEnrollment))
	api.HandleFunc("GET /api/enrollments/{id}/command", s.needGlobal(manage, s.handleEnrollmentCommand))
	api.HandleFunc("DELETE /api/enrollments/{id}", s.needGlobal(manage, s.handleDeleteEnrollment))
	api.HandleFunc("GET /api/setup-tokens", s.needGlobal(manage, s.handleSetupTokens))
	api.HandleFunc("POST /api/setup-tokens", s.needGlobal(manage, s.handleCreateSetupToken))
	api.HandleFunc("GET /api/setup-tokens/{id}", s.needGlobal(manage, s.handleSetupToken))
	api.HandleFunc("GET /api/setup-tokens/{id}/download/{arch}", s.needGlobal(manage, s.handleSetupDownload))
	api.HandleFunc("DELETE /api/setup-tokens/{id}", s.needGlobal(manage, s.handleDeleteSetupToken))
	api.HandleFunc("GET /api/jobs", s.need(view, s.handleJobs))
	api.HandleFunc("PUT /api/jobs/{id}", s.need(jobs, s.handleSaveMember))
	api.HandleFunc("DELETE /api/jobs/{id}", s.need(jobs, s.handleDeleteJob))
	api.HandleFunc("POST /api/jobs/{id}/run", s.need(run, s.handleRunJob))
	api.HandleFunc("GET /api/group-jobs", s.need(view, s.handleGroupJobs))
	api.HandleFunc("GET /api/group-jobs/{id}", s.need(view, s.handleGroupJob))
	// A group job's definition applies to clients by tag: for all clients.
	api.HandleFunc("POST /api/group-jobs", s.needGlobal(jobs, s.handleSaveGroupJob))
	api.HandleFunc("PUT /api/group-jobs/{id}", s.needGlobal(jobs, s.handleSaveGroupJob))
	api.HandleFunc("DELETE /api/group-jobs/{id}", s.needGlobal(jobs, s.handleDeleteGroupJob))
	api.HandleFunc("POST /api/group-jobs/{id}/run", s.need(run, s.handleRunGroupJob))
	api.HandleFunc("GET /api/runs", s.need(view, s.handleRuns))
	api.HandleFunc("GET /api/runs/{id}", s.need(view, s.handleRun))
	api.HandleFunc("GET /api/runs/{id}/logs", s.need(view, s.handleRunLogs))
	api.HandleFunc("POST /api/runs/{id}/cancel", signedIn(s.handleCancelRun)) // backups.run or restore, by run
	api.HandleFunc("GET /api/settings/notifications", s.need(PermNotifications, s.handleGetNotify))
	api.HandleFunc("PUT /api/settings/notifications", s.need(PermNotifications, s.handleSaveNotify))
	api.HandleFunc("POST /api/settings/notifications/test", s.need(PermNotifications, s.handleTestNotify))
	api.HandleFunc("GET /api/settings/updates", s.need(PermUpdates, s.handleGetUpdates))
	api.HandleFunc("PUT /api/settings/updates", s.need(PermUpdates, s.handleSaveUpdates))
	api.HandleFunc("GET /api/settings/encryption", signedIn(s.handleGetEncryption)) // public key only
	api.HandleFunc("PUT /api/settings/encryption", s.need(PermEncryption, s.handleSaveEncryption))
	api.HandleFunc("POST /api/updates/check", s.need(PermUpdates, s.handleCheckUpdates))
	api.HandleFunc("POST /api/updates/install", s.need(PermUpdates, s.handleInstallUpdate))
	api.HandleFunc("GET /api/permissions", s.need(PermUsers, s.handlePermissions))
	api.HandleFunc("GET /api/users", s.need(PermUsers, s.handleUsers))
	api.HandleFunc("POST /api/users", s.need(PermUsers, s.handleCreateUser))
	api.HandleFunc("PUT /api/users/{id}", s.need(PermUsers, s.handleUpdateUser))
	api.HandleFunc("DELETE /api/users/{id}", s.need(PermUsers, s.handleDeleteUser))
	api.HandleFunc("POST /api/users/{id}/password", s.need(PermUsers, s.handleResetPassword))
	api.HandleFunc("GET /api/roles", s.need(PermUsers, s.handleRoles))
	api.HandleFunc("POST /api/roles", s.need(PermUsers, s.handleSaveRole))
	api.HandleFunc("PUT /api/roles/{id}", s.need(PermUsers, s.handleSaveRole))
	api.HandleFunc("DELETE /api/roles/{id}", s.need(PermUsers, s.handleDeleteRole))
	api.HandleFunc("GET /api/audit", s.need(PermAudit, s.handleAudit))
	api.HandleFunc("GET /api/ca.pem", signedIn(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.pki.CAPEM)
	}))
	s.selfRestoreRoutes(mux) // authenticated by the restore session, not a login
	mux.Handle("/api/", s.requireUser(api))
	mux.Handle("/", webHandler())
	return mux
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

// wakeClient interrupts a pending long-poll of the client so new work is picked up immediately.
func (s *Server) wakeClient(id int64) {
	s.wakeMu.Lock()
	ch := s.wake[id]
	if ch != nil {
		close(ch)
		delete(s.wake, id)
	}
	s.wakeMu.Unlock()
}

func (s *Server) wakeChan(id int64) <-chan struct{} {
	s.wakeMu.Lock()
	defer s.wakeMu.Unlock()
	ch := s.wake[id]
	if ch == nil {
		ch = make(chan struct{})
		s.wake[id] = ch
	}
	return ch
}

// housekeeping marks lost runs, trims history, checks for stale clients,
// releases expired snapshot locks and applies retention.
func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	lastDaily := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if ids, err := s.store.MarkLost(ctx, 30*time.Minute); err == nil {
			for _, id := range ids {
				s.log.Warn("run lost", "run", id)
				if r, err := s.store.Run(ctx, id); err == nil {
					s.notify.RunFinished(ctx, r)
				}
			}
		}
		s.store.PruneRestoreSessions(ctx)
		if time.Since(lastDaily) > 24*time.Hour {
			lastDaily = time.Now()
			s.store.PruneHistory(ctx, 180*24*time.Hour)
			s.store.PruneAudit(ctx, auditRetention)
			s.notify.CheckStale(ctx)
			s.releaseLocks(ctx)
			s.applyRetention(ctx)
		}
	}
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

func statusFor(err error) int {
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}
