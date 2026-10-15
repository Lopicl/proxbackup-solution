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
	"sync"
	"time"
)

// Config configures the management server.
type Config struct {
	DataDir   string
	UIAddr    string   // admin UI + API, e.g. ":8077"
	AgentAddr string   // separate agent mTLS endpoint; empty = served on UIAddr
	PublicURL string   // URL agents use to reach the agent API, e.g. "https://backup.example.com:8077"
	Hostnames []string // extra SANs for the server certificate
	Version   string
	LocalPBS  *LocalPBS // set when installed on the PBS host itself (see localpbs.go)
	// UpdateRepo is the GitHub repository (owner/name) releases come from; empty = update.DefaultRepo.
	UpdateRepo string
	// UpdateMode is "deb" when installed from the package (see updater.go).
	UpdateMode string
}

// Server is the management server.
type Server struct {
	cfg    Config
	store  *Store
	pki    *PKI
	sealer *Sealer
	log    *slog.Logger
	notify  *Notifier
	updater *updater

	wakeMu sync.Mutex
	wake   map[int64]chan struct{} // per-client long-poll wakeups

	versions pbsVersions
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
		servers = append(servers, &http.Server{Addr: s.cfg.UIAddr, Handler: mux})
	} else {
		servers = append(servers, &http.Server{Addr: s.cfg.UIAddr, Handler: ui}, &http.Server{Addr: s.cfg.AgentAddr, Handler: agent})
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

func displayAddr(a string) string {
	if len(a) > 0 && a[0] == ':' {
		return "localhost" + a
	}
	return a
}

func (s *Server) uiRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/login-info", s.handleLoginInfo)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	admin := http.NewServeMux()
	admin.HandleFunc("GET /api/me", s.handleMe)
	admin.HandleFunc("GET /api/dashboard", s.handleDashboard)
	admin.HandleFunc("GET /api/targets", s.handleTargets)
	admin.HandleFunc("POST /api/targets", s.handleSaveTarget)
	admin.HandleFunc("PUT /api/targets/{id}", s.handleSaveTarget)
	admin.HandleFunc("DELETE /api/targets/{id}", s.handleDeleteTarget)
	admin.HandleFunc("POST /api/targets/test", s.handleTestTarget)
	admin.HandleFunc("GET /api/clients", s.handleClients)
	admin.HandleFunc("GET /api/clients/{id}", s.handleClient)
	admin.HandleFunc("DELETE /api/clients/{id}", s.handleRevokeClient)
	admin.HandleFunc("GET /api/clients/{id}/snapshots", s.handleSnapshots)
	admin.HandleFunc("POST /api/clients/{id}/restore", s.handleRestore)
	admin.HandleFunc("POST /api/password", s.handleChangePassword)
	admin.HandleFunc("GET /api/enrollments", s.handleEnrollments)
	admin.HandleFunc("POST /api/enrollments", s.handleCreateEnrollment)
	admin.HandleFunc("GET /api/enrollments/{id}/command", s.handleEnrollmentCommand)
	admin.HandleFunc("DELETE /api/enrollments/{id}", s.handleDeleteEnrollment)
	admin.HandleFunc("GET /api/jobs", s.handleJobs)
	admin.HandleFunc("POST /api/jobs", s.handleSaveJob)
	admin.HandleFunc("PUT /api/jobs/{id}", s.handleSaveJob)
	admin.HandleFunc("DELETE /api/jobs/{id}", s.handleDeleteJob)
	admin.HandleFunc("POST /api/jobs/{id}/run", s.handleRunJob)
	admin.HandleFunc("GET /api/runs", s.handleRuns)
	admin.HandleFunc("GET /api/runs/{id}", s.handleRun)
	admin.HandleFunc("GET /api/runs/{id}/logs", s.handleRunLogs)
	admin.HandleFunc("POST /api/runs/{id}/cancel", s.handleCancelRun)
	admin.HandleFunc("GET /api/settings/notifications", s.handleGetNotify)
	admin.HandleFunc("PUT /api/settings/notifications", s.handleSaveNotify)
	admin.HandleFunc("POST /api/settings/notifications/test", s.handleTestNotify)
	admin.HandleFunc("GET /api/settings/updates", s.handleGetUpdates)
	admin.HandleFunc("PUT /api/settings/updates", s.handleSaveUpdates)
	admin.HandleFunc("POST /api/updates/check", s.handleCheckUpdates)
	admin.HandleFunc("POST /api/updates/install", s.handleInstallUpdate)
	admin.HandleFunc("GET /api/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(s.pki.CAPEM)
	})
	mux.Handle("/api/", s.requireAdmin(admin))
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

// housekeeping marks lost runs, trims history and checks for stale clients.
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
		if time.Since(lastDaily) > 24*time.Hour {
			lastDaily = time.Now()
			s.store.PruneHistory(ctx, 180*24*time.Hour)
			s.notify.CheckStale(ctx)
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
