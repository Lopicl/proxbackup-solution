// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// Self-service restore: "Restore files…" in the tray app asks the agent,
// which identifies the Windows user from the named pipe and registers a
// restore session here (POST /agent/v1/restore-sessions). The tray then opens
// /#/restore/<token>: a page for that one client that needs no console login.
// The token in the URL fragment authenticates the page's API calls
// (X-Restore-Session header); it never appears in a request line.
//
// Administrators of the PC may restore everything. Other users only see and
// restore their profile folder; the agent checks that again and writes their
// files with their own Windows rights.

const (
	restoreSessionHeader = "X-Restore-Session"
	restoreSessionIdle   = time.Hour
	restoreSessionMax    = 8 * time.Hour
	// A client has at most this many live restore pages; opening another
	// one ends its oldest.
	maxLiveRestoreSessions = 10
)

type restoreSession struct {
	ClientID int64
	User     string
	SID      string
	Admin    bool
	Scope    string // "" = everything
	AgentRef string
	Expires  int64
}

var windowsDirRe = regexp.MustCompile(`^[A-Za-z]:\\[^<>:"|?*]*$`)

// CreateRestoreSession stores a restore session and ends the client's
// oldest ones beyond maxLiveRestoreSessions.
func (s *Store) CreateRestoreSession(ctx context.Context, tokenHash string, clientID int64, req api.RestoreSessionRequest, ttl time.Duration) (int64, error) {
	n := time.Now()
	expires := n.Add(min(restoreSessionIdle, ttl)).Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO restore_sessions(token_hash, client_id, user_name, user_sid, admin, scope, agent_ref,
		created_at, max_expires, expires) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		tokenHash, clientID, req.User, req.SID, req.Admin, req.Scope, req.Ref, n.Unix(), n.Add(ttl).Unix(), expires); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM restore_sessions WHERE client_id=? AND token_hash NOT IN
		(SELECT token_hash FROM restore_sessions WHERE client_id=? AND expires>? ORDER BY created_at DESC, rowid DESC LIMIT ?)`,
		clientID, clientID, n.Unix(), maxLiveRestoreSessions); err != nil {
		return 0, err
	}
	return expires, tx.Commit()
}

// RestoreSession returns a live session and extends its idle timeout.
func (s *Store) RestoreSession(ctx context.Context, tokenHash string) (*restoreSession, error) {
	rs := &restoreSession{}
	var maxExp int64
	err := s.db.QueryRowContext(ctx, `SELECT client_id, user_name, user_sid, admin, scope, agent_ref, max_expires FROM restore_sessions
		WHERE token_hash=? AND expires>?`, tokenHash, now()).Scan(&rs.ClientID, &rs.User, &rs.SID, &rs.Admin, &rs.Scope, &rs.AgentRef, &maxExp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	rs.Expires = min(time.Now().Add(restoreSessionIdle).Unix(), maxExp)
	s.db.ExecContext(ctx, `UPDATE restore_sessions SET expires=? WHERE token_hash=?`, rs.Expires, tokenHash)
	return rs, nil
}

func (s *Store) PruneRestoreSessions(ctx context.Context) {
	s.db.ExecContext(ctx, `DELETE FROM restore_sessions WHERE expires<=?`, now())
}

// handleCreateRestoreSession: POST /agent/v1/restore-sessions.
func (s *Server) handleCreateRestoreSession(w http.ResponseWriter, r *http.Request, c *Client) {
	var req api.RestoreSessionRequest
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	// Too long is refused, not cut: a shorter Scope would be a wider one.
	switch {
	case len(req.Ref) < 16 || len(req.Ref) > maxAgentToken || req.User == "" || len(req.User) > maxAgentName ||
		len(req.SID) > maxAgentName || len(req.Scope) > maxAgentPath:
		httpError(w, 400, errors.New("invalid restore session"))
		return
	case !req.Admin && !windowsDirRe.MatchString(req.Scope):
		httpError(w, 400, errors.New("a restore session for a user who isn't an administrator needs their profile folder"))
		return
	}
	if req.Admin {
		req.Scope = ""
	}
	if !s.restores.allow(c.ID, time.Now()) {
		w.Header().Set("Retry-After", "120")
		httpError(w, http.StatusTooManyRequests, errors.New("too many restore pages opened on this PC; try again in a few minutes"))
		return
	}
	ttl := time.Duration(req.TTL) * time.Second
	if ttl <= 0 || ttl > restoreSessionMax {
		ttl = restoreSessionMax
	}
	token := randToken(32)
	expires, err := s.store.CreateRestoreSession(r.Context(), hashToken(token), c.ID, req, ttl)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	s.log.Info("restore page opened on the PC", "client", c.Name, "user", req.User, "admin", req.Admin, "scope", req.Scope)
	writeJSON(w, api.RestoreSessionResponse{URL: s.uiBaseURL(r) + "/#/restore/" + token, Expires: expires})
}

// uiBaseURL is the web UI's address as the PC sees the console: the host the
// agent connected to, on the UI port if agents use a separate listener.
func (s *Server) uiBaseURL(r *http.Request) string {
	host := r.Host
	if s.cfg.AgentAddr != "" && s.cfg.AgentAddr != s.cfg.UIAddr {
		uiAddr, _, _ := strings.Cut(s.cfg.UIAddr, ",")
		if _, port, err := net.SplitHostPort(strings.TrimSpace(uiAddr)); err == nil {
			h := host
			if hh, _, err := net.SplitHostPort(host); err == nil {
				h = hh
			}
			host = net.JoinHostPort(h, port)
		}
	}
	return (&url.URL{Scheme: "https", Host: host}).String()
}

type selfRestoreHandler func(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client)

func (s *Server) requireRestoreSession(h selfRestoreHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(restoreSessionHeader)
		if token == "" {
			httpError(w, http.StatusUnauthorized, errors.New("restore session required"))
			return
		}
		rs, err := s.store.RestoreSession(r.Context(), hashToken(token))
		if err != nil {
			httpError(w, http.StatusUnauthorized, errors.New(`this restore page has expired; choose "Restore files…" in the ProxBackup tray icon again`))
			return
		}
		c, err := s.store.Client(r.Context(), rs.ClientID)
		if err != nil || c.Revoked {
			httpError(w, http.StatusUnauthorized, errors.New("this PC is no longer managed by the console"))
			return
		}
		h(w, r, rs, c)
	}
}

func (s *Server) selfRestoreRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/self-restore/session", s.requireRestoreSession(s.handleSelfSession))
	mux.HandleFunc("GET /api/self-restore/snapshots", s.requireRestoreSession(s.handleSelfSnapshots))
	mux.HandleFunc("GET /api/self-restore/catalog", s.requireRestoreSession(s.handleSelfCatalog))
	mux.HandleFunc("POST /api/self-restore/restore", s.requireRestoreSession(s.handleSelfRestore))
	mux.HandleFunc("GET /api/self-restore/runs", s.requireRestoreSession(s.handleSelfRuns))
}

func (s *Server) handleSelfSession(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) {
	writeJSON(w, map[string]any{"client_name": c.Name, "hostname": c.Hostname, "online": c.Online,
		"user": rs.User, "admin": rs.Admin, "scope": rs.Scope, "expires": rs.Expires})
}

func (s *Server) handleSelfSnapshots(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) {
	snaps, code, err := s.clientSnapshots(r.Context(), c)
	if err != nil {
		httpError(w, code, err)
		return
	}
	writeJSON(w, orEmpty(snaps))
}

// handleSelfCatalog lists a catalog directory, limited to what leads to or
// lies within the user's scope.
func (s *Server) handleSelfCatalog(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) {
	q := r.URL.Query()
	dir := strings.Trim(q.Get("path"), "/")
	archive, rel, _ := strings.Cut(dir, "/")
	var origins map[string]string
	if rs.Scope != "" {
		origins = s.archiveOrigins(r.Context(), c.ID, q.Get("backup_id"))
		if archive != "" {
			within, ancestor := api.InScope(api.OriginPath(origins[archive], rel), rs.Scope)
			if origins[archive] == "" || !within && !ancestor {
				httpError(w, http.StatusForbidden, errors.New("you can only browse your own folder "+rs.Scope))
				return
			}
		} else if !slices.ContainsFunc(slices.Collect(maps.Values(origins)), func(o string) bool {
			within, ancestor := api.InScope(api.OriginPath(o, ""), rs.Scope)
			return within || ancestor
		}) {
			// None of the snapshot's archives can hold the user's folder: the
			// listing would be empty, so the catalog isn't downloaded.
			writeJSON(w, []catalogEntry{})
			return
		}
	}
	// All restore pages of a PC share one rate of catalog loads: the agent
	// may open many.
	list, code, err := s.catalogDir(r.Context(), c, fmt.Sprintf("pc %d", c.ID), q)
	if err != nil {
		catalogError(w, code, err)
		return
	}
	if rs.Scope != "" {
		list = slices.DeleteFunc(list, func(e catalogEntry) bool {
			var p string
			if archive == "" {
				if origins[e.Name] == "" {
					return true
				}
				p = api.OriginPath(origins[e.Name], "")
			} else {
				p = api.OriginPath(origins[archive], strings.TrimPrefix(rel+"/"+e.Name, "/"))
			}
			within, ancestor := api.InScope(p, rs.Scope)
			return !within && !(ancestor && e.Type == "dir")
		})
	}
	writeJSON(w, list)
}

func (s *Server) handleSelfRestore(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) {
	var req api.RestoreSpec
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	if err := validateRestore(&req, c); err != nil {
		httpError(w, 400, err)
		return
	}
	archive := req.Archive
	if label, ok := strings.CutSuffix(archive, ".ppxar.didx"); ok {
		archive = label + ".mpxar.didx"
	}
	ctx := r.Context()
	origin := s.archiveOrigins(ctx, c.ID, req.BackupID)[archive]
	if err := api.RestoreAllowed(rs.Scope, origin, req.Paths, req.TargetDir, strings.HasSuffix(archive, ".img.fidx")); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	req.Session, req.RequestedBy = rs.AgentRef, rs.User
	runID, err := s.store.QueueRun(ctx, 0, c.ID, api.KindRestore, api.TriggerManual, &req)
	if err != nil {
		httpError(w, 400, err)
		return
	}
	s.log.Info("restore requested on the PC", "client", c.Name, "user", rs.User, "run", runID, "archive", req.Archive, "target", req.TargetDir)
	s.wakeClient(c.ID)
	writeJSON(w, map[string]int64{"run_id": runID})
}

// selfRun is a restore run as its requester sees it.
type selfRun struct {
	ID         int64        `json:"id"`
	State      string       `json:"state"`
	Archive    string       `json:"archive"`
	TargetDir  string       `json:"target_dir"`
	Paths      []string     `json:"paths"`
	QueuedAt   int64        `json:"queued_at"`
	FinishedAt int64        `json:"finished_at"`
	Progress   api.Progress `json:"progress"`
	Result     api.Result   `json:"result"`
	Error      string       `json:"error"`
}

func (s *Server) handleSelfRuns(w http.ResponseWriter, r *http.Request, rs *restoreSession, c *Client) {
	runs, err := s.store.Runs(r.Context(), RunFilter{ClientID: c.ID, Limit: 500})
	if err != nil {
		httpError(w, 500, err)
		return
	}
	out := []selfRun{}
	for _, run := range runs {
		if run.Restore == nil || run.Restore.Session != rs.AgentRef {
			continue
		}
		out = append(out, selfRun{ID: run.ID, State: run.State, Archive: run.Restore.Archive, TargetDir: run.Restore.TargetDir,
			Paths: nonNil(run.Restore.Paths), QueuedAt: run.QueuedAt, FinishedAt: run.FinishedAt, Progress: run.Progress,
			Result: run.Result, Error: run.Error})
	}
	writeJSON(w, out)
}

// validateRestore checks a restore request for client c and normalizes it.
func validateRestore(req *api.RestoreSpec, c *Client) error {
	if req.BackupID == "" || req.BackupTime == 0 || req.Archive == "" || req.TargetDir == "" {
		return errors.New("backup_id, backup_time, archive and target_dir are required")
	}
	if err := api.CheckLocalPaths("target folder", req.TargetDir); err != nil {
		return err
	}
	if !pbs.ValidArchiveName(req.Archive) || strings.HasSuffix(req.Archive, ".blob") {
		return errors.New("archive must be a .pxar.didx, .mpxar.didx or .img.fidx archive")
	}
	switch req.Overwrite {
	case "":
		req.Overwrite = "skip"
	case "skip", "overwrite", "if-newer":
	default:
		return errors.New("overwrite must be skip, overwrite or if-newer")
	}
	switch {
	case req.Namespace == c.Namespace:
		req.Namespace = ""
	case req.Namespace != "" && !slices.Contains(c.OldNamespaces, req.Namespace):
		return errors.New("snapshot namespace does not belong to this client")
	}
	req.Session, req.RequestedBy, req.SystemFolders = "", "", false
	return nil
}

// restoreSystemAllowed decides whether a console restore to client c may
// write into protected system folders (see api.ProtectedFolder): only if the
// user has the "Restore to system folders" permission (system) and the PC
// allows it (no api.FeatureNoConsoleSystemRestores). Otherwise,
// targets there are refused, and the agent skips what would land in them;
// Windows agents that can't do that get no such restores.
func restoreSystemAllowed(req *api.RestoreSpec, c *Client, system bool) error {
	pcRefuses := slices.Contains(c.Features, api.FeatureNoConsoleSystemRestores)
	if system && !pcRefuses {
		req.SystemFolders = true
		return nil
	}
	if f := api.ProtectedFolder(req.TargetDir); f != "" {
		if system {
			return fmt.Errorf(`%s is a protected system folder, and this PC doesn't allow restores there from the console (a PC administrator can allow it on the PC: proxbackup-agent policy -console-system-restores on)`, f)
		}
		return fmt.Errorf(`%s is a protected system folder: restoring there needs the "Restore to system folders" permission`, f)
	}
	// The OS is unknown until the agent first connects.
	if goos, _, _ := strings.Cut(c.OS, "/"); (goos == "windows" || goos == "") && !slices.Contains(c.Features, api.FeatureProtectedRestore) {
		return fmt.Errorf(`the agent on this PC (%s) can't keep restores out of system folders; update the agent, or ask someone with the "Restore to system folders" permission to restore`, c.AgentVersion)
	}
	return nil
}
