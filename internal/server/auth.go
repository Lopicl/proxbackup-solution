// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	sessionCookie = "proxbackup_session"
	sessionTTL    = 12 * time.Hour
	csrfHeader    = "X-PROXBACKUP-Request" // custom header: browsers won't send it cross-origin without CORS
	minPassword   = 10
)

var errInvalidLogin = errors.New("invalid username or password")

// HashPassword returns an argon2id hash in the form argon2id$<salt>$<hash>.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	h := argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, 32)
	return "argon2id$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(h)
}

func checkPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[1])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is checked for unknown users, so a sign-in takes as long whether
// or not the account exists.
var dummyHash = HashPassword("not a password")

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// EnsureAdmin creates the initial administrator "admin" if there are no users
// and returns the generated password (empty if users existed).
func (s *Server) EnsureAdmin(ctx context.Context, password string) (string, error) {
	n, err := s.store.UserCount(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	generated := password == ""
	if generated {
		password = randToken(12)
	}
	// A generated password only ever appears in the log: make the admin replace it.
	return password, s.store.SetLocalPassword(ctx, "admin", HashPassword(password), generated)
}

type ctxKey int

const (
	sessionUserKey ctxKey = 2 // *SessionUser
	auditKey       ctxKey = 3 // *auditInfo
)

func sessionUser(r *http.Request) *SessionUser {
	u, _ := r.Context().Value(sessionUserKey).(*SessionUser)
	return u
}

func access(r *http.Request) *Access {
	if u := sessionUser(r); u != nil {
		return u.Access
	}
	return nil
}

// requireUser authenticates the console session and records changes in the
// audit log.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			httpError(w, http.StatusUnauthorized, errors.New("login required"))
			return
		}
		u, err := s.store.SessionUser(r.Context(), hashToken(c.Value))
		if err != nil {
			httpError(w, http.StatusUnauthorized, errors.New("session expired"))
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) == "" {
			httpError(w, http.StatusForbidden, fmt.Errorf("missing %s header", csrfHeader))
			return
		}
		if u.MustChange && r.URL.Path != "/api/me" && r.URL.Path != "/api/password" {
			httpError(w, http.StatusForbidden, errors.New("change your password first"))
			return
		}
		ai := &auditInfo{}
		ctx := context.WithValue(r.Context(), sessionUserKey, u)
		ctx = context.WithValue(ctx, auditKey, ai)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))
		if ai.pattern != "" && (r.Method != http.MethodGet || ai.force) {
			s.recordAudit(r, u, ai, rec.status)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// need wraps a handler that requires permission p. Client-level permissions
// need it for some clients (the handler checks the client); the others, and
// all of them with global, need it for all clients.
func (s *Server) need(p Perm, h http.HandlerFunc) http.HandlerFunc {
	return s.needScope(p, false, h)
}

// needGlobal wraps a handler that requires p for all clients.
func (s *Server) needGlobal(p Perm, h http.HandlerFunc) http.HandlerFunc {
	return s.needScope(p, true, h)
}

func (s *Server) needScope(p Perm, global bool, h http.HandlerFunc) http.HandlerFunc {
	info, _ := permInfo(p)
	global = global || !info.ClientLevel
	return func(w http.ResponseWriter, r *http.Request) {
		noteRoute(r)
		a := access(r)
		if global && !a.Global(p) || !a.Has(p) {
			msg := "you don't have the permission: " + info.Label
			if global && a.Has(p) {
				msg += " (for all clients)"
			}
			httpError(w, http.StatusForbidden, errors.New(msg))
			return
		}
		h(w, r)
	}
}

// needAny wraps a handler that requires one of ps (for some clients).
func (s *Server) needAny(h http.HandlerFunc, ps ...Perm) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noteRoute(r)
		for _, p := range ps {
			if access(r).Has(p) {
				h(w, r)
				return
			}
		}
		httpError(w, http.StatusForbidden, errors.New("you don't have the permission for this"))
	}
}

// signedIn wraps a handler any signed-in user may call.
func signedIn(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noteRoute(r)
		h(w, r)
	}
}

var errClientDenied = errors.New("you don't have the permission for this client")

// allowClient loads a client and checks p for it. On failure it has written
// the error.
func (s *Server) allowClient(w http.ResponseWriter, r *http.Request, p Perm, id int64) (*Client, bool) {
	c, err := s.store.Client(r.Context(), id)
	if err != nil {
		httpError(w, statusFor(err), err)
		return nil, false
	}
	if !access(r).Client(p, c) {
		httpError(w, http.StatusForbidden, errClientDenied)
		return nil, false
	}
	auditTarget(r, "client "+c.Name)
	return c, true
}

// pathClient is allowClient for the client in the {id} path value.
func (s *Server) pathClient(w http.ResponseWriter, r *http.Request, p Perm) (*Client, bool) {
	id, err := pathID(r)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return nil, false
	}
	return s.allowClient(w, r, p, id)
}

// clientFilter returns whether a client id may be seen with p, for filtering
// lists. It also accounts for revoked clients (run history).
func (s *Server) clientFilter(ctx context.Context, a *Access, p Perm) func(id int64) bool {
	if a.Global(p) {
		return func(int64) bool { return true }
	}
	if !a.Has(p) {
		return func(int64) bool { return false }
	}
	tags, _ := s.store.ClientTags(ctx)
	return func(id int64) bool { return a.Client(p, &Client{ID: id, Tags: tags[id]}) }
}

// scopeRuns limits f to the runs of clients the user may see.
func (s *Server) scopeRuns(ctx context.Context, a *Access, f *RunFilter) {
	if a.Global(PermViewClients) {
		return
	}
	ok := s.clientFilter(ctx, a, PermViewClients)
	tags, _ := s.store.ClientTags(ctx)
	f.Scoped, f.ClientIDs = true, []int64{}
	for id := range tags {
		if ok(id) {
			f.ClientIDs = append(f.ClientIDs, id)
		}
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	req.Username = strings.TrimSpace(req.Username)
	id, hash, enabled, err := s.store.UserByName(ctx, req.Username)
	if err != nil {
		hash = dummyHash
	}
	ok := checkPassword(hash, req.Password) && err == nil
	entry := &AuditEntry{UserID: id, Username: req.Username, Action: "sign-in", IP: clientIP(r)}
	if !ok || !enabled {
		entry.Status, entry.Detail = http.StatusUnauthorized, "wrong username or password"
		if ok {
			entry.Detail = "account disabled"
		}
		s.store.AddAudit(ctx, entry)
		time.Sleep(500 * time.Millisecond)
		httpError(w, http.StatusUnauthorized, errInvalidLogin)
		return
	}
	tok := randToken(32)
	if err := s.store.CreateSession(ctx, hashToken(tok), id, sessionTTL); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	s.store.TouchLogin(ctx, id)
	entry.Status = http.StatusOK
	s.store.AddAudit(ctx, entry)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	writeJSON(w, map[string]string{"username": req.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if u, err := s.store.SessionUser(r.Context(), hashToken(c.Value)); err == nil {
			s.store.AddAudit(r.Context(), &AuditEntry{UserID: u.ID, Username: u.Name, Action: "sign-out", Status: http.StatusOK, IP: clientIP(r)})
		}
		s.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := sessionUser(r)
	me := map[string]any{"id": u.ID, "username": u.Name, "version": s.cfg.Version,
		"must_change_password": u.MustChange, "local_account": !u.External, "permissions": u.Access}
	if l := s.cfg.LocalPBS; l != nil {
		me["local_pbs"] = map[string]string{"auth_id": l.AuthID, "host": l.PublicHost}
	}
	writeJSON(w, me)
}

func checkNewPassword(pw string) error {
	if len(pw) < minPassword {
		return fmt.Errorf("the password must be at least %d characters", minPassword)
	}
	return nil
}

// handleChangePassword sets a new password for the signed-in local account.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	u := sessionUser(r)
	auditTarget(r, "user "+u.Name)
	if u.External {
		httpError(w, http.StatusBadRequest, errors.New("this account signs in through an external identity provider"))
		return
	}
	hash, err := s.store.UserPasswordHash(r.Context(), u.ID)
	if err != nil || !checkPassword(hash, req.Current) {
		time.Sleep(500 * time.Millisecond)
		httpError(w, http.StatusBadRequest, errors.New("current password is wrong"))
		return
	}
	err = checkNewPassword(req.New)
	if err == nil && req.New == req.Current {
		err = errors.New("new password must differ from the current one")
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	c, _ := r.Cookie(sessionCookie)
	if err := s.store.SetUserPassword(r.Context(), u.ID, HashPassword(req.New), false, hashToken(c.Value)); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	s.log.Info("password changed", "user", u.Name)
	writeJSON(w, map[string]bool{"ok": true})
}
