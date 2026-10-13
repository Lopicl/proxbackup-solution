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
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	sessionCookie = "proxbackup_session"
	sessionTTL    = 12 * time.Hour
	csrfHeader    = "X-PROXBACKUP-Request" // custom header: browsers won't send it cross-origin without CORS
)

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

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// EnsureAdmin creates the initial admin account if none exists and returns the
// generated password (empty if an admin already existed).
func (s *Server) EnsureAdmin(ctx context.Context, password string) (string, error) {
	n, err := s.store.AdminCount(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	generated := password == ""
	if generated {
		password = randToken(12)
	}
	// A generated password only ever appears in the log: make the admin replace it.
	return password, s.store.UpsertAdmin(ctx, "admin", HashPassword(password), generated)
}

type ctxKey int

const (
	adminKey       ctxKey = 1 // admin username (string)
	sessionUserKey ctxKey = 2 // *SessionUser
)

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			httpError(w, http.StatusUnauthorized, errors.New("login required"))
			return
		}
		u, err := s.store.SessionAdmin(r.Context(), hashToken(c.Value))
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
		ctx := context.WithValue(r.Context(), adminKey, u.Name)
		ctx = context.WithValue(ctx, sessionUserKey, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
	var id int64
	if s.cfg.LocalPBS != nil && strings.Contains(req.Username, "@") {
		// PBS account (user@realm): PBS checks the password and admin rights.
		err := s.pbsLogin(r.Context(), req.Username, req.Password)
		if err == nil {
			id, err = s.store.EnsureExternalAdmin(r.Context(), req.Username)
		}
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			code := http.StatusUnauthorized
			if !errors.Is(err, errInvalidLogin) && !errors.Is(err, errPBSLoginDenied) {
				code = http.StatusBadGateway
			}
			s.log.Warn("PBS login failed", "user", req.Username, "err", err)
			httpError(w, code, err)
			return
		}
	} else {
		var hash string
		var err error
		id, hash, err = s.store.AdminByName(r.Context(), req.Username)
		if err != nil || !checkPassword(hash, req.Password) {
			time.Sleep(500 * time.Millisecond)
			httpError(w, http.StatusUnauthorized, errInvalidLogin)
			return
		}
	}
	tok := randToken(32)
	if err := s.store.CreateSession(r.Context(), hashToken(tok), id, sessionTTL); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	writeJSON(w, map[string]string{"username": req.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value(sessionUserKey).(*SessionUser)
	me := map[string]any{"username": u.Name, "version": s.cfg.Version,
		"must_change_password": u.MustChange, "local_account": !u.External}
	if l := s.cfg.LocalPBS; l != nil {
		me["local_pbs"] = map[string]string{"auth_id": l.AuthID, "host": l.PublicHost}
	}
	writeJSON(w, me)
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
	u := r.Context().Value(sessionUserKey).(*SessionUser)
	if u.External {
		httpError(w, http.StatusBadRequest, errors.New("PBS accounts change their password in PBS"))
		return
	}
	hash, err := s.store.AdminPasswordHash(r.Context(), u.ID)
	if err != nil || !checkPassword(hash, req.Current) {
		time.Sleep(500 * time.Millisecond)
		httpError(w, http.StatusBadRequest, errors.New("current password is wrong"))
		return
	}
	switch {
	case len(req.New) < 10:
		err = errors.New("new password must be at least 10 characters")
	case req.New == req.Current:
		err = errors.New("new password must differ from the current one")
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	c, _ := r.Cookie(sessionCookie)
	if err := s.store.SetAdminPassword(r.Context(), u.ID, HashPassword(req.New), hashToken(c.Value)); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	s.log.Info("admin password changed", "user", u.Name)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleLoginInfo tells the login page whether PBS accounts can sign in.
func (s *Server) handleLoginInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"pbs_login": s.cfg.LocalPBS != nil})
}
