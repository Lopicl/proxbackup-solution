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
	sessionCookie = "pbspc_session"
	sessionTTL    = 12 * time.Hour
	csrfHeader    = "X-PBSPC-Request" // custom header: browsers won't send it cross-origin without CORS
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
	if password == "" {
		password = randToken(12)
	}
	return password, s.store.UpsertAdmin(ctx, "admin", HashPassword(password))
}

type ctxKey int

const adminKey ctxKey = 1

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			httpError(w, http.StatusUnauthorized, errors.New("login required"))
			return
		}
		_, name, err := s.store.SessionAdmin(r.Context(), hashToken(c.Value))
		if err != nil {
			httpError(w, http.StatusUnauthorized, errors.New("session expired"))
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) == "" {
			httpError(w, http.StatusForbidden, fmt.Errorf("missing %s header", csrfHeader))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminKey, name)))
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
	id, hash, err := s.store.AdminByName(r.Context(), req.Username)
	if err != nil || !checkPassword(hash, req.Password) {
		time.Sleep(500 * time.Millisecond)
		httpError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
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
	writeJSON(w, map[string]any{"username": r.Context().Value(adminKey), "version": s.cfg.Version})
}
