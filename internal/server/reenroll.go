// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"proxbackup/internal/api"
)

// Revoked clients keep their PBS namespace and snapshots. Only a
// re-enrollment, which needs PermManageRevoked, hands them to a PC again: the
// PC that uses it takes over the revoked client (name, namespaces, backups,
// run history, tags, escrowed encryption key) with a new certificate and PBS
// token. The old PC still has the encryption key in its configuration, so by
// default the client backs up with a new key from then on; the old key stays
// escrowed for the snapshots made with it. Every other enrollment gets PBS storage of its own (see
// freeStorageName), even under a revoked client's name.

// baseName is the client's name, without the "#revoked-<id>" a revoked
// client carries.
func (c *Client) baseName() string {
	return strings.TrimSuffix(c.Name, fmt.Sprintf("#revoked-%d", c.ID))
}

// tokenName is the name of the client's PBS token, which is also the last
// part of its namespace: the client name, or "<name>.<n>" for a client
// enrolled under the name of a revoked one.
func tokenName(c *Client) string {
	if _, n, ok := strings.Cut(c.TokenID, "!"); ok && n != "" {
		return n
	}
	return c.baseName()
}

// freeStorageName returns the name for a new client's PBS token and
// namespace: its own name unless a client, revoked ones included, used that
// storage; then "<name>.2", "<name>.3"… Client names can't contain dots, so
// these can't be another client's name.
func (s *Server) freeStorageName(ctx context.Context, t *Target, name string) string {
	for n := 1; ; n++ {
		leaf := name
		if n > 1 {
			leaf = fmt.Sprintf("%s.%d", name, n)
		}
		if !s.store.StorageUsed(ctx, leaf, clientNamespace(t, leaf)) {
			return leaf
		}
	}
}

// reissueToken creates a new PBS token for a revoked client under its old
// token name and grants it its namespaces again. drop deletes the token if
// the caller can't use it.
func (s *Server) reissueToken(ctx context.Context, t *Target, c *Client) (tokenID, secret string, drop func(), err error) {
	pc, err := s.adminClient(t)
	if err != nil {
		return "", "", nil, err
	}
	tok := tokenName(c)
	pc.DeleteToken(ctx, t.PBSUser, tok) // stale token of the same name
	tokenID, secret, err = pc.CreateToken(ctx, t.PBSUser, tok, "proxbackup agent "+c.baseName())
	if err != nil {
		return "", "", nil, fmt.Errorf("PBS token: %w", err)
	}
	drop = func() { pc.DeleteToken(context.WithoutCancel(ctx), t.PBSUser, tok) }
	for _, ns := range append([]string{c.Namespace}, c.OldNamespaces...) {
		if err := prepareClientNamespace(ctx, pc, t, ns, tokenID); err != nil {
			drop()
			return "", "", nil, err
		}
	}
	return tokenID, secret, drop, nil
}

// reenrollClient completes a re-enrollment: the enrolling PC takes over the
// revoked client e.ReenrollID.
func (s *Server) reenrollClient(ctx context.Context, e *Enrollment, req api.EnrollRequest) (*Client, []byte, error) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	c, err := s.store.Client(ctx, e.ReenrollID)
	if err != nil {
		return nil, nil, fmt.Errorf("client to re-enroll: %w", err)
	}
	if !c.Revoked {
		return nil, nil, errors.New("the client to re-enroll was un-revoked or re-enrolled meanwhile")
	}
	name := c.baseName()
	if s.store.ClientNameTaken(ctx, name) {
		return nil, nil, fmt.Errorf("%w: %q is used by another client meanwhile", errClientNameTaken, name)
	}
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return nil, nil, fmt.Errorf("target: %w", err)
	}
	certPEM, serial, err := s.pki.SignClientCSR([]byte(req.CSR), name)
	if err != nil {
		return nil, nil, err
	}
	var rot *keyRotation
	if e.NewCryptKey && len(c.cryptKeyEnc) > 0 {
		if rot, err = s.newKeyRotation(c); err != nil {
			return nil, nil, err
		}
	}
	tokenID, secret, drop, err := s.reissueToken(ctx, t, c)
	if err != nil {
		return nil, nil, fmt.Errorf("PBS provisioning: %w", err)
	}
	if err := s.store.ReenrollClient(ctx, c, name, req.Hostname, req.OS, serial, tokenID, s.sealer.Seal(secret, colClientToken, c.ID), rot); err != nil {
		drop()
		return nil, nil, err
	}
	if rot != nil {
		s.log.Warn("re-enrolled client backs up with a new encryption key; the old one stays escrowed for its snapshots",
			"client", name, "old_fingerprint", c.EncryptionFingerprint, "fingerprint", rot.fingerprint)
	}
	if affected, err := s.store.SyncAllGroups(ctx); err != nil {
		s.log.Error("attach group jobs", "client", name, "err", err)
	} else if err := s.membersChanged(ctx, affected); err != nil {
		s.log.Error("attach group jobs", "client", name, "err", err)
	}
	s.log.Warn("revoked client re-enrolled on a new PC, with its backups", "client", name, "id", c.ID, "hostname", req.Hostname)
	c, err = s.store.Client(ctx, c.ID)
	if err != nil {
		return nil, nil, err
	}
	return c, certPEM, nil
}

// revokedPathClient resolves the revoked client of a /api/clients/{id}/reenroll request.
func (s *Server) revokedPathClient(w http.ResponseWriter, r *http.Request) (*Client, bool) {
	c, ok := s.pathClient(w, r, PermManageRevoked)
	if !ok {
		return nil, false
	}
	auditTarget(r, "client "+c.baseName())
	if !c.Revoked {
		httpError(w, http.StatusConflict, errors.New("client is not revoked"))
		return nil, false
	}
	return c, true
}

// handleCreateReenrollment creates the enrollment command that re-enrolls a
// revoked client on a PC.
func (s *Server) handleCreateReenrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TTLHours int `json:"ttl_hours"`
		// NewKey (default true): back up with a new encryption key, as the
		// old PC has the current one.
		NewKey *bool `json:"new_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, 400, err)
		return
	}
	c, ok := s.revokedPathClient(w, r)
	if !ok {
		return
	}
	ctx, name := r.Context(), c.baseName()
	if s.cfg.PublicURL == "" {
		httpError(w, 400, errors.New("server has no -public-url configured"))
		return
	}
	if req.TTLHours <= 0 || req.TTLHours > 24*30 {
		req.TTLHours = 24
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	if pending, _ := s.store.PendingReenrollments(ctx); pending[c.ID].ID > 0 {
		httpError(w, http.StatusConflict, errors.New("this client already has a pending re-enrollment; show its command or cancel it"))
		return
	}
	if s.store.ClientNameTaken(ctx, name) {
		httpError(w, http.StatusConflict, fmt.Errorf("%q is used by another client or enrollment; revoke or cancel that one first", name))
		return
	}
	code := randToken(24)
	tok, _ := json.Marshal(api.EnrollmentToken{URL: s.cfg.PublicURL, Code: code, CAFingerprint: s.pki.CAFingerprint()})
	command := `proxbackup-agent.exe enroll ` + base64.RawURLEncoding.EncodeToString(tok)
	ttl := time.Duration(req.TTLHours) * time.Hour
	newKey := req.NewKey == nil || *req.NewKey
	if _, err := s.store.CreateEnrollment(ctx, hashToken(code), name, c.TargetID, c.ID, newKey, ttl, s.sealer.sealFor(command, colEnrollCmd)); err != nil {
		httpError(w, 500, err)
		return
	}
	switch {
	case len(c.cryptKeyEnc) == 0:
		auditDetail(r, "re-enrollment created: the PC that uses it gets the client's backups")
	case newKey:
		auditDetail(r, "re-enrollment created: the PC that uses it gets the client's backups and a new encryption key")
	default:
		auditDetail(r, "re-enrollment created: the PC that uses it gets the client's backups and keeps its encryption key")
	}
	s.log.Warn("re-enrollment of a revoked client created", "client", name, "id", c.ID)
	writeJSON(w, map[string]any{"client_name": name, "command": command, "expires": time.Now().Add(ttl).Unix()})
}

// handleReenrollmentCommand shows the command of a client's pending re-enrollment again.
func (s *Server) handleReenrollmentCommand(w http.ResponseWriter, r *http.Request) {
	c, ok := s.revokedPathClient(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	pending, err := s.store.PendingReenrollments(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	e, ok := pending[c.ID]
	if !ok {
		httpError(w, http.StatusNotFound, errors.New("no pending re-enrollment"))
		return
	}
	enc, _, err := s.store.PendingEnrollmentCommand(ctx, e.ID)
	if err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	command, err := s.sealer.Open(enc, colEnrollCmd, e.ID)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	writeJSON(w, map[string]any{"command": command, "expires": e.Expires})
}

// handleDeleteReenrollment cancels a client's pending re-enrollment.
func (s *Server) handleDeleteReenrollment(w http.ResponseWriter, r *http.Request) {
	c, ok := s.revokedPathClient(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	pending, err := s.store.PendingReenrollments(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	e, ok := pending[c.ID]
	if !ok {
		httpError(w, http.StatusNotFound, errors.New("no pending re-enrollment"))
		return
	}
	if err := s.store.DeleteEnrollment(ctx, e.ID); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
