// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// Credential rotation. Windows agents up to 0.2.14 left their data directory
// readable by every local user, so the PBS token in jobs.json and the
// certificate key in client.key may have been copied. Their clients are marked
// CredsExposed; once the agent reports api.FeatureDataDirACL, its next poll
// gets a new PBS token secret and the agent is asked for a new certificate,
// after which the old certificate serial is no longer accepted. Admins can
// request the same rotation for any client. The client encryption key can't be
// rotated: existing snapshots stay encrypted with it.

// rotateRetry is how long a failed token rotation waits before the next poll retries it.
const rotateRetry = 10 * time.Minute

// tokenRotationDue reports whether the client's PBS token secret should be
// replaced at this poll.
func (s *Server) tokenRotationDue(c *Client) bool {
	if !c.RotateToken && !(c.CredsExposed && slices.Contains(c.Features, api.FeatureDataDirACL)) {
		return false
	}
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()
	return time.Since(s.rotateFailed[c.ID]) >= rotateRetry
}

// rotateClientToken gives the client a new PBS token secret, keeping the
// token's id, so it still owns its backup groups, and its ACLs. The agent gets
// it with the config of the poll that called this, so the gap in which its
// old secret no longer works is as short as possible.
func (s *Server) rotateClientToken(ctx context.Context, c *Client) error {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()
	err := s.regenerateToken(ctx, c)
	if err != nil {
		s.rotateFailed[c.ID] = time.Now()
		return err
	}
	delete(s.rotateFailed, c.ID)
	return nil
}

func (s *Server) regenerateToken(ctx context.Context, c *Client) error {
	t, err := s.store.Target(ctx, c.TargetID)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	pc, err := s.adminClient(t)
	if err != nil {
		return err
	}
	user, name, ok := strings.Cut(c.TokenID, "!")
	if !ok {
		return fmt.Errorf("invalid token id %q", c.TokenID)
	}
	secret, err := pc.RegenerateToken(ctx, user, name)
	var ae *pbs.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusBadRequest {
		// Older PBS versions can't regenerate a secret: replace the token. The new
		// one has the same id, so it still owns the client's backup groups.
		secret, err = s.recreateToken(ctx, pc, t, c, user, name)
	}
	if err != nil {
		return fmt.Errorf("PBS token: %w", err)
	}
	secure := slices.Contains(c.Features, api.FeatureDataDirACL)
	if err := s.store.SetRotatedToken(ctx, c.ID, c.TokenID, s.sealer.Seal(secret, colClientToken, c.ID), secure); err != nil {
		return err
	}
	s.log.Info("client PBS token rotated", "client", c.Name, "id", c.ID, "token", c.TokenID)
	return nil
}

func (s *Server) recreateToken(ctx context.Context, pc *pbs.Client, t *Target, c *Client, user, name string) (string, error) {
	pc.DeleteToken(ctx, user, name) // gone already if an earlier attempt failed after it
	tokenID, secret, err := pc.CreateToken(ctx, user, name, "proxbackup agent "+name)
	if err != nil {
		return "", err
	}
	if tokenID != c.TokenID {
		return "", fmt.Errorf("PBS created token %q instead of %q", tokenID, c.TokenID)
	}
	for _, ns := range append([]string{c.Namespace}, c.OldNamespaces...) {
		if err := prepareClientNamespace(ctx, pc, t, ns, tokenID); err != nil {
			return "", err
		}
	}
	return secret, nil
}

// handleRenewCert signs a new client certificate for an agent the console
// asked to renew it. The old certificate keeps working until the agent
// connects with the new one (see requireAgent).
func (s *Server) handleRenewCert(w http.ResponseWriter, r *http.Request, c *Client) {
	if !c.CertRenew {
		httpError(w, http.StatusConflict, errors.New("no certificate renewal requested"))
		return
	}
	var req api.RenewCertRequest
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// A new certificate must come with a new key.
	if blk, _ := pem.Decode([]byte(req.CSR)); blk != nil {
		if csr, err := x509.ParseCertificateRequest(blk.Bytes); err == nil {
			oldKey, _ := x509.MarshalPKIXPublicKey(r.TLS.VerifiedChains[0][0].PublicKey)
			newKey, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
			if bytes.Equal(oldKey, newKey) {
				httpError(w, http.StatusBadRequest, errors.New("the CSR reuses the current key"))
				return
			}
		}
	}
	certPEM, serial, err := s.pki.SignClientCSR([]byte(req.CSR), c.Name)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetPendingSerial(r.Context(), c.ID, serial); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	s.log.Info("client certificate issued", "client", c.Name, "id", c.ID, "serial", serial)
	writeJSON(w, api.RenewCertResponse{CertPEM: string(certPEM)})
}

// handleRotateCredentials requests a new PBS token secret and client
// certificate for one client, applied at its next poll (at once if online).
func (s *Server) handleRotateCredentials(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermManageClients)
	if !ok {
		return
	}
	if c.Revoked {
		httpError(w, http.StatusConflict, errors.New("client is revoked"))
		return
	}
	if err := s.store.RequestRotation(r.Context(), c.ID); err != nil {
		httpError(w, statusFor(err), err)
		return
	}
	s.wakeClient(c.ID)
	writeJSON(w, map[string]bool{"ok": true})
}

// handleRotateCredentialsBulk does the same for several clients:
// {"client_ids": [...]}, or {"exposed": true} for every client whose
// credentials may have been exposed. Clients outside the user's scope are skipped.
func (s *Server) handleRotateCredentialsBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientIDs []int64 `json:"client_ids"`
		Exposed   bool    `json:"exposed"`
	}
	if err := decodeJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	cs, err := s.store.Clients(ctx)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	a := access(r)
	n := 0
	for _, c := range cs {
		if !a.Client(PermManageClients, c) || !(slices.Contains(req.ClientIDs, c.ID) || req.Exposed && c.CredsExposed) {
			continue
		}
		if err := s.store.RequestRotation(ctx, c.ID); err != nil {
			httpError(w, statusFor(err), err)
			return
		}
		s.wakeClient(c.ID)
		n++
	}
	writeJSON(w, map[string]int{"requested": n})
}
