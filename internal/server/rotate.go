// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
// CredsExposed; once the agent reports api.FeatureDataDirACL, it is asked for a
// new certificate. The first request with the new certificate makes the old
// serial invalid, and the next poll gets a new PBS token secret. Admins can
// request the same rotation for any client. The client encryption key can't be
// rotated: existing snapshots stay encrypted with it.
//
// The order matters against someone who uses a copied certificate: the new
// token only goes to the new certificate, which only the party that sent the
// CSR can use. A renewal signs one key: a CSR for a second key means two
// parties hold the old certificate, and the client is revoked.

// rotateRetry is how long a failed token rotation waits before the next poll retries it.
const rotateRetry = 10 * time.Minute

// renewalRaceWindow: a CSR made with the replaced certificate this soon after
// a renewal is the loser of a race between the agent and a copy of its
// certificate (see replacedCertUsed). Later ones are only logged, so that a
// stolen certificate can't revoke the client long after it was replaced.
const renewalRaceWindow = time.Hour

// startExposedRotation requests rotation for an exposed client whose agent
// now keeps its credentials from local users.
func (s *Server) startExposedRotation(ctx context.Context, c *Client) error {
	if !c.CredsExposed || c.RotateToken || c.CertRenew || !slices.Contains(c.Features, api.FeatureDataDirACL) {
		return nil
	}
	if err := s.store.RequestRotation(ctx, c.ID); err != nil {
		return err
	}
	c.RotateToken, c.CertRenew = true, true
	return nil
}

// tokenRotationDue reports whether the client's PBS token secret should be
// replaced at this poll: requested, and the certificate already renewed.
func (s *Server) tokenRotationDue(c *Client) bool {
	if !c.RotateToken || c.CertRenew {
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
// connects with the new one (see requireAgent). A repeated CSR for the same
// key (the agent retrying after a lost reply) gets a certificate again; one
// for another key revokes the client.
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
	blk, _ := pem.Decode([]byte(req.CSR))
	if blk == nil {
		httpError(w, http.StatusBadRequest, errors.New("no PEM certificate request"))
		return
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// A new certificate must come with a new key.
	oldKey, _ := x509.MarshalPKIXPublicKey(r.TLS.VerifiedChains[0][0].PublicKey)
	newKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if bytes.Equal(oldKey, newKey) {
		httpError(w, http.StatusBadRequest, errors.New("the CSR reuses the current key"))
		return
	}
	sum := sha256.Sum256(newKey)
	keyHash := hex.EncodeToString(sum[:])
	if c.pendingSerial != "" && c.pendingKey != keyHash {
		s.revokeCompromised(r.Context(), c, "a second certificate request for the same renewal", "remote", r.RemoteAddr)
		httpError(w, http.StatusForbidden, errors.New("unknown or revoked client"))
		return
	}
	certPEM, serial, err := s.pki.SignClientCSR([]byte(req.CSR), c.Name)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ok, err := s.store.SetPendingSerial(r.Context(), c.ID, serial, keyHash)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		// Another CSR got in between (or the renewal completed or the client was revoked meanwhile).
		if fresh, err := s.store.Client(r.Context(), c.ID); err == nil && !fresh.Revoked && fresh.CertRenew {
			s.revokeCompromised(r.Context(), fresh, "a second certificate request for the same renewal", "remote", r.RemoteAddr)
		}
		httpError(w, http.StatusForbidden, errors.New("unknown or revoked client"))
		return
	}
	s.log.Info("client certificate issued", "client", c.Name, "id", c.ID, "serial", serial)
	writeJSON(w, api.RenewCertResponse{CertPEM: string(certPEM)})
}

// revokeCompromised revokes a client whose certificate someone else holds and
// uses: its PBS token is deleted and neither serial is accepted any more. The
// PC has to be enrolled again.
func (s *Server) revokeCompromised(ctx context.Context, c *Client, reason string, logArgs ...any) {
	s.deleteClientToken(ctx, c)
	if err := s.store.RevokeCompromisedClient(ctx, c.ID, "possible credential theft: "+reason); err != nil {
		s.log.Error("could not revoke a client with a stolen certificate", "client", c.Name, "id", c.ID, "err", err)
		return
	}
	s.log.Warn("possible credential theft: client revoked; enroll the PC again", append([]any{"client", c.Name, "id", c.ID,
		"reason", reason}, logArgs...)...)
	s.wakeClient(c.ID)
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
