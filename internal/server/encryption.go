// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// Client-side encryption: each client gets its own AES-256 key, generated
// here with its first encrypted job. The console keeps it sealed with the
// master key (escrow: restores of a lost PC's backups don't depend on the PC)
// and sends it to the agent with its configuration. Optionally every
// encrypted snapshot also carries the key encrypted with an RSA master public
// key, like proxmox-backup-client --master-pubkey-file.

const encryptionSettingsKey = "encryption"

type encryptionSettings struct {
	// MasterPubKey is a PEM RSA public key ("" = no master-key copy).
	MasterPubKey string `json:"master_pubkey"`
}

// Encryption can only be turned on with a master key set, so no encrypted
// snapshot depends on the console alone for its key.
var errNoMasterKey = errors.New("set up an RSA master key in Console Settings before turning encryption on")

// hasMasterKey reports whether a master public key is configured.
func (s *Server) hasMasterKey(ctx context.Context) (bool, error) {
	var es encryptionSettings
	if err := s.store.Setting(ctx, encryptionSettingsKey, &es); err != nil {
		return false, err
	}
	return es.MasterPubKey != "", nil
}

// clientKey returns the client's key for the agent, nil if it has none.
func (s *Server) clientKey(ctx context.Context, c *Client) (*api.CryptKey, error) {
	if len(c.cryptKeyEnc) == 0 {
		return nil, nil
	}
	key, err := s.sealer.Open(c.cryptKeyEnc, colClientKey, c.ID)
	if err != nil {
		return nil, fmt.Errorf("decrypt client encryption key: %w", err)
	}
	var es encryptionSettings
	if err := s.store.Setting(ctx, encryptionSettingsKey, &es); err != nil {
		return nil, err
	}
	return &api.CryptKey{Key: key, Fingerprint: c.EncryptionFingerprint, Created: c.EncryptionCreated, MasterPubKey: es.MasterPubKey}, nil
}

// ensureClientKey generates the client's key if it has none yet.
func (s *Server) ensureClientKey(ctx context.Context, c *Client) error {
	if len(c.cryptKeyEnc) > 0 {
		return nil
	}
	key, err := pbs.GenerateKey()
	if err != nil {
		return err
	}
	cc, err := pbs.NewCryptConfig(key)
	if err != nil {
		return err
	}
	created := now()
	ok, err := s.store.SetClientKey(ctx, c.ID, s.sealer.Seal(base64.StdEncoding.EncodeToString(key[:]), colClientKey, c.ID), cc.Fingerprint(), created)
	if err != nil {
		return err
	}
	if ok {
		s.log.Info("client encryption key created", "client", c.Name, "fingerprint", cc.Fingerprint())
	}
	return nil
}

// handleClientKey downloads the client's key as a PBS key file, for restores
// with proxmox-backup-client --keyfile or the agent's -keyfile.
func (s *Server) handleClientKey(w http.ResponseWriter, r *http.Request) {
	c, ok := s.pathClient(w, r, PermRestore)
	if !ok {
		return
	}
	ctx := r.Context()
	k, err := s.clientKey(ctx, c)
	if err != nil {
		httpError(w, 500, err)
		return
	}
	if k == nil {
		httpError(w, 404, fmt.Errorf("client %s has no encryption key", c.Name))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(k.Key)
	if err != nil || len(raw) != 32 {
		httpError(w, 500, fmt.Errorf("stored encryption key is invalid"))
		return
	}
	kf, err := pbs.NewKeyFile([32]byte(raw), time.Unix(k.Created, 0))
	if err != nil {
		httpError(w, 500, err)
		return
	}
	u := sessionUser(r)
	s.log.Warn("client encryption key downloaded", "client", c.Name, "fingerprint", k.Fingerprint, "by", u.Name)
	name, _, _ := strings.Cut(c.Name, "#") // revoked clients are renamed "<name>#revoked-<id>"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-encryption-key.json"`, name))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(kf)
}

type encryptionView struct {
	encryptionSettings
	MasterBits        int    `json:"master_bits,omitempty"`
	MasterFingerprint string `json:"master_fingerprint,omitempty"` // sha256 of the public key (DER)
}

func (s *Server) handleGetEncryption(w http.ResponseWriter, r *http.Request) {
	var es encryptionSettings
	if err := s.store.Setting(r.Context(), encryptionSettingsKey, &es); err != nil {
		httpError(w, 500, err)
		return
	}
	v := encryptionView{encryptionSettings: es}
	if es.MasterPubKey != "" {
		if pub, err := pbs.ParseRSAPublicKey([]byte(es.MasterPubKey)); err == nil {
			der, _ := x509.MarshalPKIXPublicKey(pub)
			v.MasterBits, v.MasterFingerprint = pub.N.BitLen(), pbs.FormatFingerprint(sha256.Sum256(der))
		}
	}
	writeJSON(w, v)
}

func (s *Server) handleSaveEncryption(w http.ResponseWriter, r *http.Request) {
	var es encryptionSettings
	if err := decodeJSON(r, &es); err != nil {
		httpError(w, 400, err)
		return
	}
	es.MasterPubKey = strings.TrimSpace(es.MasterPubKey)
	if es.MasterPubKey != "" {
		if _, err := pbs.ParseRSAPublicKey([]byte(es.MasterPubKey)); err != nil {
			httpError(w, 400, err)
			return
		}
		es.MasterPubKey += "\n"
	}
	ctx := r.Context()
	if es.MasterPubKey == "" {
		// Keep the rule: no encrypted jobs without a master key.
		gs, err := s.store.GroupJobs(ctx)
		if err != nil {
			httpError(w, 500, err)
			return
		}
		var names []string
		for _, g := range gs {
			if g.Encrypt {
				names = append(names, g.Name)
			}
		}
		if len(names) > 0 {
			httpError(w, 409, fmt.Errorf("turn encryption off in these jobs before removing the master key: %s", strings.Join(names, ", ")))
			return
		}
	}
	if err := s.store.SetSetting(ctx, encryptionSettingsKey, es); err != nil {
		httpError(w, 500, err)
		return
	}
	// The master key is part of every agent's config.
	if cs, err := s.store.Clients(ctx); err == nil {
		for _, c := range cs {
			s.wakeClient(c.ID)
		}
	}
	s.handleGetEncryption(w, r)
}
