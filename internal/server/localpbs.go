// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"proxbackup/pkg/pbs"
)

// LocalPBS describes the Proxmox Backup Server this console runs on (the .deb
// install). The console then needs no manual setup: it registers the PBS
// datastores as targets with the admin token the package created and keeps
// their certificate fingerprint current. Console users are its own (see
// users.go), not PBS accounts.
type LocalPBS struct {
	APIAddr    string // this host's PBS API, normally "127.0.0.1:8007"
	PublicHost string // PBS address agents connect to, e.g. "pbs.example.lan:8007"
	AuthID     string // admin token created by the package, e.g. "root@pam!proxbackup-console"
	SecretFile string // file holding the token secret
}

const localTargetsInitKey = "local_pbs_targets_initialized"

func (l *LocalPBS) secret() (string, error) {
	b, err := os.ReadFile(l.SecretFile)
	if err != nil {
		return "", fmt.Errorf("local PBS token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// fingerprint returns the SHA-256 fingerprint of the certificate the local PBS
// presents. Reading it over loopback is what the PBS host itself would trust,
// and it follows certificate renewals (e.g. ACME) without reconfiguration.
func (l *LocalPBS) fingerprint(ctx context.Context) (string, error) {
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	c, err := d.DialContext(ctx, "tcp", l.APIAddr)
	if err != nil {
		return "", fmt.Errorf("local PBS: %w", err)
	}
	defer c.Close()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("local PBS sent no certificate")
	}
	return pbs.FormatFingerprint(sha256.Sum256(certs[0].Raw)), nil
}

func (l *LocalPBS) client(ctx context.Context) (*pbs.Client, string, string, error) {
	secret, err := l.secret()
	if err != nil {
		return nil, "", "", err
	}
	fp, err := l.fingerprint(ctx)
	if err != nil {
		return nil, "", "", err
	}
	c, err := pbs.NewClient(pbs.Config{Host: l.APIAddr, Fingerprint: fp, AuthID: l.AuthID, Secret: secret})
	return c, fp, secret, err
}

// localPBSLoop syncs the local targets at startup (retrying until PBS is up)
// and then hourly, to pick up certificate and token changes.
func (s *Server) localPBSLoop(ctx context.Context) {
	delay := 5 * time.Second
	for {
		if err := s.syncLocalTargets(ctx); err != nil {
			s.log.Warn("local PBS sync failed", "err", err)
		} else {
			delay = time.Hour
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Hour)
	}
}

// syncLocalTargets registers every datastore of the local PBS as a target the
// first time it runs, and afterwards refreshes the fingerprint and token secret
// of targets using the local admin token. Targets the admin deleted are not
// recreated.
func (s *Server) syncLocalTargets(ctx context.Context) error {
	l := s.cfg.LocalPBS
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pc, fp, secret, err := l.client(ctx)
	if err != nil {
		return err
	}
	ts, err := s.store.Targets(ctx)
	if err != nil {
		return err
	}
	for _, t := range ts {
		if t.AdminAuthID != l.AuthID {
			continue
		}
		old, _ := s.sealer.Open(t.adminSecretEnc, colTargetSecret, t.ID)
		if t.Fingerprint == fp && old == secret && t.Host == l.PublicHost {
			continue
		}
		t.Fingerprint, t.Host = fp, l.PublicHost
		if err := s.store.SaveTarget(ctx, t, s.sealer.sealFor(secret, colTargetSecret)); err != nil {
			return err
		}
		s.log.Info("updated local PBS target", "target", t.Name, "fingerprint", fp)
		s.wakeTargetClients(ctx, t.ID)
	}

	var done bool
	if err := s.store.Setting(ctx, localTargetsInitKey, &done); err == nil && done {
		return nil
	}
	var stores []struct {
		Store string `json:"store"`
	}
	if err := pc.Call(ctx, http.MethodGet, "admin/datastore", nil, &stores); err != nil {
		return fmt.Errorf("list datastores: %w", err)
	}
	for _, ds := range stores {
		exists := false
		for _, t := range ts {
			exists = exists || t.Datastore == ds.Store && t.AdminAuthID == l.AuthID
		}
		if exists {
			continue
		}
		t := &Target{Name: ds.Store, Host: l.PublicHost, Fingerprint: fp, Datastore: ds.Store, RootNS: "pcs",
			AdminAuthID: l.AuthID, PBSUser: "proxbackup@pbs"}
		if err := s.store.SaveTarget(ctx, t, s.sealer.sealFor(secret, colTargetSecret)); err != nil {
			return err
		}
		s.log.Info("registered local PBS datastore", "datastore", ds.Store)
	}
	return s.store.SetSetting(ctx, localTargetsInitKey, true)
}

func (s *Server) wakeTargetClients(ctx context.Context, targetID int64) {
	if cs, err := s.store.Clients(ctx); err == nil {
		for _, c := range cs {
			if c.TargetID == targetID {
				s.wakeClient(c.ID)
			}
		}
	}
}

// localFingerprintFor returns the local PBS fingerprint for targets using the
// local admin token, so the target form can leave it empty.
func (s *Server) localFingerprintFor(ctx context.Context, authID string) string {
	if l := s.cfg.LocalPBS; l != nil && authID == l.AuthID {
		fp, _ := l.fingerprint(ctx)
		return fp
	}
	return ""
}

// localSecretFor fills in the local admin token secret when a target form uses
// the local token id without a secret (the admin never sees that secret). It is
// only handed out for this PBS's address and certificate fingerprint, so a form
// cannot send the root token to another host.
func (s *Server) localSecretFor(ctx context.Context, authID, host, fp string) string {
	l := s.cfg.LocalPBS
	if l == nil || authID != l.AuthID || !sameHost(host, l.PublicHost) && !sameHost(host, l.APIAddr) {
		return ""
	}
	local, err := l.fingerprint(ctx)
	if err != nil || pbs.NormalizeFingerprint(fp) != pbs.NormalizeFingerprint(local) {
		return ""
	}
	secret, _ := l.secret()
	return secret
}

// sameHost compares PBS addresses, with the PBS default port when none is given.
func sameHost(a, b string) bool {
	norm := func(h string) string {
		h = strings.ToLower(strings.TrimSpace(h))
		if _, _, err := net.SplitHostPort(h); err != nil {
			h = net.JoinHostPort(strings.Trim(h, "[]"), "8007")
		}
		return h
	}
	return a != "" && norm(a) == norm(b)
}

// sameEndpoint reports whether a target form still points at the PBS and token
// the stored secret belongs to, so the stored secret may be reused.
func (t *Target) sameEndpoint(host, fp, authID string) bool {
	return sameHost(t.Host, host) && authID == t.AdminAuthID &&
		pbs.NormalizeFingerprint(t.Fingerprint) == pbs.NormalizeFingerprint(fp)
}
