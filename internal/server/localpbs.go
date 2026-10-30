// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"proxbackup/pkg/pbs"
)

// LocalPBS describes the Proxmox Backup Server this console runs on (the .deb
// install). Datastores added there use the PBS user the package created, with
// no password to enter, and the console keeps their certificate fingerprint
// current. Console users are its own (see users.go), not PBS accounts.
//
// That PBS user (proxbackup@pbs) has rights only on the root namespaces of
// those datastores (see pbsgrants.go). It signs in with its password and owns
// the agents' tokens: PBS lets it set ACLs only for those, and caps them at
// its own privileges.
type LocalPBS struct {
	APIAddr    string // this host's PBS API, normally "127.0.0.1:8007"
	PublicHost string // PBS address agents connect to, e.g. "pbs.example.lan:8007"
	AuthID     string // PBS user created by the package, "proxbackup@pbs" (or a token id)
	SecretFile string // file holding its password (or the token secret)
}

// legacyLocalAuthID is the root token packages up to 0.2.16 created, with
// Admin on /. The package now deletes it, and its targets move to the PBS user.
const legacyLocalAuthID = "root@pam!proxbackup-console"

// unusedLocalTargetsKey marks the one-time removal of the local targets that
// older consoles registered for every datastore, PCs or not.
const unusedLocalTargetsKey = "local_pbs_unused_targets_removed"

// pbsUser is the agent user of local targets: the console's own PBS user,
// which is the only one whose tokens it may grant ACLs to.
func (l *LocalPBS) pbsUser() string {
	if pbs.IsTokenID(l.AuthID) {
		return "proxbackup@pbs"
	}
	return l.AuthID
}

func (l *LocalPBS) secret() (string, error) {
	b, err := os.ReadFile(l.SecretFile)
	if err != nil {
		return "", fmt.Errorf("local PBS credentials: %w", err)
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
// and then hourly, to pick up certificate, password and ACL changes.
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

// syncLocalTargets refreshes the fingerprint and credentials of the local
// targets and asks for the PBS rights they need.
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
		if !t.Local {
			continue
		}
		migrated := false
		if t.AdminAuthID == legacyLocalAuthID && t.AdminAuthID != l.AuthID {
			// The package replaced the root token with the PBS user, which can
			// only manage its own tokens.
			if t.PBSUser != l.pbsUser() {
				s.log.Warn("local PBS target still uses the removed root token: its agent user isn't the console's PBS user, "+
					"so the console can't manage its clients' tokens. Set its agent user to "+l.pbsUser()+" and enroll them again",
					"target", t.Name, "agent_user", t.PBSUser)
				continue
			}
			t.AdminAuthID, migrated = l.AuthID, true
			s.log.Info("local PBS target moved off the root token", "target", t.Name, "auth_id", l.AuthID)
		}
		if t.AdminAuthID != l.AuthID {
			continue
		}
		old, _ := s.sealer.Open(t.adminSecretEnc, colTargetSecret, t.ID)
		if !migrated && t.Fingerprint == fp && old == secret && t.Host == l.PublicHost {
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
	if err := s.store.Setting(ctx, unusedLocalTargetsKey, &done); err != nil || !done {
		names, err := s.store.DeleteUnusedLocalTargets(ctx)
		if err != nil {
			return err
		}
		for _, n := range names {
			s.log.Info("removed a local datastore no PC uses: the console no longer gets rights on it. "+
				"Add it again under Datastores to back PCs up to it", "target", n)
		}
		if err := s.store.SetSetting(ctx, unusedLocalTargetsKey, true); err != nil {
			return err
		}
	}
	if err := s.syncGrants(ctx, pc, nil); err != nil {
		return fmt.Errorf("datastore rights: %w", err)
	}
	return nil
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
// local PBS user, so the target form can leave it empty.
func (s *Server) localFingerprintFor(ctx context.Context, authID, host string) string {
	if l := s.cfg.LocalPBS; l != nil && authID == l.AuthID && l.isLocalHost(host) {
		fp, _ := l.fingerprint(ctx)
		return fp
	}
	return ""
}

// localSecretFor fills in the local PBS user's password when a target form uses
// that user without a secret (the admin never sees it). It is only handed out
// for this PBS's address and certificate fingerprint, so a form cannot send it
// to another host.
func (s *Server) localSecretFor(ctx context.Context, authID, host, fp string) string {
	l := s.cfg.LocalPBS
	if l == nil || authID != l.AuthID || !l.isLocalHost(host) {
		return ""
	}
	local, err := l.fingerprint(ctx)
	if err != nil || pbs.NormalizeFingerprint(fp) != pbs.NormalizeFingerprint(local) {
		return ""
	}
	secret, _ := l.secret()
	return secret
}

func (l *LocalPBS) isLocalHost(host string) bool {
	return sameHost(host, l.PublicHost) || sameHost(host, l.APIAddr)
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
