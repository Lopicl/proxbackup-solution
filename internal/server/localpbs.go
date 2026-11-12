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

// presentedFingerprint returns the SHA-256 fingerprint of the certificate
// whatever listens on the local PBS API presents (see localFingerprint).
func (l *LocalPBS) presentedFingerprint(ctx context.Context) (string, error) {
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

// proxyCertWait is how long the console waits for the root helper to report
// the PBS certificate.
const proxyCertWait = 30 * time.Second

// localFingerprint returns the fingerprint of the local PBS's certificate. It
// is read over loopback, so it follows renewals (e.g. ACME), but only trusted
// once the root helper reports the same one for /etc/proxmox-backup/proxy.pem:
// port 8007 isn't privileged, so while proxmox-backup-proxy is down (restart,
// upgrade) any local user could listen there and collect the console's
// password. A new certificate makes the console ask the helper again.
func (s *Server) localFingerprint(ctx context.Context) (string, error) {
	fp, err := s.cfg.LocalPBS.presentedFingerprint(ctx)
	if err != nil {
		return "", err
	}
	confirmed := func(res *grantsResultFile) bool {
		return res != nil && res.ProxyFingerprint != "" && pbs.NormalizeFingerprint(res.ProxyFingerprint) == pbs.NormalizeFingerprint(fp)
	}
	if confirmed(s.grantsResult()) {
		return fp, nil
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, proxyCertWait)
	defer cancel()
	for {
		id, at, err := s.askProxyCert(ctx)
		if err != nil {
			return "", err
		}
		res := s.grantsResult()
		if confirmed(res) {
			return fp, nil
		}
		// Only an answer to a request made since this certificate showed up counts.
		if res != nil && res.ID == id && !at.Before(start) {
			s.log.Warn("the certificate on the local PBS API isn't the PBS's own: not signing in", "addr", s.cfg.LocalPBS.APIAddr,
				"presented", fp, "proxy_pem", res.ProxyFingerprint)
			return "", fmt.Errorf("local PBS: the certificate on %s isn't the one in %s", s.cfg.LocalPBS.APIAddr, pbsProxyCert)
		}
		select {
		case <-ctx.Done():
			return "", errors.New("local PBS: the console's root helper didn't confirm the PBS certificate (see journalctl -u proxbackup-server-grants)")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// askProxyCert has the root helper run again (it reports the certificate on
// every run), at most every proxyCertEvery, and returns the last request's
// id and time.
func (s *Server) askProxyCert(ctx context.Context) (string, time.Time, error) {
	s.proxyCertMu.Lock()
	defer s.proxyCertMu.Unlock()
	if time.Since(s.proxyCertAsked) >= s.proxyCertEvery {
		want, err := s.neededGrants(ctx, nil)
		if err != nil {
			return "", time.Time{}, err
		}
		if s.proxyCertAskID, err = s.requestGrants(want); err != nil {
			return "", time.Time{}, err
		}
		s.proxyCertAsked = time.Now()
	}
	return s.proxyCertAskID, s.proxyCertAsked, nil
}

// localClient signs in to the local PBS as the console's PBS user.
func (s *Server) localClient(ctx context.Context) (*pbs.Client, string, string, error) {
	l := s.cfg.LocalPBS
	secret, err := l.secret()
	if err != nil {
		return nil, "", "", err
	}
	fp, err := s.localFingerprint(ctx)
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
	pc, fp, secret, err := s.localClient(ctx)
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
		fp, _ := s.localFingerprint(ctx)
		return fp
	}
	return ""
}

// localSecretFor fills in the local PBS user's password when a target form uses
// that user without a secret (the admin never sees it). It is only handed out
// for this PBS's address and certificate fingerprint, so a form cannot send it
// to another host. A console address, if set, must be this PBS too.
func (s *Server) localSecretFor(ctx context.Context, authID, host, consoleHost, fp string) string {
	l := s.cfg.LocalPBS
	if l == nil || authID != l.AuthID || !l.isLocalHost(host) || consoleHost != "" && !l.isLocalHost(consoleHost) {
		return ""
	}
	local, err := s.localFingerprint(ctx)
	if err != nil || pbs.NormalizeFingerprint(fp) != pbs.NormalizeFingerprint(local) {
		return ""
	}
	secret, _ := l.secret()
	return secret
}

// pbsAPIHost is the address the console itself uses for a PBS at host. For
// this PBS that is its API on loopback, not the address agents get: that may
// be a reverse proxy refusing password sign-ins (docs/network.md), and the
// console signs in as its PBS user with a password. The client still pins the
// target's fingerprint, which is the same certificate.
func (s *Server) pbsAPIHost(host string) string {
	if l := s.cfg.LocalPBS; l != nil && l.APIAddr != "" && l.isLocalHost(host) {
		return l.APIAddr
	}
	return host
}

// consoleAddr is the address the console itself uses for a target at host
// with console address consoleHost (see Target.ConsoleHost): consoleHost if
// set, else pbsAPIHost(host).
func (s *Server) consoleAddr(host, consoleHost string) string {
	if consoleHost != "" {
		return consoleHost
	}
	return s.pbsAPIHost(host)
}

// orHost is the address the console's PBS calls go to as entered in a target
// form, before pbsAPIHost: consoleHost, or host when that is empty.
func orHost(consoleHost, host string) string {
	if consoleHost != "" {
		return consoleHost
	}
	return host
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
// the stored secret belongs to, so the stored secret may be reused. Both the
// agents' and the console's address count: the console sends the secret to
// the latter.
func (t *Target) sameEndpoint(host, consoleHost, fp, authID string) bool {
	return sameHost(t.Host, host) && sameHost(orHost(t.ConsoleHost, t.Host), orHost(consoleHost, host)) && authID == t.AdminAuthID &&
		pbs.NormalizeFingerprint(t.Fingerprint) == pbs.NormalizeFingerprint(fp)
}
