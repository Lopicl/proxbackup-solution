package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"proxbackup/pkg/pbs"
)

// LocalPBS describes the Proxmox Backup Server this console runs on (the .deb
// install). The console then needs no manual setup: it registers the PBS
// datastores as targets with the admin token the package created, keeps their
// certificate fingerprint current, and PBS administrators can log in to the
// console with their PBS accounts.
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
		old, _ := s.sealer.Open(t.adminSecretEnc)
		if t.Fingerprint == fp && old == secret && t.Host == l.PublicHost {
			continue
		}
		t.Fingerprint, t.Host, t.adminSecretEnc = fp, l.PublicHost, s.sealer.Seal(secret)
		if err := s.store.SaveTarget(ctx, t); err != nil {
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
			AdminAuthID: l.AuthID, PBSUser: "proxbackup@pbs", adminSecretEnc: s.sealer.Seal(secret)}
		if err := s.store.SaveTarget(ctx, t); err != nil {
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
// the local token id without a secret (the admin never sees that secret).
func (s *Server) localSecretFor(authID string) string {
	if l := s.cfg.LocalPBS; l != nil && authID == l.AuthID {
		secret, _ := l.secret()
		return secret
	}
	return ""
}

// errPBSLoginDenied means the PBS credentials were valid but the account is
// not a PBS administrator.
var errPBSLoginDenied = errors.New("this PBS account is not an administrator (needs Sys.Modify on /)")

// pbsLogin checks user@realm credentials against the local PBS and requires
// administrator rights there (Sys.Modify on /).
func (s *Server) pbsLogin(ctx context.Context, user, password string) error {
	l := s.cfg.LocalPBS
	fp, err := l.fingerprint(ctx)
	if err != nil {
		return err
	}
	hc := pinnedClient(fp)
	base := "https://" + l.APIAddr + "/api2/json/"

	form := url.Values{"username": {user}, "password": {password}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"access/ticket", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tk struct {
		Data *struct {
			Ticket string `json:"ticket"`
		} `json:"data"`
	}
	if err := doJSON(hc, req, &tk); err != nil {
		return err
	}
	if tk.Data == nil || tk.Data.Ticket == "" {
		return errInvalidLogin
	}
	if strings.Contains(tk.Data.Ticket, "!tfa!") {
		return errors.New("PBS accounts with two-factor authentication can't log in here yet; use a local console account")
	}

	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, base+"access/permissions?path=/", nil)
	req.AddCookie(&http.Cookie{Name: "PBSAuthCookie", Value: tk.Data.Ticket})
	var perms struct {
		Data map[string]map[string]bool `json:"data"`
	}
	if err := doJSON(hc, req, &perms); err != nil {
		return err
	}
	if !perms.Data["/"]["Sys.Modify"] {
		return errPBSLoginDenied
	}
	return nil
}

// pinnedClient talks to the local PBS, accepting only the certificate with fp.
func pinnedClient(fp string) *http.Client {
	want := pbs.NormalizeFingerprint(fp)
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // replaced by fingerprint pinning
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("local PBS sent no certificate")
			}
			if got := sha256.Sum256(raw[0]); hex.EncodeToString(got[:]) != want {
				return errors.New("local PBS certificate changed")
			}
			return nil
		},
	}}}
}

var errInvalidLogin = errors.New("invalid username or password")

func doJSON(hc *http.Client, req *http.Request, out any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("local PBS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errInvalidLogin
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("local PBS: HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
