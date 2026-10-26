// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"proxbackup/internal/api"
)

// Certificate renewal. When the console asks for it (PollResponse.RenewCert),
// the agent creates a new key, has the console sign a CSR for it and replaces
// client.key and client.pem. The console keeps accepting the old certificate
// until the agent connects with the new one, and rejects it from then on.
//
// The new pair is written as client.renew.key and client.renew.pem, then
// renamed over the old one, key first. finishCertRenewal completes or discards
// a swap the agent didn't finish.

// renewRetry is how long the agent waits after a failed renewal before trying again.
const renewRetry = 10 * time.Minute

// client returns the HTTP client for the console.
func (r *Runner) client() *http.Client {
	r.hcMu.Lock()
	defer r.hcMu.Unlock()
	return r.hc
}

func (r *Runner) renewCert(ctx context.Context, base string) {
	r.hcMu.Lock()
	due := time.Since(r.renewFailedAt) >= renewRetry
	r.hcMu.Unlock()
	if !due {
		return
	}
	if err := r.doRenewCert(ctx, base); err != nil {
		r.log.Warn("could not renew the client certificate; retrying later", "err", err)
		r.hcMu.Lock()
		r.renewFailedAt = time.Now()
		r.hcMu.Unlock()
		return
	}
	r.log.Info("client certificate renewed")
}

func (r *Runner) doRenewCert(ctx context.Context, base string) error {
	hostname, _ := os.Hostname()
	keyPEM, csrPEM, err := newKeyAndCSR(hostname)
	if err != nil {
		return err
	}
	var resp api.RenewCertResponse
	if err := postJSON(ctx, r.client(), base+"/agent/v1/cert", api.RenewCertRequest{CSR: string(csrPEM)}, &resp); err != nil {
		return err
	}
	if _, err := tls.X509KeyPair([]byte(resp.CertPEM), keyPEM); err != nil {
		return fmt.Errorf("console returned an unusable certificate: %w", err)
	}
	c := r.cfg
	if err := writeSecret(c.path("client.renew.key"), keyPEM); err != nil {
		return err
	}
	if err := writeSecret(c.path("client.renew.pem"), []byte(resp.CertPEM)); err != nil {
		return err
	}
	if err := os.Rename(c.path("client.renew.key"), c.path("client.key")); err != nil {
		return err
	}
	if err := os.Rename(c.path("client.renew.pem"), c.path("client.pem")); err != nil {
		return err
	}
	hc, err := c.httpClient()
	if err != nil {
		return err
	}
	// New requests open new connections with the new certificate; the old
	// client's connections finish what they're doing and are closed.
	r.hcMu.Lock()
	old := r.hc
	r.hc = hc
	r.hcMu.Unlock()
	old.CloseIdleConnections()
	return nil
}

// finishCertRenewal completes a certificate swap that was interrupted after
// the new key replaced the old one, and discards one interrupted before.
func finishCertRenewal(c *Config) {
	if _, err := os.Stat(c.path("client.renew.pem")); err != nil {
		return
	}
	if _, err := os.Stat(c.path("client.renew.key")); err == nil {
		// Nothing swapped yet: the old pair is intact and still accepted.
		os.Remove(c.path("client.renew.key"))
		os.Remove(c.path("client.renew.pem"))
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		return
	}
	os.Rename(c.path("client.renew.pem"), c.path("client.pem"))
}
