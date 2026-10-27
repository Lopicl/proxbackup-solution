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
// A renewal signs one key: the console takes a CSR for another key as a
// second party renewing with a copy of the certificate, and revokes the
// client. So the new key is written as client.renew.key before the CSR is
// sent, and a retry (after a lost reply, or a restart) asks for the same key.
// The certificate is written as client.renew.pem, then both are renamed over
// the old pair, key first. finishCertRenewal completes a swap the agent didn't
// finish.

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
	c := r.cfg
	keyPEM, csrPEM, err := renewalKeyAndCSR(c)
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

// renewalKeyAndCSR returns the key of the current renewal, created and kept
// in client.renew.key if there is none yet, and a CSR for it.
func renewalKeyAndCSR(c *Config) (keyPEM, csrPEM []byte, err error) {
	hostname, _ := os.Hostname()
	if keyPEM, err = os.ReadFile(c.path("client.renew.key")); err == nil {
		if csrPEM, err = csrFor(keyPEM, hostname); err == nil {
			return keyPEM, csrPEM, nil
		}
		// Unusable: the console can't have signed it, start over.
	}
	if keyPEM, csrPEM, err = newKeyAndCSR(hostname); err != nil {
		return nil, nil, err
	}
	return keyPEM, csrPEM, writeSecret(c.path("client.renew.key"), keyPEM)
}

// finishCertRenewal completes a certificate swap that was interrupted after
// the console's certificate was written. The console accepts it: the old pair
// can't be renewed with another key.
func finishCertRenewal(c *Config) {
	if _, err := os.Stat(c.path("client.renew.pem")); err != nil {
		return
	}
	if err := os.Rename(c.path("client.renew.key"), c.path("client.key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	os.Rename(c.path("client.renew.pem"), c.path("client.pem"))
}
