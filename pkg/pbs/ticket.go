// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

// Ticket sign-in for PBS users. A token can only set ACLs for other auth ids
// with Permissions.Modify on /access/acl, which only Admin has (and with Admin
// on /access it can grant itself Admin on /). So the console provisions agents
// as an unprivileged user signed in with its password instead: PBS lets a user
// manage its own tokens and their ACLs, and caps the tokens at the user's own
// privileges. Unprivileged tokens can't set ACLs at all.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ticketLifetime is how long a ticket is reused. PBS accepts one for 2 hours.
const ticketLifetime = time.Hour

type ticket struct {
	mu     sync.Mutex
	value  string // the PBSAuthCookie
	csrf   string // CSRFPreventionToken, required on writes
	issued time.Time
}

// tickets holds one ticket per PBS, certificate and credentials, so the
// clients the console creates for each operation share a sign-in.
var tickets = struct {
	sync.Mutex
	m map[[32]byte]*ticket
}{m: map[[32]byte]*ticket{}}

// IsTokenID reports whether id is an API token id (user@realm!name) rather than a user id.
func IsTokenID(id string) bool { return strings.Contains(id, "!") }

// authIDRe matches a PBS user id (name@realm) or API token id
// (name@realm!token). Auth ids go into request headers, so whitespace and
// control characters must never get through.
var authIDRe = regexp.MustCompile(`^[^\s\x00-\x1f\x7f:/@!]+@[A-Za-z0-9_][A-Za-z0-9._-]*(![A-Za-z0-9_][A-Za-z0-9._-]*)?$`)

// ValidAuthID reports whether id is a well-formed PBS user or token id.
func ValidAuthID(id string) bool { return authIDRe.MatchString(id) }

func ticketFor(addr string, cfg Config) *ticket {
	key := sha256.Sum256([]byte(addr + "\x00" + NormalizeFingerprint(cfg.Fingerprint) + "\x00" + cfg.AuthID + "\x00" + cfg.Secret))
	tickets.Lock()
	defer tickets.Unlock()
	if t := tickets.m[key]; t != nil {
		return t
	}
	for k, t := range tickets.m {
		if t.mu.TryLock() {
			if time.Since(t.issued) > ticketLifetime {
				delete(tickets.m, k) // a client still holding it just signs in again
			}
			t.mu.Unlock()
		}
	}
	t := &ticket{}
	tickets.m[key] = t
	return t
}

// get returns a current ticket, signing in when there is none or it is old.
func (t *ticket) get(ctx context.Context, c *Client) (string, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.value != "" && time.Since(t.issued) < ticketLifetime {
		return t.value, t.csrf, nil
	}
	t.value = ""
	b, err := json.Marshal(map[string]string{"username": c.cfg.AuthID, "password": c.cfg.Secret})
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.addr+"/api2/json/access/ticket", bytes.NewReader(b))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	var out struct {
		Ticket string `json:"ticket"`
		CSRF   string `json:"CSRFPreventionToken"`
	}
	if err := decodeAPIResponse(resp, &out); err != nil {
		return "", "", fmt.Errorf("pbs: sign in as %s: %w", c.cfg.AuthID, err)
	}
	if out.Ticket == "" || out.CSRF == "" || strings.Contains(out.Ticket, "!tfa!") {
		return "", "", fmt.Errorf("pbs: sign in as %s: no ticket (two-factor authentication is not supported)", c.cfg.AuthID)
	}
	t.value, t.csrf, t.issued = out.Ticket, out.CSRF, time.Now()
	return t.value, t.csrf, nil
}

// expire drops value after PBS refused it, unless another request already replaced it.
func (t *ticket) expire(value string) {
	t.mu.Lock()
	if t.value == value {
		t.value = ""
	}
	t.mu.Unlock()
}

// authorize adds the credentials to h and returns the ticket it used, if any.
func (c *Client) authorize(ctx context.Context, h http.Header, method string) (string, error) {
	if c.ticket == nil {
		h.Set("Authorization", "PBSAPIToken "+c.cfg.AuthID+":"+url.PathEscape(c.cfg.Secret))
		return "", nil
	}
	value, csrf, err := c.ticket.get(ctx, c)
	if err != nil {
		return "", err
	}
	h.Set("Cookie", "PBSAuthCookie="+url.QueryEscape(value))
	if method != http.MethodGet && method != http.MethodHead {
		h.Set("CSRFPreventionToken", csrf)
	}
	return value, nil
}

// retryAuth reports whether a request refused with err should be sent again
// with a new ticket (PBS restarted with a new key, or the ticket ran out).
func (c *Client) retryAuth(err error, used string) bool {
	var ae *APIError
	if used == "" || !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		return false
	}
	c.ticket.expire(used)
	return true
}
