// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// TestTicketAuth checks that a user id signs in once, sends the cookie (and
// the CSRF token on writes) and signs in again when PBS refuses the ticket.
func TestTicketAuth(t *testing.T) {
	var mu sync.Mutex
	logins, valid := 0, ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/api2/json/access/ticket" {
			var in struct{ Username, Password string }
			json.NewDecoder(r.Body).Decode(&in)
			if in.Username != "proxbackup@pbs" || in.Password != "pw:+/" {
				http.Error(w, "authentication failure", http.StatusUnauthorized)
				return
			}
			logins++
			valid = fmt.Sprintf("PBS:proxbackup@pbs:%d::sig+/=", logins)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ticket": valid, "CSRFPreventionToken": "csrf" + valid}})
			return
		}
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "unexpected token", http.StatusBadRequest)
			return
		}
		// PBS percent-decodes the cookie.
		got, err := url.PathUnescape(strings.TrimPrefix(r.Header.Get("Cookie"), "PBSAuthCookie="))
		if err != nil || got != valid {
			http.Error(w, "permission check failed", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("CSRFPreventionToken") != "csrf"+valid {
			http.Error(w, "invalid csrf token", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "4.2"}})
	}))
	defer srv.Close()
	fp := FormatFingerprint(sha256.Sum256(srv.Certificate().Raw))
	host := strings.TrimPrefix(srv.URL, "https://")
	ctx := context.Background()
	newClient := func(pw string) *Client {
		c, err := NewClient(Config{Host: host, Fingerprint: fp, AuthID: "proxbackup@pbs", Secret: pw})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c := newClient("pw:+/")
	if _, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(ctx, http.MethodPost, "access/acl", map[string]any{"path": "/"}, nil); err != nil {
		t.Fatalf("write with ticket: %v", err)
	}
	// Another client for the same PBS and credentials reuses the ticket.
	if _, err := newClient("pw:+/").Version(ctx); err != nil || logins != 1 {
		t.Fatalf("second client: %v, %d sign-ins", err, logins)
	}
	// A refused ticket is replaced once.
	mu.Lock()
	valid = "revoked"
	mu.Unlock()
	if _, err := c.Version(ctx); err != nil || logins != 2 {
		t.Fatalf("after PBS refused the ticket: %v, %d sign-ins", err, logins)
	}
	if _, err := newClient("wrong").Version(ctx); err == nil || !strings.Contains(err.Error(), "sign in") {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := NewClient(Config{Host: host, AuthID: "nobody", Secret: "x"}); err == nil {
		t.Fatal("auth id without realm accepted")
	}
}

func TestValidAuthID(t *testing.T) {
	for _, id := range []string{"proxbackup@pbs", "backup@pbs!pc-01", "root@pam!proxbackup-console", "a.b@pve!x_y.2", "domain-user@ad"} {
		if !ValidAuthID(id) {
			t.Errorf("%q rejected", id)
		}
	}
	for _, id := range []string{"", "nobody", "@pbs", "a@", "a@pbs!", "a b@pbs", "a@pbs\r\nX: y", "a@pbs!t\n", "a@pbs!t!u", "a/b@pbs", "a:b@pbs", "a@p bs"} {
		if ValidAuthID(id) {
			t.Errorf("%q accepted", id)
		}
	}
	if _, err := NewClient(Config{Host: "pbs", AuthID: "a@pbs!t\r\nX-Evil: 1", Secret: "s"}); err == nil {
		t.Error("NewClient took an auth id with CR/LF")
	}
}
