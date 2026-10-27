// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func failLogins(t *testing.T, l *loginLimiter, addr, user string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, done := l.begin(addr, user)
		if done == nil {
			t.Fatalf("attempt %d from %s as %s was throttled", i+1, addr, user)
		}
		done(false)
	}
}

func TestLoginLimiterBackoff(t *testing.T) {
	var l loginLimiter
	failLogins(t, &l, "192.0.2.1", "admin", loginFreeFails)
	wait, done := l.begin("192.0.2.1", "admin")
	if done != nil || wait <= 0 || wait > time.Second {
		t.Fatalf("after %d failures: wait %v, allowed %v", loginFreeFails, wait, done != nil)
	}
	// Another address is held back by the username alone, case-insensitively.
	if _, done := l.begin("192.0.2.2", "ADMIN"); done != nil {
		t.Fatal("other address not throttled for the same user")
	}
	// The address is held back for other usernames too.
	if _, done := l.begin("192.0.2.1", "someone"); done != nil {
		t.Fatal("same address not throttled for another user")
	}
	if _, done := l.begin("192.0.2.2", "someone"); done == nil {
		t.Fatal("unrelated address and user throttled")
	} else {
		done(true)
	}

	// Each further failure doubles the wait, up to the cap.
	l.keys["addr:192.0.2.1"].fails = loginFreeFails + 3
	if w, _ := l.begin("192.0.2.1", "x"); w <= 4*time.Second || w > 8*time.Second {
		t.Fatalf("wait after 3 more failures = %v, want ~8s", w)
	}
	l.keys["addr:192.0.2.1"].fails = loginFreeFails + 40
	if w, _ := l.begin("192.0.2.1", "x"); w <= loginMaxAddrDelay-time.Minute || w > loginMaxAddrDelay {
		t.Fatalf("capped wait = %v", w)
	}

	// Old failures are forgotten.
	for _, st := range l.keys {
		st.last = time.Now().Add(-loginForget - time.Minute)
	}
	if _, done := l.begin("192.0.2.1", "admin"); done == nil {
		t.Fatal("still throttled after the failures expired")
	}
	l.prune(time.Now())
	if len(l.keys) != 2 { // the two keys reserved by the attempt above
		t.Fatalf("prune kept %d keys", len(l.keys))
	}
}

func TestLoginLimiterTrustedAddress(t *testing.T) {
	var l loginLimiter
	_, done := l.begin("192.0.2.1", "admin")
	done(true)
	failLogins(t, &l, "198.51.100.7", "admin", loginFreeFails)
	if _, done := l.begin("198.51.100.8", "admin"); done != nil {
		t.Fatal("account not throttled for a new address")
	}
	// The owner's usual address still gets in.
	_, done = l.begin("192.0.2.1", "admin")
	if done == nil {
		t.Fatal("account owner locked out by someone else's failures")
	}
	done(true)
}

func TestLoginLimiterConcurrency(t *testing.T) {
	var l loginLimiter
	var dones []func(bool)
	for i := 0; i < loginMaxInflight; i++ {
		_, done := l.begin("2001:db8::1", "u")
		if done == nil {
			t.Fatalf("attempt %d throttled", i+1)
		}
		dones = append(dones, done)
	}
	// Same /64, other host bits.
	if _, done := l.begin("2001:db8::ffff:1", "v"); done != nil {
		t.Fatal("concurrent attempts from one /64 not limited")
	}
	for _, d := range dones {
		d(true)
	}
	if _, done := l.begin("2001:db8::ffff:1", "v"); done == nil {
		t.Fatal("still limited after the attempts finished")
	}
}

func TestLoginThrottledResponse(t *testing.T) {
	s := newTestServer(t, "")
	if _, err := s.EnsureAdmin(context.Background(), "admin-password"); err != nil {
		t.Fatal(err)
	}
	ui := s.uiRoutes()
	for i := 0; i < loginFreeFails; i++ {
		if _, code := login(t, ui, "admin", "wrong"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i+1, code)
		}
	}
	c := &session{t: t, ui: ui}
	w := c.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-password"})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("throttled sign-in: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}
