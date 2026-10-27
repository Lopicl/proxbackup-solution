// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Every argon2id call takes 64 MiB, so only a few run at once (each already
// uses two threads); the rest wait. Without this, a flood of parallel sign-ins
// could take the PBS host's memory.
var hashSlots = make(chan struct{}, max(1, min(runtime.GOMAXPROCS(0)/2, 4)))

func argonKey(pw string, salt []byte, n uint32) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(pw), salt, 2, 64*1024, 2, n)
}

const (
	loginFreeFails    = 5                // failures before attempts are held back
	loginMaxAddrDelay = 15 * time.Minute // backoff cap per client address
	loginMaxUserDelay = 5 * time.Minute  // backoff cap per username
	loginForget       = 30 * time.Minute // failures are forgotten after this long
	loginMaxInflight  = 4                // concurrent attempts per client address
	loginTrustTTL     = 30 * 24 * time.Hour
)

// loginLimiter throttles password checks per client address and per username:
// after loginFreeFails failures the next attempt has to wait, twice as long
// after each further failure. An address that signed in to an account before
// isn't held back by that account's backoff, so failures from elsewhere can't
// lock its owner out.
type loginLimiter struct {
	mu      sync.Mutex
	keys    map[string]*loginState
	trusted map[string]time.Time // "<user key>@<address key>" of successful sign-ins
}

type loginState struct {
	fails    int
	last     time.Time // last failure
	inflight int
}

// wait returns how long the next attempt must wait (<= 0: none).
func (st *loginState) wait(now time.Time, limit time.Duration) time.Duration {
	if st.fails < loginFreeFails {
		return 0
	}
	d := limit
	if n := st.fails - loginFreeFails; n < 20 {
		d = min(time.Second<<n, limit)
	}
	return st.last.Add(d).Sub(now)
}

func (l *loginLimiter) state(key string, now time.Time) *loginState {
	st := l.keys[key]
	if st == nil {
		st = &loginState{}
		l.keys[key] = st
	} else if st.fails > 0 && now.Sub(st.last) > loginForget {
		st.fails = 0
	}
	return st
}

// begin reserves a password check by addr for user. If either is throttled it
// returns how long to wait and a nil done; otherwise done must be called with
// the outcome.
func (l *loginLimiter) begin(addr, user string) (wait time.Duration, done func(ok bool)) {
	now := time.Now()
	addrKey, userKey := "addr:"+addrPrefix(addr), "user:"+hashToken(strings.ToLower(user))
	pair := userKey + "@" + addrKey
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keys == nil {
		l.keys, l.trusted = map[string]*loginState{}, map[string]time.Time{}
	}
	a, u := l.state(addrKey, now), l.state(userKey, now)
	wait = a.wait(now, loginMaxAddrDelay)
	if _, ok := l.trusted[pair]; !ok {
		wait = max(wait, u.wait(now, loginMaxUserDelay))
	}
	if wait <= 0 && a.inflight >= loginMaxInflight {
		wait = time.Second
	}
	if wait > 0 {
		return wait, nil
	}
	a.inflight++
	u.inflight++
	return 0, func(ok bool) {
		l.mu.Lock()
		defer l.mu.Unlock()
		a.inflight--
		u.inflight--
		if ok {
			u.fails = 0
			l.trusted[pair] = time.Now()
			return
		}
		for _, st := range []*loginState{a, u} {
			st.fails++
			st.last = time.Now()
		}
	}
}

// prune drops state that no longer holds anything back.
func (l *loginLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, st := range l.keys {
		if st.inflight == 0 && (st.fails == 0 || now.Sub(st.last) > loginForget) {
			delete(l.keys, k)
		}
	}
	for k, t := range l.trusted {
		if now.Sub(t) > loginTrustTTL {
			delete(l.trusted, k)
		}
	}
}

// addrPrefix keys IPv6 clients by their /64, which one host can usually pick
// addresses from freely.
func addrPrefix(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() != nil {
		return addr
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func tooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	in := fmt.Sprintf("%d seconds", secs)
	if secs == 1 {
		in = "1 second"
	} else if secs > 90 {
		in = fmt.Sprintf("%d minutes", (secs+59)/60)
	}
	httpError(w, http.StatusTooManyRequests, fmt.Errorf("too many failed sign-ins; try again in %s", in))
}
