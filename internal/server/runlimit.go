// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"slices"
	"sync"
	"time"
)

// An agent may register this many runs of its own per hour, in bursts of
// up to as many (a spool drained after a long time offline). Agents retry a
// refused registration later, so nothing is lost; the limit only keeps an
// agent from filling the console's database with runs.
const (
	runRegsPerHour = 120
	runRegsBurst   = 120
)

// An agent may open this many self-service restore pages per hour, in
// bursts of up to as many (each "Restore files…" in the tray opens one).
const (
	restoreSessionsPerHour = 30
	restoreSessionsBurst   = 10
)

// A setup token may enroll this many PCs per hour, in bursts of up to as
// many (a rollout to a room of PCs at once). A leaked setup can't flood the
// console and PBS with clients faster than that.
const (
	setupEnrollsPerHour = 60
	setupEnrollsBurst   = 30
)

// Requests one client may have open at once: an agent sends one poll, run
// report and spool delivery at a time, plus the odd certificate renewal,
// restore page or update download. Decoding a request takes up to about
// 20 MiB, so without a cap one PC (or a copy of its certificate) could
// exhaust the console's memory. At most maxWaitingPolls of them are polls
// waiting for work. A client's restore pages share their own requests, so
// its users can't starve the agent (and a terminal server has many users).
const (
	maxAgentRequests       = 8
	maxWaitingPolls        = 2
	maxRestorePageRequests = 16
)

// requestLimiter caps the requests each client has open. A poll past
// maxWaitingPolls ends the client's oldest waiting one, which answers at
// once: an agent whose connection dropped polls again while the console
// still holds its old poll, and mustn't be refused because of it.
type requestLimiter struct {
	max int

	mu      sync.Mutex
	clients map[int64]*openRequests
	warned  map[int64]time.Time // refusals logged: at most one per client and hour
}

type openRequests struct {
	n     int
	polls []chan struct{} // waiting polls, oldest first; closed to end one
}

// begin takes one of client id's requests. If they are all in use, ok is
// false and warn says whether to log it; otherwise end gives it back.
func (l *requestLimiter) begin(id int64, now time.Time) (end func(), ok, warn bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.open(id)
	if o.n >= l.max {
		if now.Sub(l.warned[id]) > time.Hour {
			l.warned[id], warn = now, true
		}
		return nil, false, warn
	}
	o.n++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		o.n--
		l.dropIdle(id, o)
	}, true, false
}

// waitPoll registers a waiting poll of client id. ended is closed when newer
// polls push it past maxWaitingPolls; done unregisters it.
func (l *requestLimiter) waitPoll(id int64) (ended <-chan struct{}, done func()) {
	ch := make(chan struct{})
	l.mu.Lock()
	defer l.mu.Unlock()
	o := l.open(id)
	if o.polls = append(o.polls, ch); len(o.polls) > maxWaitingPolls {
		close(o.polls[0])
		o.polls = o.polls[1:]
	}
	return ch, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		o.polls = slices.DeleteFunc(o.polls, func(p chan struct{}) bool { return p == ch })
		l.dropIdle(id, o)
	}
}

func (l *requestLimiter) open(id int64) *openRequests {
	if l.clients == nil {
		l.clients, l.warned = map[int64]*openRequests{}, map[int64]time.Time{}
	}
	o := l.clients[id]
	if o == nil {
		o = &openRequests{}
		l.clients[id] = o
	}
	return o
}

func (l *requestLimiter) dropIdle(id int64, o *openRequests) {
	if o.n == 0 && len(o.polls) == 0 && l.clients[id] == o {
		delete(l.clients, id)
	}
}

// prune forgets refusals logged more than an hour ago.
func (l *requestLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, t := range l.warned {
		if now.Sub(t) > time.Hour {
			delete(l.warned, id)
		}
	}
}

// rateLimiter is a token bucket per key: burst tokens, refilled at perHour.
type rateLimiter[K comparable] struct {
	perHour, burst float64

	mu      sync.Mutex
	buckets map[K]*runBucket
}

// clientLimiter is a token bucket per client.
type clientLimiter = rateLimiter[int64]

type runBucket struct {
	tokens float64
	at     time.Time
}

// allow takes a token from key's bucket if it has one.
func (l *rateLimiter[K]) allow(key K, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[K]*runBucket{}
	}
	b := l.buckets[key]
	if b == nil {
		b = &runBucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.at).Hours()*l.perHour)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops full buckets, which hold nothing back.
func (l *rateLimiter[K]) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.at).Hours()*l.perHour >= l.burst {
			delete(l.buckets, k)
		}
	}
}
