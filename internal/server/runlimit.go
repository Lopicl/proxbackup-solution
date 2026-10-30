// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
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

// clientLimiter is a token bucket per client: burst tokens, refilled at
// perHour.
type clientLimiter struct {
	perHour, burst float64

	mu      sync.Mutex
	buckets map[int64]*runBucket
}

type runBucket struct {
	tokens float64
	at     time.Time
}

// allow takes a token from client's bucket if it has one.
func (l *clientLimiter) allow(client int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[int64]*runBucket{}
	}
	b := l.buckets[client]
	if b == nil {
		b = &runBucket{tokens: l.burst, at: now}
		l.buckets[client] = b
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
func (l *clientLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.at).Hours()*l.perHour >= l.burst {
			delete(l.buckets, k)
		}
	}
}
