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

// A setup token may enroll this many PCs per hour, in bursts of up to as
// many (a rollout to a room of PCs at once). A leaked setup can't flood the
// console and PBS with clients faster than that.
const (
	setupEnrollsPerHour = 60
	setupEnrollsBurst   = 30
)

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
