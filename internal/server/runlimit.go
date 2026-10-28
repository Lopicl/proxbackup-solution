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

// runLimiter is a token bucket per client.
type runLimiter struct {
	mu      sync.Mutex
	buckets map[int64]*runBucket
}

type runBucket struct {
	tokens float64
	at     time.Time
}

// allow takes a token from client's bucket if it has one.
func (l *runLimiter) allow(client int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[int64]*runBucket{}
	}
	b := l.buckets[client]
	if b == nil {
		b = &runBucket{tokens: runRegsBurst, at: now}
		l.buckets[client] = b
	}
	b.tokens = min(runRegsBurst, b.tokens+now.Sub(b.at).Hours()*runRegsPerHour)
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops full buckets, which hold nothing back.
func (l *runLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.at).Hours()*runRegsPerHour >= runRegsBurst {
			delete(l.buckets, k)
		}
	}
}
