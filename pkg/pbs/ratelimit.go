// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"context"
	"io"
	"sync"
	"time"
)

// RateLimiter caps upload bandwidth across all requests of a session. The
// rate is looked up on every read, so it can change while a backup runs
// (time-of-day limits).
type RateLimiter struct {
	rate func() int64 // bytes per second, <= 0 = unlimited

	mu   sync.Mutex
	next time.Time // when the bytes let through so far are paid for
}

// NewRateLimiter returns a limiter that lets rate() bytes per second through.
func NewRateLimiter(rate func() int64) *RateLimiter { return &RateLimiter{rate: rate} }

// rateBurst is how far ahead of the rate the limiter lets data through, so
// short gaps between requests don't turn into lost bandwidth.
const rateBurst = 250 * time.Millisecond

// Wait blocks until n more bytes may be sent.
func (l *RateLimiter) Wait(ctx context.Context, n int) error {
	r := l.rate()
	if r <= 0 || n <= 0 {
		return ctx.Err()
	}
	now := time.Now()
	l.mu.Lock()
	if l.next.Before(now.Add(-rateBurst)) {
		l.next = now.Add(-rateBurst)
	}
	l.next = l.next.Add(time.Duration(int64(n) * int64(time.Second) / r))
	d := l.next.Sub(now)
	l.mu.Unlock()
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// rateChunk is the largest read paced at once, so even a 4 MiB chunk is
// sent as a steady stream rather than a burst followed by silence.
const rateChunk = 32 << 10

// limitedReader paces a request body through a RateLimiter.
type limitedReader struct {
	ctx context.Context
	r   io.Reader
	l   *RateLimiter
}

func (lr *limitedReader) Read(p []byte) (int, error) {
	if len(p) > rateChunk {
		p = p[:rateChunk]
	}
	n, err := lr.r.Read(p)
	if n > 0 {
		if werr := lr.l.Wait(lr.ctx, n); werr != nil {
			return 0, werr
		}
	}
	return n, err
}
