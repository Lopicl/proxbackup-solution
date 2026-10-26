// SPDX-License-Identifier: AGPL-3.0-or-later

package pbs

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestRateLimiter(t *testing.T) {
	var rate atomic.Int64
	rate.Store(400 << 10)
	l := NewRateLimiter(func() int64 { return rate.Load() })
	ctx := context.Background()
	start := time.Now()
	n, err := io.Copy(io.Discard, &limitedReader{ctx: ctx, r: bytes.NewReader(make([]byte, 400<<10)), l: l})
	if err != nil || n != 400<<10 {
		t.Fatal(n, err)
	}
	// One second's worth, minus the burst allowance.
	if d := time.Since(start); d < 600*time.Millisecond || d > 1500*time.Millisecond {
		t.Errorf("400 KiB at 400 KiB/s took %v", d)
	}

	rate.Store(0) // unlimited
	start = time.Now()
	io.Copy(io.Discard, &limitedReader{ctx: ctx, r: bytes.NewReader(make([]byte, 8<<20)), l: l})
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("unlimited copy took %v", d)
	}

	rate.Store(1) // canceled while waiting
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(cctx, 1<<20); err == nil {
		t.Error("Wait ignored the canceled context")
	}
}

// TestRateLimitedH2Upload sends a chunk-sized body through a real HTTP/2
// connection, as backup uploads do, and checks the server receives it paced.
func TestRateLimitedH2Upload(t *testing.T) {
	sc, cc := net.Pipe()
	var got atomic.Int64
	go (&http2.Server{}).ServeConn(sc, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Store(n)
		w.Write([]byte(`{"data":null}`))
	})})
	conn, err := (&http2.Transport{}).NewClientConn(cc)
	if err != nil {
		t.Fatal(err)
	}
	s := &h2Session{conn: cc, cc: conn, limit: NewRateLimiter(func() int64 { return 2 << 20 })}
	defer s.Close()
	start := time.Now()
	if err := s.call(context.Background(), http.MethodPost, "dynamic_chunk", nil, make([]byte, 2<<20), "application/octet-stream", nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 600*time.Millisecond || d > 2*time.Second || got.Load() != 2<<20 {
		t.Errorf("2 MiB at 2 MiB/s: %d bytes in %v", got.Load(), d)
	}
}
