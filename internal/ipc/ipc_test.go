// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package ipc

import (
	"context"
	"os/user"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, l, func(_ context.Context, p *Peer, req Request) Response {
		switch req.Op {
		case OpStatus:
			return Response{Status: &Status{User: p.User, Client: "pc1"}}
		case OpPause:
			return Response{Message: "paused", Status: &Status{PausedUntil: int64(req.Minutes)}}
		}
		return Response{Error: "unknown operation"}
	})
	cctx, ccancel := context.WithTimeout(ctx, 5*time.Second)
	defer ccancel()
	resp, err := Call(cctx, dir, Request{Op: OpStatus})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := user.Current()
	if resp.Status.User != u.Username || resp.Status.Client != "pc1" {
		t.Errorf("status = %+v", resp.Status)
	}
	if resp, err = Call(cctx, dir, Request{Op: OpPause, Minutes: 60}); err != nil || resp.Status.PausedUntil != 60 {
		t.Errorf("pause: %+v, %v", resp, err)
	}
	if _, err := Call(cctx, dir, Request{Op: "nope"}); err == nil || err.Error() != "unknown operation" {
		t.Errorf("unknown op: %v", err)
	}
}
