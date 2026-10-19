// SPDX-License-Identifier: AGPL-3.0-or-later

package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestPipe runs on Windows (go test -c, copied to a test VM and run over
// SSH): the network-logon deny, peer identity and impersonated file creation.
// The test process isn't SYSTEM, so its ACLs grant administrators full
// control as well (creating further pipe instances needs it).
func TestPipe(t *testing.T) {
	pipePath = `\\.\pipe\proxbackup-agent-test`
	checkServer = func(net.Conn) error { return nil }
	realSDDL := pipeSDDL
	defer func() { pipePath, checkServer, pipeSDDL = PipeName, isAgentService, realSDDL }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cctx, ccancel := context.WithTimeout(ctx, 10*time.Second)
	defer ccancel()

	// Network logons (SSH sessions included) are refused even with access granted to their group.
	pipeSDDL = realSDDL + "(A;;GA;;;BA)"
	l, err := Listen("")
	if err != nil {
		t.Fatal(err)
	}
	go Serve(ctx, l, func(context.Context, *Peer, Request) Response { return Response{} })
	if os.Getenv("SESSIONNAME") == "" { // not an interactive session
		if _, err := Call(cctx, "", Request{Op: OpStatus}); err == nil || !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "negato") {
			t.Errorf("network logon: %v, want access denied", err)
		}
	}
	l.Close()

	pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if l, err = Listen(""); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var got *Peer
	go Serve(ctx, l, func(_ context.Context, p *Peer, req Request) Response {
		k, err := p.Keep()
		if err != nil {
			return Response{Error: err.Error()}
		}
		got = k
		err = k.RunAs(func() error { return os.WriteFile(filepath.Join(dir, "as-user.txt"), []byte("x"), 0o644) })
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Message: "ok"}
	})
	if _, err := Call(cctx, "", Request{Op: OpStatus}); err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	t.Logf("peer: user=%s sid=%s profile=%s admin=%v", got.User, got.SID, got.Profile, got.Admin)
	if got.User == "" || !strings.HasPrefix(got.SID, "S-1-5-") || got.Profile == "" || !got.Admin {
		t.Errorf("peer = %+v", got)
	}
	sd, err := windows.GetNamedSecurityInfo(filepath.Join(dir, "as-user.txt"), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	t.Logf("file written while impersonating, owner %s", owner)

	// A pipe that isn't served by the agent service is refused.
	checkServer = isAgentService
	if _, err := Call(cctx, "", Request{Op: OpStatus}); err == nil {
		t.Error("a test pipe passed the agent service check")
	} else {
		t.Logf("service check: %v", err)
	}
}
