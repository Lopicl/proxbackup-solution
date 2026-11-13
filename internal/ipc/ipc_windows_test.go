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
	"unsafe"

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

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// An administrator counts as one only with the Administrators group enabled:
// a UAC-filtered token (the group deny-only) gets a user's restore scope.
func TestPeerAdminNeedsElevation(t *testing.T) {
	proc := windows.GetCurrentProcessToken()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	if !proc.IsElevated() {
		t.Skip("needs an elevated test process")
	}
	full, err := peerFromToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !full.Admin || full.Elevatable {
		t.Fatalf("elevated token: admin=%v elevatable=%v", full.Admin, full.Elevatable)
	}
	// LUA_TOKEN: what UAC gives an administrator's unelevated processes.
	const luaToken = 0x4
	var lua windows.Token
	if r, _, err := procCreateRestrictedToken.Call(uintptr(tok), luaToken, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&lua))); r == 0 {
		t.Fatalf("CreateRestrictedToken: %v", err)
	}
	defer lua.Close()
	p, err := peerFromToken(lua)
	if err != nil {
		t.Fatal(err)
	}
	if p.Admin || !p.Elevatable {
		t.Fatalf("filtered token: admin=%v elevatable=%v", p.Admin, p.Elevatable)
	}
}

// CanRead checks a security descriptor against the peer's token: the
// owner alone doesn't read, an ACE for the user (or Everyone) does.
func TestCanRead(t *testing.T) {
	var proc, imp windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &proc); err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	if err := windows.DuplicateTokenEx(proc, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatal(err)
	}
	p := &Peer{token: imp}
	defer p.Close()
	tu, err := imp.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := tu.User.Sid.String()
	sd := func(sddl string) []byte {
		s, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		return unsafe.Slice((*byte)(unsafe.Pointer(s)), s.Length())
	}
	for sddl, want := range map[string]error{
		"O:" + me + "G:SYD:(A;;FA;;;SY)":          ErrNoReadAccess, // owner, but no ACE: a deleted user's file under a reused profile path
		"O:SYG:SYD:(A;;FR;;;" + me + ")":          nil,
		"O:SYG:SYD:(A;;0x1;;;WD)":                 nil,
		"O:SYG:SYD:(A;;FA;;;SY)":                  ErrNoReadAccess,
		"O:SYG:SYD:(D;;0x1;;;WD)(A;;FA;;;WD)":     ErrNoReadAccess,
		"O:SYG:SYD:(A;;FA;;;S-1-5-21-1-2-3-1001)": ErrNoReadAccess,
	} {
		if got := p.CanRead(sd(sddl)); got != want {
			t.Errorf("%s: %v, want %v", sddl, got, want)
		}
	}
	if got := p.CanRead(nil); got != ErrNoSecurity {
		t.Errorf("no descriptor: %v", got)
	}
}
