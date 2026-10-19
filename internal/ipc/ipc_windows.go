// SPDX-License-Identifier: AGPL-3.0-or-later

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// pipeSDDL: SYSTEM full control; interactive users (local console and RDP
// logons) may read and write data (0x12018B: FILE_READ_DATA, FILE_WRITE_DATA,
// FILE_READ_EA, FILE_READ/WRITE_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE), but
// not FILE_CREATE_PIPE_INSTANCE, so they can't serve instances of the pipe
// themselves. Network logons are denied explicitly.
var pipeSDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;0x12018b;;;IU)" // variable for tests

// clientAccess is what the tray asks for: exactly what the ACL grants
// (GENERIC_WRITE would include FILE_CREATE_PIPE_INSTANCE and be denied).
const clientAccess = 0x1 | 0x2 | 0x80 | 0x100 | 0x100000

// Listen creates the agent's named pipe.
func Listen(string) (net.Listener, error) {
	return winio.ListenPipe(pipePath, &winio.PipeConfig{SecurityDescriptor: pipeSDDL, InputBufferSize: 4096, OutputBufferSize: 64 << 10})
}

// dial connects to the agent, allowing it to impersonate this user (restores
// of non-administrators run with the user's own rights). Before anything is
// sent, it checks that the pipe is served by the ProxBackup Agent service's
// own process, so no other process can impersonate the tray's user.
func dial(ctx context.Context, _ string) (net.Conn, error) {
	c, err := winio.DialPipeAccessImpLevel(ctx, pipePath, clientAccess, winio.PipeImpLevelImpersonation)
	if err != nil {
		return nil, err
	}
	if err := checkServer(c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// pipePath and checkServer are variables for tests.
var (
	pipePath    = PipeName
	checkServer = isAgentService
)

// isAgentService checks that c's server process is the running agent service.
func isAgentService(c net.Conn) error {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return errors.New("not a named pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return fmt.Errorf("pipe server: %w", err)
	}
	svcPID, err := servicePID(ServiceName)
	if err != nil {
		return fmt.Errorf("the ProxBackup Agent service: %w", err)
	}
	if pid != svcPID {
		return fmt.Errorf("%s is served by process %d, not the ProxBackup Agent service (%d)", pipePath, pid, svcPID)
	}
	return nil
}

// servicePID asks the service manager for the process of a running service
// (rights every user has).
func servicePID(name string) (uint32, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(m)
	s, err := windows.OpenService(m, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var n uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n); err != nil {
		return 0, err
	}
	if st.CurrentState != windows.SERVICE_RUNNING || st.ProcessId == 0 {
		return 0, errors.New("not running")
	}
	return st.ProcessId, nil
}

type peerToken = windows.Token

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeCli = advapi32.NewProc("ImpersonateNamedPipeClient")
)

// peerOf takes the pipe client's token by impersonating it briefly.
func peerOf(c net.Conn) (*Peer, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return nil, errors.New("not a named pipe")
	}
	tok, err := clientToken(windows.Handle(f.Fd()))
	if err != nil {
		return nil, err
	}
	p, err := peerFromToken(tok)
	if err != nil {
		tok.Close()
		return nil, err
	}
	return p, nil
}

func clientToken(h windows.Handle) (windows.Token, error) {
	runtime.LockOSThread()
	if r, _, err := procImpersonateNamedPipeCli.Call(uintptr(h)); r == 0 {
		runtime.UnlockOSThread()
		return 0, fmt.Errorf("ImpersonateNamedPipeClient: %w", err)
	}
	var imp windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ALL_ACCESS, true, &imp)
	if rerr := windows.RevertToSelf(); rerr != nil {
		// Never hand a thread that still impersonates back to the scheduler:
		// returning with it locked makes the runtime discard it.
		return 0, fmt.Errorf("RevertToSelf: %w", rerr)
	}
	runtime.UnlockOSThread()
	if err != nil {
		return 0, fmt.Errorf("OpenThreadToken: %w", err)
	}
	defer imp.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(imp, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return dup, nil
}

func peerFromToken(tok windows.Token) (*Peer, error) {
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := tu.User.Sid
	p := &Peer{SID: sid.String(), token: tok}
	if name, domain, _, err := sid.LookupAccount(""); err == nil {
		p.User = domain + `\` + name
	} else {
		p.User = p.SID
	}
	if p.Profile, err = tok.GetUserProfileDirectory(); err != nil {
		return nil, fmt.Errorf("profile folder of %s: %w", p.User, err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) {
		p.Admin = true
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return nil, err
	}
	// With UAC the group is present but deny-only until the user elevates;
	// they are an administrator either way.
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, admins) {
			p.Admin = true
		}
	}
	return p, nil
}

// Keep returns a copy of the peer that stays valid after the request (the
// agent keeps it for the user's restore session). Close it when done.
func (p *Peer) Keep() (*Peer, error) {
	var dup windows.Token
	if err := windows.DuplicateTokenEx(p.token, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return nil, err
	}
	k := *p
	k.token = dup
	return &k, nil
}

// Close releases the peer's token.
func (p *Peer) Close() {
	if p.token != 0 {
		p.token.Close()
		p.token = 0
	}
}

// RunAs runs fn on a thread that impersonates the peer, so files it creates
// are checked against, and owned by, the user. fn must not hand file system
// work to other goroutines: those run with the service's rights.
func (p *Peer) RunAs(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, p.token); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("impersonate %s: %w", p.User, err)
			return
		}
		var err error
		defer func() {
			if windows.RevertToSelf() == nil {
				runtime.UnlockOSThread()
			} // else: the goroutine exits with the thread locked, and the runtime discards it
			errc <- err
		}()
		err = fn()
	}()
	return <-errc
}
