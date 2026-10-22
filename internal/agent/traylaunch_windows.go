// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"proxbackup/internal/ipc"
)

// launchTrays starts the tray app ("proxbackup-agent tray") in every active
// user session, as that user, and again after a crash or an agent update. It
// is the same executable, so self-update keeps both in step. A user who quits
// the tray gets it back at their next logon. Failures are passed to setErr
// per session (0: listing sessions), and cleared with "".
func launchTrays(ctx context.Context, log *slog.Logger, setErr func(session uint32, msg string)) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	type trayProc struct {
		h       windows.Handle
		started time.Time
		done    bool // quit by the user, or another tray runs
		retryAt time.Time
	}
	procs := map[uint32]*trayProc{}
	defer func() {
		for _, p := range procs {
			if p.h != 0 {
				windows.CloseHandle(p.h)
			}
		}
	}()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		sessions, err := userSessions()
		if err != nil {
			log.Warn("listing user sessions", "err", err)
			setErr(0, "can't list the user sessions to start the tray app: "+err.Error())
		} else {
			setErr(0, "")
		}
		for id, p := range procs {
			if _, ok := sessions[id]; !ok { // logged off
				if p.h != 0 {
					windows.CloseHandle(p.h)
				}
				delete(procs, id)
				setErr(id, "")
			}
		}
		now := time.Now()
		for id, active := range sessions {
			p := procs[id]
			if p != nil && p.h != 0 {
				if ev, _ := windows.WaitForSingleObject(p.h, 0); ev == uint32(windows.WAIT_TIMEOUT) {
					if now.Sub(p.started) >= time.Minute {
						setErr(id, "") // up and running
					}
					continue
				}
				var code uint32
				windows.GetExitCodeProcess(p.h, &code)
				windows.CloseHandle(p.h)
				p.h = 0
				switch code {
				case ipc.TrayExitQuit, ipc.TrayExitDuplicate:
					p.done = true
					setErr(id, "")
				case ipc.TrayExitRestart:
				default:
					if now.Sub(p.started) < time.Minute {
						p.retryAt = now.Add(5 * time.Minute) // crashing at start: don't spin
						log.Warn("tray app exited", "session", id, "code", code)
						setErr(id, fmt.Sprintf("the tray app in user session %d exited right after starting (exit code %#x)", id, code))
					}
				}
			}
			if !active || p != nil && (p.done || now.Before(p.retryAt)) {
				continue
			}
			h, err := spawnTray(id, exe)
			if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
				return // not running as the service (e.g. "run" in a console)
			}
			if err != nil {
				log.Warn("starting the tray app", "session", id, "err", err)
				setErr(id, fmt.Sprintf("can't start the tray app in user session %d: %v", id, err))
				procs[id] = &trayProc{retryAt: now.Add(time.Minute)}
				continue
			}
			procs[id] = &trayProc{h: h, started: now}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// userSessions lists the sessions with a logged-on user (active or
// disconnected), excluding session 0 where services run.
func userSessions() (map[uint32]bool, error) {
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &n); err != nil {
		return nil, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	out := map[uint32]bool{}
	for _, s := range unsafe.Slice(info, n) {
		const wtsActive, wtsDisconnected = 0, 4
		if s.SessionID != 0 && (s.State == wtsActive || s.State == wtsDisconnected) {
			out[s.SessionID] = s.State == wtsActive
		}
	}
	return out, nil
}

// spawnTray starts the tray app in session as its user, on the user's
// desktop and without a console window.
func spawnTray(session uint32, exe string) (windows.Handle, error) {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return 0, err
	}
	defer windows.DestroyEnvironmentBlock(env)
	si := &windows.StartupInfo{Desktop: windows.StringToUTF16Ptr(`winsta0\default`)}
	si.Cb = uint32(unsafe.Sizeof(*si))
	var pi windows.ProcessInformation
	cmd := windows.EscapeArg(exe) + " tray"
	err := windows.CreateProcessAsUser(tok, nil, windows.StringToUTF16Ptr(cmd), nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, windows.StringToUTF16Ptr(filepath.Dir(exe)), si, &pi)
	if err != nil {
		return 0, err
	}
	windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}
