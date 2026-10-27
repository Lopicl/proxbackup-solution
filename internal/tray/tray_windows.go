// SPDX-License-Identifier: AGPL-3.0-or-later

package tray

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"proxbackup/internal/ipc"
)

const (
	pollEvery  = 5 * time.Second
	recentRows = 10
	title      = "ProxBackup"
)

// Run shows the tray icon until the user quits, and returns the process exit
// code for the agent's launcher (ipc.TrayExit*).
// replace is set when an older tray started this one after an agent update.
func Run(version, dataDir string, replace bool) int {
	if !singleInstance(replace) {
		return ipc.TrayExitDuplicate
	}
	t := &app{version: version, dataDir: dataDir, exit: ipc.TrayExitQuit}
	systray.Run(t.ready, func() {})
	return t.exit
}

// singleInstance holds a per-session mutex for the life of the process. A
// tray replacing an older version waits briefly for it to exit.
func singleInstance(replace bool) bool {
	name := windows.StringToUTF16Ptr(`Local\ProxBackupTray`)
	for i := 0; i < 20; i++ {
		h, err := windows.CreateMutex(nil, false, name)
		if err == nil {
			return true // the handle is released when the process exits
		}
		if h != 0 {
			windows.CloseHandle(h)
		}
		if err != windows.ERROR_ALREADY_EXISTS || !replace {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

type app struct {
	version, dataDir string
	exit             int

	mu     sync.Mutex
	status *ipc.Status
	state  string

	header, last, next, backup, restore, recent, pause, resume *systray.MenuItem
	recentRows                                                 []*systray.MenuItem
}

func (t *app) ready() {
	systray.SetTitle(title)
	t.header = systray.AddMenuItem(title, "")
	t.header.Disable()
	t.last = systray.AddMenuItem("", "")
	t.last.Disable()
	t.next = systray.AddMenuItem("", "")
	t.next.Disable()
	systray.AddSeparator()
	t.backup = systray.AddMenuItem("Back up now", "Run this PC's backup jobs now")
	t.restore = systray.AddMenuItem("Restore files…", "Choose files to restore from a backup, in your browser")
	t.recent = systray.AddMenuItem("Recent runs", "")
	for i := 0; i < recentRows; i++ {
		row := t.recent.AddSubMenuItem("", "")
		row.Disable()
		row.Hide()
		t.recentRows = append(t.recentRows, row)
	}
	t.pause = systray.AddMenuItem("Pause scheduled backups", "Scheduled backups wait; runs with catch-up start when the pause ends")
	pauses := map[*systray.MenuItem]int{
		t.pause.AddSubMenuItem("For 1 hour", ""):   60,
		t.pause.AddSubMenuItem("For 4 hours", ""):  4 * 60,
		t.pause.AddSubMenuItem("For 24 hours", ""): 24 * 60,
	}
	t.resume = systray.AddMenuItem("Resume scheduled backups", "")
	t.resume.Hide()
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit", "Hide the ProxBackup icon until you sign in again (backups continue)")

	t.apply(nil)
	go t.poll()
	go func() {
		for range t.backup.ClickedCh {
			go t.call(ipc.Request{Op: ipc.OpBackupNow}, false)
		}
	}()
	go func() {
		for range t.restore.ClickedCh {
			go t.openRestore()
		}
	}()
	for item, min := range pauses {
		go func() {
			for range item.ClickedCh {
				go t.call(ipc.Request{Op: ipc.OpPause, Minutes: min}, true)
			}
		}()
	}
	go func() {
		for range t.resume.ClickedCh {
			go t.call(ipc.Request{Op: ipc.OpResume}, true)
		}
	}()
	go func() {
		<-quit.ClickedCh
		systray.Quit()
	}()
}

func (t *app) poll() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		resp, err := ipc.Call(ctx, t.dataDir, ipc.Request{Op: ipc.OpStatus})
		cancel()
		if err != nil {
			t.apply(nil)
		} else {
			t.apply(resp.Status)
		}
		time.Sleep(pollEvery)
	}
}

// apply updates the menu and icon for st (nil = agent unreachable).
func (t *app) apply(st *ipc.Status) {
	if st != nil && st.Exe != "" && (st.Version != t.version || !sameFile(st.Exe)) {
		t.replace(st.Exe) // the agent was updated or moved: run the new tray
		return
	}
	v := buildView(st, time.Now())
	t.mu.Lock()
	t.status = st
	changed := v.state != t.state
	t.state = v.state
	t.mu.Unlock()
	if changed {
		systray.SetIcon(icon(v.state))
	}
	systray.SetTooltip(v.tooltip)
	t.header.SetTitle(v.header)
	setOrHide(t.last, v.last)
	setOrHide(t.next, v.next)
	enable(t.backup, st != nil && st.Configured && len(st.Jobs) > 0 && !v.running)
	if v.running {
		t.backup.SetTitle(runningText(st.Running))
	} else {
		t.backup.SetTitle("Back up now")
	}
	enable(t.restore, st != nil)
	enable(t.pause, st != nil && st.Configured)
	if v.paused {
		t.pause.Hide()
		t.resume.Show()
	} else {
		t.resume.Hide()
		t.pause.Show()
	}
	enable(t.recent, len(v.recent) > 0)
	for i, row := range t.recentRows {
		if i < len(v.recent) {
			row.SetTitle(v.recent[i])
			row.Show()
		} else {
			row.Hide()
		}
	}
}

func setOrHide(m *systray.MenuItem, s string) {
	if s == "" {
		m.Hide()
		return
	}
	m.SetTitle(s)
	m.Show()
}

func enable(m *systray.MenuItem, on bool) {
	if on {
		m.Enable()
	} else {
		m.Disable()
	}
}

// call sends req and shows the agent's error, or its message if quiet is false.
func (t *app) call(req ipc.Request, quiet bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := ipc.Call(ctx, t.dataDir, req)
	if err != nil {
		message(err.Error(), true)
		return
	}
	if resp.Status != nil {
		t.apply(resp.Status)
	}
	if !quiet && resp.Message != "" {
		message(resp.Message, false)
	}
}

// openRestore asks the agent for a restore page on the console and opens it.
func (t *app) openRestore() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := ipc.Call(ctx, t.dataDir, ipc.Request{Op: ipc.OpRestoreLink})
	if err != nil {
		message("The restore page can't be opened: "+err.Error(), true)
		return
	}
	if err := windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(resp.URL), nil, nil, windows.SW_SHOWNORMAL); err != nil {
		message(fmt.Sprintf("Open %s in your browser to restore files (%v).", resp.URL, err), true)
	}
}

// sameFile reports whether exe is this tray's executable.
func sameFile(exe string) bool {
	self, err := os.Executable()
	return err != nil || strings.EqualFold(filepath.Clean(self), filepath.Clean(exe))
}

// replace starts the tray of the updated agent and exits this one.
func (t *app) replace(exe string) {
	cmd := exec.Command(exe, "tray", "-replace")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if cmd.Start() == nil {
		t.exit = ipc.TrayExitRestart
		systray.Quit()
	}
}

func message(text string, isErr bool) {
	flags := uint32(windows.MB_OK | windows.MB_ICONINFORMATION | windows.MB_SETFOREGROUND)
	if isErr {
		flags = windows.MB_OK | windows.MB_ICONWARNING | windows.MB_SETFOREGROUND
	}
	windows.MessageBox(0, windows.StringToUTF16Ptr(text), windows.StringToUTF16Ptr(title), flags)
}
