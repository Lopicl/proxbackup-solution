// SPDX-License-Identifier: AGPL-3.0-or-later

package tray

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/ipc"
)

func TestBuildView(t *testing.T) {
	now := time.Date(2026, 10, 19, 15, 0, 0, 0, time.Local)
	ok := &ipc.RunInfo{JobID: 1, JobName: "Documents", State: api.RunSuccess, Finished: now.Add(-time.Hour).Unix()}
	failed := &ipc.RunInfo{JobID: 2, JobName: "Image", State: api.RunFailed, Finished: now.Add(-26 * time.Hour).Unix()}
	st := &ipc.Status{Client: "pc1", Online: true, Configured: true,
		Jobs:   []ipc.Job{{ID: 1, Name: "Documents", LastRun: ok, NextRun: now.Add(6 * time.Hour).Unix()}, {ID: 2, Name: "Image", LastRun: failed}},
		Recent: []ipc.RunInfo{*ok, *failed}}

	v := buildView(st, now)
	if v.state != stateFailed || v.last != "Last backup: today 14:00, success" || v.next != "Next backup: today 21:00" {
		t.Errorf("view = %+v", v)
	}
	if len(v.recent) != 2 || !strings.HasPrefix(v.recent[1], "✗ yesterday 13:00 — Image") {
		t.Errorf("recent = %q", v.recent)
	}

	st.Running = &ipc.RunningRun{JobName: "Documents", Kind: api.KindFiles, Progress: api.Progress{BytesRead: 50, BytesTotal: 200}}
	if v = buildView(st, now); v.state != stateRunning || v.tooltip != "ProxBackup: Backing up Documents (25%)…" {
		t.Errorf("running view = %+v", v)
	}
	st.Running, st.Waiting = nil, "on battery power"
	if v = buildView(st, now); v.state != stateFailed || v.next != "Backup waits: the PC is on battery power" || v.tooltip != "ProxBackup: "+v.next {
		t.Errorf("waiting view = %+v", v)
	}
	st.Waiting = ""
	st.Running, st.PausedUntil, st.Online = nil, now.Add(time.Hour).Unix(), false
	if v = buildView(st, now); !v.paused || v.state != stateIdle || v.tooltip != "ProxBackup: Backups paused until today 16:00 (console unreachable)" {
		t.Errorf("paused view = %+v", v)
	}
	if v = buildView(nil, now); v.state != stateIdle {
		t.Errorf("unreachable view = %+v", v)
	}
	if v = buildView(&ipc.Status{Configured: true, Jobs: []ipc.Job{{ID: 1}}}, now); v.last != "Not backed up yet" || v.state != stateWarn {
		t.Errorf("new PC view = %+v", v)
	}
}

func TestIcon(t *testing.T) {
	ico := icon(stateOK)
	if !bytes.Equal(ico[:6], []byte{0, 0, 1, 0, 1, 0}) {
		t.Fatalf("ico header % x", ico[:6])
	}
	img, err := png.Decode(bytes.NewReader(ico[22:]))
	if err != nil || img.Bounds().Dx() != 32 {
		t.Fatalf("png: %v", err)
	}
}
