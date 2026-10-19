// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tray is the ProxBackup tray app ("proxbackup-agent tray"): a
// notification-area icon in each user session that shows the agent's state
// and offers "Back up now", "Restore files…", recent runs and pausing
// scheduled backups. It talks to the agent service over internal/ipc.
package tray

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"time"

	"proxbackup/internal/api"
	"proxbackup/internal/ipc"
)

// Icon states.
const (
	stateOK      = "ok"
	stateRunning = "running"
	stateWarn    = "warn"
	stateFailed  = "failed"
	stateIdle    = "idle" // paused, not configured, or agent unreachable
)

// view is what the tray shows for a status (nil = agent unreachable).
type view struct {
	state   string
	tooltip string
	header  string
	last    string
	next    string
	running bool
	paused  bool
	recent  []string
}

func buildView(st *ipc.Status, now time.Time) view {
	if st == nil {
		return view{state: stateIdle, tooltip: "ProxBackup: the agent service is not running", header: "ProxBackup Agent is not running",
			last: "Backups can't start until it runs again"}
	}
	v := view{header: "ProxBackup: " + st.Client}
	// The latest result per job decides the colour: one failing job is a problem.
	var lastRun *ipc.RunInfo
	worst := stateOK
	for _, j := range st.Jobs {
		if j.LastRun == nil {
			continue
		}
		if lastRun == nil || j.LastRun.Finished > lastRun.Finished {
			lastRun = j.LastRun
		}
		switch j.LastRun.State {
		case api.RunFailed:
			worst = stateFailed
		case api.RunWarning, api.RunCanceled:
			if worst == stateOK {
				worst = stateWarn
			}
		}
	}
	switch {
	case !st.Configured || len(st.Jobs) == 0:
		v.state, v.last = stateIdle, "No backup jobs for this PC yet"
	case lastRun == nil:
		v.state, v.last = stateWarn, "Not backed up yet"
	default:
		v.state = worst
		v.last = fmt.Sprintf("Last backup: %s, %s", when(lastRun.Finished, now), lastRun.State)
	}
	var next int64
	for _, j := range st.Jobs {
		if j.NextRun > 0 && (next == 0 || j.NextRun < next) {
			next = j.NextRun
		}
	}
	if st.PausedUntil > now.Unix() {
		v.paused, v.state = true, stateIdle
		v.next = "Backups paused until " + when(st.PausedUntil, now)
	} else if next > 0 {
		v.next = "Next backup: " + when(next, now)
	}
	v.tooltip = "ProxBackup: " + v.last
	if r := st.Running; r != nil {
		v.running, v.state = true, stateRunning
		v.tooltip = "ProxBackup: " + runningText(r)
	} else if v.paused {
		v.tooltip = "ProxBackup: " + v.next
	}
	if !st.Online {
		v.tooltip += " (console unreachable)"
	}
	for _, r := range st.Recent {
		v.recent = append(v.recent, fmt.Sprintf("%s %s — %s: %s", stateMark(r.State), when(max(r.Finished, r.Started), now), r.JobName, r.State))
	}
	return v
}

func runningText(r *ipc.RunningRun) string {
	verb := "Backing up"
	if r.Kind == api.KindRestore {
		verb = "Restoring"
	}
	s := fmt.Sprintf("%s %s", verb, r.JobName)
	if p := r.Progress; p.BytesTotal > 0 {
		s += fmt.Sprintf(" (%d%%)", min(100, p.BytesRead*100/p.BytesTotal))
	} else if p.Files > 0 {
		s += fmt.Sprintf(" (%d files)", p.Files)
	}
	return s + "…"
}

func stateMark(s string) string {
	switch s {
	case api.RunSuccess:
		return "✓"
	case api.RunFailed, api.RunLost:
		return "✗"
	}
	return "!"
}

// when formats t relative to now: "today 14:02", "yesterday 21:00", "Mon 19 Oct 21:00".
func when(ts int64, now time.Time) string {
	t := time.Unix(ts, 0).In(now.Location())
	y1, m1, d1 := t.Date()
	day := func(d time.Time) time.Time {
		y, m, dd := d.Date()
		return time.Date(y, m, dd, 0, 0, 0, 0, now.Location())
	}
	switch days := int(math.Round(day(t).Sub(day(now)).Hours() / 24)); days {
	case 0:
		return "today " + t.Format("15:04")
	case -1:
		return "yesterday " + t.Format("15:04")
	case 1:
		return "tomorrow " + t.Format("15:04")
	}
	if y1 != now.Year() {
		return fmt.Sprintf("%d %s %d", d1, m1.String()[:3], y1)
	}
	return t.Format("Mon 2 Jan 15:04")
}

var stateColors = map[string]color.RGBA{
	stateOK:      {0x2e, 0x9d, 0x5a, 0xff},
	stateRunning: {0x2f, 0x6f, 0xd6, 0xff},
	stateWarn:    {0xd9, 0xa2, 0x1b, 0xff},
	stateFailed:  {0xd6, 0x45, 0x45, 0xff},
	stateIdle:    {0x8a, 0x8f, 0x98, 0xff},
}

// icon draws the tray icon for a state as an .ico (one 32×32 PNG image): a
// coloured disc with the console's "▣" mark in white.
func icon(state string) []byte {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	c := stateColors[state]
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)+0.5-n/2, float64(y)+0.5-n/2
			d := math.Hypot(dx, dy)
			if d > n/2 {
				continue
			}
			px := c
			if d > n/2-1 { // anti-aliased rim
				px.A = uint8(float64(c.A) * (n/2 - d))
			}
			ax, ay := math.Abs(dx), math.Abs(dy)
			switch {
			case ax <= 8 && ay <= 8 && (ax >= 6.5 || ay >= 6.5): // outer square
				px = white
			case ax <= 4 && ay <= 4: // inner square
				px = white
			}
			img.SetRGBA(x, y, px)
		}
	}
	var pngBuf bytes.Buffer
	png.Encode(&pngBuf, img)
	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, struct{ Reserved, Type, Count uint16 }{0, 1, 1})
	binary.Write(&ico, binary.LittleEndian, struct {
		W, H, Colors, Reserved uint8
		Planes, Bits           uint16
		Size, Offset           uint32
	}{n, n, 0, 0, 1, 32, uint32(pngBuf.Len()), 6 + 16})
	ico.Write(pngBuf.Bytes())
	return ico.Bytes()
}
