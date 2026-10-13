// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"fmt"
	"time"
)

// Window is when automatic installs may happen: on the chosen weekdays,
// starting at Time (local, "HH:MM") and lasting Minutes.
type Window struct {
	Days    []time.Weekday `json:"days"` // 0 = Sunday … 6 = Saturday
	Time    string         `json:"time"`
	Minutes int            `json:"minutes"`
}

func parseHHMM(s string) (h, m int, err error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid time %q (want HH:MM)", s)
	}
	return t.Hour(), t.Minute(), nil
}

// Validate checks the window settings.
func (w Window) Validate() error {
	if _, _, err := parseHHMM(w.Time); err != nil {
		return err
	}
	for _, d := range w.Days {
		if d < time.Sunday || d > time.Saturday {
			return fmt.Errorf("invalid weekday %d", d)
		}
	}
	if w.Minutes < 0 || w.Minutes > 24*60 {
		return fmt.Errorf("window must be between 0 and 1440 minutes")
	}
	return nil
}

func (w Window) length() time.Duration {
	if w.Minutes <= 0 {
		return time.Hour
	}
	return time.Duration(w.Minutes) * time.Minute
}

func (w Window) has(d time.Weekday) bool {
	for _, x := range w.Days {
		if x == d {
			return true
		}
	}
	return false
}

// Slot returns the start of the window that contains now, if any.
func (w Window) Slot(now time.Time) (time.Time, bool) {
	h, m, err := parseHHMM(w.Time)
	if err != nil {
		return time.Time{}, false
	}
	// The window may have started yesterday and run past midnight.
	for back := 0; back <= 1; back++ {
		d := now.AddDate(0, 0, -back)
		start := time.Date(d.Year(), d.Month(), d.Day(), h, m, 0, 0, now.Location())
		if w.has(start.Weekday()) && !now.Before(start) && now.Before(start.Add(w.length())) {
			return start, true
		}
	}
	return time.Time{}, false
}

// Next returns the start of the next window after now (zero if no day is selected).
func (w Window) Next(now time.Time) time.Time {
	h, m, err := parseHHMM(w.Time)
	if err != nil || len(w.Days) == 0 {
		return time.Time{}
	}
	for i := 0; i <= 7; i++ {
		d := now.AddDate(0, 0, i)
		start := time.Date(d.Year(), d.Month(), d.Day(), h, m, 0, 0, now.Location())
		if w.has(start.Weekday()) && start.After(now) {
			return start
		}
	}
	return time.Time{}
}
