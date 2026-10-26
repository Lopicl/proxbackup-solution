// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"fmt"
	"slices"
	"time"
)

// Bandwidth caps how fast a backup uploads to PBS. Rates are in kbit/s
// (0 = unlimited). During the optional window (PC local time, on Days or
// every day) WindowRate applies instead of Rate, e.g. a tighter limit during
// office hours.
type Bandwidth struct {
	Rate       int `json:"rate,omitempty"`
	WindowRate int `json:"window_rate,omitempty"`
	// WindowStart and WindowEnd are "HH:MM"; an end before the start runs past
	// midnight. Both empty = no window.
	WindowStart string `json:"window_start,omitempty"`
	WindowEnd   string `json:"window_end,omitempty"`
	// WindowDays are weekdays (0 = Sunday) the window starts on; empty = every day.
	WindowDays []int `json:"window_days,omitempty"`
}

// maxRate bounds a limit (100 Gbit/s), so byte arithmetic can't overflow.
const maxRate = 100_000_000

// Validate checks the limit's fields.
func (b Bandwidth) Validate() error {
	if b.Rate < 0 || b.Rate > maxRate || b.WindowRate < 0 || b.WindowRate > maxRate {
		return fmt.Errorf("bandwidth limit must be between 0 and %d kbit/s", maxRate)
	}
	if (b.WindowStart == "") != (b.WindowEnd == "") {
		return fmt.Errorf("bandwidth window needs both a start and an end time")
	}
	if b.WindowStart == "" {
		return nil
	}
	s, err1 := parseClock(b.WindowStart)
	e, err2 := parseClock(b.WindowEnd)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("bandwidth window times must be HH:MM")
	}
	if s == e {
		return fmt.Errorf("bandwidth window start and end must differ")
	}
	for _, d := range b.WindowDays {
		if d < 0 || d > 6 {
			return fmt.Errorf("bandwidth window days must be 0 (Sunday) to 6")
		}
	}
	return nil
}

// Clean validates the limit and puts it in canonical form (so an unchanged
// limit doesn't change the agent's config revision): days sorted and
// deduplicated, none when it is every day, no window fields without a window.
func (b *Bandwidth) Clean() error {
	if err := b.Validate(); err != nil {
		return err
	}
	if b.WindowStart == "" {
		b.WindowRate, b.WindowDays = 0, nil
		return nil
	}
	days := slices.Compact(slices.Sorted(slices.Values(b.WindowDays)))
	if len(days) == 0 || len(days) == 7 {
		days = nil
	}
	b.WindowDays = days
	return nil
}

// Limited reports whether the limit ever slows uploads down.
func (b Bandwidth) Limited() bool {
	return b.Rate > 0 || (b.WindowStart != "" && b.WindowRate > 0)
}

// RateAt is the limit in kbit/s at t (0 = unlimited).
func (b Bandwidth) RateAt(t time.Time) int {
	if b.inWindow(t) {
		return b.WindowRate
	}
	return b.Rate
}

func (b Bandwidth) inWindow(t time.Time) bool {
	s, err1 := parseClock(b.WindowStart)
	e, err2 := parseClock(b.WindowEnd)
	if err1 != nil || err2 != nil || s == e {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	day := int(t.Weekday())
	if s > e && m < e { // after midnight: the window started the day before
		day = (day + 6) % 7
	} else if m < s || (s < e && m >= e) {
		return false
	}
	return len(b.WindowDays) == 0 || slices.Contains(b.WindowDays, day)
}

func parseClock(v string) (int, error) {
	t, err := time.Parse("15:04", v)
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

// MinRate combines limits: the lowest non-zero rate at t (0 = unlimited).
func MinRate(t time.Time, limits ...Bandwidth) int {
	r := 0
	for _, b := range limits {
		if v := b.RateAt(t); v > 0 && (r == 0 || v < r) {
			r = v
		}
	}
	return r
}
