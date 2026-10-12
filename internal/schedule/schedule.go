// Package schedule parses job schedules and decides when a scheduled backup is
// due. It is used by the agent (which runs jobs on its own clock, in the PC's
// local time zone) and by the server (to validate schedules).
package schedule

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Parse parses a cron expression ("30 21 * * 1-5", "@daily", "@every 6h").
func Parse(spec string) (cron.Schedule, error) {
	s, err := parser.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid schedule %q: %w", spec, err)
	}
	return s, nil
}

// Validate checks a cron expression.
func Validate(spec string) error {
	_, err := Parse(spec)
	return err
}

// maxSlots bounds how many past slots are scanned (e.g. "* * * * *" after a month offline).
const maxSlots = 100000

// Due is the outcome of checking a job against the clock.
type Due struct {
	// Slot is the most recent scheduled time in (last, now]; zero if none.
	Slot time.Time
	// Count is how many slots fell in (last, now]; >1 means some were skipped
	// (e.g. the PC was off), they are coalesced into one run.
	Count int
	// OnTime is true when Slot is within the start window, i.e. the run can
	// start now as a regular scheduled run.
	OnTime bool
}

// Check finds scheduled slots after last and up to now. window is how long
// after its scheduled time a run may still start "on time".
func Check(s cron.Schedule, last, now time.Time, window time.Duration) Due {
	var d Due
	for t := s.Next(last); !t.After(now) && !t.IsZero(); t = s.Next(t) {
		d.Slot = t
		d.Count++
		if d.Count >= maxSlots {
			break
		}
	}
	if d.Count > 0 {
		d.OnTime = now.Sub(d.Slot) <= window
	}
	return d
}
