// SPDX-License-Identifier: AGPL-3.0-or-later

package schedule

import (
	"testing"
	"time"
)

func TestCheck(t *testing.T) {
	s, err := Parse("0 21 * * *")
	if err != nil {
		t.Fatal(err)
	}
	loc := time.Local
	day := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, loc) }
	win := time.Hour

	cases := []struct {
		name      string
		last, now time.Time
		count     int
		onTime    bool
		slotDay   int
	}{
		{"before slot", day(12, 9, 0), day(12, 20, 59), 0, false, 0},
		{"exactly at slot", day(12, 9, 0), day(12, 21, 0), 1, true, 12},
		{"inside window", day(12, 9, 0), day(12, 21, 59), 1, true, 12},
		{"after window (was busy/asleep)", day(12, 9, 0), day(12, 22, 30), 1, false, 12},
		{"offline for three days", day(10, 9, 0), day(13, 8, 0), 3, false, 12},
		{"already handled", day(12, 21, 0), day(12, 21, 30), 0, false, 0},
	}
	for _, c := range cases {
		d := Check(s, c.last, c.now, win)
		if d.Count != c.count || d.OnTime != c.onTime || (c.count > 0 && d.Slot.Day() != c.slotDay) {
			t.Errorf("%s: got %+v", c.name, d)
		}
	}
	if Validate("61 * * * *") == nil || Validate("@every 6h") != nil {
		t.Fatal("validation wrong")
	}
}
