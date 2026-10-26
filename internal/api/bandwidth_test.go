// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"testing"
	"time"
)

func TestBandwidthRateAt(t *testing.T) {
	at := func(day, hh, mm int) time.Time { // 2026-10-25 is a Sunday
		return time.Date(2026, 10, 25+day, hh, mm, 0, 0, time.Local)
	}
	office := Bandwidth{Rate: 50000, WindowRate: 10000, WindowStart: "08:00", WindowEnd: "18:00", WindowDays: []int{1, 2, 3, 4, 5}}
	night := Bandwidth{WindowRate: 2000, WindowStart: "22:00", WindowEnd: "06:00", WindowDays: []int{5}}
	cases := []struct {
		b    Bandwidth
		t    time.Time
		want int
	}{
		{office, at(1, 7, 59), 50000},
		{office, at(1, 8, 0), 10000},
		{office, at(1, 17, 59), 10000},
		{office, at(1, 18, 0), 50000},
		{office, at(0, 12, 0), 50000}, // Sunday
		{night, at(5, 23, 0), 2000},   // Friday night
		{night, at(6, 5, 59), 2000},   // into Saturday
		{night, at(6, 6, 0), 0},
		{night, at(6, 23, 0), 0}, // Saturday night isn't in WindowDays
		{Bandwidth{}, at(1, 12, 0), 0},
	}
	for i, c := range cases {
		if got := c.b.RateAt(c.t); got != c.want {
			t.Errorf("case %d (%s): got %d, want %d", i, c.t.Format("Mon 15:04"), got, c.want)
		}
	}
	if got := MinRate(at(1, 12, 0), office, Bandwidth{Rate: 20000}); got != 10000 {
		t.Errorf("MinRate = %d", got)
	}
	if got := MinRate(at(1, 20, 0), office, Bandwidth{Rate: 20000}); got != 20000 {
		t.Errorf("MinRate = %d", got)
	}
}

func TestBandwidthValidate(t *testing.T) {
	bad := []Bandwidth{{Rate: -1}, {WindowStart: "08:00"}, {WindowStart: "8am", WindowEnd: "18:00"},
		{WindowStart: "08:00", WindowEnd: "08:00"}, {WindowStart: "08:00", WindowEnd: "09:00", WindowDays: []int{7}}}
	for i, b := range bad {
		if b.Validate() == nil {
			t.Errorf("case %d: accepted %+v", i, b)
		}
	}
	if err := (Bandwidth{Rate: 1000, WindowRate: 0, WindowStart: "22:00", WindowEnd: "06:00"}).Validate(); err != nil {
		t.Error(err)
	}
}
