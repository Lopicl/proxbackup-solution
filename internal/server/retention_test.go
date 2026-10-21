// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

func snap(t time.Time, protected bool) pbs.SnapshotInfo {
	s := pbs.SnapshotInfo{BackupType: "host", BackupID: "pc1", BackupTime: t.Unix(), Protected: protected}
	s.Files = append(s.Files, struct {
		Filename  string `json:"filename"`
		Size      uint64 `json:"size"`
		CryptMode string `json:"crypt-mode"`
	}{Filename: "index.json.blob"})
	return s
}

func removedTimes(sel pruneSelection) []int64 {
	var out []int64
	for _, s := range sel.Remove {
		out = append(out, s.BackupTime)
	}
	slices.Sort(out)
	return out
}

func TestSelectPruneMatchesPBSBuckets(t *testing.T) {
	loc := time.UTC
	day := func(d, h int) time.Time { return time.Date(2026, 10, d, h, 0, 0, 0, loc) }
	var snaps []pbs.SnapshotInfo
	for d := 1; d <= 10; d++ {
		snaps = append(snaps, snap(day(d, 9), false), snap(day(d, 21), false))
	}
	sel := selectPrune(snaps, pbs.KeepOptions{Last: 2, Daily: 3}, 10, loc)
	// keep-last: 10th 21:00 and 09:00; keep-daily then takes the newest of the 9th, 8th, 7th.
	if sel.Kept != 5 || len(sel.Remove) != 15 || len(sel.OverCap) != 0 {
		t.Fatalf("kept %d, removed %d, over cap %v", sel.Kept, len(sel.Remove), sel.OverCap)
	}
	for _, keep := range []time.Time{day(10, 21), day(10, 9), day(9, 21), day(8, 21), day(7, 21)} {
		if slices.Contains(removedTimes(sel), keep.Unix()) {
			t.Errorf("%s removed", keep)
		}
	}
}

func TestSelectPruneFloodKeepsGoodSnapshots(t *testing.T) {
	loc := time.UTC
	good := []pbs.SnapshotInfo{
		snap(time.Date(2026, 10, 10, 21, 0, 0, 0, loc), false),
		snap(time.Date(2026, 10, 11, 21, 0, 0, 0, loc), false),
		snap(time.Date(2026, 10, 12, 21, 0, 0, 0, loc), false),
	}
	snaps := slices.Clone(good)
	// A compromised PC uploads 50 junk backups on the 13th.
	for i := range 50 {
		snaps = append(snaps, snap(time.Date(2026, 10, 13, 1, i, 0, 0, loc), false))
	}
	sel := selectPrune(snaps, pbs.KeepOptions{Last: 7}, 4, loc)
	if sel.OverCap["2026-10-13"] != 46 {
		t.Fatalf("over cap %v", sel.OverCap)
	}
	removed := removedTimes(sel)
	for _, g := range good {
		if slices.Contains(removed, g.BackupTime) {
			t.Errorf("good snapshot %d pruned", g.BackupTime)
		}
	}
	// Only the first 4 of the 13th count: 4 junk + 3 good = keep-last 7.
	if sel.Kept != 7 {
		t.Errorf("kept %d", sel.Kept)
	}
}

func TestSelectPruneProtected(t *testing.T) {
	loc := time.UTC
	at := func(d int) time.Time { return time.Date(2026, 10, d, 21, 0, 0, 0, loc) }
	var snaps []pbs.SnapshotInfo
	for d := 1; d <= 10; d++ {
		snaps = append(snaps, snap(at(d), d == 5))
	}
	sel := selectPrune(snaps, pbs.KeepOptions{Last: 2}, 4, loc)
	removed := removedTimes(sel)
	for _, keep := range []int{5, 9, 10} { // protected, keep-last 2
		if slices.Contains(removed, at(keep).Unix()) {
			t.Errorf("day %d removed", keep)
		}
	}
	if len(removed) != 7 || sel.Kept != 3 {
		t.Errorf("removed %d, kept %d", len(removed), sel.Kept)
	}
}

func TestSelectPruneUnfinished(t *testing.T) {
	loc := time.UTC
	at := func(d int) time.Time { return time.Date(2026, 10, d, 21, 0, 0, 0, loc) }
	snaps := []pbs.SnapshotInfo{snap(at(1), false), snap(at(2), false),
		{BackupTime: at(3).Unix()}, // unfinished, not the newest
		snap(at(4), false),
		{BackupTime: at(5).Unix()}, // newest, may still be running
	}
	sel := selectPrune(snaps, pbs.KeepOptions{Last: 3}, 4, loc)
	if got, want := removedTimes(sel), []int64{at(3).Unix()}; !slices.Equal(got, want) {
		t.Errorf("removed %v, want %v", got, want)
	}
}

func TestDailyCap(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		j    Job
		want int
	}{
		{Job{DailyCap: 2, Schedule: "0 * * * *"}, 2},
		{Job{Schedule: "0 21 * * *"}, 1 + capSlack},
		{Job{Schedule: "0 9,13,17 * * 1-5"}, 3 + capSlack},
		{Job{Schedule: "@every 6h"}, 4 + capSlack},
		{Job{}, 1 + capSlack}, // manual only
		{Job{Schedule: "* * * * *"}, maxDailyCap},
	}
	for _, c := range cases {
		if got := dailyCap(&c.j, now); got != c.want {
			t.Errorf("%+v: got %d, want %d", c.j, got, c.want)
		}
	}
}

func TestOverDailyCap(t *testing.T) {
	loc := time.UTC
	at := func(d, h int) int64 { return time.Date(2026, 10, d, h, 0, 0, 0, loc).Unix() }
	succ := []int64{at(18, 23), at(19, 1), at(19, 2), at(19, 3)}
	if overDailyCap(at(19, 2), succ, 2, loc) {
		t.Error("second backup of the day is within a cap of 2")
	}
	if !overDailyCap(at(19, 3), succ, 2, loc) {
		t.Error("third backup of the day is over a cap of 2")
	}
}

func TestSuccessfulBackupTimes(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	add := func(job int64, state, kind string, bt int64) {
		id, err := st.QueueRun(ctx, 0, 1, kind, "manual", nil)
		if err != nil {
			t.Fatal(err)
		}
		st.db.ExecContext(ctx, `UPDATE runs SET job_id=?, state='running' WHERE id=?`, job, id)
		st.FinishRun(ctx, id, api.Result{State: state, BackupTime: bt}, bt)
	}
	add(7, api.RunSuccess, api.KindFiles, 300)
	add(7, api.RunWarning, api.KindFiles, 200)
	add(7, api.RunFailed, api.KindFiles, 250)
	add(7, api.RunSuccess, api.KindFiles, 50) // before since
	add(8, api.RunSuccess, api.KindFiles, 260)
	got, err := st.SuccessfulBackupTimes(ctx, 7, 100)
	if err != nil || !slices.Equal(got, []int64{200, 300}) {
		t.Fatalf("got %v, %v", got, err)
	}
}
