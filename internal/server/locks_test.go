// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLockExpired(t *testing.T) {
	bt := time.Date(2026, 10, 1, 21, 0, 0, 0, time.UTC)
	l := SnapshotLock{BackupTime: bt.Unix(), LockDays: 14}
	at := func(d time.Duration) time.Time { return bt.Add(d) }
	cases := []struct {
		name string
		job  *Job
		now  time.Time
		want bool
	}{
		{"inside period", &Job{LockDays: 14}, at(13 * 24 * time.Hour), false},
		{"period over", &Job{LockDays: 14}, at(14 * 24 * time.Hour), true},
		{"job shortened its period", &Job{LockDays: 7}, at(8 * 24 * time.Hour), true},
		{"job extended its period", &Job{LockDays: 30}, at(20 * 24 * time.Hour), false},
		{"job turned locking off", &Job{LockDays: 0}, at(time.Hour), true},
		{"job deleted: recorded period", nil, at(13 * 24 * time.Hour), false},
		{"job deleted: recorded period over", nil, at(15 * 24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := lockExpired(l, c.job, c.now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSnapshotLockStore(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	l := SnapshotLock{JobID: 1, TargetID: 2, Namespace: "pcs/pc1", BackupType: "host", BackupID: "pc1", BackupTime: 100, LockDays: 14}
	if err := st.AddSnapshotLock(ctx, l); err != nil {
		t.Fatal(err)
	}
	l.LockDays = 30 // same snapshot again: updated, not duplicated
	if err := st.AddSnapshotLock(ctx, l); err != nil {
		t.Fatal(err)
	}
	locks, err := st.SnapshotLocks(ctx)
	if err != nil || len(locks) != 1 || locks[0].LockDays != 30 || locks[0].Namespace != "pcs/pc1" {
		t.Fatalf("locks = %+v, %v", locks, err)
	}
	if err := st.DeleteSnapshotLock(ctx, locks[0].ID); err != nil {
		t.Fatal(err)
	}
	if locks, _ := st.SnapshotLocks(ctx); len(locks) != 0 {
		t.Fatalf("locks after delete = %+v", locks)
	}
}
