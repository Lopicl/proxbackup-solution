// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"path/filepath"
	"testing"
)

func TestLockOrphaned(t *testing.T) {
	c := &Client{TargetID: 2, Namespace: "pcs/pc1"}
	l := SnapshotLock{TargetID: 2, Namespace: "pcs/pc1", BackupType: "host", BackupID: "pc1"}
	cases := []struct {
		name   string
		job    *Job
		client *Client
		want   bool
	}{
		{"locked job", &Job{Lock: true, BackupID: "pc1"}, c, false},
		{"job turned locking off", &Job{BackupID: "pc1"}, c, true},
		{"job deleted", nil, nil, true},
		{"backup id changed", &Job{Lock: true, BackupID: "pc1-new"}, c, true},
		{"namespace changed", &Job{Lock: true, BackupID: "pc1"}, &Client{TargetID: 2, Namespace: "new/pc1"}, true},
		{"target changed", &Job{Lock: true, BackupID: "pc1"}, &Client{TargetID: 3, Namespace: "pcs/pc1"}, true},
		{"client revoked", &Job{Lock: true, BackupID: "pc1"}, &Client{TargetID: 3, Revoked: true}, false},
	}
	for _, c := range cases {
		if got := lockOrphaned(l, c.job, c.client); got != c.want {
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
	l := SnapshotLock{JobID: 1, TargetID: 2, Namespace: "pcs/pc1", BackupType: "host", BackupID: "pc1", BackupTime: 100}
	if err := st.AddSnapshotLock(ctx, l); err != nil {
		t.Fatal(err)
	}
	l.JobID = 3 // same snapshot again: updated, not duplicated
	if err := st.AddSnapshotLock(ctx, l); err != nil {
		t.Fatal(err)
	}
	if other, _ := st.GroupSnapshotLocks(ctx, 2, "pcs/pc1", "host", "pc2"); len(other) != 0 {
		t.Fatalf("other group's locks = %+v", other)
	}
	locks, err := st.GroupSnapshotLocks(ctx, 2, "pcs/pc1", "host", "pc1")
	if err != nil || len(locks) != 1 || locks[0].JobID != 3 || locks[0].Namespace != "pcs/pc1" {
		t.Fatalf("locks = %+v, %v", locks, err)
	}
	if err := st.DeleteSnapshotLock(ctx, locks[0].ID); err != nil {
		t.Fatal(err)
	}
	if locks, _ := st.GroupSnapshotLocks(ctx, 2, "pcs/pc1", "host", "pc1"); len(locks) != 0 {
		t.Fatalf("locks after delete = %+v", locks)
	}
}
