// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"path/filepath"
	"testing"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

func TestClientStorage(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	add := func(client, job int64, state, kind string, total, up uint64, at int64) {
		id, err := st.QueueRun(ctx, 0, client, kind, "manual", nil)
		if err != nil {
			t.Fatal(err)
		}
		st.db.ExecContext(ctx, `UPDATE runs SET job_id=?, state='running' WHERE id=?`, job, id)
		st.FinishRun(ctx, id, api.Result{State: state, BytesTotal: total, BytesUploaded: up}, at)
	}
	add(1, 7, api.RunSuccess, api.KindFiles, 100, 100, 50) // superseded, before since
	add(1, 7, api.RunSuccess, api.KindFiles, 120, 20, 200)
	add(1, 7, api.RunFailed, api.KindFiles, 999, 999, 210)
	add(1, 8, api.RunWarning, api.KindFiles, 30, 5, 220)
	add(2, 9, api.RunSuccess, api.KindRestore, 500, 0, 230)
	got, err := st.ClientStorage(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if c := got[1]; c == nil || c.Protected != 150 || c.Uploaded != 25 {
		t.Errorf("client 1: %+v", c)
	}
	if got[2] != nil {
		t.Errorf("restores count as stored data: %+v", got[2])
	}
}

func TestRRDHistory(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	got := rrdHistory([]pbs.RRDPoint{{Time: 1}, {Time: 2, Used: f(5), Total: f(10)}, {Time: 3, Used: f(6)}}, 10)
	if len(got) != 1 || got[0] != (storagePoint{2, 5, 10}) {
		t.Fatalf("got %+v", got)
	}
	var pts []pbs.RRDPoint
	for i := range 5 {
		pts = append(pts, pbs.RRDPoint{Time: int64(i), Used: f(float64(i)), Total: f(10)})
	}
	got = rrdHistory(pts, 2) // buckets of 3: [0 1 2] [3 4]
	if len(got) != 2 || got[0] != (storagePoint{2, 1, 10}) || got[1] != (storagePoint{4, 3.5, 10}) {
		t.Fatalf("downsampled: %+v", got)
	}
}
