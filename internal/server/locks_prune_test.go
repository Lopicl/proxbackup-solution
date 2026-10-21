// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proxbackup/pkg/pbs"
)

// fakeProtectPBS serves the snapshot list, protected and forget calls of one
// backup group, refusing to forget protected snapshots like PBS does.
type fakeProtectPBS struct {
	mu        sync.Mutex
	protected map[int64]bool // backup time -> protected; absent = forgotten
}

func (f *fakeProtectPBS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) { json.NewEncoder(w).Encode(map[string]any{"data": v}) }
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/snapshots"):
		var out []map[string]any
		for bt, p := range f.protected {
			out = append(out, map[string]any{"backup-type": "host", "backup-id": "pc1", "backup-time": bt, "protected": p,
				"files": []map[string]any{{"filename": "index.json.blob"}}})
		}
		reply(out)
	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/protected"):
		var p struct {
			BackupTime int64 `json:"backup-time"`
			Protected  bool  `json:"protected"`
		}
		json.NewDecoder(r.Body).Decode(&p)
		if _, ok := f.protected[p.BackupTime]; !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		f.protected[p.BackupTime] = p.Protected
		reply(nil)
	case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/snapshots"):
		bt, _ := strconv.ParseInt(r.URL.Query().Get("backup-time"), 10, 64)
		if f.protected[bt] {
			http.Error(w, "snapshot is protected", http.StatusBadRequest)
			return
		}
		delete(f.protected, bt)
		reply(nil)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotImplemented)
	}
}

func TestPruneJobReleasesLocksWithRetention(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	c := groupTestClients(t, s, "pc1")[0]
	tg, _ := s.store.Target(ctx, c.TargetID)
	j := &Job{ID: 7, BackupID: "pc1", Lock: true, Retention: pbs.KeepOptions{Last: 2}}

	at := func(d int) int64 { return time.Date(2026, 10, d, 21, 0, 0, 0, time.Local).Unix() }
	f := &fakeProtectPBS{protected: map[int64]bool{}}
	for d := 1; d <= 5; d++ {
		f.protected[at(d)] = true
		if d == 2 {
			continue // protected by an operator, not the console
		}
		s.store.AddSnapshotLock(ctx, SnapshotLock{JobID: j.ID, TargetID: tg.ID, Namespace: c.Namespace, BackupType: "host",
			BackupID: "pc1", BackupTime: at(d)})
	}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	pc, err := pbs.NewClient(pbs.Config{Host: strings.TrimPrefix(srv.URL, "https://"), Fingerprint: pbs.FormatFingerprint(sum),
		AuthID: "root@pam!x", Secret: "x"})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.pruneJob(ctx, pc, tg, c, j, time.Now()); err != nil {
		t.Fatal(err)
	}
	// keep-last 2 keeps days 4 and 5, still locked; the operator's day 2 stays
	// on top; days 1 and 3 were unlocked and forgotten.
	want := map[int64]bool{at(2): true, at(4): true, at(5): true}
	if len(f.protected) != len(want) {
		t.Fatalf("left on PBS: %v", f.protected)
	}
	for bt, p := range want {
		if f.protected[bt] != p {
			t.Errorf("snapshot %d protected=%v, want %v", bt, f.protected[bt], p)
		}
	}
	locks, _ := s.store.GroupSnapshotLocks(ctx, tg.ID, c.Namespace, "host", "pc1")
	if len(locks) != 2 || locks[0].BackupTime != at(4) || locks[1].BackupTime != at(5) {
		t.Errorf("locks left: %+v", locks)
	}
}
