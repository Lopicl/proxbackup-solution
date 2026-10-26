// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"testing"

	"proxbackup/internal/api"
)

func TestRevokeAndUnrevoke(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "pc-1", "pc-2")
	c := cs[0]
	g := &GroupJob{Name: "Users", Kind: api.KindFiles, Sources: []string{`C:\Users`}, Schedule: "0 21 * * *",
		Enabled: true, CatchUp: true, WindowMinutes: 60, ChangeDetection: "metadata", Clients: []int64{c.ID, cs[1].ID}}
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}
	jobs, _ := s.store.Jobs(ctx, c.ID)
	if len(jobs) != 1 || !jobs[0].Enabled {
		t.Fatalf("jobs = %+v", jobs)
	}

	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	rc, _ := s.store.Client(ctx, c.ID)
	if !rc.Revoked || !rc.Restorable || rc.RevokedAt == 0 || rc.Name != "pc-1#revoked-"+strconv.FormatInt(c.ID, 10) {
		t.Fatalf("revoked client = %+v", rc)
	}
	if _, err := s.store.ClientBySerial(ctx, c.CertSerial); err == nil {
		t.Fatal("revoked client's certificate still accepted")
	}
	if j, _ := s.store.Job(ctx, jobs[0].ID); j.Enabled {
		t.Fatal("job still enabled")
	}
	// Revoking twice must not rename it again.
	if err := s.store.RevokeClient(ctx, c.ID); !errors.Is(err, errNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	rec := httptest.NewRecorder()
	req := asAdmin(httptest.NewRequest("DELETE", "/api/clients/1", nil))
	req.SetPathValue("id", strconv.FormatInt(c.ID, 10))
	s.handleRevokeClient(rec, req)
	if rec.Code != 409 {
		t.Fatalf("revoke of a revoked client: %d %s", rec.Code, rec.Body)
	}
	if rc2, _ := s.store.Client(ctx, c.ID); rc2.Name != rc.Name {
		t.Fatalf("name changed to %q", rc2.Name)
	}

	// The freed name stays reserved against setup-token enrollment.
	if !s.store.RevokedClientNamed(ctx, "pc-1") || s.store.RevokedClientNamed(ctx, "pc") || s.store.RevokedClientNamed(ctx, "pc-2") {
		t.Fatal("RevokedClientNamed")
	}
	if s.store.ClientNameTaken(ctx, "pc-1") {
		t.Fatal("revoked name not free for admin enrollments")
	}
	if _, _, err := s.enrollClient(ctx, &Enrollment{ClientName: "pc-1"}, api.EnrollRequest{Hostname: "x"}, true); !errors.Is(err, errClientNameTaken) {
		t.Fatalf("setup enrollment under a revoked name: %v", err)
	}

	list, err := s.store.RevokedClients(ctx, now()-86400)
	if err != nil || len(list) != 1 || list[0].ID != c.ID {
		t.Fatalf("revoked list = %v, %v", list, err)
	}

	if err := s.store.UnrevokeClient(ctx, rc, "pc-1", "proxbackup@pbs!pc-1", s.sealer.Seal("new")); err != nil {
		t.Fatal(err)
	}
	uc, err := s.store.ClientBySerial(ctx, c.CertSerial)
	if err != nil || uc.ID != c.ID || uc.Name != "pc-1" || uc.Revoked || uc.Restorable || uc.RevokedAt != 0 {
		t.Fatalf("un-revoked client = %+v, %v", uc, err)
	}
	if j, _ := s.store.Job(ctx, jobs[0].ID); !j.Enabled {
		t.Fatal("job not re-enabled")
	}
	if cfg, err := s.agentConfig(ctx, uc); err != nil || cfg.Target.Secret != "new" || len(cfg.Jobs) != 1 {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	if list, _ := s.store.RevokedClients(ctx, 0); len(list) != 0 {
		t.Fatalf("revoked list after un-revoke = %v", list)
	}
	if s.store.RevokedClientNamed(ctx, "pc-1") {
		t.Fatal("name still reserved after un-revoke")
	}
	if err := s.store.UnrevokeClient(ctx, uc, "pc-1", "x", nil); !errors.Is(err, errNotFound) {
		t.Fatalf("un-revoke of an active client: %v", err)
	}
}
