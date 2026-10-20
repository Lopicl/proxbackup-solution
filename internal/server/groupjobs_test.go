// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"proxbackup/internal/api"
)

func groupTestClients(t *testing.T, s *Server, names ...string) []*Client {
	t.Helper()
	ctx := context.Background()
	tg := &Target{Name: "pbs", Host: "pbs:8007", Datastore: "ds", AdminAuthID: "root@pam!x", PBSUser: "proxbackup@pbs", adminSecretEnc: s.sealer.Seal("x")}
	if err := s.store.SaveTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	var out []*Client
	for i, n := range names {
		c := &Client{Name: n, TargetID: tg.ID, CertSerial: string(rune('a' + i)), Namespace: "pcs/" + n, TokenID: "proxbackup@pbs!" + n,
			tokenSecretEnc: s.sealer.Seal("tok")}
		if err := s.store.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func memberClients(t *testing.T, s *Server, groupID int64) []int64 {
	t.Helper()
	jobs, err := s.store.GroupMembers(context.Background(), groupID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, j := range jobs {
		ids = append(ids, j.ClientID)
	}
	slices.Sort(ids)
	return ids
}

func TestMigrateSingleJobsToGroupJobs(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "pc-1", "pc-2", "pc-3")
	// Jobs as stored before group jobs: the definition on the row itself.
	ins := func(clientID int64, name, kind, backupID string, enabled bool) int64 {
		res, err := s.store.db.ExecContext(ctx, `INSERT INTO jobs(client_id, name, kind, backup_id, sources, excludes, volumes, schedule,
			retention, enabled, created_at, lock_days) VALUES(?,?,?,?,'["C:\\Users"]','["*.iso"]','["C:"]','0 21 * * *','{"keep-last":3}',?,1,7)`,
			clientID, name, kind, backupID, enabled)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	files := ins(cs[0].ID, "User files", "files", "pc-1", true)
	image := ins(cs[0].ID, "System", "image", "custom-img", false)
	revoked := ins(cs[2].ID, "Old", "files", "pc-3", true)
	if err := s.store.RevokeClient(ctx, cs[2].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.store.migrateGroupJobs(); err != nil {
		t.Fatal(err)
	}
	if err := s.store.migrateGroupJobs(); err != nil { // idempotent
		t.Fatal(err)
	}
	groups, err := s.store.GroupJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (revoked clients' jobs are not migrated)", len(groups))
	}
	j, err := s.store.Job(ctx, files)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := s.store.GroupJob(ctx, j.GroupID)
	if g.Name != "User files" || g.BackupID != "" || g.Schedule != "0 21 * * *" || g.LockDays != 7 || g.Retention.Last != 3 ||
		!slices.Equal(g.Clients, []int64{cs[0].ID}) || !slices.Equal(g.Excludes, []string{"*.iso"}) {
		t.Fatalf("migrated group = %+v", g)
	}
	if j.BackupID != "pc-1" || !j.Enabled || j.Name != "User files" {
		t.Fatalf("migrated member = %+v", j)
	}
	// A disabled job becomes a disabled group; a custom backup group is kept.
	j, _ = s.store.Job(ctx, image)
	g, _ = s.store.GroupJob(ctx, j.GroupID)
	if g.Enabled || !j.MemberEnabled || j.Enabled || g.BackupID != "custom-img" || j.BackupID != "custom-img" {
		t.Fatalf("disabled image job: group %+v member %+v", g, j)
	}
	if j, err := s.store.Job(ctx, revoked); err != nil || j.GroupID != 0 || j.Name != "Old" || j.Enabled {
		t.Fatalf("revoked client's job = %+v, %v", j, err)
	}

	// Converting a migrated job into a shared one: add another member.
	g.Clients = append(g.Clients, cs[1].ID)
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}
	if got := memberClients(t, s, g.ID); !slices.Equal(got, []int64{cs[0].ID, cs[1].ID}) {
		t.Fatalf("members = %v", got)
	}
	if m, _ := s.store.Jobs(ctx, cs[1].ID); len(m) != 1 || m[0].BackupID != "custom-img" {
		t.Fatalf("new member = %+v", m)
	}
}

func TestGroupJobMembers(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "pc-1", "pc-2", "pc-3")
	g := &GroupJob{Name: "Users", Kind: api.KindFiles, Sources: []string{`C:\Users`}, Excludes: []string{"*.iso"}, Schedule: "0 21 * * *",
		Enabled: true, CatchUp: true, WindowMinutes: 60, ChangeDetection: "metadata", SpreadMinutes: 30,
		Clients: []int64{cs[0].ID}, Tags: []string{"office"}}
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}
	if got := memberClients(t, s, g.ID); !slices.Equal(got, []int64{cs[0].ID}) {
		t.Fatalf("members = %v", got)
	}
	// Tagging a client attaches it, untagging detaches it.
	if _, err := s.store.SetClientTags(ctx, cs[1].ID, []string{"office"}); err != nil {
		t.Fatal(err)
	}
	if got := memberClients(t, s, g.ID); !slices.Equal(got, []int64{cs[0].ID, cs[1].ID}) {
		t.Fatalf("members after tagging = %v", got)
	}

	// Each member gets its own backup group, start delay and agent config.
	jobs, _ := s.store.GroupMembers(ctx, g.ID)
	for _, j := range jobs {
		c, _ := s.store.Client(ctx, j.ClientID)
		if j.BackupID != c.Name || j.StartDelay < 0 || j.StartDelay >= 30*60 || j.StartDelay != startDelay(g.ID, c.ID, 30) {
			t.Fatalf("member %+v", j)
		}
		cfg, err := s.agentConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Jobs) != 1 || cfg.Jobs[0].ID != j.ID || cfg.Jobs[0].StartDelay != j.StartDelay || cfg.Jobs[0].Schedule != "0 21 * * *" {
			t.Fatalf("config of %s = %+v", c.Name, cfg.Jobs)
		}
	}

	// Overrides: extra excludes reach the agent, a disabled member drops out.
	m1 := jobs[0]
	if err := s.store.SetMemberOverrides(ctx, m1.ID, true, []string{"**/Downloads", "*.iso"}); err != nil {
		t.Fatal(err)
	}
	c1, _ := s.store.Client(ctx, m1.ClientID)
	cfg, _ := s.agentConfig(ctx, c1)
	if !slices.Equal(cfg.Jobs[0].Excludes, []string{"*.iso", "**/Downloads"}) {
		t.Fatalf("excludes = %v", cfg.Jobs[0].Excludes)
	}
	// Editing the group reaches every member, keeping overrides.
	g.Schedule = "0 22 * * *"
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := s.agentConfig(ctx, c1)
	if cfg2.Rev == cfg.Rev || cfg2.Jobs[0].Schedule != "0 22 * * *" || len(cfg2.Jobs[0].Excludes) != 2 {
		t.Fatalf("after edit: %+v", cfg2.Jobs)
	}
	if err := s.store.SetMemberOverrides(ctx, m1.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := s.agentConfig(ctx, c1); len(cfg.Jobs) != 0 {
		t.Fatalf("disabled member still pushed: %+v", cfg.Jobs)
	}

	// Run now for the whole group: only enabled members get a run.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/group-jobs/1/run", nil)
	req.SetPathValue("id", "1")
	s.handleRunGroupJob(rec, req)
	var res struct {
		RunIDs  []int64 `json:"run_ids"`
		Skipped int     `json:"skipped"`
	}
	json.NewDecoder(rec.Body).Decode(&res)
	if rec.Code != 200 || len(res.RunIDs) != 1 {
		t.Fatalf("run group: %d %+v", rec.Code, res)
	}
	if r, _ := s.store.Run(ctx, res.RunIDs[0]); r.ClientID == m1.ClientID || r.GroupID != g.ID || r.JobName != "Users" {
		t.Fatalf("run = %+v", r)
	}

	// A tag-selected member can't be detached by name; an explicit one can.
	byClient := map[int64]*Job{}
	for _, j := range jobs {
		byClient[j.ClientID] = j
	}
	del := func(id int64) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/api/jobs/x", nil)
		req.SetPathValue("id", jsonNum(id))
		s.handleDeleteJob(rec, req)
		return rec.Code
	}
	if code := del(byClient[cs[1].ID].ID); code != 409 {
		t.Fatalf("detach tag member: %d", code)
	}
	if code := del(byClient[cs[0].ID].ID); code != 200 {
		t.Fatalf("detach explicit member: %d", code)
	}
	if got := memberClients(t, s, g.ID); !slices.Equal(got, []int64{cs[1].ID}) {
		t.Fatalf("members after detach = %v", got)
	}

	// The all-clients tag selects every client, including new ones.
	all := &GroupJob{Name: "Everyone", Kind: api.KindImage, Volumes: []string{"C:"}, Enabled: true, Tags: []string{AllClientsTag}}
	if err := validateGroupJob(all); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.SaveGroupJob(ctx, all); err != nil {
		t.Fatal(err)
	}
	if got := memberClients(t, s, all.ID); len(got) != 3 {
		t.Fatalf("all-clients members = %v", got)
	}
	if m, _ := s.store.Jobs(ctx, cs[2].ID); len(m) != 1 || m[0].BackupID != "pc-3-image" {
		t.Fatalf("image member = %+v", m)
	}

	// Deleting the group removes its member jobs everywhere.
	if _, err := s.store.DeleteGroupJob(ctx, all.ID); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.store.Jobs(ctx, cs[2].ID); len(m) != 0 {
		t.Fatalf("members left after delete: %+v", m)
	}
}

func TestValidateGroupJob(t *testing.T) {
	ok := GroupJob{Name: "x", Kind: api.KindFiles, Sources: []string{`C:\`}}
	for name, mod := range map[string]func(*GroupJob){
		"bad tag":    func(g *GroupJob) { g.Tags = []string{"Has Space"} },
		"spread":     func(g *GroupJob) { g.SpreadMinutes = maxSpreadMinutes + 1 },
		"backup id":  func(g *GroupJob) { g.BackupID = "a/b" },
		"no sources": func(g *GroupJob) { g.Sources = nil },
		"schedule":   func(g *GroupJob) { g.Schedule = "nonsense" },
	} {
		g := ok
		mod(&g)
		if err := validateGroupJob(&g); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	g := ok
	g.Tags = []string{" office ", "office", ""}
	if err := validateGroupJob(&g); err != nil || !slices.Equal(g.Tags, []string{"office"}) || g.WindowMinutes != 60 ||
		!strings.EqualFold(g.ChangeDetection, "metadata") {
		t.Fatalf("normalized %+v, %v", g, err)
	}
}

func jsonNum(id int64) string {
	b, _ := json.Marshal(id)
	return string(b)
}

// A job created after another was deleted can get its id back from SQLite; it
// must not inherit the deleted job's runs.
func TestDeletedJobRunsNotInherited(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	cs := groupTestClients(t, s, "pc-1", "pc-2")
	save := func(name string, client int64) *GroupJob {
		g := &GroupJob{Name: name, Kind: api.KindImage, Volumes: []string{"C:"}, Enabled: true, Clients: []int64{client}}
		if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	old := save("Old", cs[0].ID)
	oldJob := s.store.mustMember(t, old.ID)
	done, err := s.store.QueueRun(ctx, oldJob, cs[0].ID, api.KindImage, "manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.store.db.ExecContext(ctx, `UPDATE runs SET state='success', finished_at=? WHERE id=?`, now(), done)
	if _, err := s.store.QueueRun(ctx, oldJob, cs[0].ID, api.KindImage, "manual", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.DeleteGroupJob(ctx, old.ID); err != nil {
		t.Fatal(err)
	}

	nu := save("New", cs[1].ID)
	if nu.ID != old.ID || s.store.mustMember(t, nu.ID) != oldJob {
		t.Fatalf("ids not reused (group %d→%d), test proves nothing", old.ID, nu.ID)
	}
	if runs, _ := s.store.Runs(ctx, RunFilter{GroupID: nu.ID}); len(runs) != 0 {
		t.Fatalf("new group shows %d runs of the deleted one", len(runs))
	}
	if last, _ := s.store.LastRuns(ctx); last[oldJob] != nil {
		t.Fatalf("new member's last run = run %d of the deleted job", last[oldJob].ID)
	}
	// History of the client stays, and the never-started run was canceled.
	runs, _ := s.store.Runs(ctx, RunFilter{ClientID: cs[0].ID})
	if len(runs) != 2 || runs[0].State != api.RunCanceled || runs[1].State != api.RunSuccess {
		t.Fatalf("client history = %+v", runs)
	}

	// Runs left attached by older consoles are repaired at startup.
	s.store.db.ExecContext(ctx, `UPDATE runs SET job_id=? WHERE client_id=?`, oldJob, cs[0].ID)
	if err := s.store.repairJobRefs(); err != nil {
		t.Fatal(err)
	}
	if runs, _ := s.store.Runs(ctx, RunFilter{GroupID: nu.ID}); len(runs) != 0 {
		t.Fatalf("after repair the new group still shows %d foreign runs", len(runs))
	}
	own, _ := s.store.QueueRun(ctx, oldJob, cs[1].ID, api.KindImage, "manual", nil)
	s.store.repairJobRefs()
	if runs, _ := s.store.Runs(ctx, RunFilter{GroupID: nu.ID}); len(runs) != 1 || runs[0].ID != own {
		t.Fatalf("repair detached the job's own run: %+v", runs)
	}
}

func (s *Store) mustMember(t *testing.T, groupID int64) int64 {
	t.Helper()
	jobs, err := s.GroupMembers(context.Background(), groupID)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("members of %d: %v %v", groupID, jobs, err)
	}
	return jobs[0].ID
}
