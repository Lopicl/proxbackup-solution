// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakePBSRoot is the PBS as the root helper sees it.
type fakePBSRoot struct {
	ns   map[string]map[string]bool // datastore → namespaces ("" is the root)
	acls []pbsACL
}

func newFakePBSRoot(stores ...string) *fakePBSRoot {
	f := &fakePBSRoot{ns: map[string]map[string]bool{}}
	for _, s := range stores {
		f.ns[s] = map[string]bool{"": true}
	}
	return f
}

func (f *fakePBSRoot) has(a pbsACL) bool { return slices.Contains(f.acls, a) }

func (f *fakePBSRoot) Datastores(context.Context) ([]string, error) {
	var out []string
	for s := range f.ns {
		out = append(out, s)
	}
	return out, nil
}

func (f *fakePBSRoot) Namespaces(_ context.Context, store string) ([]string, error) {
	var out []string
	for n := range f.ns[store] {
		out = append(out, n)
	}
	return out, nil
}

func (f *fakePBSRoot) CreateNamespace(_ context.Context, store, parent, name string) error {
	if !f.ns[store][parent] {
		return errors.New("no parent namespace")
	}
	f.ns[store][strings.TrimPrefix(parent+"/"+name, "/")] = true
	return nil
}

func (f *fakePBSRoot) ACLs(context.Context) ([]pbsACL, error) { return slices.Clone(f.acls), nil }

func (f *fakePBSRoot) SetACL(_ context.Context, a pbsACL) error {
	f.acls = slices.DeleteFunc(f.acls, func(b pbsACL) bool { return b.Path == a.Path && b.Role == a.Role && b.UGID == a.UGID })
	f.acls = append(f.acls, a)
	return nil
}

func (f *fakePBSRoot) DeleteACL(_ context.Context, a pbsACL) error {
	f.acls = slices.DeleteFunc(f.acls, func(b pbsACL) bool { return b.Path == a.Path && b.Role == a.Role && b.UGID == a.UGID })
	return nil
}

// runGrants writes a request for namespaces and runs the helper on it.
func runGrants(t *testing.T, root *fakePBSRoot, authID string, namespaces ...grantNS) (*grantsResultFile, error) {
	t.Helper()
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, grantsDirName), 0o700)
	b, _ := json.Marshal(grantsRequest{ID: "r1", Namespaces: namespaces})
	os.WriteFile(filepath.Join(dir, grantsDirName, updateRequestFile), b, 0o600)
	err := grantLocalPBS(context.Background(), dir, authID, root, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var res grantsResultFile
	if b, rerr := os.ReadFile(filepath.Join(dir, grantsDirName, grantsResult)); rerr == nil {
		json.Unmarshal(b, &res)
	}
	if _, serr := os.Stat(filepath.Join(dir, grantsDirName, updateRequestFile)); serr == nil {
		t.Fatal("request left in place")
	}
	return &res, err
}

const pbsUser = "proxbackup@pbs"

// TestGrantsNewNamespace checks that a new root namespace is created and the
// user gets rights on it only, and that the VM backups of other namespaces
// and datastores stay out of its reach.
func TestGrantsNewNamespace(t *testing.T) {
	root := newFakePBSRoot("pcstore", "vmstore")
	root.ns["vmstore"]["pve"] = true
	others := []pbsACL{
		{"/", true, "Admin", "admin@pbs"},
		{"/datastore/pcstore/pcs/pc1", true, "DatastoreBackup", pbsUser + "!pc1"}, // an agent token
	}
	root.acls = slices.Clone(others)
	res, err := runGrants(t, root, pbsUser, grantNS{"pcstore", "pcs"}, grantNS{"vmstore", "pve"}, grantNS{"vmstore", "pcs/office"}, grantNS{"gone", "pcs"})
	if err != nil {
		t.Fatal(err)
	}
	if !root.ns["pcstore"]["pcs"] || !root.ns["vmstore"]["pcs/office"] {
		t.Fatalf("namespaces not created: %v", root.ns)
	}
	want := append(slices.Clone(others),
		pbsACL{"/datastore/pcstore/pcs", true, "DatastoreAdmin", pbsUser},
		pbsACL{"/datastore/pcstore", false, "DatastoreAudit", pbsUser},
		pbsACL{"/datastore/vmstore/pcs/office", true, "DatastoreAdmin", pbsUser},
		pbsACL{"/datastore/vmstore", false, "DatastoreAudit", pbsUser})
	if len(root.acls) != len(want) {
		t.Fatalf("ACLs %+v", root.acls)
	}
	for _, a := range want {
		if !root.has(a) {
			t.Fatalf("missing %+v in %+v", a, root.acls)
		}
	}
	if len(res.Refused) != 2 || !strings.Contains(res.Refused["/datastore/vmstore/pve"], "exists already") || res.Refused["/datastore/gone/pcs"] == "" {
		t.Fatalf("refused %v", res.Refused)
	}
	if res.ID != "r1" || !slices.Equal(res.Datastores, []string{"pcstore", "vmstore"}) {
		t.Fatalf("result %+v", res)
	}

	// Asking for less takes rights away; the namespaces stay.
	if _, err := runGrants(t, root, pbsUser, grantNS{"pcstore", "pcs"}); err != nil {
		t.Fatal(err)
	}
	if root.has(pbsACL{"/datastore/vmstore/pcs/office", true, "DatastoreAdmin", pbsUser}) || root.has(pbsACL{"/datastore/vmstore", false, "DatastoreAudit", pbsUser}) ||
		!root.has(pbsACL{"/datastore/pcstore/pcs", true, "DatastoreAdmin", pbsUser}) {
		t.Fatalf("ACLs after removal %+v", root.acls)
	}
	// Removed rights don't count as entrusted any more.
	if res, _ := runGrants(t, root, pbsUser, grantNS{"vmstore", "pcs/office"}); res.Refused["/datastore/vmstore/pcs/office"] == "" {
		t.Fatalf("existing namespace without rights granted: %+v", root.acls)
	}
}

// TestGrantsUpgrade checks that the namespaces older packages gave the user
// stay usable, and that their broader rights go.
func TestGrantsUpgrade(t *testing.T) {
	for _, legacy := range []pbsACL{
		{"/datastore", true, "DatastoreAdmin", pbsUser},              // the package before this one
		{"/datastore/pcstore/pcs", true, "DatastoreBackup", pbsUser}, // up to 0.2.16
	} {
		root := newFakePBSRoot("pcstore", "vmstore")
		root.ns["pcstore"]["pcs"], root.ns["pcstore"]["pcs/pc1"] = true, true
		root.ns["vmstore"]["pve"] = true
		root.acls = []pbsACL{legacy, {"/datastore/pcstore/other", true, "DatastoreReader", pbsUser}}
		res, err := runGrants(t, root, pbsUser, grantNS{"pcstore", "pcs"})
		if err != nil || len(res.Refused) != 0 {
			t.Fatalf("%s: %v %v", legacy.Path, err, res.Refused)
		}
		want := []pbsACL{{"/datastore/pcstore/pcs", true, "DatastoreAdmin", pbsUser}, {"/datastore/pcstore", false, "DatastoreAudit", pbsUser}}
		if len(root.acls) != 2 || !root.has(want[0]) || !root.has(want[1]) {
			t.Fatalf("%s: ACLs %+v", legacy.Path, root.acls)
		}
	}
	// A namespace below one the user may use counts too (clients' namespaces
	// from before a root namespace change).
	root := newFakePBSRoot("pcstore")
	root.ns["pcstore"]["old"], root.ns["pcstore"]["old/pc1"] = true, true
	root.acls = []pbsACL{{"/datastore/pcstore/old", true, "DatastoreAdmin", pbsUser}}
	if res, err := runGrants(t, root, pbsUser, grantNS{"pcstore", "new"}, grantNS{"pcstore", "old/pc1"}); err != nil || len(res.Refused) != 0 {
		t.Fatalf("%v %v", err, res.Refused)
	}
	if !root.has(pbsACL{"/datastore/pcstore/old/pc1", true, "DatastoreAdmin", pbsUser}) || root.has(pbsACL{"/datastore/pcstore/old", true, "DatastoreAdmin", pbsUser}) {
		t.Fatalf("ACLs %+v", root.acls)
	}
}

func TestGrantsRejectBadRequests(t *testing.T) {
	for _, g := range []grantNS{{"pcstore", ""}, {"pcstore", "../x"}, {"pcstore", "/pcs"}, {"pc/store", "pcs"}, {"", "pcs"}} {
		root := newFakePBSRoot("pcstore")
		root.acls = []pbsACL{{"/datastore", true, "DatastoreAdmin", pbsUser}}
		res, err := runGrants(t, root, pbsUser, grantNS{"pcstore", "pcs"}, g)
		if err == nil || res.Error == "" || len(root.acls) != 1 || root.ns["pcstore"]["pcs"] {
			t.Fatalf("%+v: err %v, ACLs %+v", g, err, root.acls)
		}
	}
	root := newFakePBSRoot("pcstore")
	root.acls = []pbsACL{{"/", true, "Admin", "root@pam"}}
	for _, id := range []string{"root@pam", "root@pam!console", "nobody"} {
		if _, err := runGrants(t, root, id, grantNS{"pcstore", "pcs"}); err == nil || len(root.acls) != 1 {
			t.Fatalf("%s: err %v, ACLs %+v", id, err, root.acls)
		}
	}
}

// TestNeededGrants checks which namespaces the console asks for.
func TestNeededGrants(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	local := &Target{Name: "l", Host: "pbs:8007", Datastore: "pcstore", RootNS: "pcs", AdminAuthID: pbsUser, PBSUser: pbsUser, Local: true}
	legacy := &Target{Name: "legacy", Host: "pbs:8007", Datastore: "other", AdminAuthID: pbsUser, PBSUser: pbsUser, Local: true}
	remote := &Target{Name: "r", Host: "remote:8007", Datastore: "ds", RootNS: "pcs", AdminAuthID: pbsUser, PBSUser: pbsUser}
	for _, tg := range []*Target{local, legacy, remote} {
		if err := s.store.SaveTarget(ctx, tg, s.sealer.sealFor("x", colTargetSecret)); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range []*Client{
		{Name: "pc1", TargetID: local.ID, Namespace: "pcs/pc1", TokenID: pbsUser + "!pc1"},
		{Name: "pc2", TargetID: legacy.ID, Namespace: "pc2", TokenID: pbsUser + "!pc2"},
		{Name: "pc3", TargetID: remote.ID, Namespace: "pcs/pc3", TokenID: pbsUser + "!pc3"},
	} {
		c.CertSerial = string(rune('a' + i))
		if err := s.store.CreateClient(ctx, c, s.sealer.sealFor("tok", colClientToken)); err != nil {
			t.Fatal(err)
		}
		if c.Name == "pc1" {
			s.store.db.Exec(`UPDATE clients SET old_namespaces='["before/pc1","pcs/old"]' WHERE id=?`, c.ID)
		}
		if c.Name == "pc2" {
			s.store.db.Exec(`UPDATE clients SET revoked=1, revoked_at=1 WHERE id=?`, c.ID)
		}
	}
	got, err := s.neededGrants(ctx, &Target{Name: "new", Datastore: "pcstore", RootNS: "more/pcs", Local: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []grantNS{{"other", "pc2"}, {"pcstore", "before/pc1"}, {"pcstore", "more/pcs"}, {"pcstore", "pcs"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestUnusedLocalTargetsRemoved checks the one-time removal of the local
// targets older consoles registered for every datastore.
func TestUnusedLocalTargetsRemoved(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	mk := func(name string, local bool) *Target {
		tg := &Target{Name: name, Host: "pbs:8007", Datastore: name, RootNS: "pcs", AdminAuthID: pbsUser, PBSUser: pbsUser, Local: local}
		if err := s.store.SaveTarget(ctx, tg, s.sealer.sealFor("x", colTargetSecret)); err != nil {
			t.Fatal(err)
		}
		return tg
	}
	used, pending, _, _ := mk("used", true), mk("pending", true), mk("vmstore", true), mk("remote", false)
	c := &Client{Name: "pc1", TargetID: used.ID, Namespace: "pcs/pc1", TokenID: pbsUser + "!pc1", CertSerial: "01"}
	if err := s.store.CreateClient(ctx, c, s.sealer.sealFor("tok", colClientToken)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateEnrollment(ctx, "code", "pc2", pending.ID, 0, time.Hour, s.sealer.sealFor("cmd", colEnrollCmd)); err != nil {
		t.Fatal(err)
	}
	names, err := s.store.DeleteUnusedLocalTargets(ctx)
	if err != nil || !slices.Equal(names, []string{"vmstore"}) {
		t.Fatalf("removed %v, %v", names, err)
	}
}
