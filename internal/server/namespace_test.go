// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
)

func TestClientNamespace(t *testing.T) {
	if got := clientNamespace(&Target{RootNS: "/pcs/office/"}, "pc1"); got != "pcs/office/pc1" {
		t.Errorf("got %q", got)
	}
	if got := clientNamespace(&Target{}, "pc1"); got != "pc1" {
		t.Errorf("no root: got %q", got)
	}
}

func TestMoveClientNamespace(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	tg := &Target{Name: "pbs", Host: "pbs", Datastore: "ds", RootNS: "pcs", AdminAuthID: "root@pam!x", PBSUser: "proxbackup@pbs",
		adminSecretEnc: []byte("x")}
	if err := st.SaveTarget(ctx, tg, nil); err != nil {
		t.Fatal(err)
	}
	c := &Client{Name: "pc1", TargetID: tg.ID, Namespace: "pcs/pc1", TokenID: "proxbackup@pbs!pc1"}
	if err := st.CreateClient(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	load := func() *Client {
		c, err := st.Client(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := load(); len(c.OldNamespaces) != 0 {
		t.Fatalf("new client old namespaces = %v", c.OldNamespaces)
	}
	steps := []struct {
		ns  string
		old []string
	}{
		{"office/pc1", []string{"pcs/pc1"}},
		{"backups/pc1", []string{"pcs/pc1", "office/pc1"}},
		{"pcs/pc1", []string{"office/pc1", "backups/pc1"}}, // moving back: no longer "old"
	}
	for _, s := range steps {
		if err := st.MoveClientNamespace(ctx, load(), s.ns); err != nil {
			t.Fatal(err)
		}
		if c := load(); c.Namespace != s.ns || !slices.Equal(c.OldNamespaces, s.old) {
			t.Fatalf("after move to %s: ns %q, old %v; want old %v", s.ns, c.Namespace, c.OldNamespaces, s.old)
		}
	}
}
