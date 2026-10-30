// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"proxbackup/pkg/pbs"
)

// The console's PBS user has rights only on the namespaces it backs PCs up
// to: DatastoreAdmin on each root namespace (e.g. /datastore/<store>/pcs) and
// Datastore.Audit, not propagated, on the datastore itself for its usage
// figures. Other namespaces, and the VM and container backups in them, stay
// out of its reach, and it can't reconfigure a datastore.
//
// It can't grant itself rights, and creating a root namespace needs
// Datastore.Modify on the datastore. So the console writes the namespaces it
// needs to pbs-grants/request and proxbackup-server-grants.service applies
// them as root (GrantLocalPBS). Compromising the console must not reach other
// backups that way, so the helper only grants a namespace it creates itself
// (an empty one) or one the user can already manage, and drops every other
// ACL of the user.

const (
	grantsDirName = "pbs-grants"
	grantsResult  = "result.json"
)

// grantNS is a namespace on a local datastore.
type grantNS struct {
	Store string `json:"store"`
	NS    string `json:"ns"`
}

func (g grantNS) path() string { return pbs.DatastoreACLPath(g.Store, g.NS) }

type grantsRequest struct {
	ID         string    `json:"id"`
	Namespaces []grantNS `json:"namespaces"`
}

// grantsResult is what the helper did with the last request.
type grantsResultFile struct {
	ID         string            `json:"id"`
	Time       int64             `json:"time"`
	Requested  []grantNS         `json:"requested"`
	Refused    map[string]string `json:"refused,omitempty"` // ACL path → reason
	Datastores []string          `json:"datastores"`        // all datastores of this PBS, for the target form
	Error      string            `json:"error,omitempty"`
}

var datastoreNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// pbsACL is an entry of the PBS ACL list.
type pbsACL struct {
	Path      string `json:"path"`
	Propagate bool   `json:"propagate"`
	Role      string `json:"roleid"`
	UGID      string `json:"ugid"`
}

// pbsRoot is what the helper does on the PBS as root.
type pbsRoot interface {
	Datastores(ctx context.Context) ([]string, error)
	Namespaces(ctx context.Context, store string) ([]string, error)
	CreateNamespace(ctx context.Context, store, parent, name string) error
	ACLs(ctx context.Context) ([]pbsACL, error)
	SetACL(ctx context.Context, a pbsACL) error
	DeleteACL(ctx context.Context, a pbsACL) error
}

// GrantLocalPBS is the root side (proxbackup-server grant-datastores, run by
// proxbackup-server-grants.service when the console writes a request): it
// gives authID the rights the request names, within the rules above, and
// writes the outcome for the console.
func GrantLocalPBS(ctx context.Context, dataDir, authID string, log *slog.Logger) error {
	return grantLocalPBS(ctx, dataDir, authID, pbsCLI{}, log)
}

func grantLocalPBS(ctx context.Context, dataDir, authID string, root pbsRoot, log *slog.Logger) error {
	dir, err := openHelperDir(dataDir, grantsDirName)
	if err != nil {
		return err
	}
	if dir == nil {
		log.Info("no datastore rights requested")
		return nil
	}
	defer dir.Close()
	b, found, err := readHelperRequest(dir)
	if !found && err == nil {
		log.Info("no datastore rights requested")
		return nil
	}
	var req grantsRequest
	res := grantsResultFile{Time: time.Now().Unix()}
	if err == nil {
		err = json.Unmarshal(b, &req)
	}
	if err == nil {
		res.ID, res.Requested = req.ID, req.Namespaces
		err = checkGrantsRequest(req)
	}
	// The helper replaces all ACLs of authID: never those of the superuser.
	if user, _, _ := strings.Cut(authID, "!"); err == nil && (user == "root@pam" || !strings.Contains(user, "@")) {
		err = fmt.Errorf("refusing to manage the rights of %q: give the console its own PBS user", authID)
	}
	if err == nil {
		err = applyGrants(ctx, root, authID, &res, log)
	}
	if err != nil {
		res.Error = err.Error()
		log.Error("granting datastore rights failed", "err", err)
	}
	out, _ := json.Marshal(res)
	if werr := writeHelperFile(dir, grantsResult, out); werr != nil {
		log.Warn("cannot write the result", "err", werr)
	}
	return err
}

func checkGrantsRequest(req grantsRequest) error {
	if len(req.Namespaces) > 10000 {
		return errors.New("too many namespaces requested")
	}
	for _, g := range req.Namespaces {
		// An empty namespace would be the whole datastore.
		if !datastoreNameRe.MatchString(g.Store) || !nsRe.MatchString(g.NS) {
			return fmt.Errorf("invalid namespace %q on datastore %q", g.NS, g.Store)
		}
	}
	return nil
}

// entrusted reports whether acls already give their holder backup rights at
// path, on it or propagated from a parent. The console can't set ACLs for its
// user, so a root admin gave it those (packages up to 0.2.16 DatastoreBackup
// on the root namespaces, later ones DatastoreAdmin on /datastore): the
// namespace is meant for it.
func entrusted(acls []pbsACL, path string) bool {
	for _, a := range acls {
		if !slices.Contains([]string{"Admin", "DatastoreAdmin", "DatastorePowerUser", "DatastoreBackup"}, a.Role) {
			continue
		}
		if a.Path == path || a.Propagate && (a.Path == "/" || strings.HasPrefix(path, a.Path+"/")) {
			return true
		}
	}
	return false
}

func applyGrants(ctx context.Context, root pbsRoot, authID string, res *grantsResultFile, log *slog.Logger) error {
	stores, err := root.Datastores(ctx)
	if err != nil {
		return fmt.Errorf("list datastores: %w", err)
	}
	slices.Sort(stores)
	res.Datastores = stores
	all, err := root.ACLs(ctx)
	if err != nil {
		return fmt.Errorf("list ACLs: %w", err)
	}
	var mine []pbsACL
	for _, a := range all {
		if a.UGID == authID {
			mine = append(mine, a)
		}
	}
	nsCache := map[string]map[string]bool{}
	existing := func(store string) (map[string]bool, error) {
		if m, ok := nsCache[store]; ok {
			return m, nil
		}
		list, err := root.Namespaces(ctx, store)
		if err != nil {
			return nil, err
		}
		m := map[string]bool{}
		for _, ns := range list {
			m[ns] = true
		}
		nsCache[store] = m
		return m, nil
	}
	refuse := func(g grantNS, reason string) {
		if res.Refused == nil {
			res.Refused = map[string]string{}
		}
		res.Refused[g.path()] = reason
		log.Warn("refused datastore rights", "path", g.path(), "reason", reason)
	}

	want := map[pbsACL]bool{}
	for _, g := range res.Requested {
		if !slices.Contains(stores, g.Store) {
			refuse(g, "no such datastore")
			continue
		}
		// Decided on the rights from before this run: a namespace meant for
		// the user, or one that is still empty because we create it now.
		if !entrusted(mine, g.path()) {
			have, err := existing(g.Store)
			if err != nil {
				return fmt.Errorf("list namespaces of %s: %w", g.Store, err)
			}
			if have[g.NS] {
				refuse(g, fmt.Sprintf("the namespace exists already and the console can't manage it. To use it for PCs anyway, run on the PBS: "+
					"proxmox-backup-manager acl update %s DatastoreAdmin --auth-id %s", g.path(), authID))
				continue
			}
			parent := ""
			for part := range strings.SplitSeq(g.NS, "/") {
				full := strings.TrimPrefix(parent+"/"+part, "/")
				if !have[full] {
					if err := root.CreateNamespace(ctx, g.Store, parent, part); err != nil {
						return fmt.Errorf("create namespace %s on %s: %w", full, g.Store, err)
					}
					have[full] = true
					log.Info("created namespace", "datastore", g.Store, "ns", full)
				}
				parent = full
			}
		}
		want[pbsACL{Path: g.path(), Propagate: true, Role: "DatastoreAdmin", UGID: authID}] = true
		want[pbsACL{Path: pbs.DatastoreACLPath(g.Store, ""), Propagate: false, Role: "DatastoreAudit", UGID: authID}] = true
	}
	for a := range want {
		if !slices.Contains(mine, a) {
			if err := root.SetACL(ctx, a); err != nil {
				return fmt.Errorf("grant %s on %s: %w", a.Role, a.Path, err)
			}
			log.Info("granted datastore rights", "path", a.Path, "role", a.Role, "propagate", a.Propagate)
		}
	}
	// A user ACL on a deeper path replaces the inherited role, and the user
	// needs nothing else (consoles up to 0.2.16 gave it DatastoreBackup on
	// the root namespaces, later ones DatastoreAdmin on /datastore).
	for _, a := range mine {
		if !want[a] {
			if err := root.DeleteACL(ctx, a); err != nil {
				return fmt.Errorf("remove %s on %s: %w", a.Role, a.Path, err)
			}
			log.Info("removed datastore rights", "path", a.Path, "role", a.Role)
		}
	}
	return nil
}

// pbsCLI runs the PBS command line tools (as root).
type pbsCLI struct{}

func (pbsCLI) run(ctx context.Context, out any, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, args[0], err, strings.TrimSpace(stderr.String()))
	}
	if out != nil {
		return json.Unmarshal(stdout.Bytes(), out)
	}
	return nil
}

func (c pbsCLI) Datastores(ctx context.Context) ([]string, error) {
	var list []struct {
		Name string `json:"name"`
	}
	if err := c.run(ctx, &list, "proxmox-backup-manager", "datastore", "list", "--output-format", "json"); err != nil {
		return nil, err
	}
	var names []string
	for _, d := range list {
		names = append(names, d.Name)
	}
	return names, nil
}

func (c pbsCLI) Namespaces(ctx context.Context, store string) ([]string, error) {
	var list []struct {
		NS string `json:"ns"`
	}
	if err := c.run(ctx, &list, "proxmox-backup-debug", "api", "get", "/admin/datastore/"+url.PathEscape(store)+"/namespace",
		"--output-format", "json"); err != nil {
		return nil, err
	}
	var out []string
	for _, n := range list {
		out = append(out, n.NS)
	}
	return out, nil
}

func (c pbsCLI) CreateNamespace(ctx context.Context, store, parent, name string) error {
	args := []string{"api", "create", "/admin/datastore/" + url.PathEscape(store) + "/namespace", "--name", name, "--output-format", "json"}
	if parent != "" {
		args = append(args, "--parent", parent)
	}
	return c.run(ctx, nil, "proxmox-backup-debug", args...)
}

func (c pbsCLI) ACLs(ctx context.Context) ([]pbsACL, error) {
	var list []pbsACL
	err := c.run(ctx, &list, "proxmox-backup-manager", "acl", "list", "--output-format", "json")
	return list, err
}

func (c pbsCLI) SetACL(ctx context.Context, a pbsACL) error {
	return c.run(ctx, nil, "proxmox-backup-manager", "acl", "update", a.Path, a.Role, "--auth-id", a.UGID,
		"--propagate", fmt.Sprint(a.Propagate))
}

func (c pbsCLI) DeleteACL(ctx context.Context, a pbsACL) error {
	return c.run(ctx, nil, "proxmox-backup-manager", "acl", "update", a.Path, a.Role, "--auth-id", a.UGID, "--delete", "true")
}

// ---- console side ----

func (s *Server) grantsDir() string { return filepath.Join(s.cfg.DataDir, grantsDirName) }

// neededGrants lists the namespaces the console needs on the local PBS: the
// root namespace of each local target, and namespaces of their clients
// outside it (from before a root namespace change, or of targets without
// one). extra is a target about to be saved.
func (s *Server) neededGrants(ctx context.Context, extra *Target) ([]grantNS, error) {
	ts, err := s.store.Targets(ctx)
	if err != nil {
		return nil, err
	}
	if extra != nil {
		ts = slices.DeleteFunc(ts, func(t *Target) bool { return t.ID == extra.ID })
		ts = append(ts, extra)
	}
	cs, err := s.store.Clients(ctx)
	if err != nil {
		return nil, err
	}
	// Revoked clients keep their backups (to restore, or re-enroll with them).
	revoked, err := s.store.RevokedClients(ctx, 0)
	if err != nil {
		return nil, err
	}
	cs = append(cs, revoked...)
	var out []grantNS
	for _, t := range ts {
		if !t.Local {
			continue
		}
		root := strings.Trim(t.RootNS, "/")
		if root != "" {
			out = append(out, grantNS{t.Datastore, root})
		}
		for _, c := range cs {
			if c.TargetID != t.ID || t.ID == 0 {
				continue
			}
			for _, ns := range append([]string{c.Namespace}, c.OldNamespaces...) {
				if ns != "" && (root == "" || ns != root && !strings.HasPrefix(ns, root+"/")) {
					out = append(out, grantNS{t.Datastore, ns})
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b grantNS) int { return strings.Compare(a.path(), b.path()) })
	return slices.Compact(out), nil
}

// requestGrants asks the root helper for rights on want and returns the
// request's id.
func (s *Server) requestGrants(want []grantNS) (string, error) {
	var id [8]byte
	rand.Read(id[:])
	req := grantsRequest{ID: hex.EncodeToString(id[:]), Namespaces: orEmpty(want)}
	b, _ := json.Marshal(req)
	dir := s.grantsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp := filepath.Join(dir, "request.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, filepath.Join(dir, updateRequestFile)); err != nil {
		return "", err
	}
	s.log.Info("requested datastore rights on the local PBS", "namespaces", len(want))
	if s.grantHelper != nil {
		s.grantHelper()
	}
	return req.ID, nil
}

func (s *Server) grantsResult() *grantsResultFile {
	b, err := os.ReadFile(filepath.Join(s.grantsDir(), grantsResult))
	if err != nil {
		return nil
	}
	var res grantsResultFile
	if json.Unmarshal(b, &res) != nil {
		return nil
	}
	return &res
}

// localDatastores lists the datastores of the local PBS as the root helper
// last saw them (the console itself only sees those it may use).
func (s *Server) localDatastores() []string {
	if res := s.grantsResult(); res != nil {
		return res.Datastores
	}
	return nil
}

// managesNS reports whether the console's PBS user can manage the backups in
// g (the helper's ACLs take PBS a few seconds to apply).
func managesNS(ctx context.Context, pc *pbs.Client, g grantNS) (bool, error) {
	var privs map[string]map[string]bool
	if err := pc.Call(ctx, http.MethodGet, "access/permissions", map[string]any{"path": g.path()}, &privs); err != nil {
		return false, err
	}
	_, ok := privs[g.path()]["Datastore.Modify"]
	return ok, nil
}

// syncGrants asks the root helper for the rights the console lacks or no
// longer needs. extra is a target about to be saved: then it waits until
// PBS applied them, and fails if the helper refused one of its namespaces.
func (s *Server) syncGrants(ctx context.Context, pc *pbs.Client, extra *Target) error {
	want, err := s.neededGrants(ctx, extra)
	if err != nil {
		return err
	}
	res := s.grantsResult()
	missing := res == nil || res.Error != "" || !slices.Equal(res.Requested, want)
	for _, g := range want {
		if missing {
			break
		}
		if _, refused := res.Refused[g.path()]; refused && extra == nil {
			continue // asking again would only be refused again
		}
		ok, err := managesNS(ctx, pc, g)
		if err != nil {
			return err
		}
		missing = !ok
	}
	if !missing {
		return nil
	}
	id, err := s.requestGrants(want)
	if err != nil || extra == nil {
		return err
	}
	return s.waitGrants(ctx, pc, id, extra)
}

// refreshGrants asks for the rights the local targets need now, after one
// was saved or deleted.
func (s *Server) refreshGrants(ctx context.Context) {
	l := s.cfg.LocalPBS
	if l == nil {
		return
	}
	pc, _, _, err := l.client(ctx)
	if err == nil {
		err = s.syncGrants(ctx, pc, nil)
	}
	if err != nil {
		s.log.Warn("could not update the console's rights on the local PBS", "err", err)
	}
}

// waitGrants waits for the helper's answer to request id and for PBS to
// apply the rights on t's root namespace.
func (s *Server) waitGrants(ctx context.Context, pc *pbs.Client, id string, t *Target) error {
	g := grantNS{t.Datastore, strings.Trim(t.RootNS, "/")}
	ctx, cancel := context.WithTimeout(ctx, s.grantTimeout)
	defer cancel()
	answered := false
	for {
		if res := s.grantsResult(); res != nil && res.ID == id {
			answered = true
			if res.Error != "" {
				return fmt.Errorf("granting the console access to %s failed: %s", g.path(), res.Error)
			}
			if reason, ok := res.Refused[g.path()]; ok {
				return fmt.Errorf("the console was not given access to %s: %s", g.path(), reason)
			}
			if ok, err := managesNS(ctx, pc, g); err == nil && ok {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			if !answered {
				return fmt.Errorf("the console's root helper didn't answer (see journalctl -u proxbackup-server-grants), so it has no access to %s yet", g.path())
			}
			return fmt.Errorf("PBS hasn't applied the console's access to %s yet: save again in a minute", g.path())
		case <-time.After(time.Second):
		}
	}
}
