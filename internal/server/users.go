// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Console users sign in with a local password. Their rights come from roles,
// which are sets of permissions. A role is assigned to a user for all clients
// or only for some clients and client tags; permissions that aren't about
// clients (datastores, settings, users) are only granted by assignments for
// all clients. auth_source and external_id leave room for external identities
// (OIDC) mapped onto the same users and roles.

// Perm is a permission a role can grant.
type Perm string

const (
	PermViewClients   Perm = "clients.view"   // clients, their jobs and runs, the dashboard
	PermManageClients Perm = "clients.manage" // enrollment, revoke, tags, agent updates
	PermManageJobs    Perm = "jobs.manage"    // group jobs and member settings
	PermRunBackups    Perm = "backups.run"    // start and cancel backups
	PermRestore       Perm = "restore"        // browse snapshots, restore, download client keys
	PermTargets       Perm = "targets.manage" // datastores
	PermNotifications Perm = "notifications.manage"
	PermUpdates       Perm = "updates.manage" // console update settings and installs
	PermEncryption    Perm = "encryption.manage"
	PermUsers         Perm = "users.manage" // users and roles
	PermAudit         Perm = "audit.view"
)

// PermInfo describes a permission for the UI.
type PermInfo struct {
	ID          Perm   `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// ClientLevel permissions can be limited to clients or tags; the others
	// need an assignment for all clients.
	ClientLevel bool `json:"client_level"`
}

var permissions = []PermInfo{
	{PermViewClients, "View clients", "Clients, their jobs, runs and logs, and the dashboard.", true},
	{PermManageClients, "Manage clients", "Enroll PCs, revoke and restore clients, push agent updates. Enrollment and tags need all clients.", true},
	{PermManageJobs, "Manage jobs", "Change member job settings. Creating and editing group jobs needs all clients.", true},
	{PermRunBackups, "Run backups", "Start and cancel backups.", true},
	{PermRestore, "Restore", "Browse snapshots, restore files and download client encryption keys.", true},
	{PermTargets, "Manage datastores", "Add, change and remove the PBS datastores clients back up to.", false},
	{PermNotifications, "Manage notifications", "Email and webhook notification settings.", false},
	{PermUpdates, "Manage updates", "Console update settings and installing updates.", false},
	{PermEncryption, "Manage encryption", "The master key for client-side encryption.", false},
	{PermUsers, "Manage users", "Users, roles and their permissions.", false},
	{PermAudit, "View audit log", "Sign-ins and administrative changes.", false},
}

func permInfo(p Perm) (PermInfo, bool) {
	for _, i := range permissions {
		if i.ID == p {
			return i, true
		}
	}
	return PermInfo{}, false
}

// builtinRoles are created at startup and kept in sync with this list; they
// can't be edited or deleted.
var builtinRoles = []struct {
	key, name, desc string
	perms           []Perm
}{
	{"admin", "Administrator", "Everything, including users and console settings.", []Perm{PermViewClients, PermManageClients,
		PermManageJobs, PermRunBackups, PermRestore, PermTargets, PermNotifications, PermUpdates, PermEncryption, PermUsers, PermAudit}},
	{"operator", "Operator", "Day-to-day work: clients, jobs, backups and restores.", []Perm{PermViewClients, PermManageClients,
		PermManageJobs, PermRunBackups, PermRestore}},
	{"restore", "Restore-only", "Sees clients and restores their files.", []Perm{PermViewClients, PermRestore}},
	{"readonly", "Read-only", "Sees clients, jobs and runs.", []Perm{PermViewClients}},
}

// Role is a named set of permissions.
type Role struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Permissions []Perm `json:"permissions"`
	Builtin     string `json:"builtin,omitempty"` // key of a built-in role
	Users       int    `json:"users"`             // users it is assigned to
}

// RoleAssignment grants a role to a user for all clients or for the listed
// clients and the clients carrying one of the tags.
type RoleAssignment struct {
	RoleID     int64    `json:"role_id"`
	RoleName   string   `json:"role_name,omitempty"`
	AllClients bool     `json:"all_clients"`
	Clients    []int64  `json:"clients"`
	Tags       []string `json:"tags"`
}

// User is a console account.
type User struct {
	ID         int64            `json:"id"`
	Username   string           `json:"username"`
	Enabled    bool             `json:"enabled"`
	MustChange bool             `json:"must_change_password"`
	LastLogin  int64            `json:"last_login"`
	CreatedAt  int64            `json:"created_at"`
	AuthSource string           `json:"auth_source"` // "local"; external identity providers later
	Roles      []RoleAssignment `json:"roles"`
}

// SessionUser is the account behind a console session.
type SessionUser struct {
	ID         int64
	Name       string
	External   bool // no local password
	MustChange bool
	Access     *Access
}

// ---- access evaluation ----

type scope struct {
	all     bool
	clients map[int64]bool
	tags    map[string]bool
}

func (sc *scope) merge(a *RoleAssignment) {
	if a.AllClients {
		sc.all = true
		return
	}
	for _, c := range a.Clients {
		sc.clients[c] = true
	}
	for _, t := range a.Tags {
		sc.tags[t] = true
	}
}

func (sc *scope) covers(c *Client) bool {
	if sc.all || sc.clients[c.ID] {
		return true
	}
	for _, t := range c.Tags {
		if sc.tags[t] {
			return true
		}
	}
	return false
}

// Access is what a user may do: per permission, the clients it applies to.
type Access struct {
	grants map[Perm]*scope
}

func newAccess(as []RoleAssignment, roles map[int64][]Perm) *Access {
	a := &Access{grants: map[Perm]*scope{}}
	for i := range as {
		for _, p := range roles[as[i].RoleID] {
			info, ok := permInfo(p)
			if !ok || !info.ClientLevel && !as[i].AllClients {
				continue
			}
			ps := []Perm{p}
			if info.ClientLevel && p != PermViewClients {
				ps = append(ps, PermViewClients) // acting on a client includes seeing it
			}
			for _, p := range ps {
				sc := a.grants[p]
				if sc == nil {
					sc = &scope{clients: map[int64]bool{}, tags: map[string]bool{}}
					a.grants[p] = sc
				}
				sc.merge(&as[i])
			}
		}
	}
	return a
}

// Has reports whether p is granted for at least some clients.
func (a *Access) Has(p Perm) bool { return a != nil && a.grants[p] != nil }

// Global reports whether p is granted for all clients.
func (a *Access) Global(p Perm) bool { return a.Has(p) && a.grants[p].all }

// Client reports whether p is granted for c.
func (a *Access) Client(p Perm, c *Client) bool { return a.Has(p) && a.grants[p].covers(c) }

type scopeView struct {
	All     bool     `json:"all"`
	Clients []int64  `json:"clients"`
	Tags    []string `json:"tags"`
}

// MarshalJSON lists the granted permissions with their scopes (for the UI).
func (a *Access) MarshalJSON() ([]byte, error) {
	out := map[Perm]scopeView{}
	if a != nil {
		for p, sc := range a.grants {
			v := scopeView{All: sc.all, Clients: []int64{}, Tags: []string{}}
			if !sc.all {
				for c := range sc.clients {
					v.Clients = append(v.Clients, c)
				}
				for t := range sc.tags {
					v.Tags = append(v.Tags, t)
				}
				slices.Sort(v.Clients)
				slices.Sort(v.Tags)
			}
			out[p] = v
		}
	}
	return json.Marshal(out)
}

// ---- store: schema helpers ----

func (s *Store) tableExists(name string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	return n > 0, err
}

// seedRoles creates the built-in roles and updates their permissions.
func (s *Store) seedRoles() error {
	for _, r := range builtinRoles {
		perms, _ := json.Marshal(r.perms)
		if _, err := s.db.Exec(`INSERT INTO roles(name, description, permissions, builtin, created_at) VALUES(?,?,?,?,?)
			ON CONFLICT(builtin) WHERE builtin<>'' DO UPDATE SET description=excluded.description, permissions=excluded.permissions`,
			r.name, r.desc, string(perms), r.key, now()); err != nil {
			return fmt.Errorf("role %s: %w", r.key, err)
		}
	}
	return nil
}

func (s *Store) builtinRoleID(ctx context.Context, key string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM roles WHERE builtin=?`, key).Scan(&id)
	return id, err
}

// migrateUsers moves the accounts of the old admins table to users. Every
// local account was an administrator; accounts that signed in with PBS
// credentials (user@realm) and their sessions are dropped.
func (s *Store) migrateUsers() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='admin_id'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		if _, err := s.db.Exec(`ALTER TABLE sessions RENAME COLUMN admin_id TO user_id`); err != nil {
			return err
		}
	}
	old, err := s.tableExists("admins")
	if err != nil || !old {
		return err
	}
	adminRole, err := s.builtinRoleID(context.Background(), "admin")
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`INSERT OR IGNORE INTO users(id, username, pw_hash, created_at, must_change_pw)
			SELECT id, username, pw_hash, created_at, must_change_pw FROM admins WHERE pw_hash NOT LIKE 'external:%'`,
		`DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users)`,
		fmt.Sprintf(`INSERT INTO user_roles(user_id, role_id, all_clients) SELECT id, %d, 1 FROM users
			WHERE id NOT IN (SELECT user_id FROM user_roles)`, adminRole),
		`DROP TABLE admins`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- store: users ----

func (s *Store) UserCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetLocalPassword sets the password of a local account (CLI recovery). A new
// account becomes an administrator; an existing one is enabled again.
func (s *Store) SetLocalPassword(ctx context.Context, user, hash string, mustChange bool) error {
	id, _, _, err := s.UserByName(ctx, user)
	if errors.Is(err, errNotFound) {
		adminRole, err := s.builtinRoleID(ctx, "admin")
		if err != nil {
			return err
		}
		_, err = s.CreateUser(ctx, &User{Username: user, Enabled: true, MustChange: mustChange,
			Roles: []RoleAssignment{{RoleID: adminRole, AllClients: true}}}, hash)
		return err
	}
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET pw_hash=?, must_change_pw=?, enabled=1, auth_source='local' WHERE id=?`, hash, mustChange, id)
	return err
}

// UserByName returns a user's id, password hash and whether it is enabled.
func (s *Store) UserByName(ctx context.Context, user string) (int64, string, bool, error) {
	var id int64
	var hash string
	var enabled bool
	err := s.db.QueryRowContext(ctx, `SELECT id, pw_hash, enabled FROM users WHERE username=? COLLATE NOCASE`, user).Scan(&id, &hash, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotFound
	}
	return id, hash, enabled, err
}

const userCols = `id, username, enabled, must_change_pw, last_login, created_at, auth_source`

func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	var out []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.Enabled, &u.MustChange, &u.LastLogin, &u.CreatedAt, &u.AuthSource); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, u := range out {
		if u.Roles, err = s.Assignments(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) User(ctx context.Context, id int64) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.Enabled, &u.MustChange, &u.LastLogin, &u.CreatedAt, &u.AuthSource)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Roles, err = s.Assignments(ctx, id)
	return u, err
}

// Assignments returns the roles assigned to a user.
func (s *Store) Assignments(ctx context.Context, userID int64) ([]RoleAssignment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ur.role_id, r.name, ur.all_clients, ur.clients, ur.tags FROM user_roles ur
		JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=? ORDER BY ur.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RoleAssignment{}
	for rows.Next() {
		var a RoleAssignment
		var clients, tags string
		if err := rows.Scan(&a.RoleID, &a.RoleName, &a.AllClients, &clients, &tags); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(clients), &a.Clients)
		json.Unmarshal([]byte(tags), &a.Tags)
		a.Clients, a.Tags = orEmpty(a.Clients), orEmpty(a.Tags)
		out = append(out, a)
	}
	return out, rows.Err()
}

// UserAccess evaluates the permissions of a user.
func (s *Store) UserAccess(ctx context.Context, userID int64) (*Access, error) {
	as, err := s.Assignments(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles := map[int64][]Perm{}
	for _, a := range as {
		if _, ok := roles[a.RoleID]; ok {
			continue
		}
		var perms string
		if err := s.db.QueryRowContext(ctx, `SELECT permissions FROM roles WHERE id=?`, a.RoleID).Scan(&perms); err != nil {
			return nil, err
		}
		var ps []Perm
		json.Unmarshal([]byte(perms), &ps)
		roles[a.RoleID] = ps
	}
	return newAccess(as, roles), nil
}

func setAssignments(ctx context.Context, tx *sql.Tx, userID int64, as []RoleAssignment) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, a := range as {
		clients, _ := json.Marshal(orEmpty(a.Clients))
		tags, _ := json.Marshal(orEmpty(a.Tags))
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_roles(user_id, role_id, all_clients, clients, tags) VALUES(?,?,?,?,?)`,
			userID, a.RoleID, a.AllClients, string(clients), string(tags)); err != nil {
			return err
		}
	}
	return nil
}

// errLastAdmin keeps the console from losing its last user administrator.
var errLastAdmin = errors.New("at least one enabled user must keep the right to manage users for all clients")

// checkAdminRemains fails with errLastAdmin if no enabled user could manage
// users anymore.
func checkAdminRemains(ctx context.Context, tx *sql.Tx) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT u.id) FROM users u JOIN user_roles ur ON ur.user_id=u.id
		JOIN roles r ON r.id=ur.role_id WHERE u.enabled=1 AND ur.all_clients=1 AND r.permissions LIKE ?`,
		`%"`+string(PermUsers)+`"%`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errLastAdmin
	}
	return nil
}

var errUsernameTaken = errors.New("a user with this name already exists")

// CreateUser adds a local account.
func (s *Store) CreateUser(ctx context.Context, u *User, hash string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int
	tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username=? COLLATE NOCASE`, u.Username).Scan(&n)
	if n > 0 {
		return 0, errUsernameTaken
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO users(username, pw_hash, created_at, must_change_pw, enabled) VALUES(?,?,?,?,?)`,
		u.Username, hash, now(), u.MustChange, u.Enabled)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	if err := setAssignments(ctx, tx, id, u.Roles); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// UpdateUser changes whether a user is enabled and its roles. Disabled users
// lose their sessions.
func (s *Store) UpdateUser(ctx context.Context, id int64, enabled bool, roles []RoleAssignment) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET enabled=? WHERE id=?`, enabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	if err := setAssignments(ctx, tx, id, roles); err != nil {
		return err
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
			return err
		}
	}
	if err := checkAdminRemains(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	for _, q := range []string{`DELETE FROM user_roles WHERE user_id=?`, `DELETE FROM sessions WHERE user_id=?`} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	if err := checkAdminRemains(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// SetUserPassword changes a local account's password and ends its sessions
// except keepSession (the caller's own, when users change their password).
func (s *Store) SetUserPassword(ctx context.Context, id int64, hash string, mustChange bool, keepSession string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET pw_hash=?, must_change_pw=?, auth_source='local' WHERE id=?`, hash, mustChange, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND token_hash<>?`, id, keepSession)
	return err
}

func (s *Store) UserPasswordHash(ctx context.Context, id int64) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT pw_hash FROM users WHERE id=?`, id).Scan(&hash)
	return hash, err
}

func (s *Store) TouchLogin(ctx context.Context, id int64) {
	s.db.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, now(), id)
}

// ---- store: sessions ----

func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, expires) VALUES(?,?,?)`, tokenHash, userID, time.Now().Add(ttl).Unix())
	return err
}

// SessionUser returns the enabled user behind a session, with its access.
func (s *Store) SessionUser(ctx context.Context, tokenHash string) (*SessionUser, error) {
	u := &SessionUser{}
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT u.id, u.username, u.pw_hash, u.must_change_pw FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=? AND s.expires>? AND u.enabled=1`, tokenHash, now()).Scan(&u.ID, &u.Name, &hash, &u.MustChange)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	u.External = !strings.HasPrefix(hash, "argon2id$")
	u.Access, err = s.UserAccess(ctx, u.ID)
	return u, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) {
	s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=? OR expires<?`, tokenHash, now())
}

// ---- store: roles ----

func (s *Store) Roles(ctx context.Context) ([]*Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.name, r.description, r.permissions, r.builtin,
		(SELECT COUNT(DISTINCT user_id) FROM user_roles WHERE role_id=r.id) FROM roles r
		ORDER BY r.builtin='', CASE r.builtin WHEN 'admin' THEN 0 WHEN 'operator' THEN 1 WHEN 'restore' THEN 2 ELSE 3 END, r.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Role
	for rows.Next() {
		r := &Role{}
		var perms string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &perms, &r.Builtin, &r.Users); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(perms), &r.Permissions)
		r.Permissions = orEmpty(r.Permissions)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Role(ctx context.Context, id int64) (*Role, error) {
	rs, err := s.Roles(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, errNotFound
}

var errRoleNameTaken = errors.New("a role with this name already exists")

// SaveRole creates or updates a custom role.
func (s *Store) SaveRole(ctx context.Context, r *Role) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE name=? COLLATE NOCASE AND id<>?`, r.Name, r.ID).Scan(&n)
	if n > 0 {
		return errRoleNameTaken
	}
	perms, _ := json.Marshal(orEmpty(r.Permissions))
	if r.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO roles(name, description, permissions, created_at) VALUES(?,?,?,?)`,
			r.Name, r.Description, string(perms), now())
		if err != nil {
			return err
		}
		r.ID, _ = res.LastInsertId()
	} else {
		res, err := tx.ExecContext(ctx, `UPDATE roles SET name=?, description=?, permissions=? WHERE id=? AND builtin=''`,
			r.Name, r.Description, string(perms), r.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNotFound
		}
		if err := checkAdminRemains(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var errRoleInUse = errors.New("the role is assigned to users; remove it from them first")

func (s *Store) DeleteRole(ctx context.Context, id int64) error {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_roles WHERE role_id=?`, id).Scan(&n)
	if n > 0 {
		return errRoleInUse
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id=? AND builtin=''`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ---- store: audit log ----

// AuditEntry is a sign-in or a change made through the console.
type AuditEntry struct {
	ID       int64  `json:"id"`
	Time     int64  `json:"time"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Action   string `json:"action"`
	Target   string `json:"target"` // what it applied to, e.g. "client pc-01"
	Detail   string `json:"detail"`
	Status   int    `json:"status"` // HTTP status of the request (0 = not a request)
	IP       string `json:"ip"`
}

func (s *Store) AddAudit(ctx context.Context, e *AuditEntry) error {
	if e.Time == 0 {
		e.Time = now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(ts, user_id, username, action, target, detail, status, ip) VALUES(?,?,?,?,?,?,?,?)`,
		e.Time, e.UserID, e.Username, e.Action, e.Target, e.Detail, e.Status, e.IP)
	return err
}

// AuditFilter selects audit entries, newest first.
type AuditFilter struct {
	Before int64 // entries with a smaller id (paging)
	User   string
	Limit  int
}

func (s *Store) AuditLog(ctx context.Context, f AuditFilter) ([]*AuditEntry, error) {
	q := `SELECT id, ts, user_id, username, action, target, detail, status, ip FROM audit_log WHERE 1=1`
	var args []any
	if f.Before > 0 {
		q += ` AND id<?`
		args = append(args, f.Before)
	}
	if f.User != "" {
		q += ` AND username=? COLLATE NOCASE`
		args = append(args, f.User)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += fmt.Sprintf(` ORDER BY id DESC LIMIT %d`, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		if err := rows.Scan(&e.ID, &e.Time, &e.UserID, &e.Username, &e.Action, &e.Target, &e.Detail, &e.Status, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) PruneAudit(ctx context.Context, maxAge time.Duration) {
	s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts<?`, time.Now().Add(-maxAge).Unix())
}

// ClientTags returns the tags of every client, revoked ones included (for
// filtering history by scope).
func (s *Store) ClientTags(ctx context.Context) (map[int64][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, tags FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var tags string
		if err := rows.Scan(&id, &tags); err != nil {
			return nil, err
		}
		var t []string
		json.Unmarshal([]byte(tags), &t)
		out[id] = t
	}
	return out, rows.Err()
}
