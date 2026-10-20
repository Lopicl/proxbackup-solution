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

	_ "modernc.org/sqlite"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

const schema = `
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, host TEXT NOT NULL, fingerprint TEXT NOT NULL DEFAULT '',
  datastore TEXT NOT NULL, root_ns TEXT NOT NULL DEFAULT '', admin_auth_id TEXT NOT NULL, admin_secret_enc BLOB NOT NULL,
  pbs_user TEXT NOT NULL DEFAULT 'proxbackup@pbs', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, hostname TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '',
  agent_version TEXT NOT NULL DEFAULT '', cert_serial TEXT UNIQUE, target_id INTEGER NOT NULL REFERENCES targets(id),
  namespace TEXT NOT NULL DEFAULT '', token_id TEXT NOT NULL DEFAULT '', token_secret_enc BLOB,
  last_seen INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS enrollments (
  id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, client_name TEXT NOT NULL, target_id INTEGER NOT NULL,
  expires INTEGER NOT NULL, used_at INTEGER NOT NULL DEFAULT 0, client_id INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS setup_tokens (
  id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, target_id INTEGER NOT NULL, expires INTEGER NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0, token_enc BLOB NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE, name TEXT NOT NULL,
  kind TEXT NOT NULL, backup_id TEXT NOT NULL, sources TEXT NOT NULL DEFAULT '[]', excludes TEXT NOT NULL DEFAULT '[]',
  volumes TEXT NOT NULL DEFAULT '[]', use_vss INTEGER NOT NULL DEFAULT 1, schedule TEXT NOT NULL DEFAULT '',
  retention TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL DEFAULT 0, client_id INTEGER NOT NULL, kind TEXT NOT NULL,
  state TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT '', restore_spec TEXT NOT NULL DEFAULT '',
  queued_at INTEGER NOT NULL, started_at INTEGER NOT NULL DEFAULT 0, finished_at INTEGER NOT NULL DEFAULT 0,
  last_event_at INTEGER NOT NULL DEFAULT 0, progress TEXT NOT NULL DEFAULT '{}', result TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '', snapshot TEXT NOT NULL DEFAULT '', cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS runs_client ON runs(client_id, state);
CREATE INDEX IF NOT EXISTS runs_job ON runs(job_id, queued_at);
CREATE TABLE IF NOT EXISTS run_logs (
  id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL, ts INTEGER NOT NULL, level TEXT NOT NULL, msg TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS run_logs_run ON run_logs(run_id, id);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshot_locks (
  id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL, target_id INTEGER NOT NULL, namespace TEXT NOT NULL,
  backup_type TEXT NOT NULL, backup_id TEXT NOT NULL, backup_time INTEGER NOT NULL, lock_days INTEGER NOT NULL,
  UNIQUE(target_id, namespace, backup_type, backup_id, backup_time));
CREATE TABLE IF NOT EXISTS group_jobs (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, backup_id TEXT NOT NULL DEFAULT '',
  sources TEXT NOT NULL DEFAULT '[]', excludes TEXT NOT NULL DEFAULT '[]', volumes TEXT NOT NULL DEFAULT '[]',
  use_vss INTEGER NOT NULL DEFAULT 1, schedule TEXT NOT NULL DEFAULT '', window_minutes INTEGER NOT NULL DEFAULT 60,
  catch_up INTEGER NOT NULL DEFAULT 1, retention TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1,
  change_detection TEXT NOT NULL DEFAULT 'metadata', encrypt INTEGER NOT NULL DEFAULT 0, lock_days INTEGER NOT NULL DEFAULT 0,
  spread_minutes INTEGER NOT NULL DEFAULT 0, member_tags TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL,
  daily_cap INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS restore_sessions (
  token_hash TEXT PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_name TEXT NOT NULL, user_sid TEXT NOT NULL, admin INTEGER NOT NULL, scope TEXT NOT NULL,
  agent_ref TEXT NOT NULL, created_at INTEGER NOT NULL, max_expires INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS group_job_clients (
  group_id INTEGER NOT NULL REFERENCES group_jobs(id) ON DELETE CASCADE,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE, PRIMARY KEY(group_id, client_id));
`

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// OpenStore opens (and migrates) the database at path.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writers, avoids SQLITE_BUSY
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrate adds columns introduced after the initial schema (idempotent).
func (s *Store) migrate() error {
	cols := []struct{ table, name, def string }{
		{"jobs", "window_minutes", "INTEGER NOT NULL DEFAULT 60"},
		{"jobs", "catch_up", "INTEGER NOT NULL DEFAULT 1"},
		{"runs", "uuid", "TEXT NOT NULL DEFAULT ''"},
		{"runs", "scheduled_for", "INTEGER NOT NULL DEFAULT 0"},
		{"clients", "config_rev", "TEXT NOT NULL DEFAULT ''"},
		{"clients", "schedule_state", "TEXT NOT NULL DEFAULT '[]'"},
		{"clients", "time_zone", "TEXT NOT NULL DEFAULT ''"},
		{"admins", "must_change_pw", "INTEGER NOT NULL DEFAULT 0"},
		{"enrollments", "command_enc", "BLOB"},
		// Existing file jobs move to pxar v2 too; their first run reads everything.
		{"jobs", "change_detection", "TEXT NOT NULL DEFAULT 'metadata'"},
		// Client-side encryption: the client key, sealed with the master key.
		// It is kept when the client is revoked (escrow for recovery).
		{"clients", "crypt_key_enc", "BLOB"},
		{"clients", "crypt_fingerprint", "TEXT NOT NULL DEFAULT ''"},
		{"clients", "crypt_created", "INTEGER NOT NULL DEFAULT 0"},
		{"jobs", "encrypt", "INTEGER NOT NULL DEFAULT 0"},
		// Immutable backups: days a new snapshot stays protected (0 = off).
		{"jobs", "lock_days", "INTEGER NOT NULL DEFAULT 0"},
		// Namespaces a client used before its target's root namespace changed;
		// their snapshots stay listed and restorable.
		{"clients", "old_namespaces", "TEXT NOT NULL DEFAULT '[]'"},
		// Group jobs: a jobs row is now one client's membership in a group job,
		// which holds the definition. Its own definition columns are only
		// read for rows without a group (jobs of clients revoked before).
		{"jobs", "group_id", "INTEGER NOT NULL DEFAULT 0"},
		{"jobs", "extra_excludes", "TEXT NOT NULL DEFAULT '[]'"},
		{"clients", "tags", "TEXT NOT NULL DEFAULT '[]'"},
		// Tamper-resistant retention: backups per job and day that count (0 = from the schedule).
		{"group_jobs", "daily_cap", "INTEGER NOT NULL DEFAULT 0"},
		// Scheduled backups paused by a PC user from the tray app.
		{"clients", "paused_until", "INTEGER NOT NULL DEFAULT 0"},
		{"clients", "paused_by", "TEXT NOT NULL DEFAULT ''"},
		// Revoked clients can be restored: when, the certificate serial the agent
		// still holds, and the jobs that were enabled.
		{"clients", "revoked_at", "INTEGER NOT NULL DEFAULT 0"},
		{"clients", "revoked_serial", "TEXT NOT NULL DEFAULT ''"},
		{"clients", "revoked_jobs", "TEXT NOT NULL DEFAULT '[]'"},
	}
	for _, c := range cols {
		var n int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?`, c.table, c.name).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, c.table, c.name, c.def)); err != nil {
				return err
			}
			if c.name == "must_change_pw" {
				// Existing installs: the initial "admin" may still have its generated password.
				if _, err := s.db.Exec(`UPDATE admins SET must_change_pw=1 WHERE username='admin' AND pw_hash LIKE 'argon2id$%'`); err != nil {
					return err
				}
			}
		}
	}
	if _, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS runs_uuid ON runs(client_id, uuid) WHERE uuid<>''`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS jobs_group ON jobs(group_id)`); err != nil {
		return err
	}
	if err := s.migrateGroupJobs(); err != nil {
		return err
	}
	return s.repairJobRefs()
}

// repairJobRefs unlinks runs and snapshot locks left by jobs deleted before
// detachJobs existed. SQLite hands a deleted row's id to the next insert, so
// they show up under whichever job now has that id: a run belongs to it only
// if it is for the same client and not older than the job (with a margin for
// agent clock skew); a lock only if the job writes that backup group.
func (s *Store) repairJobRefs() error {
	if _, err := s.db.Exec(`UPDATE runs SET job_id=0 WHERE job_id>0 AND NOT EXISTS (SELECT 1 FROM jobs j
		WHERE j.id=runs.job_id AND j.client_id=runs.client_id AND runs.queued_at>=j.created_at-600)`); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE snapshot_locks SET job_id=0 WHERE job_id>0 AND NOT EXISTS (SELECT 1 FROM jobs j
		WHERE j.id=snapshot_locks.job_id AND j.backup_id=snapshot_locks.backup_id)`)
	return err
}

// detachJobs unlinks run history and snapshot locks from the jobs matching
// where, ahead of their deletion, so a job that later gets one of their ids
// doesn't inherit them. Runs the agent hasn't picked up yet are canceled.
func detachJobs(ctx context.Context, db execer, where string, args ...any) error {
	sel := `job_id IN (SELECT id FROM jobs WHERE ` + where + `)`
	if _, err := db.ExecContext(ctx, `UPDATE runs SET state='canceled', finished_at=?, error='job deleted' WHERE state='queued' AND `+sel,
		append([]any{now()}, args...)...); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `UPDATE runs SET job_id=0 WHERE `+sel, args...); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, `UPDATE snapshot_locks SET job_id=0 WHERE `+sel, args...)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

var errNotFound = errors.New("not found")

func now() int64 { return time.Now().Unix() }

// ---- models ----

type Target struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
	Datastore   string `json:"datastore"`
	RootNS      string `json:"root_ns"`
	AdminAuthID string `json:"admin_auth_id"`
	PBSUser     string `json:"pbs_user"`
	CreatedAt   int64  `json:"created_at"`

	adminSecretEnc []byte
}

type Client struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	AgentVersion string `json:"agent_version"`
	TargetID     int64  `json:"target_id"`
	Namespace    string `json:"namespace"`
	// OldNamespaces hold the client's snapshots from before a root namespace change.
	OldNamespaces []string `json:"old_namespaces"`
	TokenID       string   `json:"token_id"`
	// Tags put the client into client groups; group jobs can target them.
	Tags      []string `json:"tags"`
	LastSeen  int64    `json:"last_seen"`
	Revoked   bool     `json:"revoked"`
	RevokedAt int64    `json:"revoked_at"`
	// Restorable: revoked with its certificate serial kept (see UnrevokeClient).
	Restorable bool  `json:"restorable"`
	CreatedAt  int64 `json:"created_at"`
	// Derived for the UI.
	Online      bool   `json:"online"`
	LastRun     *Run   `json:"last_run,omitempty"`
	LastSuccess int64  `json:"last_success"`
	CertSerial  string `json:"-"`
	// Reported by the agent.
	ConfigRev     string         `json:"config_rev"`
	ScheduleState []api.JobState `json:"schedule_state"`
	TimeZone      string         `json:"time_zone"`
	ConfigSynced  bool           `json:"config_synced"`
	// PausedUntil (unix seconds): a PC user paused scheduled backups from the
	// tray app until then (as last reported; check against the time).
	PausedUntil int64  `json:"paused_until"`
	PausedBy    string `json:"paused_by"`
	// AgentUpdate is the version the agent can be updated to (the console's), and
	// AgentUpdatePushed whether an admin pushed it and the agent hasn't fetched it yet.
	AgentUpdate       string `json:"agent_update,omitempty"`
	AgentUpdatePushed bool   `json:"agent_update_pushed"`
	// The client's encryption key ("" = none yet; created with the first encrypted job).
	EncryptionFingerprint string `json:"encryption_fingerprint"`
	EncryptionCreated     int64  `json:"encryption_created"`

	tokenSecretEnc []byte
	cryptKeyEnc    []byte
	revokedSerial  string
	revokedJobs    []int64
}

// Job is one client's membership in a group job: the group's definition with
// the member's own backup group and overrides applied.
type Job struct {
	ID            int64           `json:"id"`
	ClientID      int64           `json:"client_id"`
	GroupID       int64           `json:"group_id"`
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	BackupID      string          `json:"backup_id"`
	Sources       []string        `json:"sources"`
	Excludes      []string        `json:"excludes"`
	Volumes       []string        `json:"volumes"`
	UseVSS        bool            `json:"use_vss"`
	Schedule      string          `json:"schedule"`
	WindowMinutes int             `json:"window_minutes"`
	CatchUp       bool            `json:"catch_up"`
	Retention     pbs.KeepOptions `json:"retention"`
	// Enabled: the group job and this member are enabled.
	Enabled       bool  `json:"enabled"`
	GroupEnabled  bool  `json:"group_enabled"`
	MemberEnabled bool  `json:"member_enabled"`
	CreatedAt     int64 `json:"created_at"`
	// ExtraExcludes are this member's patterns on top of the group's Excludes.
	ExtraExcludes []string `json:"extra_excludes"`
	// StartDelay (seconds) spreads the members' start times over the group's
	// SpreadMinutes, so many PCs don't hit PBS in the same minute.
	SpreadMinutes int `json:"spread_minutes"`
	StartDelay    int `json:"start_delay"`
	// File jobs: metadata, data or legacy (see api.JobSpec.ChangeDetection).
	ChangeDetection string `json:"change_detection"`
	// Encrypt client-side with the client key.
	Encrypt bool `json:"encrypt"`
	// LockDays keeps each new snapshot protected on PBS for that many days (0 = off).
	LockDays int `json:"lock_days"`
	// DailyCap is the number of backups per day that are locked and count for
	// retention (0 = derived from the schedule, see dailyCap).
	DailyCap int `json:"daily_cap"`
	// Reported by the agent (it owns the schedule).
	NextRun        int64 `json:"next_run,omitempty"`
	CatchUpPending bool  `json:"catch_up_pending,omitempty"`
}

type Run struct {
	ID              int64            `json:"id"`
	JobID           int64            `json:"job_id"`
	ClientID        int64            `json:"client_id"`
	Kind            string           `json:"kind"`
	State           string           `json:"state"`
	Trigger         string           `json:"trigger"`
	QueuedAt        int64            `json:"queued_at"`
	StartedAt       int64            `json:"started_at"`
	FinishedAt      int64            `json:"finished_at"`
	LastEventAt     int64            `json:"last_event_at"`
	Progress        api.Progress     `json:"progress"`
	Result          api.Result       `json:"result"`
	Error           string           `json:"error"`
	Snapshot        string           `json:"snapshot"`
	CancelRequested bool             `json:"cancel_requested"`
	ScheduledFor    int64            `json:"scheduled_for"`
	Restore         *api.RestoreSpec `json:"restore,omitempty"`
	JobName         string           `json:"job_name"`
	ClientName      string           `json:"client_name"`
	GroupID         int64            `json:"group_id"`
}

type LogLine struct {
	ID    int64  `json:"id"`
	Time  int64  `json:"ts"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// ---- admins & sessions ----

func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

// UpsertAdmin sets a local account's password. mustChange makes the user pick
// a new one at the next sign-in (for generated passwords).
func (s *Store) UpsertAdmin(ctx context.Context, user, hash string, mustChange bool) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admins(username, pw_hash, created_at, must_change_pw) VALUES(?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash, must_change_pw=excluded.must_change_pw`, user, hash, now(), mustChange)
	return err
}

// SessionUser is the account behind an admin session.
type SessionUser struct {
	ID         int64
	Name       string
	External   bool // signed in through PBS; no local password
	MustChange bool
}

// EnsureExternalAdmin returns the admin row for an account authenticated
// elsewhere (a PBS user@realm), creating it with an unusable local password.
func (s *Store) EnsureExternalAdmin(ctx context.Context, user string) (int64, error) {
	if _, err := s.db.ExecContext(ctx, `INSERT INTO admins(username, pw_hash, created_at) VALUES(?,'external:pbs',?)
		ON CONFLICT(username) DO NOTHING`, user, now()); err != nil {
		return 0, err
	}
	id, _, err := s.AdminByName(ctx, user)
	return id, err
}

func (s *Store) AdminByName(ctx context.Context, user string) (int64, string, error) {
	var id int64
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT id, pw_hash FROM admins WHERE username=?`, user).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotFound
	}
	return id, hash, err
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, adminID int64, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash, admin_id, expires) VALUES(?,?,?)`, tokenHash, adminID, time.Now().Add(ttl).Unix())
	return err
}

func (s *Store) SessionAdmin(ctx context.Context, tokenHash string) (*SessionUser, error) {
	u := &SessionUser{}
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT a.id, a.username, a.pw_hash, a.must_change_pw FROM sessions s JOIN admins a ON a.id=s.admin_id
		WHERE s.token_hash=? AND s.expires>?`, tokenHash, now()).Scan(&u.ID, &u.Name, &hash, &u.MustChange)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotFound
	}
	u.External = strings.HasPrefix(hash, "external:")
	return u, err
}

// SetAdminPassword changes a local account's password, clears the
// must-change flag and ends the account's other sessions.
func (s *Store) SetAdminPassword(ctx context.Context, id int64, hash, keepSession string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE admins SET pw_hash=?, must_change_pw=0 WHERE id=?`, hash, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id=? AND token_hash<>?`, id, keepSession)
	return err
}

func (s *Store) AdminPasswordHash(ctx context.Context, id int64) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT pw_hash FROM admins WHERE id=?`, id).Scan(&hash)
	return hash, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) {
	s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=? OR expires<?`, tokenHash, now())
}

// ---- targets ----

const targetCols = `id, name, host, fingerprint, datastore, root_ns, admin_auth_id, admin_secret_enc, pbs_user, created_at`

func scanTarget(sc interface{ Scan(...any) error }) (*Target, error) {
	t := &Target{}
	err := sc.Scan(&t.ID, &t.Name, &t.Host, &t.Fingerprint, &t.Datastore, &t.RootNS, &t.AdminAuthID, &t.adminSecretEnc, &t.PBSUser, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotFound
	}
	return t, err
}

func (s *Store) Targets(ctx context.Context) ([]*Target, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+targetCols+` FROM targets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Target(ctx context.Context, id int64) (*Target, error) {
	return scanTarget(s.db.QueryRowContext(ctx, `SELECT `+targetCols+` FROM targets WHERE id=?`, id))
}

func (s *Store) SaveTarget(ctx context.Context, t *Target) error {
	if t.ID == 0 {
		t.CreatedAt = now()
		res, err := s.db.ExecContext(ctx, `INSERT INTO targets(name, host, fingerprint, datastore, root_ns, admin_auth_id, admin_secret_enc, pbs_user, created_at)
			VALUES(?,?,?,?,?,?,?,?,?)`, t.Name, t.Host, t.Fingerprint, t.Datastore, t.RootNS, t.AdminAuthID, t.adminSecretEnc, t.PBSUser, t.CreatedAt)
		if err != nil {
			return err
		}
		t.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE targets SET name=?, host=?, fingerprint=?, datastore=?, root_ns=?, admin_auth_id=?,
		admin_secret_enc=?, pbs_user=? WHERE id=?`, t.Name, t.Host, t.Fingerprint, t.Datastore, t.RootNS, t.AdminAuthID, t.adminSecretEnc, t.PBSUser, t.ID)
	return err
}

func (s *Store) DeleteTarget(ctx context.Context, id int64) error {
	var n int
	s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE target_id=? AND revoked=0`, id).Scan(&n)
	if n > 0 {
		return fmt.Errorf("target is used by %d clients", n)
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM targets WHERE id=?`, id)
	return err
}

// ---- clients ----

const clientCols = `id, name, hostname, os, agent_version, COALESCE(cert_serial,''), target_id, namespace, token_id, token_secret_enc, last_seen, revoked, created_at,
	config_rev, schedule_state, time_zone, crypt_key_enc, crypt_fingerprint, crypt_created, old_namespaces, tags, paused_until, paused_by,
	revoked_at, revoked_serial, revoked_jobs`

func scanClient(sc interface{ Scan(...any) error }) (*Client, error) {
	c := &Client{}
	var sched, oldNS, tags, revJobs string
	err := sc.Scan(&c.ID, &c.Name, &c.Hostname, &c.OS, &c.AgentVersion, &c.CertSerial, &c.TargetID, &c.Namespace, &c.TokenID,
		&c.tokenSecretEnc, &c.LastSeen, &c.Revoked, &c.CreatedAt, &c.ConfigRev, &sched, &c.TimeZone,
		&c.cryptKeyEnc, &c.EncryptionFingerprint, &c.EncryptionCreated, &oldNS, &tags, &c.PausedUntil, &c.PausedBy,
		&c.RevokedAt, &c.revokedSerial, &revJobs)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotFound
	}
	json.Unmarshal([]byte(sched), &c.ScheduleState)
	json.Unmarshal([]byte(oldNS), &c.OldNamespaces)
	if c.OldNamespaces == nil {
		c.OldNamespaces = []string{}
	}
	json.Unmarshal([]byte(tags), &c.Tags)
	c.Tags = nonNil(c.Tags)
	json.Unmarshal([]byte(revJobs), &c.revokedJobs)
	c.Restorable = c.Revoked && c.revokedSerial != ""
	c.Online = !c.Revoked && time.Since(time.Unix(c.LastSeen, 0)) < 2*time.Minute
	return c, err
}

func (s *Store) Clients(ctx context.Context) ([]*Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientCols+` FROM clients WHERE revoked=0 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Client(ctx context.Context, id int64) (*Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE id=?`, id))
}

func (s *Store) ClientBySerial(ctx context.Context, serial string) (*Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE cert_serial=? AND revoked=0`, serial))
}

func (s *Store) ClientNameTaken(ctx context.Context, name string) bool {
	var n int
	// Includes names reserved by enrollments that haven't been used yet.
	s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM clients WHERE name=?)
		+ (SELECT COUNT(*) FROM enrollments WHERE client_name=? AND used_at=0 AND expires>?)`, name, name, now()).Scan(&n)
	return n > 0
}

func (s *Store) CreateClient(ctx context.Context, c *Client) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO clients(name, hostname, os, cert_serial, target_id, namespace, token_id, token_secret_enc, last_seen, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, c.Name, c.Hostname, c.OS, c.CertSerial, c.TargetID, c.Namespace, c.TokenID, c.tokenSecretEnc, now(), now())
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

// MoveClientNamespace points a client at ns, remembering its current namespace
// so earlier snapshots stay reachable.
func (s *Store) MoveClientNamespace(ctx context.Context, c *Client, ns string) error {
	old := []string{}
	for _, o := range append(c.OldNamespaces, c.Namespace) {
		if o != ns && !slices.Contains(old, o) {
			old = append(old, o)
		}
	}
	b, _ := json.Marshal(old)
	if _, err := s.db.ExecContext(ctx, `UPDATE clients SET namespace=?, old_namespaces=? WHERE id=?`, ns, string(b), c.ID); err != nil {
		return err
	}
	c.Namespace, c.OldNamespaces = ns, old
	return nil
}

func (s *Store) TouchClient(ctx context.Context, id int64, req api.PollRequest) {
	sched, _ := json.Marshal(nonNilStates(req.Schedule))
	s.db.ExecContext(ctx, `UPDATE clients SET last_seen=?, hostname=?, os=?, agent_version=?, config_rev=?, schedule_state=?, time_zone=?,
		paused_until=?, paused_by=? WHERE id=?`, now(), req.Hostname, req.OS, req.AgentVersion, req.ConfigRev, sched, req.TimeZone,
		req.PausedUntil, req.PausedBy, id)
}

// SetClientKey stores a new encryption key for a client that has none. It
// returns false if the client got a key meanwhile.
func (s *Store) SetClientKey(ctx context.Context, id int64, keyEnc []byte, fingerprint string, created int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET crypt_key_enc=?, crypt_fingerprint=?, crypt_created=? WHERE id=? AND crypt_key_enc IS NULL`,
		keyEnc, fingerprint, created, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func nonNilStates(s []api.JobState) []api.JobState {
	if s == nil {
		return []api.JobState{}
	}
	return s
}

// RevokeClient disables a client, renaming it "<name>#revoked-<id>" so its
// name can be reused. The certificate serial and the enabled jobs are kept for
// UnrevokeClient. Revoking a revoked client is errNotFound.
func (s *Store) RevokeClient(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := queryIDs(ctx, tx, `SELECT id FROM jobs WHERE client_id=? AND enabled=1`, id)
	if err != nil {
		return err
	}
	if enabled == nil {
		enabled = []int64{}
	}
	b, _ := json.Marshal(enabled)
	res, err := tx.ExecContext(ctx, `UPDATE clients SET revoked=1, revoked_at=?, revoked_serial=COALESCE(cert_serial,''), revoked_jobs=?,
		cert_serial=NULL, token_secret_enc=NULL, name=name||'#revoked-'||id WHERE id=? AND revoked=0`, now(), string(b), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET enabled=0 WHERE client_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokedClients lists the clients revoked since the given time, newest first.
func (s *Store) RevokedClients(ctx context.Context, since int64) ([]*Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientCols+` FROM clients WHERE revoked=1 AND revoked_at>=? ORDER BY revoked_at DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UnrevokeClient reactivates a revoked client under name with a new PBS token:
// its agent's certificate is accepted again and the jobs enabled at the
// revocation are re-enabled.
func (s *Store) UnrevokeClient(ctx context.Context, c *Client, name, tokenID string, tokenSecretEnc []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE clients SET revoked=0, revoked_at=0, revoked_serial='', revoked_jobs='[]',
		cert_serial=revoked_serial, name=?, token_id=?, token_secret_enc=? WHERE id=? AND revoked=1 AND revoked_serial<>''`,
		name, tokenID, tokenSecretEnc, c.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	for _, j := range c.revokedJobs {
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET enabled=1 WHERE id=? AND client_id=?`, j, c.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- enrollments ----

type Enrollment struct {
	ID         int64  `json:"id"`
	ClientName string `json:"client_name"`
	TargetID   int64  `json:"target_id"`
	Expires    int64  `json:"expires"`
	UsedAt     int64  `json:"used_at"`
	ClientID   int64  `json:"client_id"`
	CreatedAt  int64  `json:"created_at"`
}

// CreateEnrollment stores a new code. commandEnc is the sealed enrollment
// command, kept so it can be shown again until the PC enrolls.
func (s *Store) CreateEnrollment(ctx context.Context, codeHash, name string, targetID int64, ttl time.Duration, commandEnc []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollments(code_hash, client_name, target_id, expires, created_at, command_enc) VALUES(?,?,?,?,?,?)`,
		codeHash, name, targetID, time.Now().Add(ttl).Unix(), now(), commandEnc)
	return err
}

// PendingEnrollmentCommand returns the sealed command of an enrollment that
// hasn't been used yet.
func (s *Store) PendingEnrollmentCommand(ctx context.Context, id int64) ([]byte, error) {
	var enc []byte
	err := s.db.QueryRowContext(ctx, `SELECT command_enc FROM enrollments WHERE id=? AND used_at=0 AND expires>?`, id, now()).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) || err == nil && len(enc) == 0 {
		return nil, errNotFound
	}
	return enc, err
}

// DeleteEnrollment cancels an enrollment that no PC has completed.
func (s *Store) DeleteEnrollment(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM enrollments WHERE id=? AND client_id=0`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *Store) Enrollments(ctx context.Context) ([]Enrollment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, client_name, target_id, expires, used_at, client_id, created_at FROM enrollments
		ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		var e Enrollment
		if err := rows.Scan(&e.ID, &e.ClientName, &e.TargetID, &e.Expires, &e.UsedAt, &e.ClientID, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClaimEnrollment atomically marks a valid code as used.
func (s *Store) ClaimEnrollment(ctx context.Context, codeHash string) (*Enrollment, error) {
	e := &Enrollment{}
	err := s.db.QueryRowContext(ctx, `UPDATE enrollments SET used_at=? WHERE code_hash=? AND used_at=0 AND expires>?
		RETURNING id, client_name, target_id, expires`, now(), codeHash, now()).Scan(&e.ID, &e.ClientName, &e.TargetID, &e.Expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("enrollment code invalid, expired or already used")
	}
	return e, err
}

func (s *Store) CompleteEnrollment(ctx context.Context, id, clientID int64) {
	s.db.ExecContext(ctx, `UPDATE enrollments SET client_id=? WHERE id=?`, clientID, id)
}

func (s *Store) ReleaseEnrollment(ctx context.Context, id int64) {
	s.db.ExecContext(ctx, `UPDATE enrollments SET used_at=0 WHERE id=? AND client_id=0`, id)
}

// ---- setup tokens ----

// SetupToken enrolls any number of PCs until it expires; each PC picks its
// own client name.
type SetupToken struct {
	ID        int64 `json:"id"`
	TargetID  int64 `json:"target_id"`
	Expires   int64 `json:"expires"`
	Uses      int   `json:"uses"`
	CreatedAt int64 `json:"created_at"`
}

// CreateSetupToken stores a new token. tokenEnc is the sealed token string,
// kept so the setup can be downloaded again until it expires.
func (s *Store) CreateSetupToken(ctx context.Context, codeHash string, targetID, expires int64, tokenEnc []byte) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO setup_tokens(code_hash, target_id, expires, token_enc, created_at) VALUES(?,?,?,?,?)`,
		codeHash, targetID, expires, tokenEnc, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetupTokens lists the tokens that haven't expired.
func (s *Store) SetupTokens(ctx context.Context) ([]SetupToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, target_id, expires, uses, created_at FROM setup_tokens WHERE expires>? ORDER BY id DESC`, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SetupToken
	for rows.Next() {
		var t SetupToken
		if err := rows.Scan(&t.ID, &t.TargetID, &t.Expires, &t.Uses, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetupTokenSealed returns the sealed token string of a valid setup token.
func (s *Store) SetupTokenSealed(ctx context.Context, id int64) ([]byte, error) {
	var enc []byte
	err := s.db.QueryRowContext(ctx, `SELECT token_enc FROM setup_tokens WHERE id=? AND expires>?`, id, now()).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return enc, err
}

// SetupTokenByCode returns a valid setup token.
func (s *Store) SetupTokenByCode(ctx context.Context, codeHash string) (*SetupToken, error) {
	t := &SetupToken{}
	err := s.db.QueryRowContext(ctx, `SELECT id, target_id, expires, uses, created_at FROM setup_tokens WHERE code_hash=? AND expires>?`,
		codeHash, now()).Scan(&t.ID, &t.TargetID, &t.Expires, &t.Uses, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return t, err
}

func (s *Store) CountSetupTokenUse(ctx context.Context, id int64) {
	s.db.ExecContext(ctx, `UPDATE setup_tokens SET uses=uses+1 WHERE id=?`, id)
}

// DeleteSetupToken revokes a token (and drops expired ones).
func (s *Store) DeleteSetupToken(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM setup_tokens WHERE id=?`, id)
	if err != nil {
		return err
	}
	s.db.ExecContext(ctx, `DELETE FROM setup_tokens WHERE expires<?`, now())
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// ---- jobs ----

// jobCols reads a member row with its group's definition. Rows without a
// group (jobs of clients revoked before group jobs existed) keep their own.
const jobCols = `j.id, j.client_id, j.group_id, COALESCE(g.name, j.name), COALESCE(g.kind, j.kind), j.backup_id,
	COALESCE(g.sources, j.sources), COALESCE(g.excludes, j.excludes), j.extra_excludes, COALESCE(g.volumes, j.volumes),
	COALESCE(g.use_vss, j.use_vss), COALESCE(g.schedule, j.schedule), COALESCE(g.retention, j.retention), j.enabled,
	COALESCE(g.enabled, 1), j.created_at, COALESCE(g.window_minutes, j.window_minutes), COALESCE(g.catch_up, j.catch_up),
	COALESCE(g.change_detection, j.change_detection), COALESCE(g.encrypt, j.encrypt), COALESCE(g.lock_days, j.lock_days),
	COALESCE(g.spread_minutes, 0), COALESCE(g.daily_cap, 0)`
const jobFrom = ` FROM jobs j LEFT JOIN group_jobs g ON g.id=j.group_id`

func scanJob(sc interface{ Scan(...any) error }) (*Job, error) {
	j := &Job{}
	var src, exc, extra, vol, ret string
	err := sc.Scan(&j.ID, &j.ClientID, &j.GroupID, &j.Name, &j.Kind, &j.BackupID, &src, &exc, &extra, &vol, &j.UseVSS, &j.Schedule, &ret,
		&j.MemberEnabled, &j.GroupEnabled, &j.CreatedAt, &j.WindowMinutes, &j.CatchUp, &j.ChangeDetection, &j.Encrypt, &j.LockDays,
		&j.SpreadMinutes, &j.DailyCap)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	json.Unmarshal([]byte(src), &j.Sources)
	json.Unmarshal([]byte(exc), &j.Excludes)
	json.Unmarshal([]byte(extra), &j.ExtraExcludes)
	json.Unmarshal([]byte(vol), &j.Volumes)
	json.Unmarshal([]byte(ret), &j.Retention)
	j.Sources, j.Excludes, j.ExtraExcludes, j.Volumes = nonNil(j.Sources), nonNil(j.Excludes), nonNil(j.ExtraExcludes), nonNil(j.Volumes)
	j.Enabled = j.MemberEnabled && j.GroupEnabled
	j.StartDelay = startDelay(j.GroupID, j.ClientID, j.SpreadMinutes)
	return j, err
}

// AllExcludes are the group's exclude patterns plus the member's own.
func (j *Job) AllExcludes() []string {
	out := slices.Clone(j.Excludes)
	for _, e := range j.ExtraExcludes {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) queryJobs(ctx context.Context, where string, args ...any) ([]*Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+jobFrom+where+` ORDER BY j.client_id, 4`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Jobs lists the member jobs of a client (all clients for clientID 0).
func (s *Store) Jobs(ctx context.Context, clientID int64) ([]*Job, error) {
	if clientID > 0 {
		return s.queryJobs(ctx, ` WHERE j.client_id=?`, clientID)
	}
	return s.queryJobs(ctx, "")
}

// GroupMembers lists the member jobs of a group job.
func (s *Store) GroupMembers(ctx context.Context, groupID int64) ([]*Job, error) {
	return s.queryJobs(ctx, ` WHERE j.group_id=?`, groupID)
}

func (s *Store) Job(ctx context.Context, id int64) (*Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobCols+jobFrom+` WHERE j.id=?`, id))
}

// SetMemberOverrides changes a member's own settings.
func (s *Store) SetMemberOverrides(ctx context.Context, id int64, enabled bool, extraExcludes []string) error {
	b, _ := json.Marshal(nonNil(extraExcludes))
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET enabled=?, extra_excludes=? WHERE id=?`, enabled, string(b), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// DeleteJob removes a job without a group (see migrateGroupJobs).
func (s *Store) DeleteJob(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := detachJobs(ctx, tx, `id=? AND group_id=0`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id=? AND group_id=0`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- runs ----

const runCols = `r.id, r.job_id, r.client_id, r.kind, r.state, r.trigger, r.restore_spec, r.queued_at, r.started_at, r.finished_at,
	r.last_event_at, r.progress, r.result, r.error, r.snapshot, r.cancel_requested, COALESCE(g.name, j.name, ''), COALESCE(c.name,''), r.scheduled_for, COALESCE(j.group_id, 0)`
const runFrom = ` FROM runs r LEFT JOIN jobs j ON j.id=r.job_id LEFT JOIN group_jobs g ON g.id=j.group_id LEFT JOIN clients c ON c.id=r.client_id`

func scanRun(sc interface{ Scan(...any) error }) (*Run, error) {
	r := &Run{}
	var rs, prog, res string
	err := sc.Scan(&r.ID, &r.JobID, &r.ClientID, &r.Kind, &r.State, &r.Trigger, &rs, &r.QueuedAt, &r.StartedAt, &r.FinishedAt,
		&r.LastEventAt, &prog, &res, &r.Error, &r.Snapshot, &r.CancelRequested, &r.JobName, &r.ClientName, &r.ScheduledFor, &r.GroupID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if rs != "" {
		r.Restore = &api.RestoreSpec{}
		json.Unmarshal([]byte(rs), r.Restore)
	}
	json.Unmarshal([]byte(prog), &r.Progress)
	json.Unmarshal([]byte(res), &r.Result)
	return r, err
}

type RunFilter struct {
	ClientID, JobID, GroupID int64
	Active                   bool
	Limit                    int
}

func (s *Store) Runs(ctx context.Context, f RunFilter) ([]*Run, error) {
	q := `SELECT ` + runCols + runFrom + ` WHERE 1=1`
	var args []any
	if f.ClientID > 0 {
		q += ` AND r.client_id=?`
		args = append(args, f.ClientID)
	}
	if f.JobID > 0 {
		q += ` AND r.job_id=?`
		args = append(args, f.JobID)
	}
	if f.GroupID > 0 {
		q += ` AND j.group_id=?`
		args = append(args, f.GroupID)
	}
	if f.Active {
		q += ` AND r.state IN ('queued','dispatched','running')`
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += fmt.Sprintf(` ORDER BY r.id DESC LIMIT %d`, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Run(ctx context.Context, id int64) (*Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+runFrom+` WHERE r.id=?`, id))
}

// QueueRun creates a queued run unless the job already has an active one.
func (s *Store) QueueRun(ctx context.Context, jobID, clientID int64, kind, trigger string, restore *api.RestoreSpec) (int64, error) {
	if jobID > 0 {
		var n int
		s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE job_id=? AND state IN ('queued','dispatched','running')`, jobID).Scan(&n)
		if n > 0 {
			return 0, errors.New("job already has an active run")
		}
	}
	rs := ""
	if restore != nil {
		b, _ := json.Marshal(restore)
		rs = string(b)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO runs(job_id, client_id, kind, state, trigger, restore_spec, queued_at) VALUES(?,?,?,?,?,?,?)`,
		jobID, clientID, kind, api.RunQueued, trigger, rs, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// RegisterRun records a run the agent started (or skipped) on its own.
// It is idempotent on (client, uuid) so agents can retry safely.
func (s *Store) RegisterRun(ctx context.Context, clientID int64, reg api.RunRegister) (int64, bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM runs WHERE client_id=? AND uuid=?`, clientID, reg.UUID).Scan(&id)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	state, started, finished, errMsg := api.RunRunning, reg.StartedAt, int64(0), ""
	if reg.State == api.RunMissed { // never started: record when it was skipped
		state, started, finished, errMsg = api.RunMissed, 0, reg.StartedAt, reg.Message
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO runs(job_id, client_id, kind, state, trigger, queued_at, started_at, finished_at,
		last_event_at, error, uuid, scheduled_for) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		reg.JobID, clientID, reg.Kind, state, reg.Trigger, reg.StartedAt, started, finished, now(), errMsg, reg.UUID, reg.ScheduledFor)
	if err != nil {
		return 0, false, err
	}
	id, _ = res.LastInsertId()
	return id, true, nil
}

// DispatchQueued marks all queued runs of a client as dispatched and returns them.
func (s *Store) DispatchQueued(ctx context.Context, clientID int64) ([]*Run, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE runs SET state='dispatched', last_event_at=? WHERE client_id=? AND state='queued' RETURNING id`, now(), clientID)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	var out []*Run
	for _, id := range ids {
		r, err := s.Run(ctx, id)
		if err == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Store) CancelRequestedFor(ctx context.Context, clientID int64) []int64 {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM runs WHERE client_id=? AND cancel_requested=1 AND state IN ('dispatched','running')`, clientID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids
}

func (s *Store) RequestCancel(ctx context.Context, id int64) error {
	// Queued runs are canceled immediately; dispatched/running ones are signalled to the agent.
	s.db.ExecContext(ctx, `UPDATE runs SET state='canceled', finished_at=?, error='canceled before start' WHERE id=? AND state='queued'`, now(), id)
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET cancel_requested=1 WHERE id=? AND state IN ('dispatched','running')`, id)
	return err
}

func (s *Store) RunProgress(ctx context.Context, id int64, p api.Progress, at int64) {
	b, _ := json.Marshal(p)
	s.db.ExecContext(ctx, `UPDATE runs SET progress=?, last_event_at=?, state=CASE WHEN state='dispatched' THEN 'running' ELSE state END,
		started_at=CASE WHEN started_at=0 THEN ? ELSE started_at END WHERE id=? AND state IN ('dispatched','running')`, b, at, at, id)
}

func (s *Store) RunStarted(ctx context.Context, id int64, at int64) {
	s.db.ExecContext(ctx, `UPDATE runs SET state='running', last_event_at=?, started_at=CASE WHEN started_at=0 THEN ? ELSE started_at END
		WHERE id=? AND state IN ('dispatched','running')`, at, at, id)
}

// FinishRun stores the final result; returns false if the run was already terminal.
// finishedAt is when the agent finished the run: reports can arrive much later
// (e.g. spooled while the server was offline), so the arrival time is not used.
func (s *Store) FinishRun(ctx context.Context, id int64, r api.Result, finishedAt int64) bool {
	b, _ := json.Marshal(r)
	if finishedAt <= 0 || finishedAt > now()+300 {
		finishedAt = now()
	}
	res, err := s.db.ExecContext(ctx, `UPDATE runs SET state=?, result=?, error=?, snapshot=?, finished_at=?, last_event_at=?,
		started_at=CASE WHEN started_at=0 THEN ? ELSE started_at END WHERE id=? AND state IN ('dispatched','running','lost')`,
		r.State, b, r.Error, r.Snapshot, finishedAt, now(), finishedAt, id)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// MarkLost flags active runs whose agent stopped reporting.
func (s *Store) MarkLost(ctx context.Context, olderThan time.Duration) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE runs SET state='lost', finished_at=?, error='agent stopped reporting'
		WHERE state IN ('dispatched','running') AND last_event_at<? RETURNING id`, now(), time.Now().Add(-olderThan).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, nil
}

// MarkMissingLost fails runs the agent says it isn't running (e.g. after an agent restart).
func (s *Store) MarkMissingLost(ctx context.Context, clientID int64, running []int64) {
	q := `UPDATE runs SET state='lost', finished_at=?, error='agent is no longer running this job'
		WHERE client_id=? AND state IN ('dispatched','running') AND last_event_at<?`
	args := []any{now(), clientID, now() - 120}
	for _, id := range running {
		q += ` AND id<>?`
		args = append(args, id)
	}
	s.db.ExecContext(ctx, q, args...)
}

func (s *Store) AddLogs(ctx context.Context, runID int64, lines []LogLine) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO run_logs(run_id, ts, level, msg) VALUES(?,?,?,?)`)
	if err != nil {
		return err
	}
	for _, l := range lines {
		if _, err := st.ExecContext(ctx, runID, l.Time, l.Level, l.Msg); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Logs(ctx context.Context, runID, afterID int64) ([]LogLine, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, level, msg FROM run_logs WHERE run_id=? AND id>? ORDER BY id LIMIT 5000`, runID, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogLine
	for rows.Next() {
		var l LogLine
		if err := rows.Scan(&l.ID, &l.Time, &l.Level, &l.Msg); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LastSuccess returns the finish time of the latest successful backup per client.
func (s *Store) LastSuccess(ctx context.Context) map[int64]int64 {
	out := map[int64]int64{}
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, MAX(finished_at) FROM runs WHERE state IN ('success','warning') AND kind<>'restore' GROUP BY client_id`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, t int64
		rows.Scan(&id, &t)
		out[id] = t
	}
	return out
}

// SuccessfulBackupTimes lists the snapshot times of a job's successful
// backups taken at or after since, oldest first.
func (s *Store) SuccessfulBackupTimes(ctx context.Context, jobID, since int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT bt FROM (SELECT CAST(json_extract(result, '$.backup_time') AS INTEGER) AS bt
		FROM runs WHERE job_id=? AND state IN ('success','warning') AND kind<>'restore') WHERE bt>=? AND bt>0 ORDER BY bt`, jobID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var t int64
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) PruneHistory(ctx context.Context, keep time.Duration) {
	cut := time.Now().Add(-keep).Unix()
	s.db.ExecContext(ctx, `DELETE FROM run_logs WHERE run_id IN (SELECT id FROM runs WHERE finished_at>0 AND finished_at<?)`, cut)
	s.db.ExecContext(ctx, `DELETE FROM runs WHERE finished_at>0 AND finished_at<?`, cut)
}

// ---- snapshot locks ----

// SnapshotLock is a snapshot the console protected on PBS (immutable backups).
// Only these are unprotected again, never snapshots an operator protected.
type SnapshotLock struct {
	ID         int64
	JobID      int64
	TargetID   int64
	Namespace  string
	BackupType string
	BackupID   string
	BackupTime int64
	// LockDays at protection time; used when the job has been deleted.
	LockDays int
}

func (s *Store) AddSnapshotLock(ctx context.Context, l SnapshotLock) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO snapshot_locks(job_id, target_id, namespace, backup_type, backup_id, backup_time, lock_days)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT DO UPDATE SET job_id=excluded.job_id, lock_days=excluded.lock_days`,
		l.JobID, l.TargetID, l.Namespace, l.BackupType, l.BackupID, l.BackupTime, l.LockDays)
	return err
}

func (s *Store) SnapshotLocks(ctx context.Context) ([]SnapshotLock, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, job_id, target_id, namespace, backup_type, backup_id, backup_time, lock_days
		FROM snapshot_locks ORDER BY backup_time`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotLock
	for rows.Next() {
		var l SnapshotLock
		if err := rows.Scan(&l.ID, &l.JobID, &l.TargetID, &l.Namespace, &l.BackupType, &l.BackupID, &l.BackupTime, &l.LockDays); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSnapshotLock(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM snapshot_locks WHERE id=?`, id)
	return err
}

// ---- settings ----

func (s *Store) Setting(ctx context.Context, key string, out any) error {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(v), out)
}

func (s *Store) SetSetting(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}
