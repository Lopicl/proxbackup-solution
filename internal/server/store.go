// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	_, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS runs_uuid ON runs(client_id, uuid) WHERE uuid<>''`)
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
	TokenID      string `json:"token_id"`
	LastSeen     int64  `json:"last_seen"`
	Revoked      bool   `json:"revoked"`
	CreatedAt    int64  `json:"created_at"`
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
	// AgentUpdate is the version the agent can be updated to (the console's), and
	// AgentUpdatePushed whether an admin pushed it and the agent hasn't fetched it yet.
	AgentUpdate       string `json:"agent_update,omitempty"`
	AgentUpdatePushed bool   `json:"agent_update_pushed"`

	tokenSecretEnc []byte
}

type Job struct {
	ID            int64           `json:"id"`
	ClientID      int64           `json:"client_id"`
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
	Enabled       bool            `json:"enabled"`
	CreatedAt     int64           `json:"created_at"`
	// File jobs: metadata, data or legacy (see api.JobSpec.ChangeDetection).
	ChangeDetection string `json:"change_detection"`
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
	config_rev, schedule_state, time_zone`

func scanClient(sc interface{ Scan(...any) error }) (*Client, error) {
	c := &Client{}
	var sched string
	err := sc.Scan(&c.ID, &c.Name, &c.Hostname, &c.OS, &c.AgentVersion, &c.CertSerial, &c.TargetID, &c.Namespace, &c.TokenID,
		&c.tokenSecretEnc, &c.LastSeen, &c.Revoked, &c.CreatedAt, &c.ConfigRev, &sched, &c.TimeZone)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNotFound
	}
	json.Unmarshal([]byte(sched), &c.ScheduleState)
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

func (s *Store) TouchClient(ctx context.Context, id int64, req api.PollRequest) {
	sched, _ := json.Marshal(nonNilStates(req.Schedule))
	s.db.ExecContext(ctx, `UPDATE clients SET last_seen=?, hostname=?, os=?, agent_version=?, config_rev=?, schedule_state=?, time_zone=?
		WHERE id=?`, now(), req.Hostname, req.OS, req.AgentVersion, req.ConfigRev, sched, req.TimeZone, id)
}

func nonNilStates(s []api.JobState) []api.JobState {
	if s == nil {
		return []api.JobState{}
	}
	return s
}

func (s *Store) RevokeClient(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE clients SET revoked=1, cert_serial=NULL, token_secret_enc=NULL, name=name||'#revoked-'||id WHERE id=?`, id)
	if err == nil {
		s.db.ExecContext(ctx, `UPDATE jobs SET enabled=0 WHERE client_id=?`, id)
	}
	return err
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

// ---- jobs ----

const jobCols = `id, client_id, name, kind, backup_id, sources, excludes, volumes, use_vss, schedule, retention, enabled, created_at, window_minutes, catch_up, change_detection`

func scanJob(sc interface{ Scan(...any) error }) (*Job, error) {
	j := &Job{}
	var src, exc, vol, ret string
	err := sc.Scan(&j.ID, &j.ClientID, &j.Name, &j.Kind, &j.BackupID, &src, &exc, &vol, &j.UseVSS, &j.Schedule, &ret, &j.Enabled, &j.CreatedAt,
		&j.WindowMinutes, &j.CatchUp, &j.ChangeDetection)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	json.Unmarshal([]byte(src), &j.Sources)
	json.Unmarshal([]byte(exc), &j.Excludes)
	json.Unmarshal([]byte(vol), &j.Volumes)
	json.Unmarshal([]byte(ret), &j.Retention)
	return j, err
}

func (s *Store) Jobs(ctx context.Context, clientID int64) ([]*Job, error) {
	q := `SELECT ` + jobCols + ` FROM jobs`
	var args []any
	if clientID > 0 {
		q += ` WHERE client_id=?`
		args = append(args, clientID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY client_id, name`, args...)
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

func (s *Store) Job(ctx context.Context, id int64) (*Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=?`, id))
}

func (s *Store) SaveJob(ctx context.Context, j *Job) error {
	src, _ := json.Marshal(nonNil(j.Sources))
	exc, _ := json.Marshal(nonNil(j.Excludes))
	vol, _ := json.Marshal(nonNil(j.Volumes))
	ret, _ := json.Marshal(j.Retention)
	if j.ID == 0 {
		j.CreatedAt = now()
		res, err := s.db.ExecContext(ctx, `INSERT INTO jobs(client_id, name, kind, backup_id, sources, excludes, volumes, use_vss, schedule, retention,
			enabled, created_at, window_minutes, catch_up, change_detection) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			j.ClientID, j.Name, j.Kind, j.BackupID, src, exc, vol, j.UseVSS, j.Schedule, ret, j.Enabled, j.CreatedAt, j.WindowMinutes, j.CatchUp,
			j.ChangeDetection)
		if err != nil {
			return err
		}
		j.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET name=?, kind=?, backup_id=?, sources=?, excludes=?, volumes=?, use_vss=?, schedule=?,
		retention=?, enabled=?, window_minutes=?, catch_up=?, change_detection=? WHERE id=?`,
		j.Name, j.Kind, j.BackupID, src, exc, vol, j.UseVSS, j.Schedule, ret, j.Enabled, j.WindowMinutes, j.CatchUp, j.ChangeDetection, j.ID)
	return err
}

func (s *Store) DeleteJob(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, id)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- runs ----

const runCols = `r.id, r.job_id, r.client_id, r.kind, r.state, r.trigger, r.restore_spec, r.queued_at, r.started_at, r.finished_at,
	r.last_event_at, r.progress, r.result, r.error, r.snapshot, r.cancel_requested, COALESCE(j.name,''), COALESCE(c.name,''), r.scheduled_for`
const runFrom = ` FROM runs r LEFT JOIN jobs j ON j.id=r.job_id LEFT JOIN clients c ON c.id=r.client_id`

func scanRun(sc interface{ Scan(...any) error }) (*Run, error) {
	r := &Run{}
	var rs, prog, res string
	err := sc.Scan(&r.ID, &r.JobID, &r.ClientID, &r.Kind, &r.State, &r.Trigger, &rs, &r.QueuedAt, &r.StartedAt, &r.FinishedAt,
		&r.LastEventAt, &prog, &res, &r.Error, &r.Snapshot, &r.CancelRequested, &r.JobName, &r.ClientName, &r.ScheduledFor)
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
	ClientID, JobID int64
	Active          bool
	Limit           int
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

func (s *Store) PruneHistory(ctx context.Context, keep time.Duration) {
	cut := time.Now().Add(-keep).Unix()
	s.db.ExecContext(ctx, `DELETE FROM run_logs WHERE run_id IN (SELECT id FROM runs WHERE finished_at>0 AND finished_at<?)`, cut)
	s.db.ExecContext(ctx, `DELETE FROM runs WHERE finished_at>0 AND finished_at<?`, cut)
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
