// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"slices"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// Group jobs: every backup job is a definition (type, sources, schedule,
// retention…) assigned to any number of clients, chosen one by one and/or by
// client tag. Each member is a row in jobs: it keeps its own id (which the
// agent schedules by), PBS backup group, run history and overrides (enabled,
// extra excludes). Members are materialized by syncGroup whenever the group
// or a client's tags change.

// AllClientsTag as a member tag selects every client.
const AllClientsTag = "*"

// maxSpreadMinutes bounds the start-time spread of a group job.
const maxSpreadMinutes = 24 * 60

var tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)

type GroupJob struct {
	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	BackupID        string          `json:"backup_id"` // "" = per client: <client> or <client>-image
	Sources         []string        `json:"sources"`
	Excludes        []string        `json:"excludes"`
	Volumes         []string        `json:"volumes"`
	UseVSS          bool            `json:"use_vss"`
	Schedule        string          `json:"schedule"`
	WindowMinutes   int             `json:"window_minutes"`
	CatchUp         bool            `json:"catch_up"`
	Retention       pbs.KeepOptions `json:"retention"`
	Enabled         bool            `json:"enabled"`
	ChangeDetection string          `json:"change_detection"`
	Encrypt         bool            `json:"encrypt"`
	LockDays        int             `json:"lock_days"`
	SpreadMinutes   int             `json:"spread_minutes"`
	DailyCap        int             `json:"daily_cap"`
	PreventSleep    bool            `json:"prevent_sleep"`
	WakeToRun       bool            `json:"wake_to_run"`
	// Members: these clients, plus every client with one of Tags.
	Clients   []int64  `json:"clients"`
	Tags      []string `json:"tags"`
	CreatedAt int64    `json:"created_at"`
}

// memberBackupID is the PBS backup-id a member of g on client name uses.
func memberBackupID(g *GroupJob, name string) string {
	switch {
	case g.BackupID != "":
		return g.BackupID
	case g.Kind == api.KindImage:
		return name + "-image"
	}
	return name
}

// startDelay is a member's stable offset within the group's spread.
func startDelay(groupID, clientID int64, spreadMinutes int) int {
	if spreadMinutes <= 0 || groupID == 0 {
		return 0
	}
	h := fnv.New32a()
	fmt.Fprintf(h, "%d/%d", groupID, clientID)
	return int(h.Sum32() % uint32(spreadMinutes*60))
}

const groupCols = `id, name, kind, backup_id, sources, excludes, volumes, use_vss, schedule, window_minutes, catch_up, retention,
	enabled, change_detection, encrypt, lock_days, spread_minutes, member_tags, created_at, daily_cap, prevent_sleep, wake_to_run`

func scanGroupJob(sc interface{ Scan(...any) error }) (*GroupJob, error) {
	g := &GroupJob{}
	var src, exc, vol, ret, tags string
	err := sc.Scan(&g.ID, &g.Name, &g.Kind, &g.BackupID, &src, &exc, &vol, &g.UseVSS, &g.Schedule, &g.WindowMinutes, &g.CatchUp, &ret,
		&g.Enabled, &g.ChangeDetection, &g.Encrypt, &g.LockDays, &g.SpreadMinutes, &tags, &g.CreatedAt, &g.DailyCap, &g.PreventSleep, &g.WakeToRun)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	json.Unmarshal([]byte(src), &g.Sources)
	json.Unmarshal([]byte(exc), &g.Excludes)
	json.Unmarshal([]byte(vol), &g.Volumes)
	json.Unmarshal([]byte(ret), &g.Retention)
	json.Unmarshal([]byte(tags), &g.Tags)
	g.Sources, g.Excludes, g.Volumes, g.Tags = nonNil(g.Sources), nonNil(g.Excludes), nonNil(g.Volumes), nonNil(g.Tags)
	g.Clients = []int64{}
	return g, err
}

// GroupJobs lists all group jobs with their explicit members.
func (s *Store) GroupJobs(ctx context.Context) ([]*GroupJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+groupCols+` FROM group_jobs ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	var out []*GroupJob
	byID := map[int64]*GroupJob{}
	for rows.Next() {
		g, err := scanGroupJob(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, g)
		byID[g.ID] = g
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT group_id, client_id FROM group_job_clients ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var gid, cid int64
		if err := rows.Scan(&gid, &cid); err != nil {
			return nil, err
		}
		if g := byID[gid]; g != nil {
			g.Clients = append(g.Clients, cid)
		}
	}
	return out, rows.Err()
}

func (s *Store) GroupJob(ctx context.Context, id int64) (*GroupJob, error) {
	g, err := scanGroupJob(s.db.QueryRowContext(ctx, `SELECT `+groupCols+` FROM group_jobs WHERE id=?`, id))
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT client_id FROM group_job_clients WHERE group_id=? ORDER BY client_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int64
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		g.Clients = append(g.Clients, cid)
	}
	return g, rows.Err()
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func saveGroupRow(ctx context.Context, db execer, g *GroupJob) error {
	src, _ := json.Marshal(nonNil(g.Sources))
	exc, _ := json.Marshal(nonNil(g.Excludes))
	vol, _ := json.Marshal(nonNil(g.Volumes))
	ret, _ := json.Marshal(g.Retention)
	tags, _ := json.Marshal(nonNil(g.Tags))
	if g.ID == 0 {
		if g.CreatedAt == 0 {
			g.CreatedAt = now()
		}
		res, err := db.ExecContext(ctx, `INSERT INTO group_jobs(name, kind, backup_id, sources, excludes, volumes, use_vss, schedule,
			window_minutes, catch_up, retention, enabled, change_detection, encrypt, lock_days, spread_minutes, member_tags, created_at,
			daily_cap, prevent_sleep, wake_to_run) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			g.Name, g.Kind, g.BackupID, src, exc, vol, g.UseVSS, g.Schedule, g.WindowMinutes, g.CatchUp, ret, g.Enabled,
			g.ChangeDetection, g.Encrypt, g.LockDays, g.SpreadMinutes, tags, g.CreatedAt, g.DailyCap, g.PreventSleep, g.WakeToRun)
		if err != nil {
			return err
		}
		g.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := db.ExecContext(ctx, `UPDATE group_jobs SET name=?, kind=?, backup_id=?, sources=?, excludes=?, volumes=?, use_vss=?,
		schedule=?, window_minutes=?, catch_up=?, retention=?, enabled=?, change_detection=?, encrypt=?, lock_days=?, spread_minutes=?,
		member_tags=?, daily_cap=?, prevent_sleep=?, wake_to_run=? WHERE id=?`,
		g.Name, g.Kind, g.BackupID, src, exc, vol, g.UseVSS, g.Schedule, g.WindowMinutes, g.CatchUp, ret, g.Enabled,
		g.ChangeDetection, g.Encrypt, g.LockDays, g.SpreadMinutes, tags, g.DailyCap, g.PreventSleep, g.WakeToRun, g.ID)
	return err
}

// SaveGroupJob stores the definition and explicit members, then attaches and
// detaches member jobs. It returns the clients whose configuration changed.
func (s *Store) SaveGroupJob(ctx context.Context, g *GroupJob) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := saveGroupRow(ctx, tx, g); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_job_clients WHERE group_id=?`, g.ID); err != nil {
		return nil, err
	}
	for _, cid := range g.Clients {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO group_job_clients(group_id, client_id) VALUES(?,?)`, g.ID, cid); err != nil {
			return nil, err
		}
	}
	affected, err := syncGroup(ctx, tx, g.ID)
	if err != nil {
		return nil, err
	}
	return affected, tx.Commit()
}

// DeleteGroupJob removes a group job and all its member jobs. Snapshots on
// PBS and run history stay. It returns the clients that lost a job.
func (s *Store) DeleteGroupJob(ctx context.Context, id int64) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	affected, err := queryIDs(ctx, tx, `SELECT DISTINCT client_id FROM jobs WHERE group_id=?`, id)
	if err != nil {
		return nil, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM group_jobs WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errNotFound
	}
	if err := detachJobs(ctx, tx, `group_id=?`, id); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE group_id=?`, id); err != nil {
		return nil, err
	}
	return affected, tx.Commit()
}

// RemoveGroupClient drops a client from a group's explicit members. It stays
// a member if one of its tags still selects it.
func (s *Store) RemoveGroupClient(ctx context.Context, groupID, clientID int64) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM group_job_clients WHERE group_id=? AND client_id=?`, groupID, clientID); err != nil {
		return nil, err
	}
	affected, err := syncGroup(ctx, tx, groupID)
	if err != nil {
		return nil, err
	}
	return affected, tx.Commit()
}

// SetClientTags changes a client's tags and re-syncs every group job.
func (s *Store) SetClientTags(ctx context.Context, clientID int64, tags []string) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	b, _ := json.Marshal(nonNil(tags))
	res, err := tx.ExecContext(ctx, `UPDATE clients SET tags=? WHERE id=? AND revoked=0`, string(b), clientID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errNotFound
	}
	affected, err := syncAllGroups(ctx, tx)
	if err != nil {
		return nil, err
	}
	return affected, tx.Commit()
}

// SyncAllGroups re-resolves the members of every group job (e.g. after a
// client enrolled, for groups that select all clients).
func (s *Store) SyncAllGroups(ctx context.Context) ([]int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	affected, err := syncAllGroups(ctx, tx)
	if err != nil {
		return nil, err
	}
	return affected, tx.Commit()
}

func syncAllGroups(ctx context.Context, tx *sql.Tx) ([]int64, error) {
	ids, err := queryIDs(ctx, tx, `SELECT id FROM group_jobs`)
	if err != nil {
		return nil, err
	}
	var affected []int64
	for _, id := range ids {
		a, err := syncGroup(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		affected = appendNew(affected, a...)
	}
	return affected, nil
}

// syncGroup makes the member jobs of a group match its members: explicit
// clients plus clients with a member tag. Members of revoked clients are left
// alone (they are disabled and keep naming their run history). It returns the
// clients whose configuration may have changed.
func syncGroup(ctx context.Context, tx *sql.Tx, groupID int64) ([]int64, error) {
	g, err := scanGroupJob(tx.QueryRowContext(ctx, `SELECT `+groupCols+` FROM group_jobs WHERE id=?`, groupID))
	if err != nil {
		return nil, err
	}
	explicit, err := queryIDs(ctx, tx, `SELECT client_id FROM group_job_clients WHERE group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	type cl struct {
		name string
		tags []string
	}
	clients := map[int64]cl{}
	rows, err := tx.QueryContext(ctx, `SELECT id, name, tags FROM clients WHERE revoked=0`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var name, tags string
		if err := rows.Scan(&id, &name, &tags); err != nil {
			rows.Close()
			return nil, err
		}
		c := cl{name: name}
		json.Unmarshal([]byte(tags), &c.tags)
		clients[id] = c
	}
	rows.Close()
	want := map[int64]bool{}
	for id, c := range clients {
		if slices.Contains(explicit, id) || slices.Contains(g.Tags, AllClientsTag) ||
			slices.ContainsFunc(c.tags, func(t string) bool { return slices.Contains(g.Tags, t) }) {
			want[id] = true
		}
	}

	var affected []int64
	have := map[int64]int64{} // client → member job
	rows, err = tx.QueryContext(ctx, `SELECT id, client_id FROM jobs WHERE group_id=?`, groupID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var jid, cid int64
		if err := rows.Scan(&jid, &cid); err != nil {
			rows.Close()
			return nil, err
		}
		have[cid] = jid
	}
	rows.Close()
	for cid, jid := range have {
		_, active := clients[cid]
		if !active {
			continue // revoked
		}
		affected = appendNew(affected, cid)
		if !want[cid] {
			if err := detachJobs(ctx, tx, `id=?`, jid); err != nil {
				return nil, err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE id=?`, jid); err != nil {
				return nil, err
			}
			continue
		}
		// Keep the legacy columns readable and the backup group current.
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET name=?, kind=?, backup_id=? WHERE id=?`,
			g.Name, g.Kind, memberBackupID(g, clients[cid].name), jid); err != nil {
			return nil, err
		}
	}
	for cid := range want {
		if _, ok := have[cid]; ok {
			continue
		}
		affected = appendNew(affected, cid)
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(client_id, group_id, name, kind, backup_id, enabled, created_at) VALUES(?,?,?,?,?,1,?)`,
			cid, groupID, g.Name, g.Kind, memberBackupID(g, clients[cid].name), now()); err != nil {
			return nil, err
		}
	}
	slices.Sort(affected)
	return affected, nil
}

// migrateGroupJobs turns every job that has no group yet into a group job
// with that job's client as its only member, keeping the job's id (agents
// schedule by it), backup group, history and locks. Jobs of revoked clients
// stay as they are.
func (s *Store) migrateGroupJobs() error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT j.id, j.client_id, c.name, j.name, j.kind, j.backup_id, j.sources, j.excludes, j.volumes,
		j.use_vss, j.schedule, j.window_minutes, j.catch_up, j.retention, j.enabled, j.change_detection, j.encrypt, j.lock_days, j.created_at
		FROM jobs j JOIN clients c ON c.id=j.client_id WHERE j.group_id=0 AND c.revoked=0 ORDER BY j.id`)
	if err != nil {
		return err
	}
	type old struct {
		g                 GroupJob
		jobID, clientID   int64
		clientName, bid   string
		src, exc, vol, rt string
	}
	var olds []old
	for rows.Next() {
		var o old
		g := &o.g
		if err := rows.Scan(&o.jobID, &o.clientID, &o.clientName, &g.Name, &g.Kind, &o.bid, &o.src, &o.exc, &o.vol, &g.UseVSS, &g.Schedule,
			&g.WindowMinutes, &g.CatchUp, &o.rt, &g.Enabled, &g.ChangeDetection, &g.Encrypt, &g.LockDays, &g.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		olds = append(olds, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, o := range olds {
		g := &o.g
		g.PreventSleep, g.WakeToRun = true, true
		json.Unmarshal([]byte(o.src), &g.Sources)
		json.Unmarshal([]byte(o.exc), &g.Excludes)
		json.Unmarshal([]byte(o.vol), &g.Volumes)
		json.Unmarshal([]byte(o.rt), &g.Retention)
		if o.bid != memberBackupID(g, o.clientName) {
			g.BackupID = o.bid // a custom backup group
		}
		if err := saveGroupRow(ctx, tx, g); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO group_job_clients(group_id, client_id) VALUES(?,?)`, g.ID, o.clientID); err != nil {
			return err
		}
		// The definition's enabled flag moved to the group; the member stays on.
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET group_id=?, enabled=1 WHERE id=?`, g.ID, o.jobID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LastRuns returns the newest backup run of every member job.
func (s *Store) LastRuns(ctx context.Context) (map[int64]*Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+runFrom+` WHERE r.id IN (SELECT MAX(id) FROM runs WHERE job_id>0 AND kind<>'restore' GROUP BY job_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out[r.JobID] = r
	}
	return out, rows.Err()
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func queryIDs(ctx context.Context, db querier, q string, args ...any) ([]int64, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func appendNew(s []int64, ids ...int64) []int64 {
	for _, id := range ids {
		if !slices.Contains(s, id) {
			s = append(s, id)
		}
	}
	return s
}
