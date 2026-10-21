// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"proxbackup/internal/schedule"
	"proxbackup/pkg/pbs"
)

// Tamper-resistant retention. A compromised PC can upload as many snapshots
// as it likes with its DatastoreBackup token (and report runs for them), so
// nothing the agent does may decide which snapshots are pruned:
//
//   - retention runs on the console's own daily schedule, never after a run;
//   - only the first dailyCap snapshots of a job per day (console time) are
//     locked and count for the keep-* buckets, later ones are pruned;
//   - console-locked snapshots (see locks.go) count like unprotected ones and
//     are only unprotected when retention removes them.
//
// Hitting the cap is a ransomware signal: it is logged and notified.

// maxDailyCap bounds the per-job backups per day.
const maxDailyCap = 100

// capSlack is what an automatic cap allows on top of the scheduled runs, for
// manual runs and catch-ups.
const capSlack = 3

// dailyCap is the number of j's backups per day that are locked and count
// for retention: the job's own setting, or the busiest day of its schedule
// in the coming week plus capSlack.
func dailyCap(j *Job, now time.Time) int {
	if j.DailyCap > 0 {
		return j.DailyCap
	}
	busiest := 1
	if sch, err := schedule.Parse(j.Schedule); j.Schedule != "" && err == nil {
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		for d := 0; d < 7; d++ {
			start, end := day.AddDate(0, 0, d), day.AddDate(0, 0, d+1)
			n := 0
			for t := sch.Next(start.Add(-time.Second)); !t.IsZero() && t.Before(end) && n < maxDailyCap; t = sch.Next(t) {
				n++
			}
			busiest = max(busiest, n)
		}
	}
	return min(busiest+capSlack, maxDailyCap)
}

func dayKey(t int64, loc *time.Location) string {
	return time.Unix(t, 0).In(loc).Format(time.DateOnly)
}

// overDailyCap reports whether the backup at backupTime is past the cap of its
// day, given the backup times of the job's successful runs.
func overDailyCap(backupTime int64, successes []int64, limit int, loc *time.Location) bool {
	day, n := dayKey(backupTime, loc), 0
	for _, t := range successes {
		if t <= backupTime && dayKey(t, loc) == day {
			n++
		}
	}
	return n > limit
}

type pruneMark int

const (
	markNone pruneMark = iota
	markKeep
	markKeepPartial
	markProtected
	markRemove
	markOverCap
)

// pruneSelection is the outcome of selectPrune.
type pruneSelection struct {
	Remove  []pbs.SnapshotInfo // to forget, including OverCap
	OverCap map[string]int     // day -> snapshots past the cap
	Kept    int
}

// selectPrune applies keep to a group like PBS prune does (same buckets, in
// local time, protected snapshots kept on top), except that snapshots past
// the first limit of their day don't count and are removed.
func selectPrune(snaps []pbs.SnapshotInfo, keep pbs.KeepOptions, limit int, loc *time.Location) pruneSelection {
	list := slices.Clone(snaps)
	slices.SortFunc(list, func(a, b pbs.SnapshotInfo) int { return int(b.BackupTime - a.BackupTime) }) // newest first
	mark := make([]pruneMark, len(list))

	// Unfinished backups: PBS keeps the newest one (it may still be running).
	for i, s := range list {
		if !s.Finished() {
			mark[i] = markRemove
			if i == 0 {
				mark[i] = markKeepPartial
			}
		}
	}
	// The cap counts every finished snapshot of the day, oldest first.
	perDay := map[string]int{}
	overCap := map[string]int{}
	for i := len(list) - 1; i >= 0; i-- {
		s := list[i]
		if !s.Finished() {
			continue
		}
		day := dayKey(s.BackupTime, loc)
		perDay[day]++
		if perDay[day] > limit && mark[i] == markNone && !s.Protected {
			mark[i] = markOverCap
			overCap[day]++
		}
	}

	at := func(s pbs.SnapshotInfo) time.Time { return time.Unix(s.BackupTime, 0).In(loc) }
	selectBy := func(n int, id func(time.Time) string) {
		if n <= 0 {
			return
		}
		included, already := map[string]bool{}, map[string]bool{}
		for i, s := range list {
			if mark[i] == markKeep {
				already[id(at(s))] = true
			}
		}
		for i, s := range list {
			if mark[i] != markNone {
				continue
			}
			if s.Protected {
				mark[i] = markProtected
				continue
			}
			sel := id(at(s))
			if already[sel] {
				continue
			}
			if included[sel] {
				mark[i] = markRemove
				continue
			}
			if len(included) >= n {
				break
			}
			included[sel] = true
			mark[i] = markKeep
		}
	}
	selectBy(keep.Last, func(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) })
	selectBy(keep.Hourly, func(t time.Time) string { return t.Format("2006/01/02/15") })
	selectBy(keep.Daily, func(t time.Time) string { return t.Format("2006/01/02") })
	selectBy(keep.Weekly, func(t time.Time) string {
		y, w := t.ISOWeek()
		return fmt.Sprintf("%d/%02d", y, w)
	})
	selectBy(keep.Monthly, func(t time.Time) string { return t.Format("2006/01") })
	selectBy(keep.Yearly, func(t time.Time) string { return t.Format("2006") })

	sel := pruneSelection{OverCap: overCap}
	for i, s := range list {
		switch {
		case s.Protected || mark[i] == markKeep || mark[i] == markKeepPartial || mark[i] == markProtected:
			sel.Kept++
		default: // markRemove, markOverCap, or outside every bucket
			sel.Remove = append(sel.Remove, s)
		}
	}
	return sel
}

// applyRetention prunes every job's backup group once a day (housekeeping).
func (s *Server) applyRetention(ctx context.Context) {
	jobs, err := s.store.Jobs(ctx, 0)
	if err != nil {
		s.log.Error("retention: list jobs", "err", err)
		return
	}
	clients := map[int64]*pbs.Client{}
	for _, j := range jobs {
		if j.Retention.IsZero() {
			continue
		}
		c, err := s.store.Client(ctx, j.ClientID)
		if err != nil || c.Revoked { // revoked clients' backups stay for recovery
			continue
		}
		t, err := s.store.Target(ctx, c.TargetID)
		if err != nil {
			continue
		}
		pc := clients[t.ID]
		if pc == nil {
			if pc, err = s.adminClient(t); err != nil {
				s.log.Error("retention", "target", t.Name, "err", err)
				continue
			}
			clients[t.ID] = pc
		}
		if err := s.pruneJob(ctx, pc, t, c, j, time.Now()); err != nil {
			s.log.Error("retention failed", "client", c.Name, "job", j.Name, "err", err)
		}
	}
}

// pruneJob applies j's retention to its backup group in c's namespace.
func (s *Server) pruneJob(ctx context.Context, pc *pbs.Client, t *Target, c *Client, j *Job, now time.Time) error {
	snaps, err := pc.ListSnapshots(ctx, t.Datastore, c.Namespace, "host", j.BackupID)
	if err != nil {
		if pbs.IsNotFound(err) {
			return nil // no backup yet
		}
		return err
	}
	// Console locks last as long as retention keeps the snapshot: they don't
	// keep it on top of the counts, and are released when it is removed.
	locks, err := s.store.GroupSnapshotLocks(ctx, t.ID, c.Namespace, "host", j.BackupID)
	if err != nil {
		return err
	}
	locked := map[int64]SnapshotLock{}
	for _, l := range locks {
		locked[l.BackupTime] = l
	}
	view := slices.Clone(snaps)
	for i := range view {
		if _, ok := locked[view[i].BackupTime]; ok {
			view[i].Protected = false
		}
	}
	limit := dailyCap(j, now)
	sel := selectPrune(view, j.Retention, limit, time.Local)
	removed := 0
	var errs []error
	for _, sn := range sel.Remove {
		if l, ok := locked[sn.BackupTime]; ok {
			if err := s.unlockSnapshot(ctx, pc, t, l); err != nil {
				errs = append(errs, fmt.Errorf("unprotect %d: %w", sn.BackupTime, err))
				continue
			}
		}
		if err := pc.ForgetSnapshot(ctx, t.Datastore, c.Namespace, "host", j.BackupID, sn.BackupTime); err != nil && !pbs.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("forget %d: %w", sn.BackupTime, err))
			continue
		}
		removed++
	}
	for day, n := range sel.OverCap {
		s.dailyCapHit(ctx, c, j, day, limit, n, "retention removed them")
	}
	if removed > 0 || len(errs) > 0 {
		s.log.Info("retention applied", "client", c.Name, "job", j.Name, "group", "host/"+j.BackupID,
			"kept", sel.Kept, "pruned", removed, "failed", len(errs))
	}
	return errors.Join(errs...)
}

// dailyCapHit logs and notifies (once per job and day) that j had more
// backups on day than its cap allows.
func (s *Server) dailyCapHit(ctx context.Context, c *Client, j *Job, day string, limit, extra int, what string) {
	s.log.Warn("daily backup cap exceeded", "client", c.Name, "job", j.Name, "day", day, "cap", limit, "extra", extra)
	key := fmt.Sprintf("%d/%s", j.ID, day)
	s.capMu.Lock()
	if s.capNotified == nil || len(s.capNotified) > 1000 {
		s.capNotified = map[string]bool{}
	}
	seen := s.capNotified[key]
	s.capNotified[key] = true
	s.capMu.Unlock()
	if !seen {
		s.notify.DailyCap(ctx, c, j, day, limit, what)
	}
}
