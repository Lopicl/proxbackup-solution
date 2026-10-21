// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"

	"proxbackup/pkg/pbs"
)

// Immutable backups: every new snapshot of a job with Lock is marked
// protected on PBS and stays protected for as long as the job's retention
// keeps it. The daily retention pass (pruneJob) unprotects a console-locked
// snapshot only right before it forgets it; with no retention, snapshots stay
// protected. PBS refuses to prune or forget protected snapshots, which guards
// against a compromised PC and operator mistakes (not against a compromised
// console: its Admin token can unprotect).

func (s *Server) lockSnapshot(ctx context.Context, pc *pbs.Client, t *Target, c *Client, j *Job, backupTime int64) error {
	if err := pc.SetProtected(ctx, t.Datastore, c.Namespace, "host", j.BackupID, backupTime, true); err != nil {
		return err
	}
	return s.store.AddSnapshotLock(ctx, SnapshotLock{JobID: j.ID, TargetID: t.ID, Namespace: c.Namespace, BackupType: "host",
		BackupID: j.BackupID, BackupTime: backupTime})
}

// lockOrphaned reports whether l is no longer under the retention of a job
// with Lock: its job was deleted or turned locking off, or the job's backup
// group moved (another target, namespace or backup id). c is j's client.
func lockOrphaned(l SnapshotLock, j *Job, c *Client) bool {
	if j == nil || !j.Lock {
		return true
	}
	if c.Revoked { // revoked clients' backups stay for recovery
		return false
	}
	return l.TargetID != c.TargetID || l.Namespace != c.Namespace || l.BackupType != "host" || l.BackupID != j.BackupID
}

// releaseLocks unprotects console-locked snapshots that no job's retention
// covers any more (see lockOrphaned). Runs daily from housekeeping, before
// applyRetention, which releases the others as it prunes them.
func (s *Server) releaseLocks(ctx context.Context) {
	locks, err := s.store.SnapshotLocks(ctx)
	if err != nil {
		s.log.Error("list snapshot locks", "err", err)
		return
	}
	clients := map[int64]*pbs.Client{}
	targets := map[int64]*Target{}
	released := 0
	for _, l := range locks {
		var job *Job
		var client *Client
		if j, err := s.store.Job(ctx, l.JobID); err == nil {
			if client, err = s.store.Client(ctx, j.ClientID); err == nil {
				job = j
			} else if !errors.Is(err, errNotFound) {
				continue
			}
		} else if !errors.Is(err, errNotFound) {
			continue
		}
		if !lockOrphaned(l, job, client) {
			continue
		}
		pc, t := clients[l.TargetID], targets[l.TargetID]
		if pc == nil {
			if t, err = s.store.Target(ctx, l.TargetID); err != nil {
				if errors.Is(err, errNotFound) {
					s.store.DeleteSnapshotLock(ctx, l.ID) // target removed: nothing to release
				}
				continue
			}
			if pc, err = s.adminClient(t); err != nil {
				s.log.Error("release snapshot locks", "target", t.Name, "err", err)
				continue
			}
			clients[l.TargetID], targets[l.TargetID] = pc, t
		}
		if err := s.unlockSnapshot(ctx, pc, t, l); err != nil {
			continue // retried tomorrow
		}
		released++
	}
	if released > 0 {
		s.log.Info("snapshot locks released", "count", released)
	}
}

// unlockSnapshot unprotects l's snapshot on t and forgets the lock.
func (s *Server) unlockSnapshot(ctx context.Context, pc *pbs.Client, t *Target, l SnapshotLock) error {
	err := pc.SetProtected(ctx, t.Datastore, l.Namespace, l.BackupType, l.BackupID, l.BackupTime, false)
	if err != nil && !pbs.IsNotFound(err) { // a vanished snapshot has nothing left to release
		s.log.Error("unprotect snapshot", "target", t.Name, "ns", l.Namespace, "group", l.BackupType+"/"+l.BackupID,
			"time", l.BackupTime, "err", err)
		return err
	}
	return s.store.DeleteSnapshotLock(ctx, l.ID)
}
