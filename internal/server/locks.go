// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"errors"
	"time"

	"proxbackup/pkg/pbs"
)

// Immutable backups, lock window: every new snapshot of a job with a lock
// period is marked protected on PBS, and releaseLocks unprotects it once it is
// older than the job's current lock period. PBS refuses to prune or forget
// protected snapshots, which guards against a compromised PC and operator
// mistakes (not against a compromised console: its Admin token can unprotect).

// maxLockDays bounds the per-job lock period.
const maxLockDays = 3650

func (s *Server) lockSnapshot(ctx context.Context, pc *pbs.Client, t *Target, c *Client, j *Job, backupTime int64) error {
	if err := pc.SetProtected(ctx, t.Datastore, c.Namespace, "host", j.BackupID, backupTime, true); err != nil {
		return err
	}
	return s.store.AddSnapshotLock(ctx, SnapshotLock{JobID: j.ID, TargetID: t.ID, Namespace: c.Namespace, BackupType: "host",
		BackupID: j.BackupID, BackupTime: backupTime, LockDays: j.LockDays})
}

// lockExpired reports whether l's lock period is over at now. The job's
// current lock period applies (shortening it releases older snapshots);
// for deleted jobs, the one recorded at protection time.
func lockExpired(l SnapshotLock, j *Job, now time.Time) bool {
	days := l.LockDays
	if j != nil {
		days = j.LockDays
	}
	return now.Unix() >= l.BackupTime+int64(days)*86400
}

// releaseLocks unprotects console-locked snapshots whose lock period is over.
// Runs daily from housekeeping.
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
		if j, err := s.store.Job(ctx, l.JobID); err == nil {
			job = j
		} else if !errors.Is(err, errNotFound) {
			continue
		}
		if !lockExpired(l, job, time.Now()) {
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
		err := pc.SetProtected(ctx, t.Datastore, l.Namespace, l.BackupType, l.BackupID, l.BackupTime, false)
		if err != nil && !pbs.IsNotFound(err) { // a vanished snapshot has nothing left to release
			s.log.Error("unprotect snapshot", "target", t.Name, "ns", l.Namespace, "group", l.BackupType+"/"+l.BackupID,
				"time", l.BackupTime, "err", err)
			continue // retried tomorrow
		}
		s.store.DeleteSnapshotLock(ctx, l.ID)
		released++
	}
	if released > 0 {
		s.log.Info("snapshot locks released", "count", released)
	}
}
