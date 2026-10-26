// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agent implements the Windows backup agent: job execution (file and
// image backups, restores) and the control-plane connection to proxbackup-server.
package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

var ioEOF = io.EOF

// Reporter receives logs and progress for a running job.
type Reporter interface {
	Log(level, msg string)
	Progress(p api.Progress)
}

// job holds per-run state shared by the backup/restore implementations.
type job struct {
	spec  api.JobSpec
	rep   Reporter
	crypt *pbs.CryptConfig // client key, nil if the client has none

	logMu sync.Mutex
	log   bytes.Buffer // uploaded as client.log.blob

	files, dirs, skipped atomic.Int64
	bytesRead, uploaded  atomic.Uint64
	bytesTotal           atomic.Uint64
	phase, archive       atomic.Value
}

func (j *job) logf(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	j.logMu.Lock()
	fmt.Fprintf(&j.log, "%s %-5s %s\n", time.Now().Format(time.RFC3339), strings.ToUpper(level), msg)
	j.logMu.Unlock()
	j.rep.Log(level, msg)
}

func (j *job) progress() api.Progress {
	p := api.Progress{
		Files: j.files.Load(), Dirs: j.dirs.Load(), Skipped: j.skipped.Load(),
		BytesRead: j.bytesRead.Load(), BytesUploaded: j.uploaded.Load(), BytesTotal: j.bytesTotal.Load(),
	}
	p.Phase, _ = j.phase.Load().(string)
	p.CurrentArchive, _ = j.archive.Load().(string)
	return p
}

func (j *job) setPhase(p string) { j.phase.Store(p) }

// Run executes spec and always returns a Result (errors are folded into it).
func Run(ctx context.Context, spec api.JobSpec, rep Reporter) api.Result {
	j := &job{spec: spec, rep: rep}
	j.setPhase("starting")
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rep.Progress(j.progress())
			case <-stop:
				return
			}
		}
	}()
	var res api.Result
	err := j.initCrypt()
	switch {
	case err != nil:
	case spec.Kind == api.KindFiles:
		res, err = j.runFiles(ctx)
	case spec.Kind == api.KindImage:
		res, err = j.runImage(ctx)
	case spec.Kind == api.KindRestore:
		res, err = j.runRestore(ctx)
	default:
		err = fmt.Errorf("unknown job kind %q", spec.Kind)
	}
	close(stop)
	rep.Progress(j.progress())
	res.Files, res.Skipped = j.files.Load(), j.skipped.Load()
	switch {
	case errors.Is(err, context.Canceled):
		res.State, res.Error = api.RunCanceled, "canceled"
	case err != nil:
		res.State, res.Error = api.RunFailed, err.Error()
		j.logf("error", "%v", err)
	case res.Skipped > 0:
		res.State = api.RunWarning
	default:
		res.State = api.RunSuccess
	}
	return res
}

func (j *job) pbsClient() (*pbs.Client, error) {
	t := j.spec.Target
	return pbs.NewClient(pbs.Config{Host: t.Host, Fingerprint: t.Fingerprint, AuthID: t.AuthID, Secret: t.Secret})
}

func (j *job) snapshotRef(t int64) pbs.SnapshotRef {
	return pbs.SnapshotRef{Store: j.spec.Target.Datastore, NS: j.spec.Target.Namespace, Type: "host", ID: j.spec.BackupID, Time: t}
}

// chunkWorkers is how many chunks are hashed, compressed, encrypted and
// uploaded at once: one per CPU, at least 4 (uploads also wait on the
// network) and at most 8 (each holds a few 4 MiB buffers).
func chunkWorkers() int { return min(max(runtime.NumCPU(), 4), 8) }

// startSession opens a backup session, making sure backup-time is newer than
// the group's last snapshot (PBS rejects equal or older times).
func (j *job) startSession(ctx context.Context, c *pbs.Client) (*pbs.BackupSession, error) {
	t := time.Now().Unix()
	s, err := c.StartBackup(ctx, j.snapshotRef(t), pbs.BackupOptions{Crypt: j.backupCrypt(), Compress: true, Concurrency: chunkWorkers(),
		OnUpload: func(n int) { j.uploaded.Add(uint64(n)) }, RateLimit: j.rateLimit()})
	if err != nil {
		return nil, fmt.Errorf("start backup session: %w", err)
	}
	return s, nil
}

// rateLimit applies the job's and the client's bandwidth limits (nil = none).
// The rate is re-evaluated as the backup goes, so a time-of-day window that
// opens or closes mid-run takes effect right away.
func (j *job) rateLimit() *pbs.RateLimiter {
	limits := []api.Bandwidth{j.spec.Bandwidth, j.spec.ClientBandwidth}
	if !limits[0].Limited() && !limits[1].Limited() {
		return nil
	}
	var last atomic.Int64
	last.Store(-1)
	return pbs.NewRateLimiter(func() int64 {
		kbit := int64(api.MinRate(time.Now(), limits...))
		if old := last.Swap(kbit); old != kbit {
			if kbit > 0 {
				j.logf("info", "upload bandwidth limited to %s", formatRate(kbit))
			} else if old >= 0 {
				j.logf("info", "upload bandwidth no longer limited")
			}
		}
		return kbit * 1000 / 8
	})
}

// formatRate renders kbit/s like the console does.
func formatRate(kbit int64) string {
	if kbit >= 1000 {
		return fmt.Sprintf("%g Mbit/s", float64(kbit)/1000)
	}
	return fmt.Sprintf("%d kbit/s", kbit)
}

func (j *job) finishSession(ctx context.Context, s *pbs.BackupSession, res *api.Result) error {
	j.logf("info", "uploading log and manifest")
	j.logMu.Lock()
	logData := bytes.Clone(j.log.Bytes())
	j.logMu.Unlock()
	if err := s.UploadBlob(ctx, "client.log.blob", logData, j.backupCrypt() != nil); err != nil {
		return err
	}
	if err := j.uploadMasterKeyCopy(ctx, s); err != nil {
		return err
	}
	if err := s.Finish(ctx); err != nil {
		return err
	}
	ref := s.Ref()
	res.Snapshot, res.BackupTime = ref.String(), ref.Time
	j.logf("info", "snapshot %s committed", ref)
	return nil
}

func addStats(res *api.Result, st pbs.Stats) {
	res.BytesTotal += st.Size
	res.BytesUploaded += st.UploadedBytes
	res.ChunksNew += st.NewChunks
	res.ChunksReused += st.ReusedChunks
}

// countingReader tracks bytes read for progress reporting.
type countingReader struct {
	r io.Reader
	n *atomic.Uint64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(uint64(n))
	return n, err
}
