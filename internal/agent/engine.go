// Package agent implements the Windows backup agent: job execution (file and
// image backups, restores) and the control-plane connection to proxbackup-server.
package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

var ioEOF = io.EOF

type readCloser interface {
	io.Reader
	io.Closer
}

// Reporter receives logs and progress for a running job.
type Reporter interface {
	Log(level, msg string)
	Progress(p api.Progress)
}

// job holds per-run state shared by the backup/restore implementations.
type job struct {
	spec api.JobSpec
	rep  Reporter

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
	var err error
	switch spec.Kind {
	case api.KindFiles:
		res, err = j.runFiles(ctx)
	case api.KindImage:
		res, err = j.runImage(ctx)
	case api.KindRestore:
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

// startSession opens a backup session, making sure backup-time is newer than
// the group's last snapshot (PBS rejects equal or older times).
func (j *job) startSession(ctx context.Context, c *pbs.Client) (*pbs.BackupSession, error) {
	t := time.Now().Unix()
	s, err := c.StartBackup(ctx, j.snapshotRef(t), pbs.BackupOptions{Compress: true, Concurrency: 4,
		OnUpload: func(n int) { j.uploaded.Add(uint64(n)) }})
	if err != nil {
		return nil, fmt.Errorf("start backup session: %w", err)
	}
	return s, nil
}

func (j *job) finishSession(ctx context.Context, s *pbs.BackupSession, res *api.Result) error {
	j.logf("info", "uploading log and manifest")
	j.logMu.Lock()
	logData := bytes.Clone(j.log.Bytes())
	j.logMu.Unlock()
	if err := s.UploadBlob(ctx, "client.log.blob", logData, false); err != nil {
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
