package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

func (j *job) runRestore(ctx context.Context) (api.Result, error) {
	var res api.Result
	spec := j.spec.Restore
	if spec == nil || spec.TargetDir == "" || spec.Archive == "" {
		return res, errors.New("restore spec incomplete")
	}
	c, err := j.pbsClient()
	if err != nil {
		return res, err
	}
	ref := pbs.SnapshotRef{Store: j.spec.Target.Datastore, NS: j.spec.Target.Namespace, Type: "host", ID: spec.BackupID, Time: spec.BackupTime}
	j.setPhase("restore")
	j.archive.Store(spec.Archive)
	r, err := c.StartReader(ctx, ref, nil)
	if err != nil {
		return res, fmt.Errorf("open snapshot %s: %w", ref, err)
	}
	defer r.Close()
	m, err := r.Manifest(ctx)
	if err != nil {
		return res, err
	}
	var fi *pbs.FileInfo
	for i := range m.Files {
		if m.Files[i].Filename == spec.Archive {
			fi = &m.Files[i]
		}
	}
	if fi == nil {
		return res, fmt.Errorf("archive %s not in snapshot %s", spec.Archive, ref)
	}
	idx, err := r.Index(ctx, spec.Archive, fi)
	if err != nil {
		return res, err
	}
	j.bytesTotal.Store(idx.Size)
	stream := r.OpenIndex(ctx, idx, 6)
	defer stream.Close()
	src := countingReader{stream, &j.bytesRead}

	if err := os.MkdirAll(spec.TargetDir, 0o755); err != nil {
		return res, err
	}
	j.logf("info", "restoring %s from %s to %s", spec.Archive, ref, spec.TargetDir)

	if strings.HasSuffix(spec.Archive, ".img.fidx") {
		out := filepath.Join(spec.TargetDir, strings.TrimSuffix(spec.Archive, ".fidx"))
		f, err := os.Create(out)
		if err != nil {
			return res, err
		}
		n, err := io.Copy(f, src)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		res.BytesTotal = uint64(n)
		j.logf("info", "wrote image %s (%d bytes)", out, n)
		return res, err
	}
	err = j.restorePxar(ctx, pxar.NewDecoder(src), spec)
	res.BytesTotal = j.bytesRead.Load()
	return res, err
}

type dirMeta struct {
	path string
	md   pxar.Metadata
}

func (j *job) restorePxar(ctx context.Context, dec *pxar.Decoder, spec *api.RestoreSpec) error {
	selected := func(p string) bool {
		if len(spec.Paths) == 0 {
			return true
		}
		for _, s := range spec.Paths {
			s = strings.Trim(strings.ReplaceAll(s, `\`, "/"), "/")
			if s == "" || p == s || strings.HasPrefix(p, s+"/") {
				return true
			}
		}
		return false
	}
	var dirs []dirMeta
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		e, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !selected(e.Path) {
			continue
		}
		target := filepath.Join(spec.TargetDir, filepath.FromSlash(e.Path))
		if !strings.HasPrefix(target, filepath.Clean(spec.TargetDir)) {
			return fmt.Errorf("refusing to restore outside target: %q", e.Path)
		}
		switch e.Kind {
		case pxar.KindDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			j.dirs.Add(1)
			dirs = append(dirs, dirMeta{target, e.Meta})
		case pxar.KindFile:
			if err := j.restoreFile(dec, e, target, spec.Overwrite); err != nil {
				return err
			}
		case pxar.KindSymlink:
			os.MkdirAll(filepath.Dir(target), 0o755)
			if err := os.Symlink(e.Target, target); err != nil {
				j.skipped.Add(1)
				j.logf("warn", "symlink %s: %v", e.Path, err)
				continue
			}
			attrs, has, ctime := fromPxarMeta(e.Meta)
			if err := applyMeta(target, time.Unix(e.Meta.MtimeSecs, int64(e.Meta.MtimeNanos)), attrs, has, ctime); err != nil {
				j.logf("warn", "metadata for %s: %v", e.Path, err)
			}
		default:
			j.logf("info", "skipping %s entry %s", e.Kind, e.Path)
		}
	}
	// Directory timestamps last, deepest first, so file creation doesn't bump them.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		attrs, has, ctime := fromPxarMeta(d.md)
		applyMeta(d.path, time.Unix(d.md.MtimeSecs, int64(d.md.MtimeNanos)), attrs, has, ctime)
	}
	return nil
}

func (j *job) restoreFile(dec *pxar.Decoder, e *pxar.Entry, target, overwrite string) error {
	mtime := time.Unix(e.Meta.MtimeSecs, int64(e.Meta.MtimeNanos))
	if st, err := os.Lstat(target); err == nil {
		switch overwrite {
		case "overwrite":
		case "if-newer":
			if !mtime.After(st.ModTime()) {
				return nil
			}
		default: // "skip"
			j.logf("info", "exists, skipped: %s", e.Path)
			return nil
		}
		// Clear read-only so we can replace it.
		os.Chmod(target, 0o644)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".proxbackup-restore"
	f, err := os.Create(tmp)
	if err != nil {
		j.skipped.Add(1)
		j.logf("warn", "cannot create %s: %v", path.Clean(e.Path), err)
		return nil
	}
	_, err = io.Copy(f, dec.Contents())
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		j.skipped.Add(1)
		j.logf("warn", "cannot replace %s: %v", e.Path, err)
		return nil
	}
	attrs, has, ctime := fromPxarMeta(e.Meta)
	if err := applyMeta(target, mtime, attrs, has, ctime); err != nil {
		j.logf("warn", "metadata for %s: %v", e.Path, err)
	}
	j.files.Add(1)
	return nil
}
