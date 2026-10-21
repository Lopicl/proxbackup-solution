// SPDX-License-Identifier: AGPL-3.0-or-later

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
	// A split archive is restored through its metadata archive.
	archive, payload := spec.Archive, ""
	if label, ok := strings.CutSuffix(archive, ".ppxar.didx"); ok {
		archive = label + ".mpxar.didx"
	}
	if label, ok := strings.CutSuffix(archive, ".mpxar.didx"); ok {
		_, payload = splitNames(label)
	}
	j.archive.Store(archive)
	r, err := c.StartReader(ctx, ref, j.crypt)
	if err != nil {
		return res, fmt.Errorf("open snapshot %s: %w", ref, err)
	}
	defer r.Close()
	m, err := r.Manifest(ctx)
	if err != nil {
		return res, err
	}
	if err := j.checkRestoreKey(m, ref); err != nil {
		return res, err
	}
	open := func(name string) (*pbs.Index, error) {
		for i := range m.Files {
			if m.Files[i].Filename == name {
				return r.Index(ctx, name, &m.Files[i])
			}
		}
		return nil, fmt.Errorf("archive %s not in snapshot %s", name, ref)
	}
	idx, err := open(archive)
	if err != nil {
		return res, err
	}
	if strings.HasSuffix(archive, ".img.fidx") && len(spec.Paths) > 0 {
		return j.restoreImageFiles(ctx, r, idx, spec)
	}
	j.bytesTotal.Store(idx.Size)
	stream := r.OpenIndex(ctx, idx, 6)
	defer stream.Close()
	src := countingReader{stream, &j.bytesRead}
	dec := pxar.NewDecoder(src)
	if payload != "" {
		pidx, err := open(payload)
		if err != nil {
			return res, err
		}
		j.bytesTotal.Add(pidx.Size)
		pstream := r.OpenIndex(ctx, pidx, 6)
		defer pstream.Close()
		dec = pxar.NewSplitDecoder(src, countingReader{pstream, &j.bytesRead})
	}

	if err := os.MkdirAll(spec.TargetDir, 0o755); err != nil {
		return res, err
	}
	j.logf("info", "restoring %s from %s to %s", archive, ref, spec.TargetDir)

	if strings.HasSuffix(archive, ".img.fidx") {
		out := filepath.Join(spec.TargetDir, strings.TrimSuffix(archive, ".fidx"))
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
	err = j.restorePxar(ctx, dec, spec)
	res.BytesTotal = j.bytesRead.Load()
	return res, err
}

// withinDir reports whether the cleaned path target is root or below it. A
// drive root like `C:\` already ends in a separator.
func withinDir(root, target string) bool {
	if target == root {
		return true
	}
	if !strings.HasSuffix(root, string(filepath.Separator)) {
		root += string(filepath.Separator)
	}
	return strings.HasPrefix(target, root)
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
	enableRestorePrivilege()
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
		if !withinDir(filepath.Clean(spec.TargetDir), target) {
			return fmt.Errorf("refusing to restore outside target: %q", e.Path)
		}
		switch e.Kind {
		case pxar.KindDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			j.dirs.Add(1)
			dirs = append(dirs, dirMeta{target, e.Meta})
			// The archive root is the target folder itself: it keeps its own
			// permissions and streams.
			if e.Path != "" {
				if err := writeStreams(target, ntFromPxar(e.Meta)); err != nil {
					j.logf("warn", "metadata for %s: %v", e.Path, err)
				}
			}
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
	// Directory timestamps and permissions last, deepest first, so file
	// creation doesn't bump them and the permissions can't get in the way.
	root := filepath.Clean(spec.TargetDir)
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		attrs, has, ctime := fromPxarMeta(d.md)
		applyMeta(d.path, time.Unix(d.md.MtimeSecs, int64(d.md.MtimeNanos)), attrs, has, ctime)
		if d.path != root {
			if err := applySecurity(d.path, ntFromPxar(d.md)); err != nil {
				j.logf("warn", "metadata for %s: %v", d.path, err)
			}
		}
	}
	return nil
}

func (j *job) restoreFile(dec *pxar.Decoder, e *pxar.Entry, target, overwrite string) error {
	attrs, has, ctime := fromPxarMeta(e.Meta)
	_, err := j.writeRestored(e.Path, target, overwrite, dec.Contents(),
		time.Unix(e.Meta.MtimeSecs, int64(e.Meta.MtimeNanos)), attrs, has, ctime, ntFromPxar(e.Meta))
	return err
}

// writeRestored writes one restored file through a temporary name and applies
// its metadata: streams first (writing them bumps the mtime), then
// timestamps and attributes, then permissions. It reports whether the file was written; existing files are
// kept according to overwrite, and unwritable targets are skipped with a warning.
func (j *job) writeRestored(rel, target, overwrite string, src io.Reader, mtime time.Time, attrs uint32, hasAttrs bool, ctime time.Time, nt ntExtras) (bool, error) {
	if st, err := os.Lstat(target); err == nil {
		switch overwrite {
		case "overwrite":
		case "if-newer":
			if !mtime.After(st.ModTime()) {
				return false, nil
			}
		default: // "skip"
			j.logf("info", "exists, skipped: %s", rel)
			return false, nil
		}
		// Clear read-only so we can replace it.
		os.Chmod(target, 0o644)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return false, err
	}
	tmp := target + ".proxbackup-restore"
	f, err := os.Create(tmp)
	if err != nil {
		j.skipped.Add(1)
		j.logf("warn", "cannot create %s: %v", path.Clean(rel), err)
		return false, nil
	}
	_, err = io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return false, fmt.Errorf("%s: %w", rel, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		j.skipped.Add(1)
		j.logf("warn", "cannot replace %s: %v", rel, err)
		return false, nil
	}
	if err := writeStreams(target, nt); err != nil {
		j.logf("warn", "metadata for %s: %v", rel, err)
	}
	if err := applyMeta(target, mtime, attrs, hasAttrs, ctime); err != nil {
		j.logf("warn", "metadata for %s: %v", rel, err)
	}
	if err := applySecurity(target, nt); err != nil {
		j.logf("warn", "metadata for %s: %v", rel, err)
	}
	j.files.Add(1)
	return true, nil
}
