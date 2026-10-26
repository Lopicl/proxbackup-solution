// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
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

	root, err := openRestoreRoot(spec.TargetDir)
	if err != nil {
		return res, err
	}
	defer root.Close()
	j.logf("info", "restoring %s from %s to %s", archive, ref, spec.TargetDir)

	if strings.HasSuffix(archive, ".img.fidx") {
		name := strings.TrimSuffix(archive, ".fidx")
		f, err := root.Create(name)
		if err != nil {
			return res, err
		}
		n, err := io.Copy(f, src)
		if err != nil {
			f.Discard()
		} else {
			err = f.Commit()
		}
		res.BytesTotal = uint64(n)
		j.logf("info", "wrote image %s (%d bytes)", filepath.Join(spec.TargetDir, name), n)
		return res, err
	}
	err = j.restorePxar(ctx, root, dec, spec)
	res.BytesTotal = j.bytesRead.Load()
	return res, err
}

// errNotFollowed and errBadName make a restore skip an entry: restores don't
// write through junctions or symbolic links below the target, which a user
// could have put there or a crafted archive could have restored.
var (
	errNotFollowed = errors.New("junction or symbolic link, not followed")
	errBadName     = errors.New("name not valid on Windows")
)

// skipEntry reports whether err only means the entry at path is skipped.
func (j *job) skipEntry(path string, err error) bool {
	if !errors.Is(err, errNotFollowed) && !errors.Is(err, errBadName) {
		return false
	}
	j.skipped.Add(1)
	j.logf("warn", "skipped %s: %v", path, err)
	return true
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
	rel string
	md  pxar.Metadata
}

func (j *job) restorePxar(ctx context.Context, root *restoreRoot, dec *pxar.Decoder, spec *api.RestoreSpec) error {
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
		rel := filepath.FromSlash(e.Path)
		if !withinDir(filepath.Clean(spec.TargetDir), filepath.Join(spec.TargetDir, rel)) {
			return fmt.Errorf("refusing to restore outside target: %q", e.Path)
		}
		switch e.Kind {
		case pxar.KindDir:
			if err := root.MkdirAll(rel); err != nil {
				if j.skipEntry(e.Path, err) {
					continue
				}
				return err
			}
			j.dirs.Add(1)
			dirs = append(dirs, dirMeta{rel, e.Meta})
			// The archive root is the target folder itself: it keeps its own
			// permissions and streams.
			if nt := ntFromPxar(e.Meta); e.Path != "" && len(nt.streams) > 0 {
				f, err := root.Open(rel)
				if err == nil {
					err = f.WriteStreams(nt)
					f.Close()
				}
				if err != nil {
					j.logf("warn", "metadata for %s: %v", e.Path, err)
				}
			}
		case pxar.KindFile:
			if err := j.restoreFile(root, dec, e, rel, spec.Overwrite); err != nil {
				return err
			}
		case pxar.KindSymlink:
			if err := root.Symlink(rel, e.Target); err != nil {
				j.skipped.Add(1)
				j.logf("warn", "symlink %s: %v", e.Path, err)
				continue
			}
			attrs, has, ctime := fromPxarMeta(e.Meta)
			f, err := root.Open(rel)
			if err == nil {
				err = f.SetMeta(time.Unix(e.Meta.MtimeSecs, int64(e.Meta.MtimeNanos)), attrs, has, ctime)
				f.Close()
			}
			if err != nil {
				j.logf("warn", "metadata for %s: %v", e.Path, err)
			}
		default:
			j.logf("info", "skipping %s entry %s", e.Kind, e.Path)
		}
	}
	// Directory timestamps and permissions last, deepest first, so file
	// creation doesn't bump them and the permissions can't get in the way.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		f, err := root.Open(d.rel)
		if err != nil {
			j.logf("warn", "metadata for %s: %v", filepath.ToSlash(d.rel), err)
			continue
		}
		attrs, has, ctime := fromPxarMeta(d.md)
		f.SetMeta(time.Unix(d.md.MtimeSecs, int64(d.md.MtimeNanos)), attrs, has, ctime)
		if d.rel != "" {
			if err := f.SetSecurity(ntFromPxar(d.md)); err != nil {
				j.logf("warn", "metadata for %s: %v", filepath.ToSlash(d.rel), err)
			}
		}
		f.Close()
	}
	return nil
}

func (j *job) restoreFile(root *restoreRoot, dec *pxar.Decoder, e *pxar.Entry, rel, overwrite string) error {
	attrs, has, ctime := fromPxarMeta(e.Meta)
	_, err := j.writeRestored(root, e.Path, rel, overwrite, dec.Contents(),
		time.Unix(e.Meta.MtimeSecs, int64(e.Meta.MtimeNanos)), attrs, has, ctime, ntFromPxar(e.Meta))
	return err
}

// writeRestored writes one restored file, rel below root (path in the
// archive), and applies its metadata before it takes its name: streams first
// (writing them bumps the mtime), then timestamps and attributes, then
// permissions. It reports whether the file was written; existing files are
// kept according to overwrite, and unwritable targets are skipped with a warning.
func (j *job) writeRestored(root *restoreRoot, path, rel, overwrite string, src io.Reader, mtime time.Time, attrs uint32, hasAttrs bool, ctime time.Time, nt ntExtras) (bool, error) {
	if old, err := root.Lstat(rel); err == nil {
		switch overwrite {
		case "overwrite":
		case "if-newer":
			if !mtime.After(old) {
				return false, nil
			}
		default: // "skip"
			j.logf("info", "exists, skipped: %s", path)
			return false, nil
		}
	}
	f, err := root.Create(rel)
	if err != nil {
		j.skipped.Add(1)
		j.logf("warn", "cannot create %s: %v", path, err)
		return false, nil
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Discard()
		return false, fmt.Errorf("%s: %w", path, err)
	}
	if err := f.WriteStreams(nt); err != nil {
		j.logf("warn", "metadata for %s: %v", path, err)
	}
	if err := f.SetMeta(mtime, attrs, hasAttrs, ctime); err != nil {
		j.logf("warn", "metadata for %s: %v", path, err)
	}
	if err := f.SetSecurity(nt); err != nil {
		j.logf("warn", "metadata for %s: %v", path, err)
	}
	if err := f.Commit(); err != nil {
		j.skipped.Add(1)
		j.logf("warn", "cannot replace %s: %v", path, err)
		return false, nil
	}
	j.files.Add(1)
	return true, nil
}
