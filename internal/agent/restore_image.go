// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"proxbackup/internal/api"
	"proxbackup/pkg/ntfs"
	"proxbackup/pkg/pbs"
)

// imageCacheChunks is how many 4 MiB image chunks a file restore keeps
// cached; MFT records and directory indexes are read many times.
const imageCacheChunks = 16

// restoreImageFiles restores selected files and folders from the NTFS file
// system inside a volume image. Only the chunks holding the MFT, the
// directory indexes and the selected files' clusters are downloaded.
func (j *job) restoreImageFiles(ctx context.Context, r *pbs.ReaderSession, idx *pbs.Index, spec *api.RestoreSpec) (api.Result, error) {
	var res api.Result
	vol, err := ntfs.Open(r.OpenIndexAt(ctx, idx, imageCacheChunks))
	if err != nil {
		return res, fmt.Errorf("%s: %w (file restore needs an NTFS volume)", spec.Archive, err)
	}

	type selection struct {
		f   *ntfs.File
		rel string
	}
	var sels []selection
	for _, p := range spec.Paths {
		f, rel, err := vol.Resolve(p)
		if errors.Is(err, ntfs.ErrNotExist) {
			return res, fmt.Errorf("%q not found on the NTFS volume in %s", p, spec.Archive)
		}
		if err != nil {
			return res, err
		}
		sels = append(sels, selection{f, rel})
	}
	// Restore each folder once, even when also selected through a parent.
	covered := func(rel string) bool {
		for _, s := range sels {
			if s.rel != rel && (s.rel == "" || strings.HasPrefix(strings.ToLower(rel), strings.ToLower(s.rel)+"/")) {
				return true
			}
		}
		return false
	}

	// First pass: total size, for progress.
	for _, s := range sels {
		if covered(s.rel) {
			continue
		}
		err := j.walkImage(ctx, vol, s.f, s.rel, false, func(f *ntfs.File, _ string) error {
			if !f.IsDir && imageSkipReason(f) == "" {
				j.bytesTotal.Add(uint64(f.Size()))
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}

	rroot, err := openRestoreRoot(spec.TargetDir)
	if err != nil {
		return res, err
	}
	defer rroot.Close()
	j.logf("info", "restoring %s from the NTFS volume in %s to %s", strings.Join(spec.Paths, ", "), spec.Archive, spec.TargetDir)
	root := filepath.Clean(spec.TargetDir)
	var dirs []*ntfs.File
	var dirRels []string
	for _, s := range sels {
		if covered(s.rel) {
			continue
		}
		err := j.walkImage(ctx, vol, s.f, s.rel, true, func(f *ntfs.File, rel string) error {
			target := filepath.FromSlash(rel)
			if !withinDir(root, filepath.Join(root, target)) {
				return fmt.Errorf("refusing to restore outside target: %q", rel)
			}
			if why := imageSkipReason(f); why != "" {
				j.skipped.Add(1)
				j.logf("warn", "skipped %s: %s", rel, why)
				return nil
			}
			if f.IsDir {
				if err := rroot.MkdirAll(target); err != nil {
					if j.skipEntry(rel, err) {
						return nil
					}
					return err
				}
				j.dirs.Add(1)
				if rel != "" {
					dirs, dirRels = append(dirs, f), append(dirRels, target)
				}
				return nil
			}
			data, err := f.Open()
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			size := uint64(data.Size())
			before := j.bytesRead.Load()
			src := countingReader{io.NewSectionReader(data, 0, data.Size()), &j.bytesRead}
			if _, err := j.writeRestored(rroot, rel, target, spec.Overwrite, src, f.Mtime, f.Attrs, true, f.Ctime, ntExtras{}); err != nil {
				return err
			}
			// Kept files count as done for progress.
			if read := j.bytesRead.Load() - before; read < size {
				j.bytesRead.Add(size - read)
			}
			if n := len(f.Streams()); n > 0 {
				j.logf("info", "%s: %d alternate data stream(s) not restored", rel, n)
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	// Directory timestamps last, deepest first, so file creation doesn't bump them.
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if f, err := rroot.Open(dirRels[i]); err == nil {
			f.SetMeta(d.Mtime, d.Attrs, true, d.Ctime)
			f.Close()
		}
	}
	res.BytesTotal = j.bytesRead.Load()
	j.logf("info", "restored %d files, %d folders from %s", j.files.Load(), j.dirs.Load(), spec.Archive)
	return res, nil
}

// walkImage calls fn for f and, for directories, everything below it in
// index order. NTFS metadata files and System Volume Information (shadow
// copy storage) are left out, and reparse points are not followed.
// Unreadable entries are skipped, with a warning when report is set.
func (j *job) walkImage(ctx context.Context, vol *ntfs.Volume, f *ntfs.File, rel string, report bool, fn func(*ntfs.File, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := fn(f, rel); err != nil {
		return err
	}
	if !f.IsDir || imageSkipReason(f) != "" {
		return nil
	}
	ents, err := f.ReadDir()
	if err != nil {
		if report {
			j.skipped.Add(1)
			j.logf("warn", "cannot list %s: %v", rel, err)
		}
		return nil
	}
	for _, e := range ents {
		if e.Ref < ntfs.FirstUserRef || (rel == "" && strings.EqualFold(e.Name, "System Volume Information")) {
			continue
		}
		child, err := vol.Get(e.Ref)
		if err != nil {
			if report {
				j.skipped.Add(1)
				j.logf("warn", "cannot read %s: %v", joinRel(rel, e.Name), err)
			}
			continue
		}
		if err := j.walkImage(ctx, vol, child, joinRel(rel, e.Name), report, fn); err != nil {
			return err
		}
	}
	return nil
}

func joinRel(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// imageSkipReason says why a file can't be restored from an image, or "".
func imageSkipReason(f *ntfs.File) string {
	switch tag := f.ReparseTag; {
	case tag == 0:
	case tag&0xFFFF0FFF == 0x9000001A: // cloud files (OneDrive)
		if !f.IsDir && f.Attrs&(attrOffline|attrRecallOnOpen|attrRecallOnDataAccess) != 0 {
			return "cloud placeholder, content not on this PC"
		}
	case tag == ntfs.ReparseTagMountPoint || tag == ntfs.ReparseTagSymlink:
		return "junction or symbolic link"
	case tag == ntfs.ReparseTagWof:
		return "compressed by Windows (CompactOS/WOF), not readable from an image"
	case tag == ntfs.ReparseTagDedup:
		return "deduplicated by Windows Server, not readable from an image"
	case f.IsDir:
		return fmt.Sprintf("reparse point (tag %#x)", tag)
	}
	if !f.IsDir && f.Encrypted() {
		return "EFS-encrypted"
	}
	return ""
}
