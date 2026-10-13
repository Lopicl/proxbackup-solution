// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

type fileSource struct {
	orig, read, archive string
}

func (j *job) runFiles(ctx context.Context) (api.Result, error) {
	var res api.Result
	if len(j.spec.Sources) == 0 {
		return res, errors.New("no sources configured")
	}
	c, err := j.pbsClient()
	if err != nil {
		return res, err
	}
	snaps := newSnapshotSet(j.spec.UseVSS, j.logf)
	defer snaps.Close()

	// Snapshot all volumes first so every archive in the snapshot is consistent.
	j.setPhase("snapshot")
	var sources []fileSource
	seen := map[string]int{}
	for _, src := range j.spec.Sources {
		read, err := snaps.Resolve(src)
		if err != nil {
			return res, err
		}
		label := ArchiveLabel(src)
		if n := seen[label]; n > 0 {
			label = fmt.Sprintf("%s-%d", label, n+1)
		}
		seen[label]++
		sources = append(sources, fileSource{orig: src, read: read, archive: label + ".pxar.didx"})
	}

	sess, err := j.startSession(ctx, c)
	if err != nil {
		return res, err
	}
	defer sess.Close()
	j.logf("info", "backup session started: %s", sess.Ref())

	excl := NewExcluder(append(append([]string{}, DefaultExcludes...), j.spec.Excludes...))
	cat := j.newCatalog()
	defer cat.Close()
	j.setPhase("upload")
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		j.archive.Store(src.archive)
		if ok, err := sess.LoadPreviousIndex(ctx, src.archive); err != nil {
			j.logf("warn", "could not load previous index for %s: %v", src.archive, err)
		} else if ok {
			j.logf("info", "%s: incremental against previous snapshot", src.archive)
		}
		st, err := j.backupSource(ctx, sess, excl, cat, src)
		if err != nil {
			return res, fmt.Errorf("%s: %w", src.orig, err)
		}
		addStats(&res, st)
		j.logf("info", "%s: %d bytes, %d chunks (%d new, %d reused), %d uploaded",
			src.archive, st.Size, st.Chunks, st.NewChunks, st.ReusedChunks, st.UploadedBytes)
	}
	if err := cat.upload(ctx, sess, &res); err != nil {
		return res, err
	}
	if err := j.finishSession(ctx, sess, &res); err != nil {
		return res, err
	}
	return res, nil
}

func (j *job) backupSource(ctx context.Context, sess *pbs.BackupSession, excl *Excluder, cat *catalog, src fileSource) (pbs.Stats, error) {
	fi, err := os.Stat(src.read)
	if err != nil {
		return pbs.Stats{}, err
	}
	aw, err := sess.NewDynamicArchive(ctx, src.archive)
	if err != nil {
		return pbs.Stats{}, err
	}
	w := &walker{j: j, ctx: ctx, excl: excl, cat: cat}
	cat.StartDirectory(src.archive)
	if fi.IsDir() {
		w.enc, err = pxar.NewEncoder(aw, toPxarMeta(fi, statMeta(fi)))
		if err == nil {
			j.dirs.Add(1)
			var entries []os.DirEntry
			if entries, err = os.ReadDir(src.read); err == nil {
				err = w.walkEntries(src.read, "", entries)
			}
		}
	} else {
		// A single file source becomes an archive with one entry.
		w.enc, err = pxar.NewEncoder(aw, pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755, MtimeSecs: fi.ModTime().Unix()})
		if err == nil {
			err = w.addEntry(filepath.Dir(src.read), "", fi)
		}
	}
	if err == nil {
		err = w.enc.Close()
	}
	if err == nil {
		cat.EndDirectory()
	}
	st, cerr := aw.Close()
	if err == nil {
		err = cerr
	}
	return st, err
}

type walker struct {
	j    *job
	ctx  context.Context
	enc  *pxar.Encoder
	excl *Excluder
	cat  *catalog // mirrors every entry written to enc
}

func (w *walker) skip(rel string, format string, args ...any) {
	w.j.skipped.Add(1)
	w.j.logf("warn", "skipped %s: %s", rel, fmt.Sprintf(format, args...))
}

// walkEntries encodes the contents of dir. os.ReadDir sorts names bytewise,
// which is exactly the order pxar requires.
func (w *walker) walkEntries(dir, rel string, entries []os.DirEntry) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	for _, de := range entries {
		crel := path.Join(rel, de.Name())
		if w.excl.MatchEntry(crel) {
			continue
		}
		fi, err := de.Info()
		if err != nil {
			w.skip(crel, "%v", err)
			continue
		}
		if err := w.addEntry(dir, rel, fi); err != nil {
			return err
		}
	}
	return nil
}

// addEntry encodes one child of dir. Only encoder/upload errors are returned;
// per-file problems are logged and the file skipped.
func (w *walker) addEntry(dir, rel string, fi fs.FileInfo) error {
	name := fi.Name()
	crel := path.Join(rel, name)
	full := filepath.Join(dir, name)
	meta := statMeta(fi)
	mode := fi.Mode()
	switch {
	case mode&fs.ModeIrregular != 0:
		// Must come before IsDir: on Windows, junctions and other non-symlink reparse
		// points report ModeDir|ModeIrregular. Following them would back up their
		// targets twice or loop (e.g. "Application Data" junctions in user profiles).
		w.j.logf("info", "not following %s (junction or other reparse point)", crel)
		return nil
	case mode.IsDir():
		// Read the listing before emitting the directory so unreadable
		// directories are skipped as a whole.
		entries, err := os.ReadDir(full)
		if err != nil {
			w.skip(crel, "%v", err)
			return nil
		}
		if err := w.enc.CreateDir([]byte(name), toPxarMeta(fi, meta)); err != nil {
			return err
		}
		w.j.dirs.Add(1)
		w.cat.StartDirectory(name)
		if err := w.walkEntries(full, crel, entries); err != nil {
			return err
		}
		w.cat.EndDirectory()
		return w.enc.FinishDir()
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(full)
		if err != nil || target == "" {
			w.skip(crel, "unreadable symlink: %v", err)
			return nil
		}
		if err := w.enc.AddSymlink([]byte(name), toPxarMeta(fi, meta), []byte(target)); err != nil {
			return err
		}
		w.cat.AddSymlink(name)
		return nil
	case mode.IsRegular():
		if meta.cloudPlaceholder {
			w.skip(crel, "cloud placeholder (not available offline)")
			return nil
		}
		f, err := os.Open(full)
		if err != nil {
			w.skip(crel, "%v", err)
			return nil
		}
		defer f.Close()
		res, err := w.enc.AddFile([]byte(name), toPxarMeta(fi, meta), uint64(fi.Size()), countingReader{f, &w.j.bytesRead})
		if err == nil || res.Short {
			// Short reads still leave a (zero padded) entry in the archive.
			w.cat.AddFile(name, uint64(fi.Size()), fi.ModTime().Unix())
		}
		if err != nil {
			if w.ctx.Err() != nil {
				return w.ctx.Err()
			}
			var pe *fs.PathError
			if errors.As(err, &pe) || res.Short {
				// Read error mid-file: the archive stays valid (zero padded) but the content is not.
				w.skip(crel, "read error, content incomplete: %v", err)
				return nil
			}
			return err
		}
		w.j.files.Add(1)
		if res.Short || res.Grew {
			w.j.logf("warn", "%s changed size while reading (use VSS for consistent backups)", crel)
		}
		return nil
	default:
		// Junctions, mount points, devices, sockets: not followed.
		w.j.logf("info", "not backing up special file %s (%s)", crel, mode.Type())
		return nil
	}
}
