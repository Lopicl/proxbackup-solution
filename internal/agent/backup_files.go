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
	orig, read string
	archive    string // .pxar.didx, or the .mpxar.didx of a split archive
	payload    string // .ppxar.didx of a split archive, "" for v1
}

// splitNames returns the metadata and payload archive names for label.
func splitNames(label string) (meta, payload string) {
	return label + ".mpxar.didx", label + ".ppxar.didx"
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
	mode := j.spec.ChangeDetection
	switch mode {
	case "":
		mode = changeLegacy
	case changeLegacy, changeData, changeMetadata:
	default:
		return res, fmt.Errorf("unknown change detection mode %q", mode)
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
		s := fileSource{orig: src, read: read, archive: label + ".pxar.didx"}
		if mode != changeLegacy {
			s.archive, s.payload = splitNames(label)
		}
		sources = append(sources, s)
	}

	sess, err := j.startSession(ctx, c)
	if err != nil {
		return res, err
	}
	defer sess.Close()
	j.logf("info", "backup session started: %s", sess.Ref())
	var prev *prevSnapshot
	if mode == changeMetadata {
		if prev, err = j.openPrevious(ctx, c, sess); err != nil {
			j.logf("warn", "change detection off, reading every file: previous snapshot: %v", err)
		}
		defer prev.Close()
	}

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
		var sts []namedStats
		var err error
		if src.payload == "" {
			var st pbs.Stats
			st, err = j.backupSource(ctx, sess, excl, cat, src)
			sts = []namedStats{{src.archive, st}}
		} else {
			sts, err = j.backupSplit(ctx, sess, excl, cat, src, prev)
		}
		if err != nil {
			return res, fmt.Errorf("%s: %w", src.orig, err)
		}
		for _, st := range sts {
			addStats(&res, st.Stats)
			j.logf("info", "%s: %d bytes, %d chunks (%d new, %d reused), %d uploaded",
				st.name, st.Size, st.Chunks, st.NewChunks, st.ReusedChunks, st.UploadedBytes)
		}
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
	err = w.encodeSource(src, fi, func(root pxar.Metadata) (*pxar.Encoder, error) { return pxar.NewEncoder(aw, root) })
	st, cerr := aw.Close()
	if err == nil {
		err = cerr
	}
	return st, err
}

// encodeSource walks src into the encoder newEnc creates for its root.
func (w *walker) encodeSource(src fileSource, fi fs.FileInfo, newEnc func(root pxar.Metadata) (*pxar.Encoder, error)) error {
	var err error
	w.cat.StartDirectory(src.archive)
	if fi.IsDir() {
		w.enc, err = newEnc(toPxarMeta(fi, statMeta(fi)))
		if err == nil {
			w.j.dirs.Add(1)
			var entries []os.DirEntry
			if entries, err = os.ReadDir(src.read); err == nil {
				err = w.walkEntries(src.read, "", entries)
			}
		}
	} else {
		// A single file source becomes an archive with one entry.
		w.enc, err = newEnc(pxar.Metadata{Mode: pxar.ModeIFDIR | 0o755, MtimeSecs: fi.ModTime().Unix()})
		if err == nil {
			err = w.addEntry(filepath.Dir(src.read), "", fi)
		}
	}
	if err == nil && w.reuse != nil {
		err = w.reuse.flush()
	}
	if err == nil {
		err = w.enc.Close()
	}
	if err == nil {
		w.cat.EndDirectory()
	}
	return err
}

// do runs an encoder (and catalog) operation that doesn't write file
// contents, in order with unchanged files still waiting for their reuse
// decision.
func (w *walker) do(op func() error) error {
	if w.reuse == nil {
		return op()
	}
	return w.reuse.do(op)
}

type walker struct {
	j    *job
	ctx  context.Context
	enc  *pxar.Encoder
	excl *Excluder
	cat  *catalog // mirrors every entry written to enc

	// Split archives: record change times; with change detection, the
	// previous metadata archive and the chunk reuse for unchanged files.
	split bool
	prev  *prevTree
	reuse *payloadReuse
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
		err = w.do(func() error {
			w.cat.StartDirectory(name)
			return w.enc.CreateDir([]byte(name), toPxarMeta(fi, meta))
		})
		if err != nil {
			return err
		}
		w.j.dirs.Add(1)
		if err := w.walkEntries(full, crel, entries); err != nil {
			return err
		}
		return w.do(func() error {
			w.cat.EndDirectory()
			return w.enc.FinishDir()
		})
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(full)
		if err != nil || target == "" {
			w.skip(crel, "unreadable symlink: %v", err)
			return nil
		}
		return w.do(func() error {
			w.cat.AddSymlink(name)
			return w.enc.AddSymlink([]byte(name), toPxarMeta(fi, meta), []byte(target))
		})
	case mode.IsRegular():
		if meta.cloudPlaceholder {
			w.skip(crel, "cloud placeholder (not available offline)")
			return nil
		}
		if w.split {
			meta.chtime = changeTime(full)
		}
		pm := toPxarMeta(fi, meta)
		size := uint64(fi.Size())
		if w.prev != nil {
			if pe := w.prev.lookup(crel); unchanged(pe, pm, size) {
				queued, err := w.reuse.queue(pe.PayloadOffset, size, func(reuse bool) error {
					if !reuse {
						return w.addFile(full, crel, fi, pm)
					}
					w.cat.AddFile(name, size, fi.ModTime().Unix())
					w.j.files.Add(1)
					return w.reuse.ref([]byte(name), pm, size, pe.PayloadOffset)
				})
				if err != nil || queued {
					return err
				}
			}
			if err := w.reuse.flush(); err != nil {
				return err
			}
		}
		return w.addFile(full, crel, fi, pm)
	default:
		// Junctions, mount points, devices, sockets: not followed.
		w.j.logf("info", "not backing up special file %s (%s)", crel, mode.Type())
		return nil
	}
}

// addFile reads a regular file into the archive.
func (w *walker) addFile(full, crel string, fi fs.FileInfo, pm pxar.Metadata) error {
	name := fi.Name()
	f, err := os.Open(full)
	if err != nil {
		w.skip(crel, "%v", err)
		return nil
	}
	defer f.Close()
	res, err := w.enc.AddFile([]byte(name), pm, uint64(fi.Size()), countingReader{f, &w.j.bytesRead})
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
}
