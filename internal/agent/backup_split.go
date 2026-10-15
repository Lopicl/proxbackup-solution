// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/hex"
	"os"

	"proxbackup/pkg/pbs"
	"proxbackup/pkg/pxar"
)

type namedStats struct {
	name string
	pbs.Stats
}

// prevSnapshot is the group's last snapshot, opened for change detection.
type prevSnapshot struct {
	r     *pbs.ReaderSession
	files map[string]pbs.FileInfo
}

func (p *prevSnapshot) Close() {
	if p != nil {
		p.r.Close()
	}
}

// openPrevious opens the snapshot the backup session continues from. It
// returns nil without error when the group has no snapshot yet.
func (j *job) openPrevious(ctx context.Context, c *pbs.Client, sess *pbs.BackupSession) (*prevSnapshot, error) {
	t, ok, err := sess.PreviousBackupTime(ctx)
	if err != nil || !ok {
		if err == nil {
			j.logf("info", "no previous snapshot, reading every file")
		}
		return nil, err
	}
	r, err := c.StartReader(ctx, j.snapshotRef(t), nil)
	if err != nil {
		return nil, err
	}
	m, err := r.Manifest(ctx)
	if err != nil {
		r.Close()
		return nil, err
	}
	p := &prevSnapshot{r: r, files: map[string]pbs.FileInfo{}}
	for _, f := range m.Files {
		p.files[f.Filename] = f
	}
	j.logf("info", "change detection against %s", j.snapshotRef(t))
	return p, nil
}

// previousSplit returns the previous payload index and a reader of the
// previous metadata archive of src, or nils when files must all be read.
func (j *job) previousSplit(ctx context.Context, sess *pbs.BackupSession, prev *prevSnapshot, src fileSource) (*pbs.Index, *pbs.IndexReader) {
	metaFI, okMeta := prev.files[src.archive]
	payFI, okPay := prev.files[src.payload]
	if !okMeta || !okPay {
		j.logf("info", "%s: not in the previous snapshot, reading every file", src.archive)
		return nil, nil
	}
	payload, err := sess.PreviousIndex(ctx, src.payload)
	if err != nil || payload == nil {
		j.logf("warn", "%s: previous payload index unavailable, reading every file: %v", src.payload, err)
		return nil, nil
	}
	// PreviousIndex comes from the backup session; make sure it is the
	// snapshot whose metadata we're about to walk.
	if csum := payload.ComputeCsum(); hex.EncodeToString(csum[:]) != payFI.Csum || payload.Size != payFI.Size {
		j.logf("warn", "%s: previous snapshot changed during the backup, reading every file", src.payload)
		return nil, nil
	}
	meta, err := prev.r.Index(ctx, src.archive, &metaFI)
	if err != nil {
		j.logf("warn", "%s: previous metadata unavailable, reading every file: %v", src.archive, err)
		return nil, nil
	}
	return payload, prev.r.OpenIndex(ctx, meta, 4)
}

// backupSplit writes src as a pxar v2 split archive. With prev (metadata
// change detection), unchanged files are not read: their contents are taken
// from the previous payload archive's chunks.
func (j *job) backupSplit(ctx context.Context, sess *pbs.BackupSession, excl *Excluder, cat *catalog, src fileSource, prev *prevSnapshot) ([]namedStats, error) {
	fi, err := os.Stat(src.read)
	if err != nil {
		return nil, err
	}
	w := &walker{j: j, ctx: ctx, excl: excl, cat: cat, split: true}
	if prev != nil {
		payload, meta := j.previousSplit(ctx, sess, prev, src)
		if meta != nil {
			defer meta.Close()
			w.prev = newPrevTree(meta)
			w.reuse = &payloadReuse{prev: payload}
		}
	}
	if w.reuse == nil {
		// Still dedupe against the previous payload's chunks.
		if _, err := sess.LoadPreviousIndex(ctx, src.payload); err != nil {
			j.logf("warn", "could not load previous index for %s: %v", src.payload, err)
		}
	}
	mw, err := sess.NewDynamicArchive(ctx, src.archive)
	if err != nil {
		return nil, err
	}
	pw, err := sess.NewDynamicArchive(ctx, src.payload)
	if err != nil {
		mw.Close()
		return nil, err
	}
	err = w.encodeSource(src, fi, func(root pxar.Metadata) (*pxar.Encoder, error) {
		enc, err := pxar.NewSplitEncoder(mw, pw, root)
		if w.reuse != nil {
			w.reuse.w, w.reuse.enc = pw, enc
		}
		return enc, err
	})
	mst, merr := mw.Close()
	pst, perr := pw.Close()
	for _, e := range []error{merr, perr} {
		if err == nil {
			err = e
		}
	}
	if err != nil {
		return nil, err
	}
	if w.prev != nil && w.prev.err != nil {
		j.logf("warn", "%s: previous metadata partly unreadable, some unchanged files were read: %v", src.archive, w.prev.err)
	}
	if r := w.reuse; r != nil {
		j.logf("info", "%s: %d unchanged files not read (%.1f MiB in %d reused chunks, %.1f MiB padding); %d read again to drop padding",
			src.archive, r.reusedFiles, float64(r.reusedBytes)/(1<<20), r.chunks, float64(r.waste)/(1<<20), r.rereadFiles)
	}
	return []namedStats{{src.archive, mst}, {src.payload, pst}}, nil
}
