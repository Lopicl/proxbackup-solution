package agent

import (
	"context"
	"errors"
	"fmt"
	"io"

	"proxbackup/internal/api"
)

func (j *job) runImage(ctx context.Context) (api.Result, error) {
	var res api.Result
	if len(j.spec.Volumes) == 0 {
		return res, errors.New("no volumes configured")
	}
	c, err := j.pbsClient()
	if err != nil {
		return res, err
	}
	// Image backups always need a consistent view of the volume.
	snaps := newSnapshotSet(true, j.logf)
	defer snaps.Close()

	type vol struct {
		name, archive, dev string
		r                  readCloser
		size               uint64
	}
	j.setPhase("snapshot")
	var vols []vol
	defer func() {
		for _, v := range vols {
			v.r.Close()
		}
	}()
	for _, v := range j.spec.Volumes {
		r, size, dev, err := snaps.openImageSource(v)
		if err != nil {
			return res, fmt.Errorf("volume %s: %w", v, err)
		}
		vols = append(vols, vol{name: v, archive: "drive-" + ArchiveLabel(v) + ".img.fidx", dev: dev, r: r, size: size})
		j.bytesTotal.Add(size)
		j.logf("info", "volume %s: %d bytes via %s", v, size, dev)
	}

	sess, err := j.startSession(ctx, c)
	if err != nil {
		return res, err
	}
	defer sess.Close()
	j.setPhase("upload")
	for _, v := range vols {
		j.archive.Store(v.archive)
		if _, err := sess.LoadPreviousIndex(ctx, v.archive); err != nil {
			j.logf("warn", "could not load previous index for %s: %v", v.archive, err)
		}
		fw, err := sess.NewFixedArchive(ctx, v.archive, v.size)
		if err != nil {
			return res, err
		}
		n, err := io.Copy(fw, countingReader{io.LimitReader(v.r, int64(v.size)), &j.bytesRead})
		if err == nil && uint64(n) != v.size {
			err = fmt.Errorf("short read: %d of %d bytes", n, v.size)
		}
		st, cerr := fw.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			return res, fmt.Errorf("%s: %w", v.name, err)
		}
		addStats(&res, st)
		j.logf("info", "%s: %d chunks (%d new, %d reused), %d bytes uploaded", v.archive, st.Chunks, st.NewChunks, st.ReusedChunks, st.UploadedBytes)
	}

	// List each volume's files from the same snapshot, so the image can be
	// browsed like a file backup.
	j.setPhase("catalog")
	cat := j.newCatalog()
	defer cat.Close()
	for _, v := range vols {
		root, ok := snaps.imageFSRoot(v.name)
		if !ok {
			continue
		}
		cat.StartDirectory(v.archive)
		if err := cat.addTree(ctx, root); err != nil {
			return res, err
		}
		cat.EndDirectory()
	}
	if err := cat.upload(ctx, sess, &res); err != nil {
		return res, err
	}
	return res, j.finishSession(ctx, sess, &res)
}
