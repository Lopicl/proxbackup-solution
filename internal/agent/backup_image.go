// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"proxbackup/internal/api"
	"proxbackup/pkg/ntfs"
	"proxbackup/pkg/pbs"
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
		r                  imageSource
		size               uint64
		alloc              *ntfs.Allocation
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
		alloc, err := volumeAllocation(r, size)
		vols = append(vols, vol{name: v, archive: api.VolumeArchive(v), dev: dev, r: r, size: size, alloc: alloc})
		j.bytesTotal.Add(size)
		if err != nil {
			j.logf("info", "volume %s: %s via %s; reading every sector (no NTFS free-space map: %v)", v, gib(size), dev, err)
		} else {
			j.logf("info", "volume %s: %s via %s, %s in use; free space is skipped", v, gib(size), dev, gib(uint64(alloc.UsedBytes())))
		}
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
		ic, err := copyImage(ctx, fw, v.r, v.size, v.alloc, &j.bytesRead)
		st, cerr := fw.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			return res, fmt.Errorf("%s: %w", v.name, err)
		}
		addStats(&res, st)
		j.logf("info", "%s: %d chunks (%d new, %d reused), %d bytes uploaded", v.archive, st.Chunks, st.NewChunks, st.ReusedChunks, st.UploadedBytes)
		j.logf("info", "%s: took %s (%s/s); %s of free space not read; disk reads %s, waiting for chunk workers %s; "+
			"%d workers spent hashing %s, compressing+encrypting %s, uploading %s",
			v.archive, st.Duration.Round(100*time.Millisecond), gib(uint64(float64(v.size)/max(st.Duration.Seconds(), 1))), gib(ic.skipped),
			ic.read.Round(100*time.Millisecond), ic.wait.Round(100*time.Millisecond), chunkWorkers(),
			st.HashTime.Round(100*time.Millisecond), st.EncodeTime.Round(100*time.Millisecond), st.UploadTime.Round(100*time.Millisecond))
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

// imageSource is a volume (or image file) opened for an image backup.
type imageSource interface {
	io.ReaderAt
	io.Closer
}

// volumeAllocation reads the NTFS cluster bitmap of a volume, so its free
// space can be skipped. Volumes that aren't NTFS return an error and are
// imaged in full.
func volumeAllocation(r io.ReaderAt, size uint64) (*ntfs.Allocation, error) {
	v, err := ntfs.Open(sectorReader{r})
	if err != nil {
		return nil, err
	}
	a, err := v.Allocation()
	if err != nil {
		return nil, err
	}
	if a.Size() > int64(size) {
		return nil, fmt.Errorf("file system (%d bytes) is larger than the volume", a.Size())
	}
	return a, nil
}

// imageCopy records what copyImage did.
type imageCopy struct {
	skipped    uint64        // free bytes passed as zeros without reading them
	read, wait time.Duration // reading the disk; blocked on the chunk workers
}

// copyImage streams size bytes of r into w in fixed-chunk-sized pieces. With
// alloc, free clusters go out as zeros: pieces holding no used cluster
// aren't read at all, and stale data in the free clusters of the others is
// cleared. VSS snapshots already read free clusters as zeros, so on Windows
// this saves reading and hashing them; sources without that (image files,
// devices on other systems) also stop uploading deleted data. Either way
// free space dedupes to a single zero chunk.
func copyImage(ctx context.Context, w io.Writer, r io.ReaderAt, size uint64, alloc *ntfs.Allocation, progress *atomic.Uint64) (imageCopy, error) {
	var c imageCopy
	buf := make([]byte, pbs.FixedChunkSize)
	bufZero := false
	for off := uint64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return c, err
		}
		n := min(uint64(len(buf)), size-off)
		p := buf[:n]
		if alloc != nil && !alloc.AnyUsed(int64(off), int64(n)) {
			if !bufZero {
				clear(buf)
				bufZero = true
			}
			c.skipped += n
		} else {
			t := time.Now()
			if _, err := r.ReadAt(p, int64(off)); err != nil {
				return c, fmt.Errorf("read at offset %d: %w", off, err)
			}
			c.read += time.Since(t)
			bufZero = false
			if alloc != nil {
				alloc.ZeroFree(p, int64(off))
			}
		}
		t := time.Now()
		if _, err := w.Write(p); err != nil {
			return c, err
		}
		c.wait += time.Since(t)
		progress.Add(n)
		off += n
	}
	return c, nil
}

// sectorReader serves reads of any size and offset from a raw volume, which
// only accepts sector-aligned ones.
type sectorReader struct{ r io.ReaderAt }

const sectorAlign = 4096 // covers 512-byte and 4K-native sectors

func (s sectorReader) ReadAt(p []byte, off int64) (int, error) {
	start := off &^ (sectorAlign - 1)
	end := (off + int64(len(p)) + sectorAlign - 1) &^ (sectorAlign - 1)
	if start == off && end == off+int64(len(p)) {
		return s.r.ReadAt(p, off)
	}
	buf := make([]byte, end-start)
	n, err := s.r.ReadAt(buf, start)
	n = max(min(n-int(off-start), len(p)), 0)
	copy(p, buf[off-start:][:n])
	if n == len(p) {
		err = nil
	}
	return n, err
}

// gib formats a byte count for the job log.
func gib(n uint64) string { return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30)) }
