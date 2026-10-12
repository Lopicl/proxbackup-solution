package agent

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"proxbackup/internal/api"
	"proxbackup/pkg/pbs"
)

// catalog builds catalog.pcat1.didx in a temp file while the archives are
// written. It is what makes snapshots browsable in the PBS GUI. A catalog
// problem never fails the backup: the snapshot is just uploaded without one.
type catalog struct {
	*pbs.CatalogWriter
	j *job
	f *os.File
}

func (j *job) newCatalog() *catalog {
	c := &catalog{j: j}
	var w io.Writer = io.Discard
	f, err := os.CreateTemp("", "proxbackup-catalog-*")
	if err != nil {
		j.logf("warn", "no catalog, snapshot won't be browsable: %v", err)
	} else {
		c.f, w = f, f
	}
	c.CatalogWriter, _ = pbs.NewCatalogWriter(w)
	return c
}

func (c *catalog) Close() {
	if c.f != nil {
		c.f.Close()
		os.Remove(c.f.Name())
	}
}

// upload finishes the catalog and adds it to the snapshot. Only session errors
// are returned; a broken catalog is logged and left out.
func (c *catalog) upload(ctx context.Context, sess *pbs.BackupSession, res *api.Result) error {
	if c.f == nil {
		return nil
	}
	if err := c.Finish(); err != nil {
		c.j.logf("warn", "no catalog, snapshot won't be browsable: %v", err)
		return nil
	}
	if _, err := c.f.Seek(0, io.SeekStart); err != nil {
		c.j.logf("warn", "no catalog, snapshot won't be browsable: %v", err)
		return nil
	}
	if _, err := sess.LoadPreviousIndex(ctx, pbs.CatalogArchiveName); err != nil {
		c.j.logf("warn", "could not load previous index for %s: %v", pbs.CatalogArchiveName, err)
	}
	aw, err := sess.NewDynamicArchive(ctx, pbs.CatalogArchiveName)
	if err != nil {
		return err
	}
	_, err = io.Copy(aw, c.f)
	st, cerr := aw.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	addStats(res, st)
	c.j.logf("info", "%s: %d bytes, %d uploaded", pbs.CatalogArchiveName, st.Size, st.UploadedBytes)
	return nil
}

// addTree lists the tree under dir into the current catalog directory. It is
// used for volume images, whose archive has no file list of its own. Reparse
// points (junctions, symlinks) are listed but not followed; unreadable
// directories are listed empty.
func (c *catalog) addTree(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, de := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		fi, err := de.Info()
		if err != nil {
			continue
		}
		switch mode := fi.Mode(); {
		case mode&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			c.AddSymlink(fi.Name())
		case mode.IsDir():
			c.StartDirectory(fi.Name())
			if err := c.addTree(ctx, filepath.Join(dir, fi.Name())); err != nil {
				return err
			}
			c.EndDirectory()
		case mode.IsRegular():
			c.AddFile(fi.Name(), uint64(fi.Size()), fi.ModTime().Unix())
		}
	}
	return nil
}
