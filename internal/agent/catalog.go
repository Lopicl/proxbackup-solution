// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"proxbackup/internal/api"
	"proxbackup/pkg/ntfs"
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

// noCatalog is a catalog that is neither written nor uploaded. Split (v2)
// archives don't need one: like proxmox-backup-client, which uploads no catalog
// in data or metadata mode, PBS and the console browse their .mpxar.didx.
func (j *job) noCatalog() *catalog {
	c := &catalog{j: j}
	c.CatalogWriter, _ = pbs.NewCatalogWriter(io.Discard)
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
// directories are listed empty. Without a snapshot, a user could swap a
// folder for a junction between its listing and its opening and get another
// folder's file names listed under theirs (the self-service restore page
// shows them): each folder is read through its handle, after g checked that
// it is the one listed. A folder that fails the check is listed empty.
func (c *catalog) addTree(ctx context.Context, dir string, g *sourceGuard) error {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	if err := g.checkFile(f, dir); err != nil {
		f.Close()
		c.j.logf("warn", "%s: %v", dir, err)
		return nil
	}
	entries, err := f.ReadDir(-1)
	f.Close()
	if err != nil && len(entries) == 0 {
		return nil
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
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
			if err := c.addTree(ctx, filepath.Join(dir, fi.Name()), g); err != nil {
				return err
			}
			c.EndDirectory()
		case mode.IsRegular():
			c.AddFile(fi.Name(), uint64(fi.Size()), fi.ModTime().Unix())
		}
	}
	return nil
}

// addNTFSTree lists the directory dir of an NTFS volume read straight from a
// snapshot into the current catalog directory, the way a file restore from
// the image reads it. Unlike addTree it isn't stopped by the cloud files
// filter: cloud storage folders (OneDrive, Dropbox, ...) that their provider
// fills in on demand can't be opened in a snapshot, and would be listed empty.
// Their online-only files aren't in the image and are left out. Reparse
// points that restoreImage doesn't follow are listed as symlinks; NTFS
// metadata files and System Volume Information are left out; unreadable
// directories are listed empty.
func (c *catalog) addNTFSTree(ctx context.Context, vol *ntfs.Volume, dir *ntfs.File, top bool) error {
	ents, err := dir.ReadDir()
	if err != nil {
		return nil
	}
	// The catalog wants bytewise order, not NTFS collation.
	slices.SortFunc(ents, func(a, b ntfs.DirEntry) int { return strings.Compare(a.Name, b.Name) })
	for _, e := range ents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Ref < ntfs.FirstUserRef || (top && strings.EqualFold(e.Name, "System Volume Information")) {
			continue
		}
		f, err := vol.Get(e.Ref)
		if err != nil {
			continue
		}
		switch skip := imageSkipReason(f); {
		case f.ReparseTag == ntfs.ReparseTagMountPoint || f.ReparseTag == ntfs.ReparseTagSymlink, f.IsDir && skip != "":
			c.AddSymlink(e.Name)
		case f.IsDir:
			c.StartDirectory(e.Name)
			if err := c.addNTFSTree(ctx, vol, f, false); err != nil {
				return err
			}
			c.EndDirectory()
		case cloudTag(f.ReparseTag) && skip != "":
			// Online-only: the content is not on this PC.
		default:
			c.AddFile(e.Name, uint64(f.Size()), f.Mtime.Unix())
		}
	}
	return nil
}
