// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxbackup/pkg/pxar"
)

func TestSymlinksCarryNoXattrs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Skip(err)
	}
	m := winMeta{attrs: attrHidden | attrArchive, ctime: time.Unix(5, 0), chtime: time.Unix(6, 0), mtime: time.Unix(7, 0)}
	for name, wantX := range map[string]bool{"f": true, "l": false} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		md := toPxarMeta(fi, m)
		if (len(md.Xattrs) > 0) != wantX || md.Flags&pxar.FlagHidden == 0 {
			t.Fatalf("%s (%v): xattrs %d, flags %#x", name, fi.Mode()&fs.ModeType, len(md.Xattrs), md.Flags)
		}
	}
}
