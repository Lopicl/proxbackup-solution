// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

func TestNTExtrasRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	sd := []byte{1, 0, 4, 0x80, 0, 0, 0, 0}
	m := winMeta{mtime: time.Unix(7, 0), nt: ntExtras{sd: sd, streams: []adsStream{
		{"Zone.Identifier", []byte("[ZoneTransfer]\r\nZoneId=3\r\n")},
		{"empty", nil},
	}}}
	md := toPxarMeta(fi, m)
	// Names a crafted archive could carry that must not be written back.
	for _, bad := range []string{"", "a:b", `..\x`, "x/y", "x\x00"} {
		md.Xattrs = append(md.Xattrs, pxar.Xattr{Name: []byte(xattrADSPrefix + bad), Value: []byte("bad")})
	}
	nt := ntFromPxar(md)
	if string(nt.sd) != string(sd) || len(nt.streams) != 2 {
		t.Fatalf("got %+v", nt)
	}
	for i, s := range nt.streams {
		if s.name != m.nt.streams[i].name || string(s.data) != string(m.nt.streams[i].data) {
			t.Fatalf("stream %d: got %q=%q", i, s.name, s.data)
		}
	}
	if validStreamName(strings.Repeat("a", maxXattrName)) {
		t.Fatal("over-long stream name accepted")
	}
}
