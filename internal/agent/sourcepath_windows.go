// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sourceGuard keeps a file backup from reading through a junction, symbolic
// link or mount point that a user put on the way to or below a source. The
// agent reads as SYSTEM, and users can replace folders they own with a
// junction to anything: in their profile, or in a folder created in C:\
// (which inherits Authenticated Users: Modify). A junction's target is
// read from the live drive even inside a snapshot. What the walk would read
// through it ends up under the source's own path, where its user may restore
// it from the tray. Below a source, junctions and links are listed but never
// followed (walker.addEntry). On top of that:
//
//   - On the way to the source, every folder is opened relative to its
//     parent's handle without following reparse points (openSource), so a
//     junction, symbolic link or mount point there fails the source.
//   - Without a snapshot, a user can swap a folder for a junction after it was
//     listed and before it is read. Every folder and file the walk opens is
//     then checked by its handle: its final path must be the one listed. A
//     snapshot can't change, so with VSS that isn't needed.
type sourceGuard struct {
	read  string // the cleaned path the source is read from
	final string // the source's final NT path; "" = no checks below it (snapshot)
}

// errRedirected is what the walk skips an entry with when it was swapped for
// a junction or link while the backup ran.
var errRedirected = errors.New("replaced by a junction or symbolic link during the backup; not followed")

// openSource checks the path to the source src, rel below root (the root of
// its drive, in its snapshot when the backup uses one), and returns its guard.
// With live set, the backup reads the drive itself: the guard then checks
// every folder and file below the source.
func openSource(src, root, rel string, live bool) (*sourceGuard, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(root), dirAccess, shareAll, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", root, err)
	}
	if rel != "" {
		shown := strings.ToUpper(src[:2])
		names := strings.Split(rel, `\`)
		for i, name := range names {
			shown += `\` + name
			var c windows.Handle
			if i < len(names)-1 {
				c, err = openChildDir(h, name, false, nil)
			} else {
				c, err = openSourceEntry(h, name)
			}
			windows.CloseHandle(h)
			if errors.Is(err, errNotFollowed) {
				return nil, fmt.Errorf("%s is a junction, symbolic link or mount point, which backups don't follow; back up the folder it points to instead", shown)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: %w", shown, err)
			}
			h = c
		}
	}
	defer windows.CloseHandle(h)
	g := &sourceGuard{read: filepath.Clean(root + rel)}
	if live {
		if g.final, err = finalPath(h); err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
	}
	return g, nil
}

// openSourceEntry opens name in the folder dir, a file or a folder, without
// following it. Junctions and symbolic links are refused.
func openSourceEntry(dir windows.Handle, name string) (windows.Handle, error) {
	h, err := ntCreate(dir, name, windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, 0, shareAll, nil)
	if err != nil {
		return 0, err
	}
	var ti fileAttributeTagInfo
	err = windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti)))
	if err == nil && ti.attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && ti.tag&reparseNameSurrogate != 0 {
		err = errNotFollowed
	}
	if err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// volumeNameNT asks GetFinalPathNameByHandle for the NT device path (with
// FILE_NAME_NORMALIZED, 0).
const volumeNameNT = 0x2

// finalPath returns the path of the file open as h, on its NT device
// (\Device\HarddiskVolume3\Users), after every link on the way.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameNT)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n+1)
	}
}

// live reports whether entries below the source must be checked.
func (g *sourceGuard) live() bool { return g != nil && g.final != "" }

// check returns errRedirected unless the file open as h is the one at p, a
// path at or below the source, rather than what a junction put in its way.
func (g *sourceGuard) check(h windows.Handle, p string) error {
	if !g.live() {
		return nil
	}
	p = filepath.Clean(p)
	rel, ok := strings.CutPrefix(p, g.read)
	if !ok || rel != "" && !strings.HasPrefix(rel, `\`) && !strings.HasSuffix(g.read, `\`) {
		return errRedirected
	}
	want := strings.TrimRight(g.final, `\`)
	if rel = strings.Trim(rel, `\`); rel != "" {
		want += `\` + rel
	}
	got, err := finalPath(h)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimRight(got, `\`), want) {
		return errRedirected
	}
	return nil
}

// checkFile is check for an open file.
func (g *sourceGuard) checkFile(f *os.File, p string) error {
	if !g.live() {
		return nil
	}
	return g.check(windows.Handle(f.Fd()), p)
}

// sameFile reports whether a and b are open on the same file (a stream of
// it, for instance).
func sameFile(a, b windows.Handle) bool {
	var fa, fb windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(a, &fa) == nil && windows.GetFileInformationByHandle(b, &fb) == nil &&
		fa.VolumeSerialNumber == fb.VolumeSerialNumber && fa.FileIndexHigh == fb.FileIndexHigh && fa.FileIndexLow == fb.FileIndexLow
}
