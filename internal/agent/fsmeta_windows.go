// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func statMeta(fi fs.FileInfo) winMeta {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return winMeta{mtime: fi.ModTime()}
	}
	return winMeta{
		attrs: d.FileAttributes,
		ctime: time.Unix(0, d.CreationTime.Nanoseconds()),
		mtime: time.Unix(0, d.LastWriteTime.Nanoseconds()),
		cloudPlaceholder: d.FileAttributes&(attrRecallOnDataAccess|attrRecallOnOpen|attrOffline) != 0 &&
			d.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0,
	}
}

// fileBasicInfo is FILE_BASIC_INFO; times are FILETIMEs.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

// longPath lets CreateFile open drive paths longer than MAX_PATH; the os
// package does the same internally.
func longPath(p string) string {
	if len(p) < 248 || strings.HasPrefix(p, `\\`) || !filepath.IsAbs(p) {
		return p
	}
	return `\\?\` + p
}

// readExtras fills in the security descriptor, the alternate data streams
// and, with withChtime, the NTFS ChangeTime of p. It returns what couldn't be
// read; the entry is still backed up.
func readExtras(p string, m *winMeta, withChtime bool) (warns []string) {
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	lp := windows.StringToUTF16Ptr(longPath(p))
	h, err := windows.CreateFile(lp, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING, flags, 0)
	withSD := err == nil
	if err != nil {
		warns = append(warns, fmt.Sprintf("security descriptor: %v", err))
		if h, err = windows.CreateFile(lp, windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING, flags, 0); err != nil {
			return warns
		}
	}
	defer windows.CloseHandle(h)
	if withChtime {
		var info fileBasicInfo
		if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
			ft := windows.Filetime{LowDateTime: uint32(info.ChangeTime), HighDateTime: uint32(info.ChangeTime >> 32)}
			m.chtime = time.Unix(0, ft.Nanoseconds())
		}
	}
	if withSD {
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			warns = append(warns, fmt.Sprintf("security descriptor: %v", err))
		} else {
			m.nt.sd = bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length()))
		}
	}
	names, err := streamNames(h)
	if err != nil {
		return append(warns, fmt.Sprintf("alternate data streams: %v", err))
	}
	for _, n := range names {
		switch {
		case !validStreamName(n.name):
			warns = append(warns, fmt.Sprintf("alternate data stream %q: name not supported", n.name))
		case n.size > maxADSSize:
			warns = append(warns, fmt.Sprintf("alternate data stream %q: %d bytes, larger than %d", n.name, n.size, maxADSSize))
		default:
			data, err := readStream(p, n.name)
			if err != nil {
				warns = append(warns, fmt.Sprintf("alternate data stream %q: %v", n.name, err))
				continue
			}
			m.nt.streams = append(m.nt.streams, adsStream{n.name, data})
		}
	}
	return warns
}

type streamName struct {
	name string
	size int64
}

// streamNames lists the named data streams of the file open as h.
func streamNames(h windows.Handle) ([]streamName, error) {
	buf := make([]uint64, 512) // FILE_STREAM_INFO entries are 8-byte aligned
	for {
		err := windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, (*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8))
		if err == windows.ERROR_HANDLE_EOF {
			return nil, nil // no data streams at all (directories)
		}
		if err == windows.ERROR_MORE_DATA && len(buf) < 1<<20 {
			buf = make([]uint64, len(buf)*4)
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	var out []streamName
	for off := 0; off+24 <= len(b); {
		next := binary.LittleEndian.Uint32(b[off:])
		nlen := int(binary.LittleEndian.Uint32(b[off+4:]))
		size := int64(binary.LittleEndian.Uint64(b[off+8:]))
		if off+24+nlen > len(b) {
			break
		}
		u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[off+24])), nlen/2)
		// ":name:$DATA"; the unnamed main stream is "::$DATA".
		full := windows.UTF16ToString(u)
		if name, ok := strings.CutSuffix(strings.TrimPrefix(full, ":"), ":$DATA"); ok && name != "" {
			out = append(out, streamName{name, size})
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out, nil
}

func readStream(p, name string) ([]byte, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(longPath(p)+":"+name), windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), name)
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxADSSize+1))
	if err == nil && len(data) > maxADSSize {
		err = fmt.Errorf("larger than %d bytes", maxADSSize)
	}
	return data, err
}

// writeStreams writes the alternate data streams of a restored file or folder.
func writeStreams(p string, nt ntExtras) error {
	var errs []error
	for _, s := range nt.streams {
		// OPEN_ALWAYS: CREATE_ALWAYS fails on hidden or system files.
		h, err := windows.CreateFile(windows.StringToUTF16Ptr(longPath(p)+":"+s.name), windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_ALWAYS, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("stream %s: %w", s.name, err))
			continue
		}
		f := os.NewFile(uintptr(h), s.name)
		err = f.Truncate(0)
		if err == nil {
			_, err = f.Write(s.data)
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("stream %s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}

var procSetFileSecurityW = windows.NewLazySystemDLL("advapi32.dll").NewProc("SetFileSecurityW")

func setFileSecurity(p string, info windows.SECURITY_INFORMATION, sd *windows.SECURITY_DESCRIPTOR) error {
	r, _, err := procSetFileSecurityW.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(longPath(p)))), uintptr(info), uintptr(unsafe.Pointer(sd)))
	if r == 0 {
		return err
	}
	return nil
}

// applySecurity writes the backed-up security descriptor as is, with the
// inherited ACEs it had, like robocopy /SEC. Setting another owner needs
// SeRestorePrivilege (see enableRestorePrivilege); without it the group and
// DACL are still applied.
func applySecurity(p string, nt ntExtras) error {
	if len(nt.sd) == 0 {
		return nil
	}
	// Copy into an aligned buffer: the xattr value sits anywhere in the archive.
	buf := make([]uint64, (len(nt.sd)+7)/8)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(nt.sd)), nt.sd)
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
	if !sd.IsValid() {
		return errors.New("invalid security descriptor")
	}
	// Without the request bit, the system drops SE_DACL_AUTO_INHERITED.
	if ctl, _, err := sd.Control(); err == nil && ctl&windows.SE_DACL_AUTO_INHERITED != 0 {
		sd.SetControl(windows.SE_DACL_AUTO_INHERIT_REQ, windows.SE_DACL_AUTO_INHERIT_REQ)
	}
	all := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	err := setFileSecurity(p, all, sd)
	if err == windows.ERROR_INVALID_OWNER || err == windows.ERROR_ACCESS_DENIED || err == windows.ERROR_PRIVILEGE_NOT_HELD {
		if err2 := setFileSecurity(p, all&^windows.OWNER_SECURITY_INFORMATION, sd); err2 == nil {
			return fmt.Errorf("owner not restored: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("permissions: %w", err)
	}
	return nil
}

var restorePrivilege sync.Once

// enableRestorePrivilege enables SeRestorePrivilege for the process, so
// restores can set any owner. The service account and elevated
// administrators hold it; for others restores keep the owner they get.
func enableRestorePrivilege() {
	restorePrivilege.Do(func() {
		var tok windows.Token
		if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok) != nil {
			return
		}
		defer tok.Close()
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &tp.Privileges[0].Luid) != nil {
			return
		}
		tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
		windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	})
}

// applyMeta restores timestamps and attributes after a file was written.
func applyMeta(p string, mtime time.Time, attrs uint32, hasAttrs bool, ctime time.Time) error {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		mt := windows.NsecToFiletime(mtime.UnixNano())
		var ct *windows.Filetime
		if !ctime.IsZero() {
			c := windows.NsecToFiletime(ctime.UnixNano())
			ct = &c
		}
		err = windows.SetFileTime(h, ct, nil, &mt)
		windows.CloseHandle(h)
	}
	if err != nil {
		err = os.Chtimes(p, mtime, mtime)
	}
	if hasAttrs || attrs != 0 {
		keep := attrs & (attrReadonly | attrHidden | attrSystem | attrArchive | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
		if keep == 0 {
			keep = windows.FILE_ATTRIBUTE_NORMAL
		}
		if aerr := windows.SetFileAttributes(windows.StringToUTF16Ptr(p), keep); aerr != nil && err == nil {
			err = aerr
		}
	}
	return err
}
