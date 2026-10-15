// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package agent

import (
	"io/fs"
	"os"
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

// changeTime returns the NTFS ChangeTime of p, or the zero time.
func changeTime(p string) time.Time {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(h)
	var info fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return time.Time{}
	}
	ft := windows.Filetime{LowDateTime: uint32(info.ChangeTime), HighDateTime: uint32(info.ChangeTime >> 32)}
	return time.Unix(0, ft.Nanoseconds())
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
