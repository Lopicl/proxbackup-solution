//go:build windows

package agent

import (
	"io/fs"
	"os"
	"syscall"
	"time"

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
