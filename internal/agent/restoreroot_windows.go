// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package agent

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// restoreRoot is the target folder of a restore. Restores run as SYSTEM with
// SeRestorePrivilege, often into folders where standard users can create
// junctions (C:\Restore, their own profile), so nothing below the target is
// opened by path. Each folder is opened relative to its parent's handle
// without following reparse points, and junctions and symbolic links are
// refused. Files are written, given their metadata and renamed into place
// through their own handles.
type restoreRoot struct {
	h    windows.Handle
	path string
	// The last folder opened, as archives list a folder's files together.
	lastRel string
	last    windows.Handle
}

// restoreEntry is a file or folder open below a restoreRoot. Entries from
// Create are new files under a temporary name until Commit.
type restoreEntry struct {
	f    *os.File
	h    windows.Handle
	dir  windows.Handle // folder of a new file, for Commit
	name string         // final name of a new file
}

const (
	shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	// Every open is synchronous, uses SeRestorePrivilege's access bypass and
	// opens a reparse point itself rather than what it points to.
	ntOpenOpts = windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT
	dirAccess  = windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES
	metaAccess = windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.READ_CONTROL | windows.WRITE_DAC

	// Junctions, symbolic links and other reparse points that stand for
	// another name have this tag bit.
	reparseNameSurrogate = 0x20000000
	symlinkFlagRelative  = 1

	fileRenameInformationEx = 65
)

// topLevelSDDL protects folders the agent creates directly below a drive
// root (like the default C:\Restore): only SYSTEM and administrators get in,
// instead of the Authenticated Users: Modify they would inherit from C:\.
const topLevelSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// ntCreate opens or creates name relative to the folder dir (or the file
// dir, for a ":stream" name) without following reparse points.
func ntCreate(dir windows.Handle, name string, access, disposition, options, share uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	return ntCreateRaw(dir, name, access, disposition, options|ntOpenOpts, share, sd)
}

func ntCreateRaw(dir windows.Handle, name string, access, disposition, options, share uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	u, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: dir, ObjectName: u, Attributes: windows.OBJ_CASE_INSENSITIVE, SecurityDescriptor: sd}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition, options|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if st, ok := err.(windows.NTStatus); ok {
		return 0, st.Errno()
	}
	return h, err
}

// checkName refuses names Windows can't hold or would read differently:
// ":" would address an alternate data stream, a trailing dot or space is
// dropped by most programs, and device names open devices.
func checkName(name string) error {
	bad := name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:*?"<>|`) ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ")
	for _, c := range name {
		bad = bad || c < 32
	}
	base, _, _ := strings.Cut(strings.ToUpper(name), ".")
	base = strings.TrimRight(base, " ")
	switch r := []rune(base); {
	case base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$":
		bad = true
	case len(r) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && strings.ContainsRune("0123456789¹²³", r[3]):
		bad = true
	}
	if bad {
		return fmt.Errorf("%q: %w", name, errBadName)
	}
	return nil
}

type fileAttributeTagInfo struct {
	attrs, tag uint32
}

// openChildDir opens the folder name in parent, creating it with sd if
// missing and create is set. Junctions and symbolic links are refused.
func openChildDir(parent windows.Handle, name string, create bool, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	const opts = windows.FILE_DIRECTORY_FILE
	h, err := ntCreate(parent, name, dirAccess, windows.FILE_OPEN, opts, shareAll, nil)
	if create && errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		h, err = ntCreate(parent, name, dirAccess, windows.FILE_CREATE, opts, shareAll, sd)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			h, err = ntCreate(parent, name, dirAccess, windows.FILE_OPEN, opts, shareAll, nil)
		}
	}
	if err != nil {
		return 0, err
	}
	var ti fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti))); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	if ti.attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return h, nil
	}
	defer windows.CloseHandle(h)
	if ti.tag&reparseNameSurrogate != 0 {
		return 0, errNotFollowed
	}
	// Other reparse points (OneDrive folders) are handled by their file
	// system filter: open the folder normally, provided that is still the
	// same folder.
	var want, got windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &want); err != nil {
		return 0, err
	}
	h2, err := ntCreateRaw(parent, name, dirAccess, windows.FILE_OPEN, opts|windows.FILE_OPEN_FOR_BACKUP_INTENT, shareAll, nil)
	if err != nil {
		return 0, err
	}
	if err := windows.GetFileInformationByHandle(h2, &got); err != nil || got.VolumeSerialNumber != want.VolumeSerialNumber ||
		got.FileIndexHigh != want.FileIndexHigh || got.FileIndexLow != want.FileIndexLow {
		windows.CloseHandle(h2)
		return 0, errNotFollowed
	}
	return h2, nil
}

// openRestoreRoot opens the target folder of a restore, creating it as
// needed. Every folder on the way is opened like those below it, so a
// junction anywhere in the path is refused rather than followed.
func openRestoreRoot(dir string) (*restoreRoot, error) {
	enableRestorePrivilege()
	dir = filepath.Clean(dir)
	vol := filepath.VolumeName(dir)
	if vol == "" || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("target folder %q is not a full path", dir)
	}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(vol+`\`), dirAccess, shareAll, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s\\: %w", vol, err)
	}
	p := vol + `\`
	if rest := strings.Trim(dir[len(vol):], `\`); rest != "" {
		for i, name := range strings.Split(rest, `\`) {
			p = filepath.Join(p, name)
			if err := checkName(name); err != nil {
				windows.CloseHandle(h)
				return nil, fmt.Errorf("target folder %s: %w", p, err)
			}
			var sd *windows.SECURITY_DESCRIPTOR
			if i == 0 {
				sd, _ = windows.SecurityDescriptorFromString(topLevelSDDL)
			}
			c, err := openChildDir(h, name, true, sd)
			windows.CloseHandle(h)
			if errors.Is(err, errNotFollowed) {
				return nil, fmt.Errorf("target folder: %s is a junction or symbolic link; restore to the folder it points to instead", p)
			}
			if err != nil {
				return nil, fmt.Errorf("target folder %s: %w", p, err)
			}
			h = c
		}
	}
	return &restoreRoot{h: h, path: dir}, nil
}

func (r *restoreRoot) Close() error {
	if r.last != 0 {
		windows.CloseHandle(r.last)
	}
	return windows.CloseHandle(r.h)
}

// dir opens the folder rel (relative to the root, "" for the root itself),
// creating missing folders with create.
func (r *restoreRoot) dir(rel string, create bool) (windows.Handle, error) {
	if r.last == 0 || rel != r.lastRel {
		h, err := r.walk(rel, create)
		if err != nil {
			return 0, err
		}
		if r.last != 0 {
			windows.CloseHandle(r.last)
		}
		r.last, r.lastRel = h, rel
	}
	var h windows.Handle
	p := windows.CurrentProcess()
	return h, windows.DuplicateHandle(p, r.last, p, &h, 0, false, windows.DUPLICATE_SAME_ACCESS)
}

func (r *restoreRoot) walk(rel string, create bool) (windows.Handle, error) {
	h, err := ntCreate(r.h, "", dirAccess, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, shareAll, nil)
	if err != nil || rel == "" {
		return h, err
	}
	done := ""
	for _, name := range strings.Split(rel, `\`) {
		done = filepath.Join(done, name)
		err := checkName(name)
		var c windows.Handle
		if err == nil {
			c, err = openChildDir(h, name, create, nil)
		}
		windows.CloseHandle(h)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", done, err)
		}
		h = c
	}
	return h, nil
}

func (r *restoreRoot) MkdirAll(rel string) error {
	h, err := r.dir(rel, true)
	if err == nil {
		windows.CloseHandle(h)
	}
	return err
}

// Lstat returns the modification time of rel, without following a link.
func (r *restoreRoot) Lstat(rel string) (time.Time, error) {
	parent, name := filepath.Split(rel)
	d, err := r.dir(strings.TrimSuffix(parent, `\`), false)
	if err != nil {
		return time.Time{}, err
	}
	defer windows.CloseHandle(d)
	h, err := ntCreate(d, name, windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, 0, shareAll, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, fi.LastWriteTime.Nanoseconds()), nil
}

// Open opens rel (a link itself, not its target) to set its metadata.
func (r *restoreRoot) Open(rel string) (*restoreEntry, error) {
	parent, name := filepath.Split(rel)
	d, err := r.dir(strings.TrimSuffix(parent, `\`), false)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(d)
	var h windows.Handle
	for _, access := range []uint32{metaAccess | windows.WRITE_OWNER, metaAccess, windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES} {
		if h, err = ntCreate(d, name, access, windows.FILE_OPEN, 0, shareAll, nil); err != windows.ERROR_ACCESS_DENIED {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	return &restoreEntry{f: os.NewFile(uintptr(h), rel), h: h}, nil
}

// Create creates a new file that takes the name rel on Commit, replacing
// what is there. No one else can open it until then.
func (r *restoreRoot) Create(rel string) (*restoreEntry, error) {
	parent, name := filepath.Split(rel)
	if err := checkName(name); err != nil {
		return nil, err
	}
	d, err := r.dir(strings.TrimSuffix(parent, `\`), true)
	if err != nil {
		return nil, err
	}
	tmp := fmt.Sprintf("%s.proxbackup-restore-%08x", name, rand.Uint32())
	var h windows.Handle
	for _, access := range []uint32{windows.WRITE_OWNER, 0} {
		access |= windows.GENERIC_WRITE | windows.DELETE | metaAccess
		if h, err = ntCreate(d, tmp, access, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, 0, nil); err != windows.ERROR_ACCESS_DENIED {
			break
		}
	}
	if err != nil {
		windows.CloseHandle(d)
		return nil, err
	}
	return &restoreEntry{f: os.NewFile(uintptr(h), rel), h: h, dir: d, name: name}, nil
}

// Symlink creates the symbolic link rel pointing to target, like os.Symlink.
func (r *restoreRoot) Symlink(rel, target string) error {
	parent, name := filepath.Split(rel)
	if err := checkName(name); err != nil {
		return err
	}
	d, err := r.dir(strings.TrimSuffix(parent, `\`), true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(d)
	target = strings.ReplaceAll(target, "/", `\`)
	// A link to a folder must be a directory itself.
	opts := uint32(windows.FILE_NON_DIRECTORY_FILE)
	dest := target
	if filepath.VolumeName(target) == "" {
		if strings.HasPrefix(target, `\`) {
			dest = filepath.VolumeName(r.path) + target // relative to the drive
		} else {
			dest = filepath.Join(r.path, parent, target)
		}
	}
	if fi, err := os.Stat(dest); err == nil && fi.IsDir() {
		opts = windows.FILE_DIRECTORY_FILE
	}
	h, err := ntCreate(d, name, windows.GENERIC_WRITE|windows.DELETE, windows.FILE_CREATE, opts, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	buf := symlinkReparseData(target)
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		deleteByHandle(h)
		return err
	}
	return nil
}

// symlinkReparseData is the REPARSE_DATA_BUFFER CreateSymbolicLink writes
// for target.
func symlinkReparseData(target string) []byte {
	subst, flags := target, uint32(symlinkFlagRelative)
	switch {
	case strings.HasPrefix(target, `\\?\`):
		subst, target, flags = `\??\`+target[4:], target[4:], 0
	case strings.HasPrefix(target, `\\`):
		subst, flags = `\??\UNC\`+target[2:], 0
	case len(target) >= 3 && target[1] == ':' && target[2] == '\\':
		subst, flags = `\??\`+target, 0
	}
	s, p := utf16.Encode([]rune(subst)), utf16.Encode([]rune(target))
	path := append(s, p...)
	buf := make([]byte, 20+2*len(path))
	le := func(off int, v uint32, n int) {
		for i := range n {
			buf[off+i] = byte(v >> (8 * i))
		}
	}
	le(0, windows.IO_REPARSE_TAG_SYMLINK, 4)
	le(4, uint32(len(buf)-8), 2)
	le(8, 0, 2)                 // SubstituteNameOffset
	le(10, uint32(2*len(s)), 2) // SubstituteNameLength
	le(12, uint32(2*len(s)), 2) // PrintNameOffset
	le(14, uint32(2*len(p)), 2) // PrintNameLength
	le(16, flags, 4)
	for i, c := range path {
		le(20+2*i, uint32(c), 2)
	}
	return buf
}

func (e *restoreEntry) Write(p []byte) (int, error) { return e.f.Write(p) }

func (e *restoreEntry) Close() error {
	if e.dir != 0 {
		windows.CloseHandle(e.dir)
	}
	return e.f.Close()
}

// Commit gives a new file its name, replacing what is there, and closes it.
func (e *restoreEntry) Commit() error {
	defer e.Close()
	err := renameByHandle(e.h, e.dir, e.name, windows.FILE_RENAME_REPLACE_IF_EXISTS|windows.FILE_RENAME_IGNORE_READONLY_ATTRIBUTE, fileRenameInformationEx)
	if err == windows.ERROR_INVALID_PARAMETER || err == windows.ERROR_NOT_SUPPORTED {
		// Before Windows 10 1809, or not NTFS: clear read-only by hand.
		clearReadonly(e.dir, e.name)
		err = renameByHandle(e.h, e.dir, e.name, 1, windows.FileRenameInformation)
	}
	if err != nil {
		deleteByHandle(e.h)
	}
	return err
}

// Discard deletes a new file and closes it.
func (e *restoreEntry) Discard() {
	deleteByHandle(e.h)
	e.Close()
}

type fileRenameInfo struct {
	Flags          uint32 // ReplaceIfExists for FileRenameInformation
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// renameByHandle moves the file open as h to name in the folder dir.
func renameByHandle(h, dir windows.Handle, name string, flags, class uint32) error {
	n := utf16.Encode([]rune(name))
	size := max(unsafe.Offsetof(fileRenameInfo{}.FileName)+2*uintptr(len(n)), unsafe.Sizeof(fileRenameInfo{}))
	buf := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	info.Flags, info.RootDirectory, info.FileNameLength = flags, dir, uint32(2*len(n))
	copy(unsafe.Slice(&info.FileName[0], len(n)), n)
	var iosb windows.IO_STATUS_BLOCK
	err := windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(info)), uint32(size), class)
	if st, ok := err.(windows.NTStatus); ok {
		return st.Errno()
	}
	return err
}

func deleteByHandle(h windows.Handle) {
	var iosb windows.IO_STATUS_BLOCK
	flags := uint32(windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS | windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	if windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&flags)), 4, windows.FileDispositionInformationEx) != nil {
		del := uint32(1)
		windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&del)), 4, windows.FileDispositionInformation)
	}
}

// clearReadonly clears the read-only attribute of the file name in dir so it
// can be replaced, unless it has other names: they could be anywhere.
func clearReadonly(dir windows.Handle, name string) {
	h, err := ntCreate(dir, name, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, shareAll, nil)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &fi) != nil || fi.FileAttributes&attrReadonly == 0 || fi.NumberOfLinks != 1 {
		return
	}
	info := fileBasicInfo{FileAttributes: fi.FileAttributes &^ attrReadonly}
	if info.FileAttributes == 0 {
		info.FileAttributes = windows.FILE_ATTRIBUTE_NORMAL
	}
	windows.SetFileInformationByHandle(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
}

// WriteStreams writes the alternate data streams of the entry.
func (e *restoreEntry) WriteStreams(nt ntExtras) error {
	var errs []error
	for _, s := range nt.streams {
		// OPEN_ALWAYS: CREATE_ALWAYS fails on hidden or system files. The
		// stream must share with e's own handle; a new file's is exclusive.
		h, err := ntCreate(e.h, ":"+s.name, windows.GENERIC_WRITE, windows.FILE_OPEN_IF, 0, shareAll, nil)
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

func filetime(t time.Time) int64 {
	ft := windows.NsecToFiletime(t.UnixNano())
	return int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
}

// SetMeta sets the timestamps and attributes of the entry. Set them after
// writing: writes bump the modification time.
func (e *restoreEntry) SetMeta(mtime time.Time, attrs uint32, hasAttrs bool, ctime time.Time) error {
	info := fileBasicInfo{LastWriteTime: filetime(mtime)}
	if !ctime.IsZero() {
		info.CreationTime = filetime(ctime)
	}
	if hasAttrs || attrs != 0 {
		info.FileAttributes = attrs & (attrReadonly | attrHidden | attrSystem | attrArchive | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
		if info.FileAttributes == 0 {
			info.FileAttributes = windows.FILE_ATTRIBUTE_NORMAL
		}
	}
	return windows.SetFileInformationByHandle(e.h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
}

// SetSecurity writes the backed-up security descriptor as is, with the
// inherited ACEs it had, like robocopy /SEC. Setting another owner needs
// SeRestorePrivilege (see enableRestorePrivilege); without it the group and
// DACL are still applied. The descriptor goes to this entry only, not
// inherited by what is below it.
func (e *restoreEntry) SetSecurity(nt ntExtras) error {
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
	err := windows.SetKernelObjectSecurity(e.h, all, sd)
	if err == windows.ERROR_INVALID_OWNER || err == windows.ERROR_ACCESS_DENIED || err == windows.ERROR_PRIVILEGE_NOT_HELD {
		for _, info := range []windows.SECURITY_INFORMATION{all &^ windows.OWNER_SECURITY_INFORMATION, windows.DACL_SECURITY_INFORMATION} {
			if windows.SetKernelObjectSecurity(e.h, info, sd) == nil {
				return fmt.Errorf("owner not restored: %w", err)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("permissions: %w", err)
	}
	return nil
}
