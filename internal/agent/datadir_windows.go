// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The data dir holds the agent's key, PBS tokens and encryption keys, and a
// spool the agent trusts: only SYSTEM and Administrators may touch it. Go's
// mode bits do nothing on Windows, and ProgramData lets every user read its
// subfolders and create files in them.
const (
	dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// What the entries below it inherit, set explicitly: the walk uses the
	// low-level call that neither computes nor propagates inheritance.
	dataSubdirSDDL = "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)"
	dataFileSDDL   = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
)

// programData is the ProgramData folder as the system configures it
// (HKLM). %ProgramData% comes from the caller's environment, which an
// unelevated process can change in HKCU\Environment before an admin's
// elevated setup reads it, and steer the data dir somewhere it can write.
func programData() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0); err == nil && p != "" {
		return p
	}
	return `C:\ProgramData`
}

// SecureDataDir creates dir readable by SYSTEM and Administrators only, or
// resets the owner and permissions of an existing one and everything in it.
//
// Windows checks access when a handle is opened: new permissions don't take
// away what a user opened before. So a data dir that is a link, or that
// SYSTEM or Administrators don't own, is refused: a user who created it may
// keep a handle that can change its permissions (PrepareDataDir moves such a
// dir aside at enrollment). Inside it, reparse points, hard-linked files and
// entries owned by anyone else are deleted, never followed, and returned in
// removed. start (the service starting) also deletes leftover temporary files.
func SecureDataDir(dir string, start bool) (removed []RemovedEntry, err error) {
	enableOwnerPrivileges()
	root, err := sddlSD(dataDirSDDL)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: root}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	if err := windows.CreateDirectory(windows.StringToUTF16Ptr(dir), sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	sub, err := sddlSD(dataSubdirSDDL)
	if err != nil {
		return nil, err
	}
	file, err := sddlSD(dataFileSDDL)
	if err != nil {
		return nil, err
	}
	s := &dirSecurer{root: root, sub: sub, file: file, start: start}
	h, e, err := s.secure(0, dir, true)
	if err != nil {
		return nil, fmt.Errorf("secure %s: %w", dir, err)
	}
	defer windows.CloseHandle(h)
	if why := e.foreign(); why != "" {
		return nil, fmt.Errorf("refusing to use %s as the data directory: %s; enroll this PC again to replace it", dir, why)
	}
	d, err := reopen(h, dirAccess, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	defer windows.CloseHandle(d)
	err = s.walk(d, dir, false)
	return s.removed, err
}

// PrepareDataDir makes sure an enrollment writes into a data dir the agent
// created. An existing one that is a link, that SYSTEM or Administrators don't
// own, or that holds files but no agent.json is moved aside to
// <dir>.untrusted-<time> (aside; why says what was wrong with it): handles a
// user opened in it stay with the moved folder. Windows can't move a folder
// while a file in it is open, so that fails until the program holding it
// exits.
func PrepareDataDir(dir string) (aside, why string, err error) {
	enableOwnerPrivileges()
	if why, err = foreignDataDir(dir); err != nil || why == "" {
		return "", why, err
	}
	base := dir + ".untrusted-" + time.Now().Format("20060102-150405")
	for i := 0; ; i++ {
		aside = base
		if i > 0 {
			aside += "-" + randomHex(2)
		}
		// Without MOVEFILE_REPLACE_EXISTING; a link is moved, not followed.
		err = windows.MoveFileEx(windows.StringToUTF16Ptr(dir), windows.StringToUTF16Ptr(aside), 0)
		if (err != windows.ERROR_ALREADY_EXISTS && err != windows.ERROR_FILE_EXISTS) || i == 5 {
			break
		}
	}
	if err != nil {
		return "", why, fmt.Errorf("%s can't be used as the data directory (%s) and moving it aside failed; "+
			"if another user's program has files in it open, sign that user out or restart the PC, then try again: %w", dir, why, err)
	}
	return aside, why, nil
}

// foreignDataDir is why dir can't take an enrollment ("" = it can, or it
// doesn't exist).
func foreignDataDir(dir string) (string, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(dir), windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("open %s: %w", dir, err)
	}
	e, err := inspect(h)
	windows.CloseHandle(h)
	if err != nil {
		return "", fmt.Errorf("inspect %s: %w", dir, err)
	}
	if why := e.foreign(); why != "" {
		return why, nil
	}
	// One the agent created and secured but didn't enroll in (an earlier
	// try that failed) is empty.
	if fi, err := os.Lstat(filepath.Join(dir, "agent.json")); err == nil && fi.Mode().IsRegular() {
		return "", nil
	}
	if f, err := os.Open(dir); err == nil {
		names, _ := f.Readdirnames(1)
		f.Close()
		if len(names) == 0 {
			return "", nil
		}
	}
	return "it holds files but no agent.json", nil
}

// readSecret reads a file of the data dir. It fails while another program has
// the file open for writing: a handle a user opened before the data dir was
// secured keeps its access (see SecureDataDir).
func readSecret(p string) ([]byte, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err == windows.ERROR_SHARING_VIOLATION {
		err = fmt.Errorf("another program has it open for writing: %w", err)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(h), p)
	defer f.Close()
	return io.ReadAll(f)
}

type dirSecurer struct {
	root, sub, file *windows.SECURITY_DESCRIPTOR
	start           bool
	removed         []RemovedEntry
}

// walk secures the entries of the folder open as d (at path dir, for
// messages) and deletes those that must go. drop deletes them all: d is
// being removed. Nothing is opened, listed or deleted by path: a user who
// planted a folder could otherwise swap it for a junction between a check
// and the next use, and have SYSTEM delete files anywhere. Each entry is
// opened relative to d without following reparse points, then listed and
// deleted through its own handle.
func (s *dirSecurer) walk(d windows.Handle, dir string, drop bool) error {
	names, err := listDir(d)
	if err != nil {
		return fmt.Errorf("list %s: %w", dir, err)
	}
	var errs []error
	for _, name := range names {
		if err := s.walkEntry(d, dir, name, drop); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *dirSecurer) walkEntry(d windows.Handle, dir, name string, drop bool) error {
	p := filepath.Join(dir, name)
	h, e, err := s.secure(d, name, false)
	if err != nil {
		return fmt.Errorf("secure %s: %w", p, err)
	}
	defer windows.CloseHandle(h)
	if testAfterSecure != nil {
		testAfterSecure(p)
	}
	why := ""
	switch {
	case e.link:
		why = removedLink
	case drop || !e.trusted():
		why = removedForeign
	case s.start && !e.isDir && isTempName(name):
		why = removedTemp
	}
	if e.isDir && !e.link {
		sub, err := reopen(h, dirAccess, windows.FILE_DIRECTORY_FILE)
		if err != nil {
			return fmt.Errorf("open %s: %w", p, err)
		}
		err = s.walk(sub, p, why != "")
		windows.CloseHandle(sub)
		if err != nil {
			return err
		}
	}
	if why == "" {
		return nil
	}
	del, err := reopen(h, windows.DELETE, 0)
	if err == nil {
		err = deleteByHandle(del)
		windows.CloseHandle(del)
	}
	if err != nil {
		return fmt.Errorf("remove %s: %w", p, err)
	}
	s.removed = append(s.removed, RemovedEntry{p, why})
	return nil
}

// testAfterSecure lets tests act between securing an entry and using it.
var testAfterSecure func(p string)

// reopen opens the file or folder open as h again, with other access. It
// is the same object whatever has been renamed meanwhile: an empty name
// relative to a handle names that handle's file.
func reopen(h windows.Handle, access, options uint32) (windows.Handle, error) {
	return ntCreate(h, "", access, windows.FILE_OPEN, options, shareAll, nil)
}

// listDir returns the names in the folder open as d, which needs
// FILE_LIST_DIRECTORY and synchronous I/O.
func listDir(d windows.Handle) ([]string, error) {
	// FILE_FULL_DIR_INFO: NextEntryOffset at 0, FileNameLength at 60 and
	// FileName at 68 (bytes).
	const nameLenOff, nameOff = 60, 68
	buf := make([]uint64, 8<<10) // 64 KiB, 8-byte aligned
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8)
	var names []string
	class := uint32(windows.FileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(d, class, &b[0], uint32(len(b)))
		if err == windows.ERROR_NO_MORE_FILES {
			slices.Sort(names)
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		class = windows.FileFullDirectoryInfo
		for off := uint32(0); ; {
			next := *(*uint32)(unsafe.Pointer(&b[off]))
			n := *(*uint32)(unsafe.Pointer(&b[off+nameLenOff])) / 2
			name := string(utf16.Decode(unsafe.Slice((*uint16)(unsafe.Pointer(&b[off+nameOff])), n)))
			if name != "." && name != ".." {
				names = append(names, name)
			}
			if next == 0 {
				break
			}
			off += next
		}
	}
}

// secure opens name in the folder d (the path name itself for the root,
// d = 0) without following reparse points, and sets its owner and DACL
// through that handle. Nothing is changed on a link (a reparse point, or a
// file with more than one link), nor on a root that is foreign. The handle
// stays open for the caller to close.
func (s *dirSecurer) secure(d windows.Handle, name string, root bool) (windows.Handle, dataEntry, error) {
	const access = windows.READ_CONTROL | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_READ_ATTRIBUTES
	var h windows.Handle
	var err error
	if root {
		h, err = windows.CreateFile(windows.StringToUTF16Ptr(name), access, shareAll, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	} else {
		h, err = ntCreate(d, name, access, windows.FILE_OPEN, 0, shareAll, nil)
	}
	if err != nil {
		return 0, dataEntry{}, err
	}
	e, err := s.setSecurity(h, root)
	if err != nil {
		windows.CloseHandle(h)
		return 0, e, err
	}
	return h, e, nil
}

func (s *dirSecurer) setSecurity(h windows.Handle, root bool) (dataEntry, error) {
	e, err := inspect(h)
	if err != nil || e.link || (root && e.foreign() != "") {
		return e, err
	}
	sd := s.file
	switch {
	case root:
		sd = s.root
	case e.isDir:
		sd = s.sub
	}
	// Not SetSecurityInfo: on a directory it propagates the inheritable ACEs
	// to everything below, following the links this walk is about to remove.
	// Owner first: once it is Administrators, we may rewrite the DACL even
	// if a user set one that locks us out.
	if err := windows.SetKernelObjectSecurity(h, windows.OWNER_SECURITY_INFORMATION, sd); err != nil {
		return e, fmt.Errorf("set owner: %w", err)
	}
	if err := windows.SetKernelObjectSecurity(h, windows.DACL_SECURITY_INFORMATION, sd); err != nil {
		return e, fmt.Errorf("set permissions: %w", err)
	}
	return e, nil
}

// dataEntry is what inspect found out about an entry of the data dir.
type dataEntry struct {
	isDir bool
	link  bool         // a reparse point, or a file with more than one link
	owner *windows.SID // nil for a link
}

// inspect reads the kind and owner of the file or directory open as h.
func inspect(h windows.Handle) (dataEntry, error) {
	var e dataEntry
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return e, err
	}
	e.isDir = fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!e.isDir && fi.NumberOfLinks > 1) {
		e.link = true
		return e, nil
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return e, fmt.Errorf("read owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return e, fmt.Errorf("read owner: %w", err)
	}
	if owner != nil {
		e.owner, err = owner.Copy()
	}
	return e, err
}

// trusted reports whether SYSTEM or Administrators own e. Standard users
// can't give those ownership; whoever else created it may hold handles that
// keep their access.
func (e dataEntry) trusted() bool {
	return e.owner != nil && (e.owner.IsWellKnown(windows.WinLocalSystemSid) || e.owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// foreign is why e can't be the data dir ("" = it can).
func (e dataEntry) foreign() string {
	switch {
	case e.link:
		return "it is a link"
	case !e.isDir:
		return "it is not a directory"
	case !e.trusted():
		return "it belongs to " + accountName(e.owner) + ", not to SYSTEM or Administrators"
	}
	return ""
}

func accountName(sid *windows.SID) string {
	if sid == nil {
		return "nobody"
	}
	account, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil:
		return sid.String()
	case domain != "":
		return domain + `\` + account
	}
	return account
}

func sddlSD(sddl string) (*windows.SECURITY_DESCRIPTOR, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("security descriptor %q: %w", sddl, err)
	}
	// Without the request bit, the system drops SE_DACL_AUTO_INHERITED.
	sd.SetControl(windows.SE_DACL_AUTO_INHERIT_REQ, windows.SE_DACL_AUTO_INHERIT_REQ)
	return sd, nil
}

var ownerPrivileges sync.Once

// enableOwnerPrivileges lets the process open any file in the data dir for
// changing its security and set Administrators as owner, whatever a user
// did to it. SYSTEM and elevated administrators hold these privileges.
func enableOwnerPrivileges() {
	ownerPrivileges.Do(func() {
		var tok windows.Token
		if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok) != nil {
			return
		}
		defer tok.Close()
		for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
			tp := windows.Tokenprivileges{PrivilegeCount: 1}
			if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &tp.Privileges[0].Luid) != nil {
				continue
			}
			tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
			windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
		}
	})
}
