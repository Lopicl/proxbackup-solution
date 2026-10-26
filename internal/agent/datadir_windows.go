// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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

// SecureDataDir creates dir readable by SYSTEM and Administrators only, or
// resets the owner and permissions of an existing one and everything in it.
// A data dir that is a reparse point (junction, symlink) is refused; reparse
// points and hard-linked files inside it are deleted, never followed, and
// returned in removed.
func SecureDataDir(dir string) (removed []string, err error) {
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
	s := &dirSecurer{root: root, sub: sub, file: file}
	isDir, ok, err := s.secure(dir, true)
	if err != nil {
		return nil, fmt.Errorf("secure %s: %w", dir, err)
	}
	if !ok || !isDir {
		return nil, fmt.Errorf("refusing to use %s as the data directory: it is a link or not a directory", dir)
	}
	return s.removed, s.walk(dir)
}

type dirSecurer struct {
	root, sub, file *windows.SECURITY_DESCRIPTOR
	removed         []string
}

func (s *dirSecurer) walk(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, de := range entries {
		p := filepath.Join(dir, de.Name())
		isDir, ok, err := s.secure(p, false)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("secure %s: %w", p, err))
		case !ok:
			if err := os.Remove(p); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", p, err))
			} else {
				s.removed = append(s.removed, p)
			}
		case isDir:
			if err := s.walk(p); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// secure sets the owner and DACL of p through a handle that doesn't follow
// reparse points. ok is false (and nothing is changed) for a reparse point or
// a file with more than one link; root refuses those instead.
func (s *dirSecurer) secure(p string, root bool) (isDir, ok bool, err error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p),
		windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, false, err
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return false, false, err
	}
	isDir = fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!isDir && fi.NumberOfLinks > 1) {
		return isDir, false, nil
	}
	sd := s.file
	switch {
	case root:
		sd = s.root
	case isDir:
		sd = s.sub
	}
	// Not SetSecurityInfo: on a directory it propagates the inheritable ACEs
	// to everything below, following the links this walk is about to remove.
	// Owner first: once it is Administrators, we may rewrite the DACL even
	// if a user set one that locks us out.
	if err := windows.SetKernelObjectSecurity(h, windows.OWNER_SECURITY_INFORMATION, sd); err != nil {
		return isDir, false, fmt.Errorf("set owner: %w", err)
	}
	if err := windows.SetKernelObjectSecurity(h, windows.DACL_SECURITY_INFORMATION, sd); err != nil {
		return isDir, false, fmt.Errorf("set permissions: %w", err)
	}
	return isDir, true, nil
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
