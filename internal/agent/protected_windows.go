// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"proxbackup/internal/api"
)

// fileKey identifies a folder whatever path leads to it: case, short (8.3)
// names, another drive letter for the same volume.
type fileKey struct {
	vol uint64
	id  [16]byte
}

// protectedFolders are the folders a restore keeps out of, by fileKey, with
// their paths for messages. Restores open every folder by handle (see
// restoreRoot) and check each one, so a target like C:\ can't reach
// C:\Windows through the archive's own folders either.
type protectedFolders map[fileKey]string

const profileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// startupRel is a user's Startup folder, below the profile.
var startupRel = filepath.Join("AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")

// loadProtected finds the protected folders of this PC (the same as
// api.ProtectedFolder's, where they really are): Windows, Program Files,
// ProgramData, the agent's own folders, the Default user profile and every
// user's Startup folder. It fails if the Windows folder can't be found.
func loadProtected() (protectedFolders, error) {
	var paths []string
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_Windows, windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX64,
		windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_ProgramData} {
		if p, err := windows.KnownFolderPath(id, 0); err == nil {
			paths = append(paths, p)
		}
	}
	for _, v := range []string{"SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"} {
		if p := os.Getenv(v); p != "" {
			paths = append(paths, p)
		}
	}
	if d := os.Getenv("SystemDrive"); d != "" {
		paths = append(paths, d+`\Program Files (Arm)`)
	}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Dir(exe))
	}
	paths = append(paths, DefaultDataDir())
	if agentDataDir != "" {
		paths = append(paths, agentDataDir)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileList, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS); err == nil {
		if p := regPath(k, "Default"); p != "" {
			paths = append(paths, p)
		}
		sids, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sid := range sids {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, profileList+`\`+sid, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if p := regPath(sk, "ProfileImagePath"); p != "" {
				paths = append(paths, filepath.Join(p, startupRel))
			}
			sk.Close()
		}
	}

	pf := protectedFolders{}
	for _, p := range paths {
		h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.FILE_READ_ATTRIBUTES, shareAll, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			continue // missing (no such profile or Program Files), or unreadable while restoring as a PC user
		}
		if k, err := handleKey(h); err == nil {
			if _, ok := pf[k]; !ok {
				pf[k] = p
			}
		}
		windows.CloseHandle(h)
	}
	win, err := windows.KnownFolderPath(windows.FOLDERID_Windows, 0)
	if err != nil {
		win = os.Getenv("SystemRoot")
	}
	if !pf.has(win) {
		return nil, errors.New("can't find the Windows folder to keep the restore out of it")
	}
	return pf, nil
}

// regPath reads the folder path in the value name of k, expanding variables.
func regPath(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	if p, err := registry.ExpandString(v); err == nil {
		return p
	}
	return v
}

// has reports whether the folder p is protected.
func (pf protectedFolders) has(p string) bool {
	if p == "" {
		return false
	}
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(p), windows.FILE_READ_ATTRIBUTES, shareAll, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	k, err := handleKey(h)
	_, ok := pf[k]
	return err == nil && ok
}

// checkPath returns an error wrapping errProtected if the folder path is
// protected by its name (api.ProtectedFolder), before it is opened: a
// missing one, like a user's Startup folder, mustn't be created either.
func (pf protectedFolders) checkPath(path string) error {
	if len(pf) == 0 {
		return nil
	}
	if f := api.ProtectedFolder(path); f != "" {
		return fmt.Errorf(`%s is a %w: restoring there needs the "Restore to system folders" permission`, f, errProtected)
	}
	return nil
}

// check returns an error wrapping errProtected if the folder open as h is
// protected, or if it can't tell.
func (pf protectedFolders) check(h windows.Handle) error {
	if len(pf) == 0 {
		return nil
	}
	k, err := handleKey(h)
	if err != nil {
		return fmt.Errorf("can't check for a protected system folder: %w", err)
	}
	if p, ok := pf[k]; ok {
		return fmt.Errorf(`%s is a %w: restoring there needs the "Restore to system folders" permission`, p, errProtected)
	}
	return nil
}

// fileIDInfo is FILE_ID_INFO.
type fileIDInfo struct {
	vol uint64
	id  [16]byte
}

// handleKey returns the fileKey of the file open as h: its 128-bit ID (ReFS
// needs all of it), or the 64-bit one where that isn't available (FAT).
func handleKey(h windows.Handle) (fileKey, error) {
	var info fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err == nil {
		return fileKey(info), nil
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return fileKey{}, err
	}
	k := fileKey{vol: uint64(fi.VolumeSerialNumber)}
	for i, b := range []uint32{fi.FileIndexLow, fi.FileIndexHigh} {
		for j := range 4 {
			k.id[4*i+j] = byte(b >> (8 * j))
		}
	}
	return k, nil
}
