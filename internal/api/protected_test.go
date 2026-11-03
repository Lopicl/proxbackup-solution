// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "testing"

func TestProtectedFolder(t *testing.T) {
	for p, want := range map[string]string{
		`C:\Windows`:                  `C:\Windows`,
		`c:/windows/system32`:         `c:\windows`,
		`C:\Program Files\ProxBackup`: `C:\Program Files`,
		`D:\Program Files (x86)\App`:  `D:\Program Files (x86)`,
		`C:\ProgramData\proxbackup`:   `C:\ProgramData`,
		`C:\Windows.\System32`:        `C:\Windows`,
		`C:\Windows \System32`:        `C:\Windows`,
		`C:\Restore\..\Windows\Temp`:  `C:\Windows`,
		`C:\.\Windows`:                `C:\Windows`,
		`C:\Users\Default\NTUSER.DAT`: `C:\Users\Default`,
		`C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x`: `C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
		`C:\`:                                    "",
		`C:\Users`:                               "",
		`C:\Users\bob\AppData\Roaming\Microsoft`: "",
		`C:\Restore\Windows`:                     "",
		`C:\WindowsApps`:                         "",
		`C:\Users\Defaults`:                      "",
		`\\server\share\Windows`:                 "",
	} {
		if got := ProtectedFolder(p); got != want {
			t.Errorf("ProtectedFolder(%q) = %q, want %q", p, got, want)
		}
	}
}
