// SPDX-License-Identifier: AGPL-3.0-or-later

package ipc

import "testing"

func TestCheckRestoreURL(t *testing.T) {
	const console = "https://Console.example:8443"
	for _, u := range []string{
		"https://console.example:8077/#/restore/abc",
		"https://console.example/#/restore/abc",
		"https://CONSOLE.example:8443/#/restore/abc",
	} {
		if got, err := CheckRestoreURL(u, console); err != nil || got == "" {
			t.Errorf("%s: %q %v", u, got, err)
		}
	}
	for _, u := range []string{
		"",
		`\\192.0.2.1\share\evil.exe`,
		`C:\Windows\System32\calc.exe`,
		"calc.exe",
		"file:///C:/Windows/System32/calc.exe",
		"http://console.example/#/restore/abc",
		"https://user:pw@console.example/#/restore/abc",
		"https://evil.example/#/restore/abc",
		"https://console.example.evil.example/",
		"https:console.example",
		"ms-settings:",
	} {
		if got, err := CheckRestoreURL(u, console); err == nil {
			t.Errorf("%q accepted as %q", u, got)
		}
	}
	// Without the console's URL only the form is checked.
	if _, err := CheckRestoreURL("https://elsewhere.example/x", ""); err != nil {
		t.Error(err)
	}
	if _, err := CheckRestoreURL(`\\192.0.2.1\share`, ""); err == nil {
		t.Error("UNC path accepted")
	}
}
