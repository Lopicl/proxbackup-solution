// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "testing"

func TestExcluder(t *testing.T) {
	e := NewExcluder(append(DefaultExcludes, `**\Downloads`, "*.iso"))
	for path, want := range map[string]bool{
		"pagefile.sys":                         true,
		"Users/alice/AppData/Local/Temp/x.dat": true,
		"Users/alice/appdata/local/temp":       true, // case-insensitive
		"Users/alice/Downloads":                true,
		"Users/alice/Documents/a.ISO":          true,
		"Users/alice/Documents/report.docx":    false,
		"Windows/Temp":                         true,
		"Users/Windows/Temp":                   false, // anchored pattern
		"System Volume Information":            true,
		"Users/alice/Documents/notes.tmp":      true,
	} {
		if got := e.Match(path); got != want {
			t.Errorf("Match(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestArchiveLabel(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Users`:              "c-users",
		`C:\`:                   "c",
		`D:\Data\Projekte 2026`: "d-data-projekte-2026",
		`C:\Users\Jörg`:         "c-users-j-rg",
		`\\?\Volume{1}\x`:       "volume-1-x",
	} {
		if got := ArchiveLabel(in); got != want {
			t.Errorf("ArchiveLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
