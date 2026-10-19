// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "testing"

func TestSourceArchives(t *testing.T) {
	m := SourceArchives([]string{`C:\Users`, `C:/users`, `D:\`})
	want := map[string]string{
		"c-users.pxar.didx": `C:\Users`, "c-users.mpxar.didx": `C:\Users`,
		"c-users-2.pxar.didx": `C:/users`, "c-users-2.mpxar.didx": `C:/users`,
		"d.pxar.didx": `D:\`, "d.mpxar.didx": `D:\`,
	}
	if len(m) != len(want) {
		t.Fatalf("got %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
	if got := VolumeArchive("C:"); got != "drive-c.img.fidx" {
		t.Errorf("VolumeArchive = %q", got)
	}
}

func TestInScope(t *testing.T) {
	const scope = `C:\Users\Alice`
	for _, c := range []struct {
		p                string
		within, ancestor bool
	}{
		{`C:\Users\Alice`, true, false},
		{`c:\users\alice\Documents\x.txt`, true, false},
		{`C:\Users\Alice\`, true, false},
		{`C:\Users`, false, true},
		{`C:\`, false, true},
		{`C:\Users\Alice2`, false, false},
		{`C:\Users\Bob\Documents`, false, false},
		{`C:\Users\Alice\..\Bob`, false, false},
		{`D:\Users\Alice`, false, false},
	} {
		w, a := InScope(c.p, scope)
		if w != c.within || a != c.ancestor {
			t.Errorf("InScope(%q) = %v, %v; want %v, %v", c.p, w, a, c.within, c.ancestor)
		}
	}
	if w, _ := InScope(`D:\anything`, ""); !w {
		t.Error("empty scope must allow everything")
	}
}

func TestRestoreAllowed(t *testing.T) {
	const scope = `C:\Users\Alice`
	for _, c := range []struct {
		origin, target string
		paths          []string
		image, ok      bool
	}{
		{`C:\Users`, `C:\Users`, []string{"Alice/Documents"}, false, true},                // original location
		{`C:\Users`, `C:\Users\Alice\Restored`, []string{"Alice/Documents"}, false, true}, // own folder
		{`C:\Users`, `C:\Users`, []string{"Bob/Documents"}, false, false},                 // someone else's files
		{`C:\Users`, `C:\Users`, nil, false, false},                                       // the whole archive
		{`C:\Users\Alice\Documents`, `C:\Users\Alice\Documents`, nil, false, true},        // archive within the folder
		{`C:\Users`, `C:\Windows\System32`, []string{"Alice/Documents"}, false, false},    // writing elsewhere
		{`C:\Users`, `C:\Users\Alice\..\Bob`, []string{"Alice/x"}, false, false},          // dot-dot
		{`C:\`, `C:\`, []string{"Users/Alice/Desktop"}, true, true},                       // file from an image
		{`C:\`, `C:\Users\Alice\img`, nil, true, false},                                   // raw image
		{`C:\`, `C:\`, []string{"/"}, true, false},                                        // every file of the volume
		{"", `C:\Users\Alice\x`, []string{"Alice"}, false, false},                         // unknown origin
	} {
		err := RestoreAllowed(scope, c.origin, c.paths, c.target, c.image)
		if (err == nil) != c.ok {
			t.Errorf("RestoreAllowed(%q, %v → %q) = %v, want ok=%v", c.origin, c.paths, c.target, err, c.ok)
		}
	}
	if err := RestoreAllowed("", "", nil, `C:\Windows`, true); err != nil {
		t.Errorf("admins (empty scope) are unrestricted: %v", err)
	}
}
