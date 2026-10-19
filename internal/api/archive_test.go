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
