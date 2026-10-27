// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "testing"

func TestLocalPath(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\`: true, `C:\Users`: true, `d:/data`: true,
		`\\attacker\share`: false, `//attacker/share`: false, `\\?\UNC\attacker\share`: false,
		`\\?\C:\x`: false, `\\.\C:`: false, `C:`: false, `C:Users`: false, `Users`: false, ``: false,
		`/home/x`: false, `1:\x`: false,
	} {
		if got := LocalPath(p); got != want {
			t.Errorf("LocalPath(%q) = %v", p, got)
		}
	}
	for v, want := range map[string]bool{
		`C:`: true, `C:\`: true, `z:`: true,
		`C:\Users`: false, `\\.\C:`: false, `\\?\Volume{x}\`: false, `\\attacker\share`: false, ``: false,
	} {
		if got := LocalVolume(v); got != want {
			t.Errorf("LocalVolume(%q) = %v", v, got)
		}
	}
	if CheckLocalPaths("source", `C:\Users`, `\\x\y`) == nil || CheckLocalPaths("source", `C:\a`, `D:\b`) != nil {
		t.Error("CheckLocalPaths")
	}
}
