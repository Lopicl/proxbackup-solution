// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"strings"
	"testing"
)

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

func TestQuotePath(t *testing.T) {
	for p, want := range map[string]string{
		`\\192.0.2.1\share`:  `"\\192.0.2.1\share"`,
		`C:\Users\anna`:      `"C:\Users\anna"`,
		"C:\\a\nb":           `"C:\\a\nb"`,
		`C:\say "hi"`:        `"C:\\say \"hi\""`,
		"C:\\x\u202egpj.exe": `"C:\\x\u202egpj.exe"`,
		"C:\\\xff":           `"C:\\\xff"`,
	} {
		if got := QuotePath(p); got != want {
			t.Errorf("QuotePath(%q) = %s, want %s", p, got, want)
		}
	}
	// The console sends this message as JSON; once decoded it reads as typed.
	err := CheckLocalPaths("target folder", `\\192.0.2.1\share`)
	if err == nil || !strings.Contains(err.Error(), `target folder "\\192.0.2.1\share" must be`) {
		t.Errorf("message: %v", err)
	}
}
