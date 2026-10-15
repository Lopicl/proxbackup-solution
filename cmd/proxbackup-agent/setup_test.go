// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/url"
	"testing"
)

func TestConsoleURL(t *testing.T) {
	base, _ := url.Parse("https://backup.example.com:8077")
	for in, want := range map[string]string{
		"10.0.0.5":                 "https://10.0.0.5:8077",
		"10.0.0.5:9000":            "https://10.0.0.5:9000",
		"pbs.lan":                  "https://pbs.lan:8077",
		"fd00::5":                  "https://[fd00::5]:8077",
		"[fd00::5]:9000":           "https://[fd00::5]:9000",
		"https://other.example:1/": "https://other.example:1",
	} {
		if got, err := consoleURL(base, in); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := consoleURL(base, " "); err == nil {
		t.Error("empty host accepted")
	}
}
