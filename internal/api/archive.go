// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"regexp"
	"strconv"
	"strings"
)

var archiveUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// ArchiveLabel turns a source path into an archive base name:
// `C:\Users\Alice` → "c-users-alice", `C:\` → "c".
func ArchiveLabel(src string) string {
	s := strings.ToLower(strings.ReplaceAll(src, `\`, "/"))
	s = strings.ReplaceAll(s, ":", "")
	s = archiveUnsafe.ReplaceAllString(strings.Trim(s, "/"), "-")
	s = strings.Trim(strings.ReplaceAll(s, "/", "-"), "-.")
	if s == "" {
		s = "root"
	}
	if c := s[0]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
		s = "x" + s
	}
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

// SourceArchives maps the archives a files job with these sources writes
// (both the legacy .pxar.didx and the split .mpxar.didx name) to their source.
func SourceArchives(sources []string) map[string]string {
	m := map[string]string{}
	seen := map[string]int{}
	for _, src := range sources {
		label := ArchiveLabel(src)
		if n := seen[label]; n > 0 {
			label += "-" + strconv.Itoa(n+1)
		}
		seen[label]++
		m[label+".pxar.didx"] = src
		m[label+".mpxar.didx"] = src
	}
	return m
}

// VolumeArchive is the archive a volume image job writes for volume v.
func VolumeArchive(v string) string { return "drive-" + ArchiveLabel(v) + ".img.fidx" }
