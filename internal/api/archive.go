// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"errors"
	"fmt"
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

// OriginPath is the path on the PC of rel (slash-separated, relative to the
// archive root) in an archive backed up from origin: OriginPath(`C:\Users`,
// "alice/Documents") = `C:\Users\alice\Documents`.
func OriginPath(origin, rel string) string {
	origin = strings.TrimRight(strings.ReplaceAll(origin, "/", `\`), `\`)
	rel = strings.Trim(strings.ReplaceAll(rel, `\`, "/"), "/")
	if rel == "" {
		if strings.HasSuffix(origin, ":") {
			return origin + `\`
		}
		return origin
	}
	return origin + `\` + strings.ReplaceAll(rel, "/", `\`)
}

// InScope relates the Windows path p to the folder scope (case-insensitive):
// within is true if p is scope or below it, ancestor if p is above scope (so
// browsing p leads to scope). An empty scope means everything is within.
// Paths with ".." segments are never within.
func InScope(p, scope string) (within, ancestor bool) {
	if scope == "" {
		return true, false
	}
	norm := func(s string) string {
		return strings.ToLower(strings.TrimRight(strings.ReplaceAll(s, "/", `\`), `\`))
	}
	p, scope = norm(p), norm(scope)
	for _, seg := range strings.Split(p, `\`) {
		if seg == ".." || seg == "." {
			return false, false
		}
	}
	switch {
	case p == scope || strings.HasPrefix(p, scope+`\`):
		return true, false
	case strings.HasPrefix(scope, p+`\`):
		return false, true
	}
	return false, false
}

// RestoreAllowed checks a restore of paths (relative to the archive root,
// empty = all of it) from an archive backed up from origin into targetDir
// against scope (empty = no restriction). Files must come from within scope
// and be written within it: either targetDir is within scope, or it is the
// original location and every path is within scope.
func RestoreAllowed(scope, origin string, paths []string, targetDir string, image bool) error {
	if scope == "" {
		return nil
	}
	if origin == "" {
		return errors.New("this archive's source is no longer in the client's jobs, so it can't be checked against your folder")
	}
	if image && len(paths) == 0 {
		return errors.New("restoring a whole volume image needs administrator rights")
	}
	if len(paths) == 0 {
		paths = []string{""}
	}
	for _, rel := range paths {
		if rel == "/" {
			rel = ""
		}
		if in, _ := InScope(OriginPath(origin, rel), scope); !in {
			return fmt.Errorf("%s is outside your folder %s", OriginPath(origin, rel), scope)
		}
	}
	if in, _ := InScope(targetDir, scope); in {
		return nil
	}
	if strings.EqualFold(strings.TrimRight(targetDir, `\/`), strings.TrimRight(OriginPath(origin, ""), `\`)) {
		return nil
	}
	return fmt.Errorf("restore to a folder within %s or to the original location", scope)
}
