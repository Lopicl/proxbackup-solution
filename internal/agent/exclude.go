package agent

import (
	"path"
	"regexp"
	"strings"
)

// DefaultExcludes are always applied to Windows file backups unless disabled.
var DefaultExcludes = []string{
	"pagefile.sys", "hiberfil.sys", "swapfile.sys", "DumpStack.log.tmp",
	"System Volume Information", "$Recycle.Bin", "$WinREAgent",
	"Windows/Temp", "**/AppData/Local/Temp", "**/AppData/Local/Microsoft/Windows/INetCache",
	"**/AppData/Local/Packages/*/AC/INetCache", "**/AppData/Local/CrashDumps",
	"Windows/SoftwareDistribution/Download", "ProgramData/Microsoft/Windows Defender/Scans",
	"**/node_modules/.cache", "**/*.tmp",
}

// Excluder matches archive-relative, slash-separated paths case-insensitively.
//
// Pattern rules (gitignore-like, simplified):
//   - a pattern without '/' matches the base name at any depth ("*.tmp", "Thumbs.db")
//   - a pattern with '/' is anchored at the source root ("Windows/Temp")
//   - "**" matches any number of path segments ("**/AppData/Local/Temp")
//   - a matching directory excludes everything below it
type Excluder struct {
	base  []*regexp.Regexp
	paths []*regexp.Regexp
}

// NewExcluder compiles patterns; backslashes are treated as separators.
func NewExcluder(patterns []string) *Excluder {
	e := &Excluder{}
	for _, p := range patterns {
		p = strings.Trim(strings.ReplaceAll(strings.TrimSpace(p), `\`, "/"), "/")
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		re := regexp.MustCompile("(?i)^" + globToRegexp(p) + "$")
		if strings.Contains(p, "/") {
			e.paths = append(e.paths, re)
		} else {
			e.base = append(e.base, re)
		}
	}
	return e
}

// Match reports whether rel (relative to the source root) or one of its
// ancestor directories is excluded.
func (e *Excluder) Match(rel string) bool {
	for p := rel; p != "." && p != "/" && p != ""; p = path.Dir(p) {
		if e.MatchEntry(p) {
			return true
		}
	}
	return false
}

// MatchEntry checks rel itself only. The walker uses it because it never
// descends into excluded directories, so ancestors are already known to be included.
func (e *Excluder) MatchEntry(rel string) bool {
	if e == nil {
		return false
	}
	base := path.Base(rel)
	for _, re := range e.base {
		if re.MatchString(base) {
			return true
		}
	}
	for _, re := range e.paths {
		if re.MatchString(rel) {
			return true
		}
	}
	return false
}

func globToRegexp(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '*' && i+1 < len(p) && p[i+1] == '*':
			i++
			if i+1 < len(p) && p[i+1] == '/' {
				i++
				b.WriteString("(?:.*/)?")
			} else {
				b.WriteString(".*")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

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
