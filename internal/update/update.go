// Package update finds ProxBackup releases on GitHub and downloads their
// assets, verified against the release's SHA256SUMS file.
//
// Release layout (produced by scripts/release.sh): tag v<VERSION> with assets
//
//	proxbackup-server_<VERSION>_<arch>.deb    Debian package (amd64, arm64)
//	proxbackup-server-linux-<arch>            standalone server binary
//	proxbackup-agent-windows-<arch>.exe       Windows agent
//	SHA256SUMS                                sha256sum output for all of the above
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultRepo is the GitHub repository releases are published to.
const DefaultRepo = "Lopicl/proxbackup-solution"

// SumsAsset is the checksum file every release carries.
const SumsAsset = "SHA256SUMS"

// Version is a MAJOR.MINOR.BUILD.TOTAL version (see scripts/version.sh).
type Version [4]int

var versionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)\.(\d+)$`)

// ParseVersion accepts "1.2.3.4" or "v1.2.3.4". Development builds ("dev")
// don't parse.
func ParseVersion(s string) (Version, bool) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, false
	}
	var v Version
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3]) }

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for i := range v {
		if v[i] != o[i] {
			if v[i] < o[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Newer reports whether candidate is a newer version than current. Unparsable
// versions are never newer, and nothing is newer than a development build.
func Newer(candidate, current string) bool {
	c, ok1 := ParseVersion(candidate)
	v, ok2 := ParseVersion(current)
	return ok1 && ok2 && c.Compare(v) > 0
}

// Asset names for a version and architecture.
func DebAsset(version, arch string) string { return fmt.Sprintf("proxbackup-server_%s_%s.deb", version, arch) }
func ServerAsset(goos, arch string) string { return fmt.Sprintf("proxbackup-server-%s-%s", goos, arch) }
func AgentAsset(arch string) string        { return fmt.Sprintf("proxbackup-agent-windows-%s.exe", arch) }

// Release is the part of the GitHub release object we use.
type Release struct {
	Tag         string    `json:"tag_name"`
	Name        string    `json:"name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	Assets      []Asset   `json:"assets"`
}

// Asset is a release file.
type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

// Version is the release's version (from its tag); ok is false for tags that
// aren't ProxBackup versions.
func (r *Release) Version() (string, bool) {
	v, ok := ParseVersion(r.Tag)
	if !ok {
		return "", false
	}
	return v.String(), true
}

// Asset looks up a file by name.
func (r *Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return Asset{}, false
}

var errNotFound = errors.New("not found")

// Client talks to GitHub.
type Client struct {
	Repo string // owner/name; DefaultRepo if empty
	HTTP *http.Client
	// API is the GitHub API base URL (tests point it elsewhere).
	API string
}

func (c *Client) repo() string {
	if c.Repo != "" {
		return c.Repo
	}
	return DefaultRepo
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

func (c *Client) api() string {
	if c.API != "" {
		return strings.TrimRight(c.API, "/")
	}
	return "https://api.github.com"
}

func (c *Client) get(ctx context.Context, url string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "proxbackup-updater")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		msg := strings.TrimSpace(string(body))
		var e struct{ Message string }
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: GET %s", errNotFound, url)
		}
		return nil, fmt.Errorf("GET %s: %s: %s", url, resp.Status, msg)
	}
	return resp, nil
}

// Releases lists the repository's published releases with a valid version
// tag, newest first.
func (c *Client) Releases(ctx context.Context) ([]Release, error) {
	resp, err := c.get(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=30", c.api(), c.repo()), "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var all []Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&all); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}
	var out []Release
	for _, r := range all {
		if _, ok := r.Version(); ok && !r.Draft {
			out = append(out, r)
		}
	}
	return out, nil
}

// Latest returns the newest release by version, skipping pre-releases unless
// allowed. It returns nil (and no error) if there is none.
func (c *Client) Latest(ctx context.Context, prerelease bool) (*Release, error) {
	rs, err := c.Releases(ctx)
	if err != nil {
		return nil, err
	}
	var best *Release
	for i := range rs {
		r := &rs[i]
		if r.Prerelease && !prerelease {
			continue
		}
		if best == nil {
			best = r
			continue
		}
		v, _ := r.Version()
		b, _ := best.Version()
		if Newer(v, b) {
			best = r
		}
	}
	return best, nil
}

// ByVersion returns the release tagged v<version>.
func (c *Client) ByVersion(ctx context.Context, version string) (*Release, error) {
	resp, err := c.get(ctx, fmt.Sprintf("%s/repos/%s/releases/tags/v%s", c.api(), c.repo(), version), "application/vnd.github+json")
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("%s has no release v%s", c.repo(), version)
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&r); err != nil {
		return nil, err
	}
	if r.Draft {
		return nil, fmt.Errorf("release v%s is a draft", version)
	}
	return &r, nil
}

// Sums downloads and parses the release's SHA256SUMS: file name → hex digest.
func (c *Client) Sums(ctx context.Context, r *Release) (map[string]string, error) {
	a, ok := r.Asset(SumsAsset)
	if !ok {
		return nil, fmt.Errorf("release %s has no %s", r.Tag, SumsAsset)
	}
	resp, err := c.get(ctx, a.URL, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return ParseSums(b)
}

// ParseSums parses `sha256sum` output ("<hex>  <name>" or "<hex> *<name>").
func ParseSums(b []byte) (map[string]string, error) {
	sums := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		sum, name := strings.ToLower(f[0]), strings.TrimPrefix(f[1], "*")
		if len(sum) != 64 {
			continue
		}
		if _, err := hex.DecodeString(sum); err != nil {
			continue
		}
		sums[name] = sum
	}
	if len(sums) == 0 {
		return nil, errors.New("SHA256SUMS lists no files")
	}
	return sums, nil
}

// Download fetches asset name of release r into dir/name and verifies it
// against SHA256SUMS. An existing file with the right checksum is reused.
// It returns the path and the digest.
func (c *Client) Download(ctx context.Context, r *Release, sums map[string]string, name, dir string) (string, string, error) {
	want, ok := sums[name]
	if !ok {
		return "", "", fmt.Errorf("%s is not listed in %s of %s", name, SumsAsset, r.Tag)
	}
	dst := filepath.Join(dir, name)
	if got, err := FileSHA256(dst); err == nil && got == want {
		return dst, want, nil
	}
	a, ok := r.Asset(name)
	if !ok {
		return "", "", fmt.Errorf("release %s has no asset %s", r.Tag, name)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	resp, err := c.get(ctx, a.URL, "application/octet-stream")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(dir, name+".*.part")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 1<<30)); err != nil {
		tmp.Close()
		return "", "", fmt.Errorf("download %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", "", fmt.Errorf("%s: checksum mismatch (got %s, want %s)", name, got, want)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", "", err
	}
	return dst, want, nil
}

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
