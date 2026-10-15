// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// pxar v2 split archives can be browsed and restored by PBS 3.3 and later.
const splitArchiveMajor, splitArchiveMinor = 3, 3

// pbsVersions caches the PBS version of each target. Agent polls build the
// job configuration, so lookups must be cheap and must not stall when a PBS
// is unreachable.
type pbsVersions struct {
	mu sync.Mutex
	m  map[int64]pbsVersion
}

type pbsVersion struct {
	major, minor int
	known        bool
	checked      time.Time
}

// targetVersion returns the cached PBS version of t, refreshing it hourly
// (every 5 minutes while it's unknown).
func (s *Server) targetVersion(ctx context.Context, t *Target) pbsVersion {
	s.versions.mu.Lock()
	v, ok := s.versions.m[t.ID]
	s.versions.mu.Unlock()
	if ok && (time.Since(v.checked) < time.Hour || !v.known && time.Since(v.checked) < 5*time.Minute) {
		return v
	}
	nv := pbsVersion{checked: time.Now()}
	if pc, err := s.adminClient(t); err == nil {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if info, err := pc.Version(ctx); err == nil {
			str, _ := info["version"].(string)
			if _, err := fmt.Sscanf(str, "%d.%d", &nv.major, &nv.minor); err == nil {
				nv.known = true
			}
		}
	}
	if !nv.known && ok && v.known {
		nv.major, nv.minor, nv.known = v.major, v.minor, true // keep the last good answer
	}
	s.versions.mu.Lock()
	if s.versions.m == nil {
		s.versions.m = map[int64]pbsVersion{}
	}
	s.versions.m[t.ID] = nv
	s.versions.mu.Unlock()
	return nv
}

// supportsSplitArchives reports whether a PBS version can read pxar v2.
func (v pbsVersion) supportsSplitArchives() bool {
	return v.major > splitArchiveMajor || v.major == splitArchiveMajor && v.minor >= splitArchiveMinor
}

// changeDetection is the mode sent to the agent for job j: the job's own,
// except that PBS servers before 3.3 get pxar v1 ("legacy"). An unknown
// version (PBS unreachable since the console started) keeps the job's mode;
// the backup itself would fail anyway.
func (s *Server) changeDetection(ctx context.Context, t *Target, j *Job) string {
	mode := j.ChangeDetection
	if j.Kind != "files" || mode == "" || mode == "legacy" {
		return mode
	}
	if v := s.targetVersion(ctx, t); v.known && !v.supportsSplitArchives() {
		return "legacy"
	}
	return mode
}
