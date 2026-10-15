// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"testing"
	"time"
)

func TestChangeDetectionFallsBackForOldPBS(t *testing.T) {
	s := &Server{}
	tgt := &Target{ID: 1}
	seed := func(major, minor int, known bool) {
		s.versions.m = map[int64]pbsVersion{1: {major: major, minor: minor, known: known, checked: time.Now()}}
	}
	files := &Job{Kind: "files", ChangeDetection: "metadata"}
	cases := []struct {
		major, minor int
		known        bool
		job          *Job
		want         string
	}{
		{4, 2, true, files, "metadata"},
		{3, 3, true, files, "metadata"},
		{3, 2, true, files, "legacy"},
		{2, 4, true, &Job{Kind: "files", ChangeDetection: "data"}, "legacy"},
		{3, 2, false, files, "metadata"}, // unknown version: keep the job's mode
		{3, 2, true, &Job{Kind: "files", ChangeDetection: "legacy"}, "legacy"},
		{3, 2, true, &Job{Kind: "image"}, ""},
	}
	for _, c := range cases {
		seed(c.major, c.minor, c.known)
		if got := s.changeDetection(context.Background(), tgt, c.job); got != c.want {
			t.Errorf("PBS %d.%d (known %v), %s/%q: got %q, want %q", c.major, c.minor, c.known, c.job.Kind, c.job.ChangeDetection, got, c.want)
		}
	}
}
