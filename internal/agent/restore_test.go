// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"path/filepath"
	"testing"
)

func TestWithinDir(t *testing.T) {
	sep := string(filepath.Separator)
	root := filepath.Join(sep, "data", "restore")
	for target, want := range map[string]bool{
		root:                                   true,
		filepath.Join(root, "a", "b"):          true,
		filepath.Join(sep, "data", "restorex"): false,
		filepath.Join(sep, "data"):             false,
	} {
		if got := withinDir(root, target); got != want {
			t.Errorf("withinDir(%q, %q) = %v", root, target, got)
		}
	}
	// A filesystem/drive root ends in a separator already.
	if !withinDir(sep, filepath.Join(sep, "Users", "alice")) {
		t.Error("files below the root rejected")
	}
}
