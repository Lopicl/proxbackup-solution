//go:build !windows

package agent

import (
	"errors"
	"os"
)

// snapshotSet is a no-op on non-Windows platforms: paths are read live.
// This keeps the agent buildable and testable on Linux/macOS.
type snapshotSet struct {
	useVSS bool
	logf   func(level, format string, args ...any)
}

func newSnapshotSet(useVSS bool, logf func(level, format string, args ...any)) *snapshotSet {
	if useVSS {
		logf("warn", "VSS is only available on Windows; reading live files")
	}
	return &snapshotSet{logf: logf}
}

func (s *snapshotSet) Resolve(src string) (string, error) { return src, nil }

func (s *snapshotSet) Close() {}

// imageFSRoot: images are files or block devices here, with no mounted file
// system to list.
func (s *snapshotSet) imageFSRoot(vol string) (string, bool) { return "", false }

// openImageSource opens a file or block device path for an image backup.
func (s *snapshotSet) openImageSource(vol string) (readCloser, uint64, string, error) {
	f, err := os.Open(vol)
	if err != nil {
		return nil, 0, "", err
	}
	size, err := f.Seek(0, 2)
	if err == nil {
		_, err = f.Seek(0, 0)
	}
	if err != nil {
		f.Close()
		return nil, 0, "", err
	}
	if size <= 0 {
		f.Close()
		return nil, 0, "", errors.New("image source is empty")
	}
	return f, uint64(size), vol, nil
}
