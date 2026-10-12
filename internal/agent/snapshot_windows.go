//go:build windows

package agent

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/mxk/go-vss"
	"golang.org/x/sys/windows"
)

// snapshotSet creates at most one VSS shadow copy per volume and maps live
// paths into the snapshot device namespace.
type snapshotSet struct {
	mu     sync.Mutex
	useVSS bool
	byVol  map[string]*vss.ShadowCopy // key: volume mount point, e.g. `C:\`
	logf   func(level, format string, args ...any)
}

func newSnapshotSet(useVSS bool, logf func(level, format string, args ...any)) *snapshotSet {
	return &snapshotSet{useVSS: useVSS, byVol: map[string]*vss.ShadowCopy{}, logf: logf}
}

// Resolve returns the path to read src from (inside a snapshot when VSS is on).
func (s *snapshotSet) Resolve(src string) (string, error) {
	if !s.useVSS {
		return src, nil
	}
	vol, rel, err := vss.SplitVolume(src)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.byVol[strings.ToUpper(vol)]
	if sc == nil {
		s.logf("info", "creating VSS snapshot of %s", vol)
		id, err := vss.Create(vol)
		if err != nil {
			return "", fmt.Errorf("VSS snapshot of %s failed: %w", vol, err)
		}
		if sc, err = vss.Get(id); err != nil {
			vss.Remove(id)
			return "", err
		}
		s.byVol[strings.ToUpper(vol)] = sc
		s.logf("info", "VSS snapshot %s ready at %s", sc.ID, sc.DeviceObject)
	}
	if rel == "." || rel == "" {
		return sc.DeviceObject + `\`, nil
	}
	return sc.DeviceObject + `\` + rel, nil
}

// VolumeDevice returns the raw device path for an image backup of vol ("C:").
func (s *snapshotSet) VolumeDevice(vol string) (string, error) {
	vol = strings.TrimRight(vol, `\`) + `\`
	if !s.useVSS {
		return `\\.\` + strings.TrimRight(vol, `\`), nil
	}
	root, err := s.Resolve(vol)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(root, `\`), nil
}

// Close deletes all shadow copies created by this set.
func (s *snapshotSet) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for vol, sc := range s.byVol {
		if err := sc.Remove(); err != nil {
			s.logf("warn", "removing VSS snapshot of %s: %v", vol, err)
		}
	}
	s.byVol = map[string]*vss.ShadowCopy{}
}

const ioctlDiskGetLengthInfo = 0x7405C

// openVolume opens a raw volume/snapshot device and returns its size.
func openVolume(dev string) (*windows.Handle, uint64, error) {
	h, err := windows.CreateFile(windows.StringToUTF16Ptr(dev), windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", dev, err)
	}
	var size int64
	var ret uint32
	err = windows.DeviceIoControl(h, ioctlDiskGetLengthInfo, nil, 0, (*byte)(unsafe.Pointer(&size)), 8, &ret, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, 0, fmt.Errorf("query size of %s: %w", dev, err)
	}
	if size <= 0 {
		windows.CloseHandle(h)
		return nil, 0, errors.New("volume reports zero size")
	}
	return &h, uint64(size), nil
}

type volumeReader struct{ h windows.Handle }

func (v *volumeReader) Read(p []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(v.h, p, &n, nil)
	if err == nil && n == 0 {
		return 0, ioEOF
	}
	return int(n), err
}

func (v *volumeReader) Close() error { return windows.CloseHandle(v.h) }

// openImageSource opens vol (e.g. "C:") for an image backup.
func (s *snapshotSet) openImageSource(vol string) (readCloser, uint64, string, error) {
	dev, err := s.VolumeDevice(vol)
	if err != nil {
		return nil, 0, "", err
	}
	h, size, err := openVolume(dev)
	if err != nil {
		return nil, 0, "", err
	}
	return &volumeReader{h: *h}, size, dev, nil
}
