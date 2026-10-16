// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfs

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"testing"
)

// testdata/volume.img.gz is a 40 MiB NTFS volume formatted and filled by
// Windows 11 (testdata/mkvolume.ps1): a fragmented file, an LZNT1-compressed
// file, a sparse file, a 400-entry directory (index allocation), a file with
// 121 hard links (attribute list), a junction, an alternate data stream and
// non-ASCII names. manifest.json holds what Windows reported for every file.
func openTestVolume(t *testing.T) *Volume {
	t.Helper()
	f, err := os.Open("testdata/volume.img.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	img, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type manifestEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Attrs  uint32 `json:"attrs"`
	Mtime  int64  `json:"mtime"`
}

func TestFilesMatchWindows(t *testing.T) {
	v := openTestVolume(t)
	raw, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []manifestEntry
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		f, err := v.Lookup(w.Path)
		if err != nil {
			t.Errorf("%s: %v", w.Path, err)
			continue
		}
		s, err := f.Open()
		if err != nil {
			t.Errorf("%s: %v", w.Path, err)
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, io.NewSectionReader(s, 0, s.Size()))
		if err != nil {
			t.Errorf("%s: read: %v", w.Path, err)
			continue
		}
		if n != w.Size || hex.EncodeToString(h.Sum(nil)) != w.SHA256 {
			t.Errorf("%s: got %d bytes %x, want %d bytes %s", w.Path, n, h.Sum(nil), w.Size, w.SHA256)
		}
		if f.Attrs != w.Attrs {
			t.Errorf("%s: attrs %#x, want %#x", w.Path, f.Attrs, w.Attrs)
		}
		if f.Mtime.Unix() != w.Mtime {
			t.Errorf("%s: mtime %d, want %d", w.Path, f.Mtime.Unix(), w.Mtime)
		}
	}
}

func TestWalkFindsEveryFile(t *testing.T) {
	v := openTestVolume(t)
	raw, _ := os.ReadFile("testdata/manifest.json")
	var want []manifestEntry
	json.Unmarshal(raw, &want)
	files := map[string]bool{}
	var walk func(dir *File, p string)
	walk = func(dir *File, p string) {
		ents, err := dir.ReadDir()
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for _, e := range ents {
			if e.Ref < FirstUserRef || (p == "" && e.Name == "System Volume Information") {
				continue
			}
			f, err := v.Get(e.Ref)
			if err != nil {
				t.Fatalf("%s/%s: %v", p, e.Name, err)
			}
			switch {
			case f.ReparseTag != 0:
			case f.IsDir:
				walk(f, path.Join(p, e.Name))
			default:
				files[path.Join(p, e.Name)] = true
			}
		}
	}
	root, err := v.Root()
	if err != nil {
		t.Fatal(err)
	}
	walk(root, "")
	if len(files) != len(want) {
		t.Errorf("walk found %d files, want %d", len(files), len(want))
	}
	for _, w := range want {
		if !files[w.Path] {
			t.Errorf("walk missed %s", w.Path)
		}
	}
}

func TestDirectoryAndSpecialFiles(t *testing.T) {
	v := openTestVolume(t)
	many, err := v.Lookup("MANY") // case-insensitive
	if err != nil {
		t.Fatal(err)
	}
	if ents, err := many.ReadDir(); err != nil || len(ents) != 400 {
		t.Fatalf("many: %d entries, %v", len(ents), err)
	}
	links, err := v.Lookup("links")
	if err != nil {
		t.Fatal(err)
	}
	ents, err := links.ReadDir()
	if err != nil || len(ents) != 121 {
		t.Fatalf("links: %d entries, %v", len(ents), err)
	}
	for _, e := range ents[1:] {
		if e.Ref != ents[0].Ref {
			t.Fatalf("hard link %s has ref %d, want %d", e.Name, e.Ref, ents[0].Ref)
		}
	}

	j, err := v.Lookup("junction")
	if err != nil {
		t.Fatal(err)
	}
	if j.ReparseTag != ReparseTagMountPoint {
		t.Errorf("junction reparse tag %#x", j.ReparseTag)
	}

	small, err := v.Lookup(`docs\small.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if got := small.Streams(); len(got) != 1 || got[0] != "extra" {
		t.Fatalf("streams %q", got)
	}
	s, err := small.OpenStream("extra")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(io.NewSectionReader(s, 0, s.Size()))
	if string(b) != "stream\r\n" {
		t.Errorf("ADS content %q", b)
	}

	if _, err := v.Lookup("docs/missing.txt"); !errors.Is(err, ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := v.Lookup("random.bin/x"); !errors.Is(err, ErrNotExist) {
		t.Errorf("path through a file: %v", err)
	}
}

func TestFragmentedFileHasManyRuns(t *testing.T) {
	v := openTestVolume(t)
	f, err := v.Lookup("fragmented.bin")
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.runs) < 2 {
		t.Errorf("fragmented.bin has %d runs; the test volume should fragment it", len(s.runs))
	}
}

func TestNotNTFS(t *testing.T) {
	if _, err := Open(bytes.NewReader(make([]byte, 4096))); err == nil {
		t.Fatal("zeros opened as NTFS")
	}
}
