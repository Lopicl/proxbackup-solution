// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"os"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"proxbackup/pkg/ntfs"
	"proxbackup/pkg/pbs"
)

// alignedOnly fails reads that a raw Windows volume would reject.
type alignedOnly struct {
	b     []byte
	reads int
}

func (a *alignedOnly) ReadAt(p []byte, off int64) (int, error) {
	if off%512 != 0 || len(p)%512 != 0 {
		return 0, errors.New("unaligned read")
	}
	a.reads++
	return bytes.NewReader(a.b).ReadAt(p, off)
}

func testNTFSImage(t *testing.T) []byte {
	t.Helper()
	f, err := os.Open("../../pkg/ntfs/testdata/volume.img.gz")
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
	return img
}

func TestCopyImageSkipsFreeSpace(t *testing.T) {
	img := testNTFSImage(t)
	alloc, err := volumeAllocation(&alignedOnly{b: img}, uint64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	// Stale data in free space, as on a real disk.
	dirty := bytes.Clone(img)
	cs := alloc.ClusterSize()
	for off := int64(0); off < alloc.Size(); off += cs {
		if !alloc.AnyUsed(off, cs) {
			rand.New(rand.NewSource(off)).Read(dirty[off : off+cs])
		}
	}

	var out bytes.Buffer
	var progress atomic.Uint64
	src := &alignedOnly{b: dirty}
	ic, err := copyImage(context.Background(), &out, src, uint64(len(dirty)), alloc, &progress)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), img) {
		t.Fatal("copy differs from the image with its free space zeroed")
	}
	if progress.Load() != uint64(len(img)) || ic.skipped == 0 {
		t.Errorf("progress %d, skipped %d", progress.Load(), ic.skipped)
	}
	t.Logf("skipped %d of %d bytes", ic.skipped, len(img))
	v, err := ntfs.Open(bytes.NewReader(out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Lookup("MANY"); err != nil {
		t.Error(err)
	}

	// Without a map every byte is copied as is.
	out.Reset()
	if _, err := copyImage(context.Background(), &out, src, uint64(len(dirty)), nil, &progress); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), dirty) {
		t.Error("copy without allocation map differs from the source")
	}
}

func TestVolumeAllocationRejectsNonNTFS(t *testing.T) {
	b := make([]byte, 1<<20)
	if _, err := volumeAllocation(&alignedOnly{b: b}, uint64(len(b))); err == nil {
		t.Error("blank volume accepted as NTFS")
	}
}

func TestSectorReader(t *testing.T) {
	data := make([]byte, 64<<10)
	rand.New(rand.NewSource(1)).Read(data)
	sr := sectorReader{&alignedOnly{b: data}}
	for _, c := range []struct{ off, n int }{{0, 512}, {3, 10}, {4000, 200}, {8192, 4096}, {len(data) - 7, 7}} {
		p := make([]byte, c.n)
		n, err := sr.ReadAt(p, int64(c.off))
		if err != nil || n != c.n || !bytes.Equal(p, data[c.off:c.off+c.n]) {
			t.Errorf("ReadAt(%d, %d) = %d, %v", c.off, c.n, n, err)
		}
	}
	p := make([]byte, 100)
	if n, err := sr.ReadAt(p, int64(len(data)-50)); n != 50 || err == nil {
		t.Errorf("read past end = %d, %v", n, err)
	}
}

// The image catalog read from NTFS lists every file Windows sees, in the
// bytewise order the catalog needs, with the junction as a symlink.
func TestNTFSCatalogListsEveryFile(t *testing.T) {
	img := testNTFSImage(t)
	vol, err := ntfs.Open(newBlockCache(&alignedOnly{b: img}, int64(len(img)), 4))
	if err != nil {
		t.Fatal(err)
	}
	root, err := vol.Root()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := pbs.NewCatalogWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	c := &catalog{CatalogWriter: w}
	c.StartDirectory("c.img.fidx")
	if err := c.addNTFSTree(context.Background(), vol, root, true); err != nil {
		t.Fatal(err)
	}
	if err := c.EndDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	r, err := pbs.NewCatalogReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	type file struct {
		size  uint64
		mtime int64
	}
	files := map[string]file{}
	var symlinks []string
	var walk func(dir string)
	walk = func(dir string) {
		ents, err := r.ListDir("/c.img.fidx/" + dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if !slices.IsSortedFunc(ents, func(a, b pbs.CatalogEntry) int { return strings.Compare(a.Name, b.Name) }) {
			t.Errorf("%s: entries not in bytewise order", dir)
		}
		for _, e := range ents {
			p := path.Join(dir, e.Name)
			switch e.Type {
			case pbs.CatalogDir:
				walk(p)
			case pbs.CatalogFile:
				files[p] = file{e.Size, e.Mtime}
			case pbs.CatalogSymlink:
				symlinks = append(symlinks, p)
			}
		}
	}
	walk("")

	raw, err := os.ReadFile("../../pkg/ntfs/testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []struct {
		Path  string
		Size  uint64
		Mtime int64
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(files) != len(want) {
		t.Errorf("catalog has %d files, want %d", len(files), len(want))
	}
	for _, w := range want {
		if got, ok := files[w.Path]; !ok {
			t.Errorf("catalog misses %s", w.Path)
		} else if got != (file{w.Size, w.Mtime}) {
			t.Errorf("%s: size %d mtime %d, want %d %d", w.Path, got.size, got.mtime, w.Size, w.Mtime)
		}
	}
	if !slices.Equal(symlinks, []string{"junction"}) {
		t.Errorf("symlinks %q, want the junction", symlinks)
	}
}

func TestBlockCacheReads(t *testing.T) {
	img := make([]byte, 3*cacheBlockSize+1536) // ends mid-block, on a sector
	rand.New(rand.NewSource(1)).Read(img)
	c := newBlockCache(&alignedOnly{b: img}, int64(len(img)), 2)
	rnd := rand.New(rand.NewSource(2))
	for range 500 {
		off := rnd.Int63n(int64(len(img)))
		p := make([]byte, rnd.Intn(2*cacheBlockSize))
		n, err := c.ReadAt(p, off)
		want := min(len(p), len(img)-int(off))
		if n != want || !bytes.Equal(p[:n], img[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d bytes, %d) = %d, %v; want %d bytes", len(p), off, n, err, want)
		}
		if (err != nil) != (n < len(p)) {
			t.Fatalf("ReadAt(%d bytes, %d): err %v with %d bytes", len(p), off, err, n)
		}
	}
	if len(c.blocks) > 2 {
		t.Errorf("%d blocks cached, max 2", len(c.blocks))
	}
}
