// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math/rand"
	"os"
	"sync/atomic"
	"testing"

	"proxbackup/pkg/ntfs"
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
