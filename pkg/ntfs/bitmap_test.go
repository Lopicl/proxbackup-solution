// SPDX-License-Identifier: AGPL-3.0-or-later

package ntfs

import (
	"bytes"
	"math/rand"
	"testing"
)

// Zeroing every free cluster must leave all files intact: that is what image
// backups rely on when they skip free space.
func TestZeroFreeKeepsFiles(t *testing.T) {
	img := loadTestImage(t)
	v, err := Open(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.Allocation()
	if err != nil {
		t.Fatal(err)
	}
	used := a.UsedBytes()
	if used <= 0 || used >= int64(len(img)) {
		t.Fatalf("used %d of %d bytes", used, len(img))
	}
	t.Logf("%d of %d bytes in use (cluster %d)", used, len(img), a.ClusterSize())

	// The image's free space is already zero; fill it with junk, as a used
	// disk would hold. A used cluster wrongly marked free would corrupt files.
	dirty := bytes.Clone(img)
	cs := a.ClusterSize()
	for c := int64(0); c < a.clusters; c++ {
		if !a.used(c) {
			for i := c * cs; i < (c+1)*cs; i++ {
				dirty[i] = 0xA5
			}
		}
	}
	dv, err := Open(bytes.NewReader(dirty))
	if err != nil {
		t.Fatal(err)
	}
	checkManifest(t, dv)

	zeroed := bytes.Clone(dirty)
	a.ZeroFree(zeroed, 0)
	if !bytes.Equal(zeroed, img) {
		t.Error("ZeroFree did not restore the original image")
	}
	zv, err := Open(bytes.NewReader(zeroed))
	if err != nil {
		t.Fatal(err)
	}
	checkManifest(t, zv)
}

func TestAnyUsedMatchesClusters(t *testing.T) {
	v := openTestVolume(t)
	a, err := v.Allocation()
	if err != nil {
		t.Fatal(err)
	}
	cs := a.ClusterSize()
	size := a.clusters*cs + 512
	rng := rand.New(rand.NewSource(1))
	for range 5000 {
		off := rng.Int63n(size)
		n := min(rng.Int63n(64*cs)+1, size-off)
		want := false
		for c := off / cs; c <= (off+n-1)/cs; c++ {
			want = want || a.used(c)
		}
		if got := a.AnyUsed(off, n); got != want {
			t.Fatalf("AnyUsed(%d, %d) = %v, want %v", off, n, got, want)
		}
	}
}
