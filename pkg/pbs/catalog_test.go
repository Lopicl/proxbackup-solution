package pbs

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestCatalogI64(t *testing.T) {
	// Expected bytes follow catalog_encode_i64 in pbs-datastore/src/catalog.rs.
	for v, want := range map[int64][]byte{
		0:    {0},
		1:    {1},
		127:  {127},
		128:  {128, 1},
		-1:   {129, 0},
		-128: {128, 129, 0},
	} {
		got := appendCatalogI64(nil, v)
		if !bytes.Equal(got, want) {
			t.Errorf("encode %d = %v, want %v", v, got, want)
		}
	}
	for _, v := range []int64{0, 1, -1, 127, 128, -129, 1791812322, -1791812322, math.MaxInt64, math.MinInt64 + 1} {
		b := appendCatalogI64(nil, v)
		got, n, err := decodeCatalogI64(b)
		if err != nil || got != v || n != len(b) || catalogI64Len(b) != len(b) {
			t.Errorf("roundtrip %d: got %d n=%d len=%d err=%v", v, got, n, catalogI64Len(b), err)
		}
	}
}

func TestCatalogLayout(t *testing.T) {
	// One archive with one file: tables are written child first, then root,
	// then the root offset.
	var buf bytes.Buffer
	c, _ := NewCatalogWriter(&buf)
	c.StartDirectory("a.pxar.didx")
	c.AddFile("f", 5, 7)
	if err := c.EndDirectory(); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{}, MagicCatalogFile[:]...)
	child := []byte{6, 1, 'f', 1, 'f', 5, 7} // len, count, type, namelen, name, size, mtime
	want = append(want, child...)
	root := []byte{1, 'd', 11}
	root = append(root, "a.pxar.didx"...)
	root = append(root, byte(len(want)-8)) // distance from root table back to child table
	want = append(want, byte(len(root)))
	want = append(want, root...)
	want = binary.LittleEndian.AppendUint64(want, uint64(8+len(child)))
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("catalog bytes\n got %v\nwant %v", buf.Bytes(), want)
	}
}

func TestCatalogRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	c, err := NewCatalogWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	c.StartDirectory("drive-c.img.fidx")
	c.StartDirectory("Users")
	c.StartDirectory("alice")
	for i := 0; i < 300; i++ { // big enough for multi-byte varints
		c.AddFile(string(rune('a'+i%26))+string(rune('0'+i/26)), uint64(i)<<20, int64(1700000000+i))
	}
	c.EndDirectory()
	c.AddSymlink("Default User")
	c.EndDirectory()
	c.AddFile("pagefile.sys", 4<<30, -5)
	c.EndDirectory()
	c.StartDirectory("c-data.pxar.didx")
	c.AddFile("ünïcödé ファイル.txt", 0, 0)
	c.EndDirectory()
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}

	r, err := NewCatalogReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	check := func(p string, want ...string) []CatalogEntry {
		t.Helper()
		es, err := r.ListDir(p)
		if err != nil {
			t.Fatalf("ListDir(%q): %v", p, err)
		}
		if len(es) < len(want) {
			t.Fatalf("ListDir(%q): %d entries, want at least %d", p, len(es), len(want))
		}
		for i, w := range want {
			if string(es[i].Type)+":"+es[i].Name != w {
				t.Errorf("ListDir(%q)[%d] = %c:%s, want %s", p, i, es[i].Type, es[i].Name, w)
			}
		}
		return es
	}
	check("/", "d:drive-c.img.fidx", "d:c-data.pxar.didx")
	es := check("/drive-c.img.fidx", "d:Users", "f:pagefile.sys")
	if es[1].Size != 4<<30 || es[1].Mtime != -5 {
		t.Errorf("pagefile.sys: size %d mtime %d", es[1].Size, es[1].Mtime)
	}
	check("/drive-c.img.fidx/Users", "d:alice", "l:Default User")
	es = check("/drive-c.img.fidx/Users/alice/")
	if len(es) != 300 || es[299].Size != 299<<20 || es[299].Mtime != 1700000299 {
		t.Errorf("alice: %d entries, last %+v", len(es), es[len(es)-1])
	}
	check("/c-data.pxar.didx", "f:ünïcödé ファイル.txt")
	if _, err := r.ListDir("/drive-c.img.fidx/pagefile.sys"); err == nil {
		t.Error("listing a file should fail")
	}
}
