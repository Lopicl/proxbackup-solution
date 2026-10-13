// SPDX-License-Identifier: AGPL-3.0-or-later

package pxar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"testing"
)

func TestBSTPermuteMatchesUpstreamExample(t *testing.T) {
	// From pxar binary_tree_array.rs doc test.
	want := [][2]int{{3, 0}, {1, 1}, {0, 3}, {2, 4}, {4, 2}}
	var got [][2]int
	bstPermute(5, func(s, d int) { got = append(got, [2]int{s, d}) })
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Every size must produce a valid BST permutation.
	for n := 1; n < 300; n++ {
		arr := make([]int, n)
		seen := make([]bool, n)
		bstPermute(n, func(s, d int) { arr[d] = s; seen[d] = true })
		for i := range n {
			if !seen[i] {
				t.Fatalf("n=%d: slot %d unfilled", n, i)
			}
			if l := 2*i + 1; l < n && arr[l] >= arr[i] {
				t.Fatalf("n=%d: left child not smaller", n)
			}
			if r := 2*i + 2; r < n && arr[r] <= arr[i] {
				t.Fatalf("n=%d: right child not larger", n)
			}
		}
	}
}

func dirMeta() Metadata { return Metadata{Mode: ModeIFDIR | 0o755, MtimeSecs: 1700000000} }
func fileMeta() Metadata {
	return Metadata{Mode: ModeIFREG | 0o644, MtimeSecs: 1700000001, MtimeNanos: 5}
}

type testFile struct {
	path string
	data string
}

func buildArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := NewEncoder(&buf, dirMeta())
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	add := func(name, data string) {
		t.Helper()
		m := fileMeta()
		if name == "hidden.txt" {
			m.Flags = FlagHidden
			m.Xattrs = []Xattr{{Name: []byte("user.proxbackup.attrs"), Value: []byte{0x22, 0, 0, 0}}}
		}
		_, err := enc.AddFile([]byte(name), m, uint64(len(data)), bytes.NewReader([]byte(data)))
		must(err)
	}
	add("a.txt", "alpha")
	must(enc.CreateDir([]byte("docs"), dirMeta()))
	add("empty", "")
	add("readme.md", "# hi\n")
	must(enc.CreateDir([]byte("sub"), dirMeta()))
	add("deep.bin", string(bytes.Repeat([]byte{1, 2, 3}, 5000)))
	must(enc.FinishDir())
	must(enc.FinishDir())
	add("hidden.txt", "secret")
	must(enc.AddSymlink([]byte("link"), fileMeta(), []byte("a.txt")))
	must(enc.CreateDir([]byte("z-empty-dir"), dirMeta()))
	must(enc.FinishDir())
	must(enc.Close())
	return buf.Bytes()
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	data := buildArchive(t)
	dec := NewDecoder(bytes.NewReader(data))
	var got []string
	for {
		e, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		line := fmt.Sprintf("%s %q", e.Kind, e.Path)
		switch e.Kind {
		case KindFile:
			b, err := io.ReadAll(dec.Contents())
			if err != nil {
				t.Fatal(err)
			}
			if uint64(len(b)) != e.Size {
				t.Fatalf("%s: size %d != %d", e.Path, len(b), e.Size)
			}
			line += fmt.Sprintf(" %d", len(b))
			if e.Path == "hidden.txt" {
				if e.Meta.Flags != FlagHidden || len(e.Meta.Xattrs) != 1 || string(b) != "secret" {
					t.Fatalf("hidden.txt metadata lost: %+v", e.Meta)
				}
			}
		case KindSymlink:
			line += " -> " + e.Target
		}
		got = append(got, line)
	}
	want := []string{
		`dir ""`, `file "a.txt" 5`, `dir "docs"`, `file "docs/empty" 0`, `file "docs/readme.md" 5`,
		`dir "docs/sub"`, `file "docs/sub/deep.bin" 15000`, `file "hidden.txt" 6`, `symlink "link" -> a.txt`,
		`dir "z-empty-dir"`,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got:\n%v\nwant:\n%v", got, want)
	}
}

// lookup implements pxar's random-access goodbye-table search to validate
// offsets: given the archive and the end offset of a directory, find name.
func lookup(t *testing.T, data []byte, dirEnd uint64, name string) (start, end uint64, ok bool) {
	le := binary.LittleEndian
	tail := data[dirEnd-goodbyeItemSize : dirEnd]
	if le.Uint64(tail) != GoodbyeTailMarker {
		t.Fatalf("no tail marker at %d", dirEnd)
	}
	gbSize := le.Uint64(tail[16:])
	gbStart := dirEnd - gbSize
	if le.Uint64(data[gbStart:]) != TypeGoodbye {
		t.Fatal("goodbye header missing")
	}
	n := int((gbSize-headerSize)/goodbyeItemSize) - 1
	items := data[gbStart+headerSize:]
	h := HashFilename([]byte(name))
	i := 0
	for i < n {
		it := items[i*goodbyeItemSize:]
		ih := le.Uint64(it)
		switch {
		case h == ih:
			off := gbStart - le.Uint64(it[8:])
			// must point at FILENAME with that name
			if le.Uint64(data[off:]) != TypeFilename {
				t.Fatalf("goodbye offset for %s does not point at FILENAME", name)
			}
			fl := le.Uint64(data[off+8:])
			if string(data[off+headerSize:off+fl-1]) != name {
				t.Fatalf("goodbye offset for %s points at wrong name", name)
			}
			return off, off + le.Uint64(it[16:]), true
		case h < ih:
			i = 2*i + 1
		default:
			i = 2*i + 2
		}
	}
	return 0, 0, false
}

func TestGoodbyeTableLookup(t *testing.T) {
	data := buildArchive(t)
	end := uint64(len(data))
	// root tail marker must point to offset 0 (root ENTRY)
	tail := data[end-goodbyeItemSize:]
	gbStart := end - binary.LittleEndian.Uint64(tail[16:])
	if gbStart-binary.LittleEndian.Uint64(tail[8:]) != 0 {
		t.Fatal("root tail marker does not point at offset 0")
	}
	for _, n := range []string{"a.txt", "docs", "hidden.txt", "link", "z-empty-dir"} {
		if _, _, ok := lookup(t, data, end, n); !ok {
			t.Fatalf("lookup %s failed", n)
		}
	}
	if _, _, ok := lookup(t, data, end, "nope"); ok {
		t.Fatal("found nonexistent entry")
	}
	_, docsEnd, _ := lookup(t, data, end, "docs")
	if _, subEnd, ok := lookup(t, data, docsEnd, "sub"); !ok {
		t.Fatal("docs/sub not found")
	} else if _, _, ok := lookup(t, data, subEnd, "deep.bin"); !ok {
		t.Fatal("docs/sub/deep.bin not found")
	}
}

func TestManyEntriesAndOrdering(t *testing.T) {
	var buf bytes.Buffer
	enc, _ := NewEncoder(&buf, dirMeta())
	var names []string
	for i := range 1000 {
		names = append(names, fmt.Sprintf("f%04d", i))
	}
	sort.Strings(names)
	for _, n := range names {
		if _, err := enc.AddFile([]byte(n), fileMeta(), 1, bytes.NewReader([]byte{'x'})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := enc.AddFile([]byte("a"), fileMeta(), 0, bytes.NewReader(nil)); err == nil {
		t.Fatal("out of order name accepted")
	}
	if err := enc.Close(); err == nil {
		t.Log("encoder closed after error (sticky error expected)")
	}
}

func TestShortAndGrowingFiles(t *testing.T) {
	var buf bytes.Buffer
	enc, _ := NewEncoder(&buf, dirMeta())
	res, err := enc.AddFile([]byte("grew"), fileMeta(), 3, bytes.NewReader([]byte("abcdef")))
	if err != nil || !res.Grew {
		t.Fatalf("grew: %+v %v", res, err)
	}
	res, err = enc.AddFile([]byte("short"), fileMeta(), 10, bytes.NewReader([]byte("abc")))
	if err != nil || !res.Short {
		t.Fatalf("short: %+v %v", res, err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	dec := NewDecoder(&buf)
	dec.Next()
	e, _ := dec.Next()
	b, _ := io.ReadAll(dec.Contents())
	if e.Path != "grew" || string(b) != "abc" {
		t.Fatalf("grew contents %q", b)
	}
	e, _ = dec.Next()
	b, _ = io.ReadAll(dec.Contents())
	if e.Path != "short" || !bytes.Equal(b, []byte("abc\x00\x00\x00\x00\x00\x00\x00")) {
		t.Fatalf("short contents %q", b)
	}
}
