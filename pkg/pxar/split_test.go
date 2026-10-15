// SPDX-License-Identifier: AGPL-3.0-or-later

package pxar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

func buildSplit(t *testing.T) (meta, payload []byte) {
	t.Helper()
	var m, p bytes.Buffer
	enc, err := NewSplitEncoder(&m, &p, dirMeta())
	if err != nil {
		t.Fatal(err)
	}
	addTestTree(t, enc)
	return m.Bytes(), p.Bytes()
}

func TestSplitRoundTrip(t *testing.T) {
	meta, payload := buildSplit(t)
	le := binary.LittleEndian
	if le.Uint64(meta) != TypeFormatVersion || le.Uint64(meta[16:]) != 2 {
		t.Fatal("metadata stream does not start with FORMAT_VERSION 2")
	}
	if le.Uint64(payload) != TypePayloadStart || le.Uint64(payload[len(payload)-16:]) != TypePayloadTail {
		t.Fatal("payload stream markers missing")
	}
	if bytes.Contains(meta, []byte("secret")) {
		t.Fatal("file contents leaked into the metadata stream")
	}
	dec := NewSplitDecoder(bytes.NewReader(meta), bytes.NewReader(payload))
	if got := decodeListing(t, dec); fmt.Sprint(got) != fmt.Sprint(testTreeListing) {
		t.Fatalf("got:\n%v\nwant:\n%v", got, testTreeListing)
	}
	if dec.Version() != 2 {
		t.Fatalf("version %d", dec.Version())
	}
	// A split decoder reads v1 archives too.
	if got := decodeListing(t, NewSplitDecoder(bytes.NewReader(buildArchive(t)), bytes.NewReader(nil))); fmt.Sprint(got) != fmt.Sprint(testTreeListing) {
		t.Fatalf("v1 through split decoder: %v", got)
	}
}

func TestSplitMetadataOnly(t *testing.T) {
	meta, payload := buildSplit(t)
	dec := NewDecoder(bytes.NewReader(meta))
	files := 0
	for {
		e, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind != KindFile {
			continue
		}
		files++
		h := payload[e.PayloadOffset:]
		if !e.PayloadRef || binary.LittleEndian.Uint64(h) != TypePayload || binary.LittleEndian.Uint64(h[8:]) != headerSize+e.Size {
			t.Fatalf("%s: reference %d does not point at its PAYLOAD", e.Path, e.PayloadOffset)
		}
		if n, _ := io.Copy(io.Discard, dec.Contents()); n != 0 {
			t.Fatal("contents without a payload stream")
		}
	}
	if files != 5 {
		t.Fatalf("%d files", files)
	}
}

func TestSplitGoodbyeLookup(t *testing.T) {
	meta, _ := buildSplit(t)
	end := uint64(len(meta))
	tail := meta[end-goodbyeItemSize:]
	gbStart := end - binary.LittleEndian.Uint64(tail[16:])
	if gbStart != binary.LittleEndian.Uint64(tail[8:]) {
		t.Fatal("root tail marker does not point at offset 0")
	}
	start, stop, ok := lookup(t, meta, end, "hidden.txt")
	if !ok {
		t.Fatal("hidden.txt not found")
	}
	// The item covers FILENAME..PAYLOAD_REF in the metadata stream.
	if binary.LittleEndian.Uint64(meta[stop-headerSize-payloadRefSize:]) != TypePayloadRef || stop-start > 200 {
		t.Fatalf("hidden.txt goodbye range %d..%d", start, stop)
	}
	_, docsEnd, _ := lookup(t, meta, end, "docs")
	if _, _, ok := lookup(t, meta, docsEnd, "readme.md"); !ok {
		t.Fatal("docs/readme.md not found")
	}
}

// TestSplitReuse rebuilds an archive that takes "keep" from the previous
// payload stream, copying a padded range around it like reused chunks do.
func TestSplitReuse(t *testing.T) {
	var m1, p1 bytes.Buffer
	enc, _ := NewSplitEncoder(&m1, &p1, dirMeta())
	for _, f := range []struct{ name, data string }{{"a", "AAAA"}, {"keep", "kept contents"}, {"z", "ZZ"}} {
		if _, err := enc.AddFile([]byte(f.name), fileMeta(), uint64(len(f.data)), bytes.NewReader([]byte(f.data))); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	var keepOff, keepSize uint64
	dec := NewDecoder(bytes.NewReader(m1.Bytes()))
	for {
		e, err := dec.Next()
		if err != nil {
			break
		}
		if e.Path == "keep" {
			keepOff, keepSize = e.PayloadOffset, e.Size
		}
	}
	// "Chunk": from inside a's contents to inside z's PAYLOAD header.
	old := p1.Bytes()
	from, to := keepOff-2, keepOff+headerSize+keepSize+3
	var m2, p2 bytes.Buffer
	enc, _ = NewSplitEncoder(&m2, &p2, dirMeta())
	if _, err := enc.AddFile([]byte("a"), fileMeta(), 3, bytes.NewReader([]byte("new"))); err != nil {
		t.Fatal(err)
	}
	if err := enc.AddPayloadRef([]byte("b"), fileMeta(), keepSize, enc.PayloadPosition()); err == nil {
		t.Fatal("reference past the payload stream accepted")
	}
	base := enc.PayloadPosition()
	p2.Write(old[from:to])
	if err := enc.SkipPayload(to - from); err != nil {
		t.Fatal(err)
	}
	if err := enc.AddPayloadRef([]byte("keep"), fileMeta(), keepSize, base+keepOff-from); err != nil {
		t.Fatal(err)
	}
	if err := enc.AddPayloadRef([]byte("keep2"), fileMeta(), keepSize, base+keepOff-from); err == nil {
		t.Fatal("backwards reference accepted")
	}
	if _, err := enc.AddFile([]byte("z"), fileMeta(), 1, bytes.NewReader([]byte("!"))); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	dec = NewSplitDecoder(bytes.NewReader(m2.Bytes()), bytes.NewReader(p2.Bytes()))
	for {
		e, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == KindFile {
			b, err := io.ReadAll(dec.Contents())
			if err != nil {
				t.Fatal(err)
			}
			got[e.Path] = string(b)
		}
	}
	if fmt.Sprint(got) != "map[a:new keep:kept contents z:!]" {
		t.Fatalf("got %v", got)
	}
}

func TestSplitSkipsUnreadContents(t *testing.T) {
	meta, payload := buildSplit(t)
	dec := NewSplitDecoder(bytes.NewReader(meta), bytes.NewReader(payload))
	for {
		e, err := dec.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Path == "hidden.txt" {
			b, _ := io.ReadAll(dec.Contents())
			if string(b) != "secret" {
				t.Fatalf("hidden.txt = %q", b)
			}
		}
	}
}

func TestSplitRejectsCorruptReference(t *testing.T) {
	meta, payload := buildSplit(t)
	bad := bytes.Clone(payload)
	// Damage the PAYLOAD header of the first file.
	binary.LittleEndian.PutUint64(bad[headerSize+8:], 1)
	dec := NewSplitDecoder(bytes.NewReader(meta), bytes.NewReader(bad))
	for {
		_, err := dec.Next()
		if err == io.EOF {
			t.Fatal("corrupt payload stream decoded")
		}
		if err != nil {
			return
		}
	}
}
