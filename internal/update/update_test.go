package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cand, cur string
		want      bool
	}{
		{"0.1.14.15", "0.1.13.14", true},
		{"v0.2.0.16", "0.1.13.14", true},
		{"0.1.13.14", "0.1.13.14", false},
		{"0.1.9.10", "0.1.13.14", false},
		{"1.0.0.20", "dev", false},
		{"garbage", "0.1.0.0", false},
	} {
		if got := Newer(c.cand, c.cur); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.cand, c.cur, got, c.want)
		}
	}
}

func TestParseSums(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	m, err := ParseSums([]byte(sum + "  a.deb\n" + sum + " *b.exe\nnot a line\n"))
	if err != nil || m["a.deb"] != sum || m["b.exe"] != sum || len(m) != 2 {
		t.Fatalf("ParseSums = %v, %v", m, err)
	}
	if _, err := ParseSums([]byte("nothing\n")); err == nil {
		t.Fatal("expected an error for an empty list")
	}
}

func TestWindow(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	w := Window{Days: []time.Weekday{time.Sunday, time.Wednesday}, Time: "23:30", Minutes: 60}
	// 2026-10-14 is a Wednesday.
	in := time.Date(2026, 10, 14, 23, 45, 0, 0, loc)
	if s, ok := w.Slot(in); !ok || !s.Equal(time.Date(2026, 10, 14, 23, 30, 0, 0, loc)) {
		t.Fatalf("Slot(%v) = %v, %v", in, s, ok)
	}
	// Past midnight, still inside Wednesday's window.
	if _, ok := w.Slot(time.Date(2026, 10, 15, 0, 15, 0, 0, loc)); !ok {
		t.Fatal("window should extend past midnight")
	}
	if _, ok := w.Slot(time.Date(2026, 10, 15, 0, 31, 0, 0, loc)); ok {
		t.Fatal("window should have ended")
	}
	if _, ok := w.Slot(time.Date(2026, 10, 13, 23, 45, 0, 0, loc)); ok {
		t.Fatal("Tuesday is not selected")
	}
	if n := w.Next(in); !n.Equal(time.Date(2026, 10, 18, 23, 30, 0, 0, loc)) {
		t.Fatalf("Next = %v", n)
	}
	if err := (Window{Time: "25:00"}).Validate(); err == nil {
		t.Fatal("expected invalid time")
	}
}

func TestLatestAndDownload(t *testing.T) {
	payload := []byte("agent binary")
	sum := sha256.Sum256(payload)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases":
			rel := func(tag string, pre bool) Release {
				return Release{Tag: tag, Prerelease: pre, Assets: []Asset{
					{Name: SumsAsset, URL: srv.URL + "/dl/sums"},
					{Name: AgentAsset("amd64"), URL: srv.URL + "/dl/agent"},
				}}
			}
			json.NewEncoder(w).Encode([]Release{rel("v0.1.2.3", false), rel("v0.3.0.9", true), rel("v0.2.0.5", false), rel("nightly", false)})
		case "/dl/sums":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), AgentAsset("amd64"))
		case "/dl/agent":
			w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &Client{Repo: "o/r", API: srv.URL}
	ctx := context.Background()
	r, err := c.Latest(ctx, false)
	if err != nil || r.Tag != "v0.2.0.5" {
		t.Fatalf("Latest = %+v, %v", r, err)
	}
	if r, _ := c.Latest(ctx, true); r.Tag != "v0.3.0.9" {
		t.Fatalf("Latest(prerelease) = %s", r.Tag)
	}
	sums, err := c.Sums(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p, got, err := c.Download(ctx, r, sums, AgentAsset("amd64"), dir)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("Download = %s, %s, %v", p, got, err)
	}
	if b, _ := os.ReadFile(p); string(b) != string(payload) {
		t.Fatal("downloaded content differs")
	}
	sums[AgentAsset("amd64")] = strings.Repeat("00", 32)
	os.Remove(p)
	if _, _, err := c.Download(ctx, r, sums, AgentAsset("amd64"), dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}
