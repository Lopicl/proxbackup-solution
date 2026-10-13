// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxbackup/internal/update"
)

// fakeGitHub serves releases v0.1.0.1 (the running console) and v0.1.1.2.
func fakeGitHub(t *testing.T) *httptest.Server {
	agent := []byte("agent 0.1.0.1")
	sum := sha256.Sum256(agent)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := func(v string) update.Release {
			var assets []update.Asset
			for _, n := range []string{update.SumsAsset, update.AgentAsset("amd64"), update.AgentAsset("arm64")} {
				assets = append(assets, update.Asset{Name: n, URL: srv.URL + "/dl/" + v + "/" + n})
			}
			return update.Release{Tag: "v" + v, HTMLURL: "https://example/" + v, Assets: assets}
		}
		switch {
		case r.URL.Path == "/repos/o/r/releases":
			json.NewEncoder(w).Encode([]update.Release{rel("0.1.1.2"), rel("0.1.0.1")})
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/releases/tags/v"):
			json.NewEncoder(w).Encode(rel(strings.TrimPrefix(r.URL.Path, "/repos/o/r/releases/tags/v")))
		case strings.HasSuffix(r.URL.Path, "/"+update.SumsAsset):
			for _, a := range []string{"amd64", "arm64"} {
				fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), update.AgentAsset(a))
			}
		case strings.Contains(r.URL.Path, "/dl/"):
			w.Write(agent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestServer(t *testing.T, mode string) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(Config{DataDir: t.TempDir(), Version: "0.1.0.1", UpdateMode: mode, UpdateRepo: "o/r"}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.Close() })
	s.updater.gh.API = fakeGitHub(t).URL
	return s
}

func TestUpdaterCheckAndAgentOffer(t *testing.T) {
	s := newTestServer(t, "deb")
	ctx := context.Background()
	if err := s.updater.Check(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.updater.Status(ctx)
	if st.Latest != "0.1.1.2" || !st.Available || st.AgentVersion != "0.1.0.1" || len(st.AgentArchs) != 2 {
		t.Fatalf("status = %+v", st)
	}
	if st.NextInstall == 0 {
		t.Fatal("default settings should schedule the install")
	}
	o := s.updater.agentOffer(ctx, "windows/arm64", "0.0.9.0")
	if o == nil || o.Version != "0.1.0.1" || o.URL != "/agent/v1/update/windows-arm64" || o.Size != int64(len("agent 0.1.0.1")) {
		t.Fatalf("offer = %+v", o)
	}
	for _, c := range [][2]string{{"windows/amd64", "0.1.0.1"}, {"windows/amd64", "0.2.0.0"}, {"windows/amd64", "dev"}, {"linux/amd64", "0.0.1.0"}} {
		if o := s.updater.agentOffer(ctx, c[0], c[1]); o != nil {
			t.Errorf("unexpected offer for %v: %+v", c, o)
		}
	}
	us := s.updater.settings(ctx)
	us.Agents = false
	s.store.SetSetting(ctx, "updates", us)
	if o := s.updater.agentOffer(ctx, "windows/amd64", "0.0.9.0"); o != nil {
		t.Fatal("agent updates are disabled")
	}
}

func TestUpdaterDebInstallRequest(t *testing.T) {
	s := newTestServer(t, "deb")
	ctx := context.Background()
	if err := s.updater.Install(ctx); err == nil {
		t.Fatal("install before any check should fail")
	}
	s.updater.Check(ctx)
	if err := s.updater.Install(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "updates", updateRequestFile))
	if err != nil || !strings.Contains(string(b), `"0.1.1.2"`) {
		t.Fatalf("request = %s, %v", b, err)
	}
	if st := s.updater.Status(ctx); !st.Installing || st.LastResult == nil || st.LastResult.To != "0.1.1.2" {
		t.Fatalf("status = %+v", st)
	}
	if err := s.updater.Install(ctx); err == nil {
		t.Fatal("second install while one is pending should fail")
	}
}

func TestApplyUpdateRejectsBadRequests(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "updates"), 0o700)
	req := filepath.Join(dir, "updates", updateRequestFile)
	for _, body := range []string{`{"version":"0.1.0.1"}`, `{"version":"0.0.1.0"}`, `{"version":"../../x"}`, `junk`} {
		os.WriteFile(req, []byte(body), 0o600)
		err := ApplyUpdate(context.Background(), "0.1.0.1", dir, t.TempDir(), "o/r", log)
		if err == nil {
			t.Errorf("request %s was accepted", body)
		}
		if _, err := os.Stat(req); err == nil {
			t.Errorf("request %s was not consumed", body)
		}
		var res UpdateResult
		if b, _ := os.ReadFile(filepath.Join(dir, "updates", updateResultFile)); json.Unmarshal(b, &res) == nil && res.State == "installing" {
			t.Errorf("request %s left state installing", body)
		}
	}
	// No request: nothing to do.
	if err := ApplyUpdate(context.Background(), "0.1.0.1", dir, t.TempDir(), "o/r", log); err != nil {
		t.Fatal(err)
	}
}
