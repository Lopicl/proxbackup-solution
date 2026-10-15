// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
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
	"time"

	"proxbackup/internal/api"
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
	o := s.updater.agentOffer(ctx, 1, "windows/arm64", "0.0.9.0")
	if o == nil || o.Version != "0.1.0.1" || o.URL != "/agent/v1/update/windows-arm64" || o.Size != int64(len("agent 0.1.0.1")) {
		t.Fatalf("offer = %+v", o)
	}
	for _, c := range [][2]string{{"windows/amd64", "0.1.0.1"}, {"windows/amd64", "0.2.0.0"}, {"windows/amd64", "dev"}, {"linux/amd64", "0.0.1.0"}} {
		if o := s.updater.agentOffer(ctx, 1, c[0], c[1]); o != nil {
			t.Errorf("unexpected offer for %v: %+v", c, o)
		}
	}
	us := s.updater.settings(ctx)
	us.Agents = false
	s.store.SetSetting(ctx, "updates", us)
	if o := s.updater.agentOffer(ctx, 1, "windows/amd64", "0.0.9.0"); o != nil {
		t.Fatal("agent updates are disabled")
	}
}

func TestPushAgentUpdate(t *testing.T) {
	s := newTestServer(t, "deb")
	ctx := context.Background()
	us := s.updater.settings(ctx)
	us.Agents = false
	s.store.SetSetting(ctx, "updates", us)
	c := &Client{ID: 7, Name: "pc", OS: "windows/amd64", AgentVersion: "0.0.9.0"}

	if v, pushed := s.updater.agentUpdate(c); v != "0.1.0.1" || pushed {
		t.Fatalf("agentUpdate = %q, %v", v, pushed)
	}
	if o := s.updater.agentOffer(ctx, c.ID, c.OS, c.AgentVersion); o != nil {
		t.Fatal("offer before the push with agent updates off")
	}
	for _, bad := range []*Client{
		{ID: 8, OS: "windows/amd64", AgentVersion: "0.1.0.1"},
		{ID: 9, OS: "linux/amd64", AgentVersion: "0.0.9.0"},
	} {
		if err := s.updater.PushAgent(ctx, bad); err == nil {
			t.Errorf("push to %+v accepted", bad)
		}
	}
	if err := s.updater.PushAgent(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, pushed := s.updater.agentUpdate(c); !pushed {
		t.Fatal("push not recorded")
	}
	o := s.updater.agentOffer(ctx, c.ID, c.OS, c.AgentVersion)
	if o == nil || !o.Force || o.Version != "0.1.0.1" {
		t.Fatalf("offer = %+v", o)
	}
	if o := s.updater.agentOffer(ctx, 99, c.OS, c.AgentVersion); o != nil {
		t.Fatal("push leaked to another client")
	}
	// Once the agent runs the console's version, the push is over.
	if o := s.updater.agentOffer(ctx, c.ID, c.OS, "0.1.0.1"); o != nil {
		t.Fatal("offer to an up-to-date agent")
	}
	if o := s.updater.agentOffer(ctx, c.ID, c.OS, c.AgentVersion); o != nil {
		t.Fatal("push should be cleared")
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

func TestPushAgentUpdateWakesPoll(t *testing.T) {
	s := newTestServer(t, "deb")
	ctx := context.Background()
	us := s.updater.settings(ctx)
	us.Agents = false
	s.store.SetSetting(ctx, "updates", us)
	tg := &Target{Name: "pbs", Host: "pbs.lan", Datastore: "ds", AdminAuthID: "root@pam!t", PBSUser: "proxbackup@pbs", adminSecretEnc: []byte{}}
	if err := s.store.SaveTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	c := &Client{Name: "pc", OS: "windows/amd64", TargetID: tg.ID, tokenSecretEnc: s.sealer.Seal("secret")}
	if err := s.store.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.AgentVersion = "0.0.9.0"
	poll := func() api.PollResponse {
		cfg, _ := s.agentConfig(ctx, c)
		body, _ := json.Marshal(api.PollRequest{OS: c.OS, AgentVersion: c.AgentVersion, ConfigRev: cfg.Rev})
		w := httptest.NewRecorder()
		s.handlePoll(w, httptest.NewRequest("POST", "/agent/v1/poll?wait=30", bytes.NewReader(body)), c)
		var resp api.PollResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("poll: %d %s", w.Code, w.Body)
		}
		return resp
	}
	done := make(chan api.PollResponse)
	go func() { done <- poll() }()
	time.Sleep(200 * time.Millisecond)
	if err := s.updater.PushAgent(ctx, c); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-done:
		if resp.Update == nil || !resp.Update.Force {
			t.Fatalf("poll response = %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pushing the update did not wake the poll")
	}
}
