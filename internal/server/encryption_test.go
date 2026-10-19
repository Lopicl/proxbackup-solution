// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"

	"proxbackup/pkg/pbs"
)

func TestClientEncryptionKey(t *testing.T) {
	s := newTestServer(t, "")
	ctx := context.Background()
	tg := &Target{Name: "pbs", Host: "pbs:8007", Datastore: "ds", AdminAuthID: "root@pam!x", PBSUser: "proxbackup@pbs", adminSecretEnc: s.sealer.Seal("x")}
	if err := s.store.SaveTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	c := &Client{Name: "pc-1", TargetID: tg.ID, CertSerial: "01", Namespace: "pcs/pc-1", TokenID: "proxbackup@pbs!pc-1", tokenSecretEnc: s.sealer.Seal("tok")}
	if err := s.store.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	reload := func() *Client {
		c, err := s.store.Client(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if cfg, err := s.agentConfig(ctx, c); err != nil || cfg.Crypt != nil {
		t.Fatalf("no key expected yet: %+v %v", cfg, err)
	}
	if err := s.ensureClientKey(ctx, c); err != nil {
		t.Fatal(err)
	}
	c = reload()
	if err := s.ensureClientKey(ctx, &Client{ID: c.ID, Name: c.Name}); err != nil { // stale copy without a key: keeps the stored one
		t.Fatal(err)
	}
	if fp := reload().EncryptionFingerprint; fp != c.EncryptionFingerprint || len(fp) != 95 {
		t.Fatalf("key changed or missing: %q vs %q", fp, c.EncryptionFingerprint)
	}

	g := &GroupJob{Name: "files", Kind: "files", Sources: []string{`C:\Users`}, Enabled: true, Encrypt: true, ChangeDetection: "metadata",
		Clients: []int64{c.ID}}
	if _, err := s.store.SaveGroupJob(ctx, g); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.agentConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Crypt == nil || cfg.Crypt.Fingerprint != c.EncryptionFingerprint || len(cfg.Jobs) != 1 || !cfg.Jobs[0].Encrypt {
		t.Fatalf("config = %+v", cfg)
	}
	spec := cfg.Spec(cfg.Jobs[0])
	if !spec.Encrypt || spec.Crypt == nil {
		t.Fatal("spec lost the key")
	}

	// Escrow download: a PBS key file with the same key.
	req := httptest.NewRequest("GET", "/api/clients/1/encryption-key", nil)
	req.SetPathValue("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), sessionUserKey, &SessionUser{Name: "admin"}))
	rec := httptest.NewRecorder()
	s.handleClientKey(rec, req)
	if rec.Code != 200 {
		t.Fatalf("download: %d %s", rec.Code, rec.Body)
	}
	key, err := pbs.ParseKeyFile(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	cc, _ := pbs.NewCryptConfig(key)
	if cc.Fingerprint() != c.EncryptionFingerprint {
		t.Fatal("downloaded key does not match")
	}

	// Master public key: validated, then part of the agent config.
	put := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleSaveEncryption(rec, httptest.NewRequest("PUT", "/api/settings/encryption", strings.NewReader(body)))
		return rec
	}
	if rec := put(`{"master_pubkey":"garbage"}`); rec.Code != 400 {
		t.Fatalf("garbage master key: %d", rec.Code)
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemKey, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if rec := put(`{"master_pubkey":` + string(pemKey) + `}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"master_bits":2048`) {
		t.Fatalf("master key: %d %s", rec.Code, rec.Body)
	}
	if cfg2, _ := s.agentConfig(ctx, c); cfg2.Crypt.MasterPubKey == "" || cfg2.Rev == cfg.Rev {
		t.Fatal("master key not pushed")
	}

	// Revoking keeps the key for recovery.
	if err := s.store.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if rc := reload(); rc.EncryptionFingerprint != c.EncryptionFingerprint || len(rc.cryptKeyEnc) == 0 {
		t.Fatal("revoke dropped the key")
	}
}
