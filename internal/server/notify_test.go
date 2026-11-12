// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// fakeSMTP speaks just enough SMTP to authenticate. Like Exchange Online it
// advertises only the given mechanisms and rejects others with 504 5.7.4.
func fakeSMTP(t *testing.T, mechs string) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		say := func(s string) { conn.Write([]byte(s + "\r\n")) }
		read := func() string { l, _ := r.ReadString('\n'); return strings.TrimRight(l, "\r\n") }
		dec := func(s string) string { b, _ := base64.StdEncoding.DecodeString(s); return string(b) }
		say("220 fake")
		for {
			l := read()
			switch f := strings.Fields(l); {
			case l == "":
				return
			case f[0] == "EHLO":
				say("250-fake")
				say("250 AUTH " + mechs)
			case l == "AUTH LOGIN":
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u := dec(read())
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				got <- "LOGIN " + u + ":" + dec(read())
				say("235 2.7.0 Authentication successful")
			case f[0] == "AUTH" && f[1] == "PLAIN" && strings.Contains(mechs, "PLAIN"):
				got <- "PLAIN " + strings.ReplaceAll(dec(f[2]), "\x00", ":")
				say("235 2.7.0 Authentication successful")
			case f[0] == "AUTH":
				say("504 5.7.4 Unrecognized authentication type")
			case f[0] == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestSMTPAuthMechanism(t *testing.T) {
	for _, tc := range []struct{ mechs, want string }{
		{"LOGIN", "LOGIN user:secret"}, // Azure Communication Services
		{"PLAIN LOGIN", "PLAIN :user:secret"},
	} {
		addr, got := fakeSMTP(t, tc.mechs)
		c, err := smtp.Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		// localhost: the auth mechanisms allow clear text there.
		if err := c.Hello("localhost"); err != nil {
			t.Fatal(err)
		}
		if err := c.Auth(smtpAuth(c, "user", "secret", "127.0.0.1")); err != nil {
			t.Fatalf("%s: %v", tc.mechs, err)
		}
		if g := <-got; g != tc.want {
			t.Errorf("%s: got %q, want %q", tc.mechs, g, tc.want)
		}
		c.Quit()
	}
}

func TestSaveNotifyDropsPasswordOnHostChange(t *testing.T) {
	s := newTestServer(t, "deb")
	ctx := context.Background()
	save := func(body string) notifyView {
		r := httptest.NewRequest("PUT", "/api/settings/notifications", strings.NewReader(body))
		r = r.WithContext(context.WithValue(ctx, auditKey, &auditInfo{}))
		w := httptest.NewRecorder()
		s.handleSaveNotify(w, r)
		if w.Code != 200 {
			t.Fatalf("save %s: %d %s", body, w.Code, w.Body)
		}
		var v notifyView
		json.Unmarshal(w.Body.Bytes(), &v)
		return v
	}
	// Store a password for the original server.
	if v := save(`{"smtp_host":"smtp.example.com","smtp_user":"alerts","smtp_password":"s3cret","smtp_tls":"starttls"}`); !v.SMTPPassSet {
		t.Fatal("password not stored")
	}
	// Repointing the host without a new password must drop the stored one, so
	// it can't be sent to a server the saver chose (credential theft).
	if v := save(`{"smtp_host":"attacker.example.net","smtp_user":"alerts","smtp_tls":"tls"}`); v.SMTPPassSet {
		t.Fatal("stored SMTP password kept after a host change")
	}
	// Same host and user: the password is kept.
	save(`{"smtp_host":"smtp.example.com","smtp_user":"alerts","smtp_password":"s3cret","smtp_tls":"starttls"}`)
	if v := save(`{"smtp_host":"smtp.example.com","smtp_user":"alerts","smtp_tls":"tls"}`); !v.SMTPPassSet {
		t.Fatal("password dropped although the server is unchanged")
	}
	// Changing just the user also drops it.
	if v := save(`{"smtp_host":"smtp.example.com","smtp_user":"someone-else","smtp_tls":"tls"}`); v.SMTPPassSet {
		t.Fatal("stored SMTP password kept after a user change")
	}
}

func TestValidWebhookURL(t *testing.T) {
	ok := []string{"", "https://hooks.example.com/x", "http://10.0.0.1:9000/y"}
	bad := []string{"file:///etc/passwd", "gopher://x", "/just/a/path", "ftp://host/x", "not a url at all::"}
	for _, u := range ok {
		if err := validWebhookURL(u); err != nil {
			t.Errorf("validWebhookURL(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := validWebhookURL(u); err == nil {
			t.Errorf("validWebhookURL(%q) = nil, want error", u)
		}
	}
}

func TestStaleDays(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		ago  time.Duration
		min  int
		want int
	}{
		{3*24*time.Hour + time.Hour, 3, 3},
		{10*24*time.Hour + time.Hour, 3, 10},
		{time.Hour, 3, 3},
	} {
		if got := staleDays(now.Add(-c.ago).Unix(), c.min); got != c.want {
			t.Errorf("staleDays(%v ago, %d) = %d, want %d", c.ago, c.min, got, c.want)
		}
	}
}
