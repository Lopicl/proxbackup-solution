// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/smtp"
	"strings"
	"testing"
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
