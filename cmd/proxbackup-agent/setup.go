// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"proxbackup/internal/agent"
	"proxbackup/internal/api"
)

// embeddedSetupToken returns the setup token appended to this executable
// (a setup .exe downloaded from the console) and the size of the plain agent.
func embeddedSetupToken() (token string, exeSize int64, ok bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", 0, false
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", 0, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, false
	}
	token, exeSize, ok, err = api.ReadSetupTrailer(f, fi.Size())
	return token, exeSize, ok && err == nil
}

// setup enrolls this PC with a setup token, asking for the client name and
// the console address, then installs and starts the service.
func setup(dataDir, token string) error {
	t, err := agent.ParseEnrollmentToken(token)
	if err != nil {
		return err
	}
	fmt.Println("ProxBackup Agent setup", version)
	fmt.Println()
	if t.Expires > 0 {
		exp := time.Unix(t.Expires, 0)
		if time.Now().After(exp) {
			return fmt.Errorf("this setup expired at %s; download a new one from the ProxBackup Console", exp.Format("2006-01-02 15:04"))
		}
		fmt.Printf("This setup is valid until %s.\n\n", exp.Format("2006-01-02 15:04"))
	}
	in := bufio.NewReader(os.Stdin)

	if cfg, err := agent.LoadConfig(dataDir); err == nil {
		fmt.Printf("This PC is already enrolled as %q with %s.\n", cfg.ClientName, cfg.ServerURL)
		if !strings.HasPrefix(strings.ToLower(prompt(in, "Enroll it again as a new client? (y/N)", "n")), "y") {
			return installService(dataDir)
		}
	}

	hostname, _ := os.Hostname()
	u, err := url.Parse(t.URL)
	if err != nil {
		return fmt.Errorf("invalid console URL in the setup token: %w", err)
	}
	name := prompt(in, "Client name", hostname)
	host := prompt(in, "ProxBackup host/IP", cmp.Or(t.Host, u.Hostname()))
	for {
		et := *t
		if et.URL, err = consoleURL(u, host); err != nil {
			fmt.Println("  ", err)
			host = prompt(in, "ProxBackup host/IP", host)
			continue
		}
		fmt.Printf("\nEnrolling %q with %s ...\n", name, et.URL)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cfg, err := agent.EnrollWith(ctx, dataDir, &et, name)
		cancel()
		if err == nil {
			fmt.Printf("Enrolled as %q (client %d).\n\n", cfg.ClientName, cfg.ClientID)
			break
		}
		fmt.Println("  ", err)
		switch code := agent.HTTPStatus(err); {
		case code == http.StatusConflict || code == http.StatusBadRequest:
			name = prompt(in, "Client name", name)
		case code == http.StatusForbidden:
			return errors.New("the console rejected the setup token (expired or revoked); download a new setup")
		case code != 0:
			if !strings.HasPrefix(strings.ToLower(prompt(in, "Try again? (Y/n)", "y")), "y") {
				return err
			}
		default: // console not reached
			host = prompt(in, "ProxBackup host/IP", host)
		}
	}
	return installService(dataDir)
}

func prompt(in *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, _ := in.ReadString('\n')
	return cmp.Or(strings.TrimSpace(line), def)
}

// consoleURL replaces the host of the token's URL with what was entered:
// "host", "host:port" or a full URL.
func consoleURL(base *url.URL, entered string) (string, error) {
	entered = strings.TrimSpace(entered)
	if entered == "" {
		return "", errors.New("enter the console's host name or IP address")
	}
	if strings.Contains(entered, "://") {
		u, err := url.Parse(entered)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("invalid URL %q", entered)
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	u := *base
	if h, p, err := net.SplitHostPort(entered); err == nil {
		u.Host = net.JoinHostPort(h, p)
	} else if port := base.Port(); port != "" {
		u.Host = net.JoinHostPort(strings.Trim(entered, "[]"), port)
	} else {
		u.Host = entered
		if strings.Contains(entered, ":") && !strings.HasPrefix(entered, "[") {
			u.Host = "[" + entered + "]" // bare IPv6
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}
