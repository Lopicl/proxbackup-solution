// Command proxbackup-server is ProxBackup Console, the management server for ProxBackup agents.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"proxbackup/internal/server"
)

// version is set at build time from ./VERSION (see Makefile).
var version = "dev"

func main() {
	cfg := server.Config{Version: version}
	var hosts string
	flag.StringVar(&cfg.DataDir, "data-dir", envOr("PROXBACKUP_DATA_DIR", "/var/lib/proxbackup"), "data directory (database, CA, keys)")
	flag.StringVar(&cfg.UIAddr, "ui-addr", envOr("PROXBACKUP_UI_ADDR", ":8443"), "admin web UI listen address")
	flag.StringVar(&cfg.AgentAddr, "agent-addr", envOr("PROXBACKUP_AGENT_ADDR", ":8444"), "agent API listen address (mTLS)")
	flag.StringVar(&cfg.PublicURL, "public-url", os.Getenv("PROXBACKUP_PUBLIC_URL"), "agent-facing URL, e.g. https://backup.example.com:8444")
	flag.StringVar(&hosts, "hostnames", os.Getenv("PROXBACKUP_HOSTNAMES"), "comma separated host names/IPs for the server certificate")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: proxbackup-server [flags]\n       proxbackup-server passwd [username]   set an admin password\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.Hostnames = append(cfg.Hostnames, h)
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := server.New(cfg, log)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if flag.Arg(0) == "passwd" {
		user := flag.Arg(1)
		if user == "" {
			user = "admin"
		}
		fmt.Printf("New password for %s: ", user)
		pw, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		pw = strings.TrimSpace(pw)
		if len(pw) < 8 {
			fatal(fmt.Errorf("password must be at least 8 characters"))
		}
		if err := srv.Store().UpsertAdmin(ctx, user, server.HashPassword(pw)); err != nil {
			fatal(err)
		}
		fmt.Println("password updated")
		return
	}

	if pw, err := srv.EnsureAdmin(ctx, os.Getenv("PROXBACKUP_ADMIN_PASSWORD")); err != nil {
		fatal(err)
	} else if pw != "" && os.Getenv("PROXBACKUP_ADMIN_PASSWORD") == "" {
		log.Warn("created initial admin account — change this password", "username", "admin", "password", pw)
	}
	if cfg.PublicURL == "" {
		log.Warn("-public-url is not set; enrollment tokens cannot be created until it is")
	}
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "proxbackup-server:", err)
	os.Exit(1)
}
