// SPDX-License-Identifier: AGPL-3.0-or-later

// Command proxbackup-server is ProxBackup Console, the management server for ProxBackup agents.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"proxbackup/internal/server"
	"proxbackup/internal/update"
)

// version is set at build time from ./VERSION (see Makefile).
var version = "dev"

func main() {
	// Subcommands that must not open the data directory.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "apply-update":
			applyUpdate(os.Args[2:])
			return
		}
	}
	cfg := server.Config{Version: version}
	var hosts string
	var local server.LocalPBS
	var localPBS bool
	flag.StringVar(&cfg.DataDir, "data-dir", envOr("PROXBACKUP_DATA_DIR", "/var/lib/proxbackup"), "data directory (database, CA, keys)")
	flag.StringVar(&cfg.UIAddr, "listen", envOr("PROXBACKUP_LISTEN", ":8077"), "listen address for the web UI and the agent API")
	flag.StringVar(&cfg.AgentAddr, "agent-addr", os.Getenv("PROXBACKUP_AGENT_ADDR"), "optional separate listen address for the agent API (mTLS)")
	flag.StringVar(&cfg.PublicURL, "public-url", os.Getenv("PROXBACKUP_PUBLIC_URL"), "agent-facing URL, e.g. https://backup.example.com:8077")
	flag.StringVar(&hosts, "hostnames", os.Getenv("PROXBACKUP_HOSTNAMES"), "comma separated host names/IPs for the server certificate")
	flag.BoolVar(&localPBS, "local-pbs", os.Getenv("PROXBACKUP_LOCAL_PBS") == "1", "running on the PBS host: register its datastores and allow PBS admin logins")
	flag.StringVar(&local.APIAddr, "local-pbs-api", envOr("PROXBACKUP_LOCAL_PBS_API", "127.0.0.1:8007"), "local PBS API address")
	flag.StringVar(&local.AuthID, "local-pbs-auth-id", envOr("PROXBACKUP_LOCAL_PBS_AUTH_ID", "root@pam!proxbackup-console"), "local PBS admin token id")
	flag.StringVar(&local.SecretFile, "local-pbs-secret-file", envOr("PROXBACKUP_LOCAL_PBS_SECRET_FILE", credentialPath("pbs-token")), "file with the local PBS admin token secret")
	flag.StringVar(&local.PublicHost, "pbs-public-host", os.Getenv("PROXBACKUP_PBS_PUBLIC_HOST"), "PBS address agents use (default: host of -public-url, port 8007)")
	flag.StringVar(&cfg.UpdateRepo, "update-repo", os.Getenv("PROXBACKUP_UPDATE_REPO"), "GitHub repository (owner/name) to take updates from (default "+update.DefaultRepo+")")
	cfg.UpdateMode = os.Getenv("PROXBACKUP_UPDATE_MODE") // "deb", set by the package's unit file
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: proxbackup-server [flags]\n       proxbackup-server passwd [username]   set an admin password\n       proxbackup-server version\n       proxbackup-server apply-update        install a requested update (run as root by proxbackup-server-update.service)\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.Hostnames = append(cfg.Hostnames, h)
		}
	}
	if localPBS {
		if local.PublicHost == "" {
			u, err := url.Parse(cfg.PublicURL)
			if err != nil || u.Hostname() == "" {
				fatal(fmt.Errorf("-local-pbs needs -public-url (or -pbs-public-host)"))
			}
			local.PublicHost = net.JoinHostPort(u.Hostname(), "8007")
		}
		cfg.LocalPBS = &local
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
		if err := srv.Store().UpsertAdmin(ctx, user, server.HashPassword(pw), false); err != nil {
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
	if err := srv.Run(ctx); errors.Is(err, server.ErrRestart) {
		log.Info("re-executing the updated binary")
		fatal(reexec())
	} else if err != nil && ctx.Err() == nil {
		fatal(err)
	}
}

// applyUpdate is run as root by proxbackup-server-update.service.
func applyUpdate(args []string) {
	fs := flag.NewFlagSet("apply-update", flag.ExitOnError)
	dataDir := fs.String("data-dir", envOr("PROXBACKUP_DATA_DIR", "/var/lib/proxbackup"), "console data directory")
	cacheDir := fs.String("cache-dir", envOr("CACHE_DIRECTORY", "/var/cache/proxbackup"), "root-owned download directory")
	repo := fs.String("update-repo", os.Getenv("PROXBACKUP_UPDATE_REPO"), "GitHub repository (owner/name)")
	fs.Parse(args)
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.ApplyUpdate(ctx, version, *dataDir, *cacheDir, *repo, log); err != nil {
		fatal(err)
	}
}

// credentialPath returns a systemd credential (LoadCredential=) if one was
// passed, else the file the .deb package writes.
func credentialPath(name string) string {
	if d := os.Getenv("CREDENTIALS_DIRECTORY"); d != "" {
		return filepath.Join(d, name)
	}
	return "/etc/proxbackup/" + name
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
