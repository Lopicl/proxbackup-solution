// SPDX-License-Identifier: AGPL-3.0-or-later

// Command proxbackup-agent is the Windows backup agent. It runs as a Windows
// service, receives jobs from proxbackup-server and backs up directly to a
// Proxmox Backup Server. It also has standalone commands for ad-hoc use.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kardianos/service"

	"proxbackup/internal/agent"
	"proxbackup/internal/api"
)

// version is set at build time from ./VERSION (see Makefile).
var version = "dev"

const usage = `proxbackup-agent — Proxmox Backup Server agent for Windows

Usage:
  proxbackup-agent enroll <token>         enroll with a proxbackup-server (token from the web UI)
  proxbackup-agent install | uninstall    install/remove the Windows service
  proxbackup-agent start | stop           start/stop the service
  proxbackup-agent run                    run in the foreground (what the service executes)
  proxbackup-agent backup  [flags]        ad-hoc file backup straight to PBS (no server needed)
  proxbackup-agent image   [flags]        ad-hoc volume image backup
  proxbackup-agent restore [flags]        restore an archive from PBS
  proxbackup-agent version

Global flags:
  -data-dir string   agent state directory (default %s)

Run "proxbackup-agent backup -h" for the ad-hoc flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, agent.DefaultDataDir())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fs.String("data-dir", agent.DefaultDataDir(), "agent state directory")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var err error
	switch cmd {
	case "version":
		fmt.Println(version)
	case "enroll":
		fs.Parse(args)
		if fs.NArg() != 1 {
			fatalf("usage: proxbackup-agent enroll <token>")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		var cfg *agent.Config
		if cfg, err = agent.Enroll(ctx, *dataDir, fs.Arg(0)); err == nil {
			fmt.Printf("enrolled as %q (client %d) with %s\n", cfg.ClientName, cfg.ClientID, cfg.ServerURL)
		}
	case "run", "install", "uninstall", "start", "stop":
		fs.Parse(args)
		err = serviceCommand(cmd, *dataDir, log)
	case "backup", "image", "restore":
		err = adhoc(cmd, fs, args, dataDir)
	default:
		fmt.Fprintf(os.Stderr, usage, agent.DefaultDataDir())
		os.Exit(2)
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "proxbackup-agent: "+format+"\n", args...)
	os.Exit(1)
}

type program struct {
	dataDir string
	log     *slog.Logger
	cancel  context.CancelFunc
	done    chan struct{}
}

func (p *program) Start(service.Service) error {
	cfg, err := agent.LoadConfig(p.dataDir)
	if err != nil {
		return err
	}
	r, err := agent.NewRunner(cfg, version, p.log)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	go func() {
		defer close(p.done)
		p.log.Info("agent started", "server", cfg.ServerURL, "client", cfg.ClientName, "version", version)
		r.Run(ctx)
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel != nil {
		p.cancel()
		select {
		case <-p.done:
		case <-time.After(20 * time.Second):
		}
	}
	return nil
}

func serviceCommand(cmd, dataDir string, log *slog.Logger) error {
	p := &program{dataDir: dataDir, log: log}
	svc, err := service.New(p, &service.Config{
		Name:        "proxbackup-agent",
		DisplayName: "ProxBackup Agent",
		Description: "Backs up this PC to Proxmox Backup Server (managed by ProxBackup Console).",
		Arguments:   []string{"run", "-data-dir", dataDir},
		Option:      service.KeyValue{"StartType": "automatic", "OnFailure": "restart", "OnFailureDelayDuration": "30s"},
	})
	if err != nil {
		return err
	}
	if cmd == "run" {
		if service.Interactive() {
			// Foreground: stop on Ctrl-C.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			if err := p.Start(svc); err != nil {
				return err
			}
			<-ctx.Done()
			return p.Stop(svc)
		}
		return svc.Run()
	}
	// Re-running the enrollment command on an enrolled PC must work: keep an
	// installed service, and restart a running one so it loads the new config.
	st, stErr := svc.Status()
	switch {
	case cmd == "install" && stErr == nil:
		fmt.Println("service install: already installed")
		return nil
	case cmd == "start" && stErr == nil && st == service.StatusRunning:
		cmd = "restart"
	}
	if err := service.Control(svc, cmd); err != nil {
		return err
	}
	fmt.Printf("service %s: ok\n", cmd)
	return nil
}

// stdoutReporter prints job events for ad-hoc commands.
type stdoutReporter struct{ last time.Time }

func (r *stdoutReporter) Log(level, msg string) {
	fmt.Printf("%s %-5s %s\n", time.Now().Format("15:04:05"), strings.ToUpper(level), msg)
}

func (r *stdoutReporter) Progress(p api.Progress) {
	if time.Since(r.last) < 5*time.Second {
		return
	}
	r.last = time.Now()
	fmt.Printf("%s       %s: %d files, %d dirs, %.1f MiB read, %.1f MiB uploaded\n", time.Now().Format("15:04:05"),
		p.Phase, p.Files, p.Dirs, float64(p.BytesRead)/(1<<20), float64(p.BytesUploaded)/(1<<20))
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

func adhoc(cmd string, fs *flag.FlagSet, args []string, _ *string) error {
	var sources, excludes, paths listFlag
	host := fs.String("pbs", "", "PBS host[:port]")
	fp := fs.String("fingerprint", "", "PBS certificate SHA-256 fingerprint")
	authID := fs.String("auth-id", "", "API token id (user@realm!name)")
	secretFile := fs.String("secret-file", "", "file containing the API token secret (or env PROXBACKUP_SECRET)")
	store := fs.String("store", "", "datastore")
	ns := fs.String("ns", "", "namespace")
	id := fs.String("id", "", "backup id (default: hostname)")
	vssFlag := fs.Bool("vss", true, "use a VSS snapshot (Windows)")
	backupTime := fs.Int64("time", 0, "restore: snapshot time (unix seconds)")
	archive := fs.String("archive", "", "restore: archive name, e.g. c-users.pxar.didx")
	target := fs.String("target", "", "restore: target directory")
	overwrite := fs.String("overwrite", "skip", "restore: skip | overwrite | if-newer")
	fs.Var(&sources, "source", "backup: path to back up (repeatable); image: volume, e.g. C:")
	fs.Var(&excludes, "exclude", "backup: exclude pattern (repeatable)")
	fs.Var(&paths, "path", "restore: only restore this archive path (repeatable)")
	fs.Parse(args)

	secret := os.Getenv("PROXBACKUP_SECRET")
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
		if strings.HasPrefix(secret, "{") { // accept the JSON printed by `proxmox-backup-manager user generate-token`
			var t struct{ Value string }
			if json.Unmarshal(b, &t) == nil {
				secret = t.Value
			}
		}
	}
	if *id == "" {
		h, _ := os.Hostname()
		*id = strings.ToLower(strings.Split(h, ".")[0])
	}
	spec := api.JobSpec{
		RunID:    0,
		Target:   api.PBSTarget{Host: *host, Fingerprint: *fp, Datastore: *store, Namespace: *ns, AuthID: *authID, Secret: secret},
		BackupID: *id,
		UseVSS:   *vssFlag,
		Excludes: excludes,
	}
	switch cmd {
	case "backup":
		spec.Kind, spec.Sources = api.KindFiles, sources
	case "image":
		spec.Kind, spec.Volumes = api.KindImage, sources
	case "restore":
		spec.Kind = api.KindRestore
		spec.Restore = &api.RestoreSpec{BackupID: *id, BackupTime: *backupTime, Archive: *archive, Paths: paths, TargetDir: *target, Overwrite: *overwrite}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res := agent.Run(ctx, spec, &stdoutReporter{})
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if res.State == api.RunFailed || res.State == api.RunCanceled {
		return fmt.Errorf("%s: %s", res.State, res.Error)
	}
	return nil
}
