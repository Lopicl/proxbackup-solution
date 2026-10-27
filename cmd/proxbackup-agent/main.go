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
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"

	"proxbackup/internal/agent"
	"proxbackup/internal/api"
	"proxbackup/internal/tray"
)

// version is set at build time from ./VERSION (see Makefile).
var version = "dev"

const usage = `proxbackup-agent — Proxmox Backup Server agent for Windows

Usage:
  proxbackup-agent enroll <token>         enroll with a proxbackup-server (token from the web UI), then
                                          install and start the service (Windows; -no-install: enroll only)
  proxbackup-agent setup <token>          interactive setup with a setup token: asks for the client
                                          name and console address, then installs and starts the service
  proxbackup-agent install                install the service to Program Files and start it
  proxbackup-agent uninstall              remove the Windows service
  proxbackup-agent start | stop           start (restart if running) / stop the service
  proxbackup-agent run                    run in the foreground (what the service executes)
  proxbackup-agent tray                   the notification-area icon (the service starts it in each user session)
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
		if token, _, ok := embeddedSetupToken(); ok {
			// A setup .exe from the console, started by double-click.
			runSetup(agent.DefaultDataDir(), token)
			return
		}
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
		noInstall := fs.Bool("no-install", false, "only enroll: don't install and start the service")
		fs.Parse(args)
		if fs.NArg() != 1 {
			fatalf("usage: proxbackup-agent enroll [-no-install] <token>")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		var cfg *agent.Config
		if cfg, err = agent.Enroll(ctx, *dataDir, fs.Arg(0)); err == nil {
			fmt.Printf("enrolled as %q (client %d) with %s\n", cfg.ClientName, cfg.ClientID, cfg.ServerURL)
			// On Linux and macOS the package manages the service.
			if runtime.GOOS == "windows" && !*noInstall {
				err = installService(*dataDir)
			}
		}
	case "setup":
		fs.Parse(args)
		if fs.NArg() != 1 {
			fatalf("usage: proxbackup-agent setup <token>")
		}
		runSetup(*dataDir, fs.Arg(0))
	case "tray":
		replace := fs.Bool("replace", false, "take over from the tray of an older agent version")
		fs.Parse(args)
		os.Exit(tray.Run(version, *dataDir, *replace))
	case "run", "install", "uninstall", "start", "stop":
		fs.Parse(args)
		var dirErr error
		var removed []string
		if cmd == "run" {
			// Before anything is written there: only SYSTEM and Administrators
			// may access the data dir (see agent.SecureDataDir).
			removed, dirErr = agent.SecureDataDir(*dataDir)
		}
		if cmd == "run" && dirErr == nil {
			// The service has no console: also log to <data dir>\logs\agent.log.
			if lf, lerr := agent.OpenLogFile(*dataDir); lerr == nil {
				defer lf.Close()
				log = slog.New(slog.NewTextHandler(lf.WithConsole(os.Stderr), nil))
			} else {
				log.Warn("can't open the log file; logging to stderr only", "err", lerr)
			}
		}
		for _, p := range removed {
			log.Warn("removed a link from the data directory", "path", p)
		}
		if cmd == "install" {
			err = installService(*dataDir)
		} else if err = serviceCommand(cmd, *dataDir, log, dirErr); err != nil && cmd == "run" {
			log.Error("agent stopped", "err", err)
		}
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
	dirErr  error // from securing the data dir: the agent won't run
	log     *slog.Logger
	cancel  context.CancelFunc
	done    chan struct{}
}

func (p *program) Start(s service.Service) error {
	if p.dirErr != nil {
		p.log.Error("can't secure the data directory", "err", p.dirErr)
		if sl, err := s.SystemLogger(nil); err == nil {
			sl.Error("can't secure the data directory: " + p.dirErr.Error())
		}
		return p.dirErr
	}
	if !service.Interactive() {
		if moved, err := relocate(p.dataDir); err != nil {
			p.log.Warn("can't move the agent to Program Files; it keeps running from here", "err", err)
		} else if moved {
			// Report the service as started, then exit: the service manager
			// restarts it from the new place (as after a self-update).
			p.log.Info("moved the agent to Program Files, restarting")
			go func() {
				time.Sleep(time.Second)
				agent.RestartService()
				os.Exit(3)
			}()
			return nil
		}
	}
	cfg, err := agent.LoadConfig(p.dataDir)
	if err != nil {
		p.log.Error("can't load the agent configuration", "err", err)
		return err
	}
	r, err := agent.NewRunner(cfg, version, p.log)
	if err != nil {
		p.log.Error("can't start the agent", "err", err)
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

// newService describes the agent service; exe is the binary it runs (empty = this one).
func newService(p *program, dataDir, exe string) (service.Service, error) {
	return service.New(p, &service.Config{
		Name:        "proxbackup-agent",
		DisplayName: "ProxBackup Agent",
		Description: "Backs up this PC to Proxmox Backup Server (managed by ProxBackup Console).",
		Executable:  exe,
		Arguments:   []string{"run", "-data-dir", dataDir},
		Option:      service.KeyValue{"StartType": "automatic", "OnFailure": "restart", "OnFailureDelayDuration": "30s"},
	})
}

// runSetup runs the interactive setup with administrator rights and keeps
// the console window open until the user has read the outcome.
func runSetup(dataDir, token string) {
	relaunched, err := elevate()
	if relaunched {
		return
	}
	if err == nil {
		err = setup(dataDir, token)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nSetup failed:", err)
	}
	fmt.Print("\nPress Enter to close.")
	fmt.Scanln()
	if err != nil {
		os.Exit(1)
	}
}

func serviceCommand(cmd, dataDir string, log *slog.Logger, dirErr error) error {
	p := &program{dataDir: dataDir, dirErr: dirErr, log: log}
	svc, err := newService(p, dataDir, "")
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
	changeDetection := fs.String("change-detection", "metadata", "backup: metadata | data (pxar v2 split archives) | legacy (pxar v1, PBS before 3.3)")
	backupTime := fs.Int64("time", 0, "restore: snapshot time (unix seconds)")
	archive := fs.String("archive", "", "restore: archive name, e.g. c-users.mpxar.didx or c-users.pxar.didx")
	target := fs.String("target", "", "restore: target directory")
	overwrite := fs.String("overwrite", "skip", "restore: skip | overwrite | if-newer")
	keyFile := fs.String("keyfile", "", "PBS key file (kdf none, e.g. downloaded from the console): backups are encrypted with it, restores decrypt with it")
	masterPub := fs.String("master-pubkey", "", "backup with -keyfile: RSA master public key (PEM); the key is stored in the snapshot encrypted with it")
	bwlimit := fs.Int("bwlimit", 0, "backup/image: upload limit in kbit/s (0 = unlimited)")
	fs.Var(&sources, "source", "backup: path to back up (repeatable); image: volume, e.g. C:")
	fs.Var(&excludes, "exclude", "backup: exclude pattern (repeatable)")
	fs.Var(&paths, "path", "restore: only restore this archive path (repeatable); for an .img.fidx archive, a file or folder on its NTFS volume (/ for all), restored without writing the whole image")
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
	spec.Bandwidth.Rate = *bwlimit
	if err := spec.Bandwidth.Validate(); err != nil {
		return err
	}
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		if spec.Crypt, err = agent.KeyFromFile(b); err != nil {
			return err
		}
		spec.Encrypt = true
		if *masterPub != "" {
			pem, err := os.ReadFile(*masterPub)
			if err != nil {
				return err
			}
			spec.Crypt.MasterPubKey = string(pem)
		}
	}
	switch cmd {
	case "backup":
		spec.Kind, spec.Sources, spec.ChangeDetection = api.KindFiles, sources, *changeDetection
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
