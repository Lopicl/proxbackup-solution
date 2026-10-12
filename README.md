# ProxBackup Solution

Centrally managed backups of Windows PCs to **Proxmox Backup Server**, natively. The agent speaks the
PBS backup protocol itself (no Linux proxy, no `proxmox-backup-client` needed), so PC backups are
ordinary PBS snapshots: deduplicated, verifiable, syncable, prunable.

| Component | What it is |
|-----------|------------|
| `proxbackup-agent` | **ProxBackup Agent**, a Windows service. Runs its own schedule from the configuration the server pushes, including catch-up of missed runs, and keeps working while the server is offline. VSS snapshot → pxar archive or volume image → chunks uploaded straight to PBS. Also runs restores. |
| `proxbackup-server` | **ProxBackup Console**, the on-premises management server with an embedded web UI: enrollment, jobs and schedules, run history and live logs, snapshot browser, restore, retention, notifications. |
| `pkg/pbs`, `pkg/pxar` | Go implementations of the PBS client protocol and the pxar v1 archive format. |

See [docs/architecture.md](docs/architecture.md) for the design, security model and roadmap.

## Quick start

```sh
git config core.hooksPath .githooks   # once per clone: enables build-number bumping
make            # builds web UI + bin/proxbackup-server (linux/amd64, darwin) + bin/proxbackup-agent.exe (windows/amd64)
make deb        # bin/proxbackup-server_<version>_{amd64,arm64}.deb for installing on a PBS host
```

1. **Server, on the PBS host (recommended):** copy the `.deb` to the Proxmox Backup Server and run
   ```sh
   apt install ./proxbackup-server_<version>_amd64.deb
   ```
   The package creates an admin API token `root@pam!proxbackup-console`, registers every
   datastore of this PBS as a target, and starts the console on **port 8077**. Open
   `https://<pbs-host>:8077` and sign in with a PBS administrator such as `root@pam`. Settings
   (public URL, host names) are in `/etc/proxbackup/proxbackup.env`. `apt purge` removes the
   console and its token; backups stay in PBS.

   *Standalone instead:* create a PBS API token with the Admin role on `/`, then run
   `proxbackup-server -public-url https://backup.example.lan:8077 -hostnames backup.example.lan`,
   open port 8077, sign in as `admin` (initial password in the log, or set
   `PROXBACKUP_ADMIN_PASSWORD`; change it with `proxbackup-server passwd`) and add the PBS under
   *PBS servers → Add*.
2. **Target:** on the PBS host this is done for you. Check *PBS servers* and adjust the root
   namespace (default `pcs`) if you like.
3. **Client:** go to *Clients → Add client*. Copy the command it shows to the PC and run it in an
   elevated prompt:
   ```bat
   proxbackup-agent.exe enroll <token> && proxbackup-agent.exe install && proxbackup-agent.exe start
   ```
   The server creates the PBS namespace `pcs/<client>` and a token that has **DatastoreBackup on
   that namespace only**. Running the command again on an enrolled PC re-enrolls it.
4. **Jobs:** on the client page, create a *Files* job (default `C:\Users`, daily, with retention) or
   a *Volume image* job. The schedule is pushed to the PC, and the **agent** starts the backup on
   the PC's own clock. If the PC is off, asleep or busy during the start window, the job either
   catches up as soon as possible (default) or is recorded as *missed*. *Run now* triggers it
   from the server immediately.

Ad-hoc use without a server (handy for testing):

```bat
proxbackup-agent.exe backup -pbs pbs.lan -fingerprint aa:bb:... -auth-id "user@pbs!pc" -secret-file token.txt ^
                       -store ds1 -ns pcs/test -source C:\Users\alice
proxbackup-agent.exe restore ... -id <backup-id> -time <unix-time> -archive c-users-alice.pxar.didx -target C:\Restore
```

## Development

Requires Go ≥ 1.26 and Node ≥ 20.

```sh
make test          # unit tests (blob/chunker/index/pxar)
make e2e           # starts a PBS 4.x container and runs the protocol E2E test against it
cd web && PROXBACKUP_DEV_API=https://127.0.0.1:8077 npm run dev   # UI dev server with API proxy
```

## Versioning

The version lives in [`VERSION`](VERSION) as `MAJOR.MINOR.BUILD.TOTAL`:

| Part | Meaning | Resets |
|------|---------|--------|
| `MAJOR` | breaking / milestone release | never |
| `MINOR` | feature release | when MAJOR is bumped |
| `BUILD` | build number within the current MAJOR.MINOR | to 0 on minor or major bumps |
| `TOTAL` | build counter for the whole project | never |

Every commit is a build. The pre-commit hook (`.githooks/`, enabled with
`git config core.hooksPath .githooks`) runs `scripts/version.sh build`, so `0.1.4.17` becomes
`0.1.5.18`. Feature and milestone releases are bumped explicitly, and the hook then leaves the
staged VERSION alone:

```sh
scripts/version.sh minor   # 0.1.5.18 -> 0.2.0.19
scripts/version.sh major   # 0.2.3.22 -> 1.0.0.23
```

`make` stamps the version into both binaries. The web UI shows it in the sidebar, and agents
report theirs to the server.

Development happens on the `alpha` branch, which is the default.

## Status

The MVP has been verified end to end against **PBS 4.2** (Docker), with the agent running on macOS:

- backup sessions, dynamic and fixed indexes, incremental chunk reuse, manifest
- PBS's own pxar reader extracting files from our archives
- server-side verify, prune and retention
- enrollment and mTLS, least-privilege PBS provisioning
- agent-side scheduling: on-time runs, catch-up after the agent was down, `missed` records with
  catch-up off, and backups while the ProxBackup Console was offline (reported afterwards)
- run events, file and image restores (byte-identical)

**Verified on Windows 11 (ARM64 VM) against PBS 4.2:** VSS snapshots, file backup and restore
(contents, attributes, timestamps, symlinks; junctions skipped), incremental reuse, volume
images, and browsing both in the PBS GUI. **Not yet verified:** the service wrapper and
server-driven scheduling.

Known gaps (see the roadmap):

- volume images are browsable in the PBS GUI file browser (via `catalog.pcat1.didx`), but single
  files can't be downloaded from them there: PBS only extracts files from pxar archives. File
  backups are browsable and downloadable.
- no client-side encryption
- no NTFS ACLs or alternate data streams
- no tray app
- image restore writes a `.img` file. Bare-metal recovery of Windows and Linux machines via a
  Linux-based rescue boot image is planned (roadmap phase 4). Macs will get data restore onto a
  fresh macOS install instead.
- macOS/Linux agents are development builds only: no snapshots, no Unix owners/permissions/
  xattrs/ACLs (planned in roadmap phase 3, see *Platform support* in the architecture doc)
