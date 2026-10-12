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
```

1. **PBS:** create an API token with admin rights for the server, e.g. `root@pam!proxbackup` with
   *privilege separation off*. Note the certificate fingerprint (Dashboard → *Show Fingerprint*).
2. **Server:**
   ```sh
   proxbackup-server -data-dir /var/lib/proxbackup -public-url https://backup.example.lan:8444 -hostnames backup.example.lan
   ```
   The initial `admin` password is printed once in the log. You can set it beforehand with
   `PROXBACKUP_ADMIN_PASSWORD`, or change it later with `proxbackup-server passwd`.
   Open `https://backup.example.lan:8443`, then go to *PBS servers → Add* and use *Test connection*.
3. **Client:** go to *Clients → Add client*. Copy the command it shows to the PC and run it in an
   elevated prompt:
   ```bat
   proxbackup-agent.exe enroll <token> && proxbackup-agent.exe install && proxbackup-agent.exe start
   ```
   The server creates the PBS namespace `pcs/<client>` and a token that has **DatastoreBackup on
   that namespace only**.
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
cd web && PROXBACKUP_DEV_API=https://127.0.0.1:8443 npm run dev   # UI dev server with API proxy
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

**Not yet verified on real Windows:** the Windows-only code paths (VSS via `go-vss`, raw volume
reads, attribute and timestamp restore, the service wrapper). They compile and vet cleanly for
`windows/amd64`. Test them on a Windows 10/11 VM before rolling out.

Known gaps (see the roadmap):

- no `catalog.pcat1.didx` yet, so the PBS GUI file browser can't list our archives (single-file
  download via the PBS API works, and so does restore through ProxBackup)
- no client-side encryption
- no NTFS ACLs or alternate data streams
- no tray app
- image restore writes a `.img` file. Bare-metal recovery of Windows and Linux machines via a
  Linux-based rescue boot image is planned (roadmap phase 4). Macs will get data restore onto a
  fresh macOS install instead.
- macOS/Linux agents are development builds only: no snapshots, no Unix owners/permissions/
  xattrs/ACLs (planned in roadmap phase 3, see *Platform support* in the architecture doc)
