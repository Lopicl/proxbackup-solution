# ProxBackup Solution

Centrally managed backups of Windows PCs to **Proxmox Backup Server**, natively. The agent speaks the
PBS backup protocol itself (no Linux proxy, no `proxmox-backup-client` needed), so PC backups are
ordinary PBS snapshots: deduplicated, verifiable, syncable, prunable.

| Component | What it is |
| --- | --- |
| `proxbackup-agent` | **ProxBackup Agent**, a Windows service. Runs its own schedule from the configuration the server pushes, including catch-up of missed runs, and keeps working while the server is offline. VSS snapshot → pxar archive or volume image → chunks uploaded straight to PBS. Also runs restores. |
| `proxbackup-server` | **ProxBackup Console**, the on-premises management server with an embedded web UI: enrollment, jobs and schedules, run history and live logs, snapshot browser, restore, retention, notifications. |
| `pkg/pbs`, `pkg/pxar` | Go implementations of the PBS client protocol and the pxar archive format (v1, and v2 split archives). |

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
proxbackup-agent.exe restore ... -id <backup-id> -time <unix-time> -archive c-users-alice.mpxar.didx -target C:\Restore
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
| --- | --- | --- |
| `MAJOR` | breaking / milestone release | never |
| `MINOR` | feature release | when MAJOR is bumped |
| `BUILD` | build number within the current MAJOR.MINOR | to 0 on minor or major bumps |
| `TOTAL` | build counter for the whole project | never |

Only package builds bump the version: `make deb`, `make dist`, and `scripts/release.sh`
(once per release) run `scripts/version.sh build`, so `0.1.4.17` becomes `0.1.5.18`. Commits
and plain `make server`/`make agent` builds leave it alone; commit the bumped `VERSION` after a
package build. `make dist BUMP=0` packages the current version without bumping (the Release
workflow uses it for the version `release.sh` tagged). Feature and milestone releases are
bumped explicitly:

```sh
scripts/version.sh minor   # 0.1.5.18 -> 0.2.0.19
scripts/version.sh major   # 0.2.3.22 -> 1.0.0.23
```

`make` stamps the version into both binaries. The web UI shows it in the sidebar, and agents
report theirs to the server.

Development happens on the `alpha` branch, which is the default.

## Releases and automatic updates

```sh
make release                      # tag HEAD as v<VERSION> and push the tag
scripts/release.sh --local        # or: build with `make dist` and publish from this machine via gh
scripts/release.sh --local --prerelease   # pre-release from a branch other than alpha
```

Every release of a commit on `alpha` is published as a GitHub pre-release, so only consoles that
opt in to pre-releases install it.

Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml): it
checks that the tag matches `VERSION`, runs the tests, builds `make dist` and publishes a GitHub
release with these assets:

| Asset | Used by |
| --- | --- |
| `proxbackup-server_<version>_{amd64,arm64}.deb` | consoles installed from the package |
| `proxbackup-server-linux-{amd64,arm64}` | standalone consoles |
| `proxbackup-agent-windows-{amd64,arm64}.exe` | agents (served to them by the console) |
| `SHA256SUMS` | every download is checked against it |

The console checks the releases every 6 hours. Under *Settings → Updates* you pick the weekdays,
time and window length for automatic installs, or install right away with *Install now*:

* **.deb installs:** the console runs unprivileged, so it only writes a request. The root unit
  `proxbackup-server-update.service`, started by `proxbackup-server-update.path`, downloads the
  package from GitHub itself, verifies it, refuses to downgrade and runs `dpkg -i`. Its log is in
  `journalctl -u proxbackup-server-update`.
* **Standalone:** the console downloads the new binary, swaps it in and re-executes itself.
* **Agents** follow the console. A Windows agent older than the console is offered the console's
  version over its mTLS connection. When no backup is running it verifies the binary, replaces
  itself and restarts.

Consoles from before this feature (≤ 0.1.13) have to be upgraded by hand once.
`PROXBACKUP_UPDATE_REPO` (in `/etc/proxbackup/proxbackup.env`) points updates at another
repository.

## Status

The MVP has been verified end to end against **PBS 4.2** (Docker), with the agent running on macOS:

- backup sessions, dynamic and fixed indexes, incremental chunk reuse, manifest
- PBS's own pxar reader extracting files from our archives, including pxar v2 split archives
  whose unchanged files reuse the previous snapshot's chunks
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

## License

Copyright © 2026 Matteo Lo Piccolo.

ProxBackup Solution is free software, licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`), the same
license as Proxmox Backup Server. The PBS chunker in `pkg/pbs` is a port of the one in
proxmox-backup (© Proxmox Server Solutions GmbH, AGPL-3.0).

If you run a modified version of the ProxBackup Console as a network service, the AGPL requires
you to offer its users the corresponding source code.
