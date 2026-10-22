# ProxBackup Solution

Centrally managed Windows PC backups to **Proxmox Backup Server**.

The agent speaks the PBS backup protocol itself — no Linux proxy, no `proxmox-backup-client` — so
PC backups are ordinary PBS snapshots: deduplicated, verifiable, syncable and prunable.

- **Files and volume images**, taken from a VSS snapshot and uploaded straight to PBS
- **Agent-side scheduling** with catch-up of missed runs; keeps working while the console is offline
- **Group jobs** across many PCs, selected by name or tag
- **Client-side encryption** with key escrow in the console
- **Immutable backups** and tamper-resistant retention
- **Per-file restore** from file backups and volume images, in the console or from the PC's tray icon
- **Automatic updates** of the console and agents

See [docs/architecture.md](docs/architecture.md) for the design, security model and roadmap.

## Components

| Component | Description |
| --- | --- |
| `proxbackup-agent` | **ProxBackup Agent** — Windows service. Runs the schedule pushed by the console, backs up (VSS → pxar archive or volume image → chunks to PBS) and restores. Tray icon per user session: status, *Back up now*, pause, recent runs, *Restore files…* |
| `proxbackup-server` | **ProxBackup Console** — on-premises management server with web UI: enrollment, jobs, run history and live logs, snapshot/file browser, restore, retention, locks, encryption keys, notifications, updates. |
| `pkg/pbs`, `pkg/pxar` | Go implementations of the PBS client protocol and the pxar format (v1 and v2 split archives). |

## Quick start

### 1. Build

```sh
git config core.hooksPath .githooks   # once per clone
make        # web UI + bin/proxbackup-server (linux/amd64, darwin) + bin/proxbackup-agent.exe (windows/amd64)
make deb    # bin/proxbackup-server_<version>_{amd64,arm64}.deb
```

### 2. Install the console

**On the PBS host (recommended):**

```sh
apt install ./proxbackup-server_<version>_amd64.deb
```

The package creates the API token `root@pam!proxbackup-console`, registers every local datastore
as a target and starts the console on `https://<pbs-host>:8077`. Sign in with a PBS administrator
(e.g. `root@pam`).

- Settings (public URL, host names): `/etc/proxbackup/proxbackup.env`
- `apt purge` removes the console and its token; backups stay in PBS.
- Ports, firewall rules, hiding the console and PBS web UIs from PCs (nginx example), and hosts
  with several interfaces: [docs/network.md](docs/network.md)

**Standalone:**

1. Create a PBS API token with the Admin role on `/`.
2. Run `proxbackup-server -public-url https://backup.example.lan:8077 -hostnames backup.example.lan`
   and open port 8077.
3. Sign in as `admin` (initial password in the log, or set `PROXBACKUP_ADMIN_PASSWORD`; change it
   with `proxbackup-server passwd`).
4. Add the PBS under *PBS servers → Add*.

### 3. Check the target

Under *PBS servers*, adjust the root namespace if needed (default `pcs`). Clients live in
`<root>/<client>`; changing the root creates the new namespace and moves enrolled clients, while
older snapshots stay listed and restorable.

### 4. Enroll clients

**One PC:** *Clients → Add client*, then run the shown command in an elevated prompt:

```bat
proxbackup-agent.exe enroll <token> && proxbackup-agent.exe install && proxbackup-agent.exe start
```

The console creates the namespace `pcs/<client>` and a PBS token with **DatastoreBackup on that
namespace only**. Running the command again re-enrolls the PC.

**Many PCs:** *Clients → Create agent setup* creates a temporary token (4 h by default) and a setup
`.exe`. On each PC, double-click it, confirm the client name and console address, and it enrolls
the PC, installs the agent to `C:\Program Files\ProxBackup` and starts the service
(equivalent: `proxbackup-agent.exe setup <token>`). Revoke the setup when done.

### 5. Create jobs

On the client page create a *Files* job (default `C:\Users`, daily, with retention) or a
*Volume image* job; on the **Jobs** page, a job can target many PCs by name, tag or all clients.

| Option | Behaviour |
| --- | --- |
| Schedule | Pushed to the PC and started by the agent on its own clock. Missed windows (PC off, asleep, busy) catch up ASAP by default, or are recorded as *missed*. With catch-up on, a run cut off by the agent going offline (PC shut down, network lost) is repeated once the agent has been back online for 30 minutes. *Run now* starts it from the console. |
| Group jobs | Each PC keeps its own backup group and history, can be disabled or get extra excludes. An optional start spread staggers start times. |
| Encryption | Client-side; the console escrows the key. Needs an RSA master key first (Console Settings can generate one), so backups stay recoverable without the console. |
| Keep awake | On by default. The PC doesn't go to sleep on idle while a backup or restore runs (sleep the user asks for still happens). |
| Wake for backups | On by default. A sleeping or hibernated PC wakes up for its scheduled backup, then sleeps again. Needs *Allow wake timers* in the power plan; a PC that is shut down stays off. |
| Immutable backups | On by default. Snapshots are protected against prune and deletion for a minimum period (default 14 days), then for as long as retention keeps them. |
| Retention | Runs on the console once a day. Only a capped number of backups per job and day count, so a compromised PC can't flood its group to push good snapshots out. |

### 6. Restore

- **Console:** client page → *Snapshots* → *Browse files*. Pick files and folders and restore them
  to their original location or another folder. Works for file backups and volume images
  (NTFS is read straight from the image), encrypted or not. Whole volume images can be restored as
  a `.img` file.
- **On the PC:** tray icon → *Restore files…* opens the same browser without a console login.
  Administrators can restore anything; other users only their own profile folder, written with
  their own Windows permissions.

### Ad-hoc use without a console

Handy for testing:

```bat
proxbackup-agent.exe backup -pbs pbs.lan -fingerprint aa:bb:... -auth-id "user@pbs!pc" -secret-file token.txt ^
                       -store ds1 -ns pcs/test -source C:\Users\alice
proxbackup-agent.exe restore ... -id <backup-id> -time <unix-time> -archive c-users-alice.mpxar.didx -target C:\Restore
```

## Status

Phase 1 (MVP) is complete; phase 2 is in progress as **alpha 0.2**.

| Phase 2 | Items |
| --- | --- |
| Done | Group jobs, client-side encryption with key escrow, immutable backups, tamper-resistant retention, file restore from volume images, per-file restore browser, new top bar (profile menu, Console Settings), tray app with self-service restore, NTFS ACLs and alternate data streams in file backups |
| Open | Console user management with granular permissions, bandwidth and metered-network/battery limits |
| Moved | Guided pull-sync to a second PBS (immutable off-host copy) and SMB/NFS share backups → phase 5 |

### Verified

**Against PBS 4.2 (Docker), agent on macOS:**

- backup sessions, dynamic and fixed indexes, incremental chunk reuse, manifest
- PBS's own pxar reader extracting our archives, including v2 split archives reusing the previous
  snapshot's chunks
- server-side verify, prune and retention
- enrollment, mTLS and least-privilege PBS provisioning
- agent-side scheduling: on-time runs, catch-up, `missed` records, backups while the console was
  offline (reported afterwards)
- run events, file and image restores (byte-identical)

**On Windows 11 (ARM64 VM) against PBS 4.2:** VSS snapshots, file backup and restore (contents,
attributes, timestamps, NTFS ACLs, alternate data streams, symlinks; junctions skipped), incremental reuse, volume images, browsing
in the PBS GUI, single-file restore from volume images, restores from the console's file browser,
and the agent as a Windows service installed by enrollment or the setup `.exe`.

### Known gaps

- **Volume images in the PBS GUI** are browsable but files can't be downloaded there (PBS only
  extracts from pxar). Restore from the console instead (no ADS, junctions, EFS or
  CompactOS-compressed files).
- **Encrypted snapshots** can't be browsed in the PBS GUI. Restore from the console, or with
  `proxmox-backup-client --keyfile` using the key from the client's page.
- **NTFS ACLs and alternate data streams** are kept by file backups (owner, group and DACL, no
  auditing SACL; streams up to 64 KiB), not by file restores from volume images. Restoring with
  `proxmox-backup-client` onto ext4 may need `--ignore-xattrs`.
- **Console sign-in** is a local `admin` or PBS administrator; roles and an audit log come later in
  phase 2.
- **Whole-volume restore** writes a `.img` file. Bare-metal recovery via a Linux rescue image is
  planned for phase 4; Macs will get data restore onto a fresh macOS install.
- **macOS/Linux agents** are development builds: no snapshots, no Unix owners/permissions/xattrs/ACLs
  (phase 3, see *Platform support* in the architecture doc).

## Development

Requires Go ≥ 1.26 and Node ≥ 20. Development happens on `alpha` (the default branch).

```sh
make test   # go vet (host + windows) and all unit tests
make e2e    # protocol E2E test against a PBS 4.x container
cd web && PROXBACKUP_DEV_API=https://127.0.0.1:8077 npm run dev   # UI dev server with API proxy
```

### Versioning

[`VERSION`](VERSION) holds `MAJOR.MINOR.BUILD.TOTAL`:

| Part | Meaning | Resets |
| --- | --- | --- |
| `MAJOR` | breaking / milestone release | never |
| `MINOR` | feature release | on MAJOR bump |
| `BUILD` | build number within MAJOR.MINOR | on MINOR or MAJOR bump |
| `TOTAL` | build counter for the whole project | never |

- **Only package builds bump it:** `make deb`, `make dist` and `scripts/release.sh` run
  `scripts/version.sh build` (`0.1.4.17` → `0.1.5.18`). Commits and plain `make server`/`make agent`
  don't. Commit the bumped `VERSION` and `.build-source` afterwards.
- **Rebuilding the same source** only bumps TOTAL (`0.1.5.18` → `0.1.5.19`); `.build-source`
  records the git tree each bump was made from, ignoring `VERSION`.
- **No bump:** `make dist BUMP=0` (used by the Release workflow).
- **Feature/milestone releases** are bumped explicitly:

  ```sh
  scripts/version.sh minor   # 0.1.5.18 -> 0.2.0.19
  scripts/version.sh major   # 0.2.3.22 -> 1.0.0.23
  ```

The version is stamped into both binaries and the agent exe's Windows version resource; the web UI
shows it in the top bar and agents report theirs to the console.

### Releases

```sh
make release                               # tag HEAD as v<VERSION> and push the tag
scripts/release.sh --local                 # or build with `make dist` and publish via gh
scripts/release.sh --local --prerelease    # pre-release from a branch other than alpha
```

Pushing a `v*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml): it checks
the tag against `VERSION`, runs the tests, builds `make dist` and publishes a GitHub release. The
description lists the commits since the previous release (minus version bumps) and doubles as the
release notes shown in consoles.

| Asset | Used by |
| --- | --- |
| `proxbackup-server_<version>_{amd64,arm64}.deb` | consoles installed from the package |
| `proxbackup-server-linux-{amd64,arm64}` | standalone consoles |
| `proxbackup-agent-windows-{amd64,arm64}.exe` | agents (served by the console) |
| `SHA256SUMS` | integrity check for every download |

**Pre-releases:** releases of `alpha` commits are published as GitHub pre-releases, installed only
by consoles that opt in. Packages built from `alpha` are opted in by default ("Include
pre-releases" under *Console Settings → Updates*). `scripts/prerelease.sh` decides what counts as
`alpha`; override with `make dist PRERELEASE=0`.

## Automatic updates

The console checks GitHub every 6 hours. Under *Console Settings → Updates* pick the weekdays, time
and window for automatic installs, or click *Install now*; release notes for every version in
between are shown.

| Installation | How it updates |
| --- | --- |
| `.deb` | The unprivileged console writes a request; the root unit `proxbackup-server-update.service` (triggered by `.path`) downloads and verifies the package, refuses downgrades and runs `dpkg -i`. Logs: `journalctl -u proxbackup-server-update`. |
| Standalone | The console downloads the new binary, swaps it in and re-executes itself. |
| Agents | Follow the console: an older agent is offered the console's version over mTLS and, when idle, verifies it, replaces itself and restarts. |

Consoles ≤ 0.1.13 must be upgraded by hand once. `PROXBACKUP_UPDATE_REPO` (in
`/etc/proxbackup/proxbackup.env`) points updates at another repository.

## License

Copyright © 2026 Matteo Lo Piccolo.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`), like Proxmox Backup Server. The PBS chunker in `pkg/pbs` is a port of the one
in proxmox-backup (© Proxmox Server Solutions GmbH, AGPL-3.0).

If you run a modified ProxBackup Console as a network service, the AGPL requires you to offer its
users the corresponding source code.
