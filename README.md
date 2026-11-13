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
- **Console users and roles**: built-in and custom roles, optionally limited to clients or tags, and an audit log
- **Storage dashboard**: datastore usage now and over time, and the data each client keeps
- **Automatic updates** of the console and agents

See [docs/architecture.md](docs/architecture.md) for the design, security model and roadmap.

## Components

| Component | Description |
| --- | --- |
| `proxbackup-agent` | **ProxBackup Agent** — Windows service. Runs the schedule pushed by the console, backs up (VSS → pxar archive or volume image → chunks to PBS) and restores. Tray icon per user session: status, *Back up now*, pause (limited to a number of days in a row, default 1), recent runs, *Restore files…* |
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

The package creates the PBS user `proxbackup@pbs` (password in `/etc/proxbackup/pbs-password`),
which the console signs in as and which owns the PCs' tokens, and starts the console on
`https://<pbs-host>:8077`. Sign in as `admin` with the initial password from
`journalctl -u proxbackup-server`; you must replace it at the first sign-in. Then add the datastores
for PCs (step 3).

- The user only has rights on the datastores you add, and only below their root namespace:
  DatastoreAdmin on `/datastore/<store>/<root>`, plus DatastoreAudit on `/datastore/<store>` (not
  propagated) for the usage on the dashboard. VM and container backups in other namespaces stay out
  of its reach. The root helper `proxbackup-server-grants.service` sets these ACLs; it creates the
  root namespace, and only grants one that is new or that the user could already use (see
  `journalctl -u proxbackup-server-grants`). It also removes the user's other ACLs.
- Settings (public URL, host names): `/etc/proxbackup/proxbackup.env`
- Upgrading replaces the user's DatastoreAdmin on `/datastore` with the rights above, and drops
  the datastores no PC uses from the console. From 0.2.16 or older it also deletes the old
  `root@pam!proxbackup-console` token (Admin on `/`).
- `apt purge` removes the console and the user's password. Backups stay in PBS. While the user
  still owns PC tokens, it keeps them and its rights, so those PCs keep backing up (purge prints how
  to remove it). Without tokens, purge removes its ACLs and the user.
- Ports, firewall rules, hiding the console and PBS web UIs from PCs (nginx example), and hosts
  with several interfaces: [docs/network.md](docs/network.md)

**Standalone:**

1. Create a PBS user `proxbackup@pbs` with a password, the root namespace (e.g. `pcs`), and give
   the user DatastoreAdmin on `/datastore/<store>/pcs` and DatastoreAudit on `/datastore/<store>`
   (not propagated), nothing else. Use it as *PBS admin* and agent user of the datastore (step 4);
   it can only grant rights to its own tokens. An API token with Admin on `/` also works.
2. Run `proxbackup-server -public-url https://backup.example.lan:8077 -hostnames backup.example.lan`
   and open port 8077.
3. Sign in as `admin` (initial password in the log, or set `PROXBACKUP_ADMIN_PASSWORD`). Lost it?
   `proxbackup-server passwd [user]` sets a new one.
4. Add the PBS datastore under *Console Settings* (gear icon) → *Datastores* → *Add datastore*.
   If *Host* is a reverse proxy for agents that refuses password sign-ins
   ([docs/network.md](docs/network.md)), set *Console address* to PBS itself (e.g. `pbs:8007`).

### 3. Check the target

Under *Datastores*, add the datastore PCs back up to, or check it on a standalone console. Adjust
the root namespace if needed (default `pcs`; required on the PBS host, and not one holding other
backups). Clients live in `<root>/<client>`; changing the root creates the new namespace and moves
enrolled clients, while older snapshots stay listed and restorable.

### 4. Enroll clients

**One PC:** *Clients → Add client*, then run the shown command in an elevated prompt:

```bat
proxbackup-agent.exe enroll <token>
```

It enrolls the PC, copies the agent to `C:\Program Files\ProxBackup` and installs and starts the
service there, wherever the `.exe` was run from, so the download can be deleted afterwards
(`enroll -no-install` only enrolls; `install` installs and starts on its own). Agents that an
older `install` left in another folder move there by themselves the next time they start. The console
creates the namespace `pcs/<client>` and a PBS token with **DatastoreBackup on that namespace
only**. Running the command again re-enrolls the PC.

**Many PCs:** *Clients → Create agent setup* creates a temporary token (4 h by default) and a setup
`.exe`. On each PC, double-click it, confirm the client name and console address, and it enrolls
the PC, installs the agent to `C:\Program Files\ProxBackup` and starts the service
(equivalent: `proxbackup-agent.exe setup <token>`). Optionally limit how many PCs it may enroll;
each setup enrolls at most 60 PCs per hour. Revoke the setup when done. A setup can't use the name
of a revoked client.

**Revoked clients:** *Clients → Revoked clients* (needs the *Manage revoked clients* permission,
Administrators only by default) lists every revoked client. Revoked clients keep their backups.
*Un-revoke* reconnects the same PC. *Re-enroll* creates an enrollment command, and the PC that runs
it takes over the client: its name, backups, history, encryption keys and jobs. The old PC's
configuration holds the encryption key, so by default the client gets a new key for future backups;
the old key stays escrowed for the existing snapshots (restores pick the right key, and the client
page lists older keys for download). *Add client* under a
revoked client's name points there; otherwise the new client gets backups of its own and can't
see the old ones.

**Credentials:** agents up to 0.2.14 left `%ProgramData%\proxbackup` (PBS token, certificate key,
encryption key) readable by every user of the PC. The console flags those clients as
*credentials exposed*. Once their agents are updated, *Rotate exposed credentials* under Clients
gives each a new client certificate, then a new PBS token secret, the next time it connects (do
it while the PCs are on). *Rotate* on the client page does the same for any client. If a copy of
the old certificate also asks for a new one, or either party uses the old certificate after the
switch, the console revokes the client as *possible credential theft* and sends a notification;
re-enroll it under *Revoked clients*. The encryption key stays: earlier backups need it.
Agents up to 0.2.16 could hand the new certificate to a user who had planted files in the folder
while it was open: rotate those clients again once their agents are updated and the PCs restarted.

### 5. Create jobs

On the client page create a *Files* job (default `C:\Users`, daily, with retention) or a
*Volume image* job; on the **Jobs** page, a job can target many PCs by name, tag or all clients.

| Option | Behaviour |
| --- | --- |
| Schedule | Pushed to the PC and started by the agent on its own clock. Missed windows (PC off, asleep, busy) catch up ASAP by default, or are recorded as *missed*. After boot or wake-up a catch-up, or a run the PC woke up for, waits until the PC reaches the console again (at most 10 minutes; half the start window for a run on time), so it doesn't fail before the network is up. With catch-up on, a run cut off by the agent going offline (PC shut down, network lost) is repeated once the agent has been back online for 30 minutes. *Run now* starts it from the console. |
| Group jobs | Each PC keeps its own backup group and history, can be disabled or get extra excludes. An optional start spread staggers start times. A job is for Windows PCs (`C:\...` folders) or macOS and Linux (`/...`): only clients of that OS are members. Volume images are Windows only. |
| Encryption | Client-side; the console escrows the key. Needs an RSA master key first (Console Settings can generate one), so backups stay recoverable without the console. |
| Keep awake | On by default. The PC doesn't go to sleep on idle while a backup or restore runs (sleep the user asks for still happens). |
| Wake for backups | On by default. A sleeping or hibernated PC wakes up for its scheduled backup, then sleeps again. Needs *Allow wake timers* in the power plan; a PC that is shut down stays off. |
| Bandwidth | Off by default. An upload limit (Mbit/s) per job and/or per client (client page); the lower one wins. Each can have a time window in PC local time with its own limit, e.g. tighter during office hours; it switches mid-run. |
| Battery / metered network | Per job, for scheduled runs: run as usual, wait until the PC is plugged in / off the metered network, or also stop a running backup (repeated later). New jobs wait on metered networks. A run that waits starts on time within its window, later as a catch-up, or is recorded as *missed* without catch-up. The tray and console show why it waits. |
| Immutable backups | On by default. Snapshots are protected against prune and deletion for a minimum period (default 14 days), then for as long as retention keeps them. |
| Cloud storage folders | OneDrive, Dropbox, iCloud, Box and other *files on demand* folders are backed up and browsable, with the files downloaded to the PC; online-only files are left out (logged as skipped, nothing is downloaded). Folders a sync app only lists on demand can't be read from a VSS snapshot by *Files* jobs (Windows refuses); *Volume image* jobs list and restore them. Google Drive's streamed `G:` drive is a virtual drive: use its *Mirror files* mode. |
| Retention | Runs on the console once a day. Only a capped number of backups per job and day count, so a compromised PC can't flood its group to push good snapshots out. |

### 6. Restore

- **Console:** client page → *Snapshots* → *Browse files*. Pick files and folders and restore them
  to their original location or another folder. Works for file backups and volume images
  (NTFS is read straight from the image), encrypted or not. Whole volume images can be restored as
  a `.img` file.
- **On the PC:** tray icon → *Restore files…* opens the same browser without a console login.
  Administrators can restore anything when the tray runs elevated; other users, and
  administrators whose tray isn't elevated (the usual case with UAC), only their own profile
  folder, written with their own Windows permissions, and only files their account could read
  when they were backed up (older backups without recorded permissions need an administrator).
  The page works for up to 8 hours (1 hour for administrators).
- Restores never write through a junction or symbolic link in the target folder (that entry is
  skipped with a warning), and refuse a target whose path contains one. A folder the agent creates
  directly on a drive (like `C:\Restore`) is open only to SYSTEM and administrators. Backups never
  read through one either: below a source it is skipped, and one on the way to a source fails the
  source (back up the folder it points to instead).
- **System folders.** The agent restores as SYSTEM, so a restore into Windows, Program Files,
  ProgramData, the agent's own folders, the Default user profile or a user's Startup folder could
  replace what the PC runs. Only console users with *Restore to system folders* (Administrator and
  Operator roles) and PC administrators may do that, and from the console only on PCs that allow
  it: new installs don't, until a PC administrator runs `proxbackup-agent policy
  -console-system-restores on` (PCs installed before this policy existed allow it until changed). For everyone
  else, the console and the agent refuse such targets and skip what would land in them (a restore
  to `C:\` skips `C:\Windows` and files directly in `C:\`).
  Older agents can't enforce this, so they only take restores from users with that permission
  until they are updated.
- On Windows, backup sources, volumes and restore targets must be on a local drive (`C:\...`). Network paths
  (`\\server\share`) are refused by the console and the agent, so the agent never signs in to
  another machine with the PC's account.

### 7. Users

*Console Settings* (gear icon) → *Users* adds console users and gives them roles: Administrator, Operator, Restore-only,
Read-only or custom ones, each for all clients or only chosen clients and tags. Restore-only users
can restore files anywhere except system folders (see *Restore*); they can still write into users'
profiles, so give the role only to people you'd trust with those users' accounts. Users with
*Manage users* can only grant permissions they have themselves, and can't change users who have
more; with every permission it amounts to Administrator. The *Audit log* tab lists
sign-ins and every change for two years; it keeps only the newest 100,000 failed sign-ins. Users change their own password under the profile menu. Repeated failed
sign-ins from one address or for one username are slowed down (HTTP 429 with the time to wait).
Users who signed in from an address before aren't slowed down by others' failures there (shared
NAT); only their own failed attempts count. Changing the host or
fingerprint of a datastore that clients use needs *Restore* for all clients too, because clients send their
PBS tokens to that host.

### 8. Monitor

The *Dashboard* shows the usage of each datastore (now and over the last day, week, month or
year) and how much data each client's latest backups hold. *Runs* lists active and recent runs.
A run's log keeps at most 20,000 lines (8 MiB). Each client keeps at most 256 MiB of run logs and
results, and the oldest are removed first. The console also cuts every other string an agent sends to
a short length, and a PC opens at most 30 restore pages per hour (10 live at once), so a misbehaving
agent can't fill the console's disk.

### Troubleshooting

The agent service logs to `%ProgramData%\proxbackup\logs\agent.log` (rotated at 5 MiB, 3 old files
kept). `%ProgramData%\proxbackup` is accessible to SYSTEM and Administrators only (the agent
resets its permissions on every start), so open the log from an elevated prompt. Setup moves a
`proxbackup` folder the agent didn't create aside to `proxbackup.untrusted-<time>` (check it, then
delete it), and the service won't start from one: enroll the PC again. If it can't start the tray icon in a user session, the client page in the console says so.

### Ad-hoc use without a console

Handy for testing:

```bat
proxbackup-agent.exe backup -pbs pbs.lan -fingerprint aa:bb:... -auth-id "user@pbs!pc" -secret-file token.txt ^
                       -store ds1 -ns pcs/test -source C:\Users\alice [-bwlimit 20000]
proxbackup-agent.exe restore ... -id <backup-id> -time <unix-time> -archive c-users-alice.mpxar.didx -target C:\Restore
```

## Status

Phase 1 (MVP) is complete; phase 2 is in progress as **alpha 0.2**.

| Phase 2 | Items |
| --- | --- |
| Done | Group jobs, client-side encryption with key escrow, immutable backups, tamper-resistant retention, file restore from volume images, per-file restore browser, new top bar (profile menu, Console Settings), tray app with self-service restore, NTFS ACLs and alternate data streams in file backups, console users with roles (client/tag scopes) and an audit log, upload bandwidth limits (per job/client, time-of-day), metered-network/battery policies |
| Moved | Guided pull-sync to a second PBS (immutable off-host copy) and SMB/NFS share backups → phase 5 |

### Verified

**Against PBS 4.2 (Docker), agent on macOS:**

- backup sessions, dynamic and fixed indexes, incremental chunk reuse, manifest
- PBS's own pxar reader extracting our archives, including v2 split archives reusing the previous
  snapshot's chunks
- server-side verify, prune and retention
- enrollment, mTLS and least-privilege PBS provisioning, as an unprivileged user signed in with a
  ticket (PBS 4.2.8)
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
- **Whole-volume restore** writes a `.img` file. Bare-metal recovery via a Linux rescue image is
  planned for phase 4; Macs will get data restore onto a fresh macOS install.
- **macOS/Linux agents** are development builds: no snapshots, no Unix owners/permissions/xattrs/ACLs
  (phase 3, see *Platform support* in the architecture doc).

## Development

Requires Go ≥ 1.26 and Node ≥ 20. Releases are built with the patched toolchain pinned in `go.mod` (`toolchain` line; Go downloads it automatically) and fail on any reachable `govulncheck` finding. Development happens on `alpha` (the default branch).

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
| `SHA256SUMS.minisig` | its signature (see below) |

**Signed releases:** `internal/update/release.pub` holds the minisign public key. Builds carrying it
only install releases whose `SHA256SUMS.minisig` checks out. The secret key stays on the
maintainer's machine (`~/.minisign/proxbackup.key`, or `$PROXBACKUP_SIGNING_KEY`). Keep it, and its
password, backed up offline and off GitHub: without it, consoles can't install updates anymore.
The Release workflow therefore publishes drafts, and `scripts/release.sh --sign <version>` signs
`SHA256SUMS` on your machine and publishes the draft (`--local` signs before uploading). Both need
`minisign` (`brew install minisign`).

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
| Agents | Follow the console: an older agent is offered the console's version over mTLS and, when idle, checks it against the release's signed `SHA256SUMS` with its own built-in key, replaces itself and restarts. Agents never install an older version. |

Consoles ≤ 0.1.13 must be upgraded by hand once. `PROXBACKUP_UPDATE_REPO` (in
`/etc/proxbackup/proxbackup.env`) points updates at another repository.

## License

Copyright © 2026 Matteo Lo Piccolo.

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`), like Proxmox Backup Server. The PBS chunker in `pkg/pbs` is a port of the one
in proxmox-backup (© Proxmox Server Solutions GmbH, AGPL-3.0).

If you run a modified ProxBackup Console as a network service, the AGPL requires you to offer its
users the corresponding source code.
