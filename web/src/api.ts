// SPDX-License-Identifier: AGPL-3.0-or-later

// Typed client for the proxbackup-server admin API.

export interface Progress {
  phase: string
  files: number
  dirs: number
  bytes_read: number
  bytes_uploaded: number
  bytes_total?: number
  current_archive?: string
  skipped: number
}

export interface Result {
  state: string
  error?: string
  snapshot?: string
  bytes_total: number
  bytes_uploaded: number
  chunks_new: number
  chunks_reused: number
  files: number
  skipped: number
}

export interface RestoreSpec {
  backup_id: string
  backup_time: number
  archive: string
  paths?: string[]
  target_dir: string
  overwrite: 'skip' | 'overwrite' | 'if-newer'
  ns?: string // namespace of a snapshot taken before the client moved
}

export interface Run {
  id: number
  job_id: number
  client_id: number
  kind: string
  state: string
  trigger: string
  queued_at: number
  started_at: number
  finished_at: number
  last_event_at: number
  progress: Progress
  result: Result
  error: string
  snapshot: string
  cancel_requested: boolean
  restore?: RestoreSpec
  scheduled_for: number
  job_name: string
  client_name: string
  group_id: number
}

export interface Client {
  id: number
  name: string
  hostname: string
  os: string
  agent_version: string
  target_id: number
  namespace: string
  token_id: string
  tags: string[] // client groups; group jobs can select clients by tag
  last_seen: number
  online: boolean
  last_run?: Run
  last_success: number
  created_at: number
  config_synced: boolean
  time_zone: string
  agent_update?: string // version the agent can be updated to (the console's)
  agent_update_pushed: boolean
  encryption_fingerprint: string // '' until the first encrypted job is saved
  encryption_created: number
  paused_until: number // scheduled backups paused from the tray app until then (unix s; compare with now)
  paused_by: string
  revoked: boolean
  revoked_at: number
  restorable: boolean // revoked and can be un-revoked (its agent reconnects)
}

// A revoked client is renamed "<name>#revoked-<id>"; this is its name before.
export const clientName = (c: Client) => (c.revoked ? c.name.replace(/#revoked-\d+$/, '') : c.name)

export interface Keep {
  'keep-last'?: number
  'keep-hourly'?: number
  'keep-daily'?: number
  'keep-weekly'?: number
  'keep-monthly'?: number
  'keep-yearly'?: number
}

// The definition shared by the members of a group job.
export interface JobDefinition {
  name: string
  kind: 'files' | 'image'
  backup_id: string // group job: '' = per client (<client> or <client>-image)
  sources: string[]
  excludes: string[]
  volumes: string[]
  use_vss: boolean
  change_detection: 'metadata' | 'data' | 'legacy'
  encrypt: boolean
  schedule: string
  window_minutes: number
  catch_up: boolean
  retention: Keep
  lock_days: number // snapshots stay protected on PBS at least this long and while retention keeps them (0 = off)
  daily_cap: number // backups per day that are locked and count for retention (0 = from the schedule)
  spread_minutes: number // members' start times are spread over this many minutes
  prevent_sleep: boolean // keep the PC from going to sleep while a run is going
  wake_to_run: boolean // wake the PC from sleep or hibernation for scheduled runs
  enabled: boolean
}

// One client's membership in a group job: the group's definition with the
// member's backup group and overrides.
export interface Job extends JobDefinition {
  id: number
  client_id: number
  group_id: number
  group_enabled: boolean
  member_enabled: boolean
  extra_excludes: string[]
  start_delay: number // seconds after the scheduled time this member starts
  next_run?: number
  catch_up_pending?: boolean
}

export const ALL_CLIENTS = '*'

export interface GroupJob extends JobDefinition {
  id: number
  clients: number[] // explicit members
  tags: string[] // plus every client with one of these tags ('*' = all clients)
  created_at: number
}

export interface GroupMember extends Job {
  client_name: string
  online: boolean
  explicit: boolean
  via_tags: string[]
  last_run?: Run
}

export interface GroupJobView extends GroupJob {
  members: GroupMember[]
}

export interface Target {
  id: number
  name: string
  host: string
  fingerprint: string
  datastore: string
  root_ns: string
  admin_auth_id: string
  pbs_user: string
}

export interface Snapshot {
  'backup-type': string
  'backup-id': string
  'backup-time': number
  size: number
  owner: string
  protected: boolean
  files: { filename: string; size: number; 'crypt-mode': string }[]
  verification?: { state: string }
  ns: string
  old?: boolean // in a namespace the client used before
}

/** One row of a snapshot's file catalog. */
export interface CatalogEntry {
  name: string
  type: 'dir' | 'file' | 'symlink' | 'other'
  size?: number
  mtime?: number
  origin?: string // archives (catalog root): the path on the PC they were backed up from
}

export interface LogLine {
  id: number
  ts: number
  level: string
  msg: string
}

export interface Dashboard {
  clients: number
  online: number
  stale: number
  active_runs: number
  failed_recent: number
  recent_runs: Run[]
  active: Run[]
}

export interface NotifySettings {
  webhook_url: string
  smtp_host: string
  smtp_port: number
  smtp_user: string
  smtp_password?: string
  smtp_password_set?: boolean
  smtp_from: string
  smtp_to: string
  smtp_tls: string
  on_success: boolean
  on_failure: boolean
  stale_days: number
}

export interface EncryptionSettings {
  master_pubkey: string
  master_bits?: number
  master_fingerprint?: string
}

export interface UpdateSettings {
  auto_install: boolean
  window: { days: number[]; time: string; minutes: number }
  prerelease: boolean
  agents: boolean
}

export interface UpdateResult {
  state: 'installing' | 'success' | 'failed'
  from: string
  to: string
  time: number
  error?: string
}

export interface ReleaseNote {
  version: string
  url: string
  published_at: number
  body?: string
}

export interface UpdateStatus {
  current: string
  mode: '' | 'deb' | 'binary'
  mode_note?: string
  repo: string
  last_check: number
  check_error?: string
  latest?: string
  latest_url?: string
  notes?: ReleaseNote[]
  published_at?: number
  available: boolean
  next_install?: number
  installing: boolean
  last_result?: UpdateResult
  agent_version?: string
  agent_archs?: string[]
  agent_cache_error?: string
}

export interface Updates {
  settings: UpdateSettings
  status: UpdateStatus
}

export class ApiError extends Error {
  status: number
  constructor(status: number, msg: string) {
    super(msg)
    this.status = status
  }
}

export interface Me {
  username: string
  version: string
  must_change_password: boolean
  local_account: boolean
  local_pbs?: { auth_id: string; host: string }
}

export interface Enrollment {
  id: number
  client_name: string
  target_id: number
  expires: number
  used_at: number
  client_id: number
  created_at: number
}

export interface SetupToken {
  id: number
  target_id: number
  expires: number
  uses: number
  created_at: number
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

// Saves a GET response through the browser (errors come back as JSON).
async function download(path: string, filename: string) {
  const res = await fetch('/api' + path, { credentials: 'same-origin' })
  if (!res.ok) {
    const data = await res.json().catch(() => null)
    if (res.status === 401) onUnauthorized()
    throw new ApiError(res.status, data?.error ?? res.statusText)
  }
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 60000)
}

async function request<T>(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
  const res = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: {
      'X-PROXBACKUP-Request': '1',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    if (res.status === 401 && path !== '/login' && !headers) onUnauthorized()
    throw new ApiError(res.status, data?.error ?? res.statusText)
  }
  return data as T
}

export const api = {
  login: (username: string, password: string) => request<{ username: string }>('POST', '/login', { username, password }),
  logout: () => request('POST', '/logout'),
  loginInfo: () => request<{ pbs_login: boolean }>('GET', '/login-info'),
  me: () => request<Me>('GET', '/me'),
  changePassword: (current_password: string, new_password: string) => request('POST', '/password', { current_password, new_password }),
  dashboard: () => request<Dashboard>('GET', '/dashboard'),

  targets: () => request<Target[]>('GET', '/targets'),
  saveTarget: (t: Partial<Target> & { admin_secret?: string }) =>
    t.id ? request<Target>('PUT', `/targets/${t.id}`, strip(t, ['id', 'created_at'])) : request<Target>('POST', '/targets', t),
  deleteTarget: (id: number) => request('DELETE', `/targets/${id}`),
  testTarget: (t: Partial<Target> & { admin_secret?: string }) =>
    request<{ version: string; release: string; datastores: string[]; datastore_found: boolean }>('POST', '/targets/test', t),

  clients: () => request<Client[]>('GET', '/clients'),
  client: (id: number) => request<{ client: Client; jobs: Job[]; runs: Run[] }>('GET', `/clients/${id}`),
  revokeClient: (id: number) => request('DELETE', `/clients/${id}`),
  revokedClients: () => request<Client[]>('GET', '/clients/revoked'),
  unrevokeClient: (id: number) => request('POST', `/clients/${id}/unrevoke`),
  pushAgentUpdate: (id: number) => request<{ version: string }>('POST', `/clients/${id}/agent-update`),
  snapshots: (id: number) => request<Snapshot[]>('GET', `/clients/${id}/snapshots`),
  // Lists a directory of a snapshot's catalog: "/" lists the archives, "/<archive>/<dir>" their contents.
  catalog: (id: number, snap: Snapshot, path: string) =>
    request<CatalogEntry[]>(
      'GET',
      `/clients/${id}/catalog?` +
        new URLSearchParams({ ns: snap.ns, backup_id: snap['backup-id'], backup_time: String(snap['backup-time']), path }).toString(),
    ),
  restore: (id: number, spec: RestoreSpec) => request<{ run_id: number }>('POST', `/clients/${id}/restore`, spec),
  // The client's encryption key as a PBS key file (proxmox-backup-client --keyfile).
  downloadClientKey: (c: Client) => download(`/clients/${c.id}/encryption-key`, `${c.name}-encryption-key.json`),

  enrollments: () => request<Enrollment[]>('GET', '/enrollments'),
  enrollmentCommand: (id: number) => request<{ command: string }>('GET', `/enrollments/${id}/command`),
  deleteEnrollment: (id: number) => request('DELETE', `/enrollments/${id}`),
  createEnrollment: (client_name: string, target_id: number, ttl_hours: number) =>
    request<{ client_name: string; token: string; command: string }>('POST', '/enrollments', { client_name, target_id, ttl_hours }),

  setupTokens: () => request<SetupToken[]>('GET', '/setup-tokens'),
  setupToken: (id: number) => request<{ token: string; command: string }>('GET', `/setup-tokens/${id}`),
  createSetupToken: (target_id: number, ttl_hours: number) =>
    request<{ id: number; expires: number; token: string; command: string }>('POST', '/setup-tokens', { target_id, ttl_hours }),
  deleteSetupToken: (id: number) => request('DELETE', `/setup-tokens/${id}`),
  // Saves the setup .exe for arch through the browser.
  downloadSetup: (id: number, arch: 'amd64' | 'arm64') => download(`/setup-tokens/${id}/download/${arch}`, `proxbackup-agent-setup-${arch}.exe`),

  // Member jobs: overrides, detach, run one member.
  saveMember: (id: number, m: { enabled: boolean; extra_excludes: string[] }) => request<Job>('PUT', `/jobs/${id}`, m),
  detachMember: (id: number) => request('DELETE', `/jobs/${id}`),
  runJob: (id: number) => request<{ run_id: number }>('POST', `/jobs/${id}/run`),

  groupJobs: () => request<GroupJobView[]>('GET', '/group-jobs'),
  groupJob: (id: number) => request<{ job: GroupJobView; runs: Run[] }>('GET', `/group-jobs/${id}`),
  saveGroupJob: (g: Partial<GroupJob>) => {
    const body = strip(g, ['id', 'created_at', 'members'])
    return g.id ? request<GroupJob>('PUT', `/group-jobs/${g.id}`, body) : request<GroupJob>('POST', '/group-jobs', body)
  },
  deleteGroupJob: (id: number) => request('DELETE', `/group-jobs/${id}`),
  runGroupJob: (id: number) => request<{ run_ids: number[]; skipped: number }>('POST', `/group-jobs/${id}/run`),
  setClientTags: (id: number, tags: string[]) => request<{ tags: string[] }>('PUT', `/clients/${id}/tags`, { tags }),

  runs: (q: { client_id?: number; active?: boolean; limit?: number } = {}) => {
    const p = new URLSearchParams()
    if (q.client_id) p.set('client_id', String(q.client_id))
    if (q.active) p.set('active', '1')
    if (q.limit) p.set('limit', String(q.limit))
    return request<Run[]>('GET', `/runs?${p}`)
  },
  run: (id: number) => request<Run>('GET', `/runs/${id}`),
  runLogs: (id: number, after: number) => request<LogLine[]>('GET', `/runs/${id}/logs?after=${after}`),
  cancelRun: (id: number) => request('POST', `/runs/${id}/cancel`),

  notifySettings: () => request<NotifySettings>('GET', '/settings/notifications'),
  saveNotifySettings: (s: NotifySettings) => request<NotifySettings>('PUT', '/settings/notifications', strip(s, ['smtp_password_set'])),
  testNotify: () => request('POST', '/settings/notifications/test'),

  encryptionSettings: () => request<EncryptionSettings>('GET', '/settings/encryption'),
  saveEncryptionSettings: (s: EncryptionSettings) => request<EncryptionSettings>('PUT', '/settings/encryption', { master_pubkey: s.master_pubkey }),

  updates: () => request<Updates>('GET', '/settings/updates'),
  saveUpdateSettings: (s: UpdateSettings) => request<Updates>('PUT', '/settings/updates', s),
  checkUpdates: () => request<Updates>('POST', '/updates/check'),
  installUpdate: () => request<Updates>('POST', '/updates/install'),
}

function strip<T extends object>(o: T, keys: string[]): Partial<T> {
  const c = { ...o } as Record<string, unknown>
  for (const k of keys) delete c[k]
  return c as Partial<T>
}

// ---- self-service restore (the page the tray app opens; no console login) ----

/** A PC user's restore session, opened from the tray app. */
export interface RestoreSession {
  client_name: string
  hostname: string
  online: boolean
  user: string // DOMAIN\name
  admin: boolean // may restore everything
  scope: string // the folder the user may restore ('' for administrators)
  expires: number
}

/** A restore run requested on the self-service page. */
export interface SelfRun {
  id: number
  state: string
  archive: string
  target_dir: string
  paths: string[]
  queued_at: number
  finished_at: number
  progress: Progress
  result: Result
  error: string
}

const snapQuery = (snap: Snapshot, path: string) =>
  new URLSearchParams({ ns: snap.ns, backup_id: snap['backup-id'], backup_time: String(snap['backup-time']), path }).toString()

/** The API of a restore session; token comes from the page URL (#/restore/<token>). */
export function selfRestoreApi(token: string) {
  const h = { 'X-Restore-Session': token }
  return {
    session: () => request<RestoreSession>('GET', '/self-restore/session', undefined, h),
    snapshots: () => request<Snapshot[]>('GET', '/self-restore/snapshots', undefined, h),
    catalog: (snap: Snapshot, path: string) => request<CatalogEntry[]>('GET', '/self-restore/catalog?' + snapQuery(snap, path), undefined, h),
    restore: (spec: RestoreSpec) => request<{ run_id: number }>('POST', '/self-restore/restore', spec, h),
    runs: () => request<SelfRun[]>('GET', '/self-restore/runs', undefined, h),
  }
}
