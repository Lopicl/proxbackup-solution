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
}

export interface Keep {
  'keep-last'?: number
  'keep-hourly'?: number
  'keep-daily'?: number
  'keep-weekly'?: number
  'keep-monthly'?: number
  'keep-yearly'?: number
}

export interface Job {
  id: number
  client_id: number
  name: string
  kind: 'files' | 'image'
  backup_id: string
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
  lock_days: number // snapshots stay protected on PBS this long (0 = off)
  enabled: boolean
  next_run?: number
  catch_up_pending?: boolean
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

export interface UpdateStatus {
  current: string
  mode: '' | 'deb' | 'binary'
  mode_note?: string
  repo: string
  last_check: number
  check_error?: string
  latest?: string
  latest_url?: string
  latest_notes?: string
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: {
      'X-PROXBACKUP-Request': '1',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    if (res.status === 401 && path !== '/login') onUnauthorized()
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
  pushAgentUpdate: (id: number) => request<{ version: string }>('POST', `/clients/${id}/agent-update`),
  snapshots: (id: number) => request<Snapshot[]>('GET', `/clients/${id}/snapshots`),
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

  saveJob: (j: Partial<Job>) =>
    j.id ? request<Job>('PUT', `/jobs/${j.id}`, strip(j, ['id', 'next_run', 'catch_up_pending', 'client_id', 'created_at'])) : request<Job>('POST', '/jobs', strip(j, ['next_run', 'catch_up_pending'])),
  deleteJob: (id: number) => request('DELETE', `/jobs/${id}`),
  runJob: (id: number) => request<{ run_id: number }>('POST', `/jobs/${id}/run`),

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
