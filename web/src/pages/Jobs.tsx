// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState, type ReactNode } from 'react'
import { ALL_CLIENTS, api, type Bandwidth, type Policy, type GroupJob, type GroupJobView, type GroupMember, type Job, type Keep } from '../api'
import { RunsTable } from './RunsTable'
import { usePerms } from '../perms'
import { ago, Card, dateTime, Empty, ErrorBox, Field, Link, Modal, OnlineDot, StateBadge, useLoad } from '../ui'

// Every backup job is a group job: one definition, any number of member
// clients (chosen by name or by tag), each with its own backup group, history
// and agent-side schedule.

export function Jobs() {
  const { data, error, reload } = useLoad(api.groupJobs, [], 10000)
  const [editing, setEditing] = useState<Partial<GroupJob> | null>(null)
  const [msg, setMsg] = useState('')
  const perms = usePerms()
  // A job's definition applies to clients by tag: editing needs all clients.
  const canEdit = perms.all('jobs.manage')
  return (
    <>
      <h1>Jobs</h1>
      <ErrorBox error={error} />
      {msg && <div className="notice">{msg}</div>}
      <Card
        title={`${data?.length ?? 0} backup jobs`}
        actions={
          canEdit && (
            <button className="primary" onClick={() => setEditing(newGroupJob([]))}>
              New job
            </button>
          )
        }
      >
        {!data ? null : data.length === 0 ? (
          <Empty>No backup jobs yet. A job can back up one PC or many: pick clients by name or by tag.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>What</th>
                <th>Schedule</th>
                <th>Members</th>
                <th>Last runs</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.map((g) => (
                <tr key={g.id} className={g.enabled ? '' : 'disabled'}>
                  <td>
                    <Link to={`/jobs/${g.id}`}>
                      <b>{g.name}</b>
                    </Link>
                    <JobTags j={g} />
                  </td>
                  <td>{g.kind === 'files' ? 'Files' : 'Volume image'}</td>
                  <td className="ellipsis" title={what(g).join(', ')}>
                    {what(g).join(', ')}
                  </td>
                  <td>
                    <ScheduleText j={g} />
                  </td>
                  <td>
                    <b>{g.members.length}</b> <MemberSelection g={g} />
                  </td>
                  <td>
                    <RunSummary members={g.members} />
                  </td>
                  <td className="row-actions">
                    {perms.can('backups.run') && (
                      <button className="small" disabled={g.members.length === 0} onClick={() => runGroup(g, setMsg, reload)}>
                        Run now
                      </button>
                    )}
                    {canEdit && (
                      <button className="small ghost" onClick={() => setEditing(g)}>
                        Edit
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {editing && (
        <GroupJobEditor
          job={editing}
          onClose={(saved) => {
            setEditing(null)
            if (saved && !editing.id) location.hash = `/jobs/${saved.id}`
            reload()
          }}
        />
      )}
    </>
  )
}

async function runGroup(g: GroupJobView, setMsg: (m: string) => void, reload: () => void) {
  try {
    const r = await api.runGroupJob(g.id)
    setMsg(
      `${r.run_ids.length} run${r.run_ids.length === 1 ? '' : 's'} of “${g.name}” queued` +
        (r.skipped ? `, ${r.skipped} member${r.skipped === 1 ? '' : 's'} skipped (a run is already in progress)` : '') +
        '. Offline PCs start when they come online.',
    )
    reload()
  } catch (e) {
    setMsg((e as Error).message)
  }
}

export function JobDetail({ id }: { id: number }) {
  const { data, error, reload } = useLoad(() => api.groupJob(id), [id], 5000)
  const [editing, setEditing] = useState(false)
  const [member, setMember] = useState<GroupMember | null>(null)
  const [msg, setMsg] = useState('')
  const perms = usePerms()
  if (error) return <ErrorBox error={error} />
  if (!data) return null
  const g = data.job
  return (
    <>
      <div className="title-row">
        <h1>
          {g.name}
          <JobTags j={g} />
        </h1>
        <div>
          {perms.can('backups.run') && (
            <button onClick={() => runGroup(g, setMsg, reload)} disabled={g.members.length === 0}>
              {perms.all('backups.run') ? 'Run now on all members' : 'Run now on your clients'}
            </button>
          )}{' '}
          {perms.all('jobs.manage') && (
            <button className="primary" onClick={() => setEditing(true)}>
              Edit job
            </button>
          )}
        </div>
      </div>
      <div className="facts">
        <span>
          Type <b>{g.kind === 'files' ? 'Files' : 'Volume image'}</b>
        </span>
        <span>
          {g.kind === 'files' ? 'Folders' : 'Volumes'} <b>{what(g).join(', ')}</b>
        </span>
        {g.excludes.length > 0 && (
          <span>
            Excludes <b>{g.excludes.join(', ')}</b>
          </span>
        )}
        <span>
          Schedule <ScheduleText j={g} />
        </span>
        {g.schedule && g.spread_minutes > 0 && (
          <span title="Each member starts at a fixed offset within this range">
            Start spread <b>{g.spread_minutes} min</b>
          </span>
        )}
        <span>
          Retention <b>{keepText(g.retention)}</b>
        </span>
        {bandwidthLimited(g.bandwidth) && (
          <span>
            Upload limit <b>{bandwidthText(g.bandwidth)}</b>
          </span>
        )}
        <span>
          Backup group <code>host/{g.backup_id || (g.kind === 'image' ? '<client>-image' : '<client>')}</code>
        </span>
        <span>
          Members <MemberSelection g={g} />
        </span>
      </div>
      {msg && <div className="notice">{msg}</div>}
      <Card title={`Members (${g.members.length})`}>
        {g.members.length === 0 ? (
          <Empty>No clients yet. Edit the job to add clients or tags.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Client</th>
                <th>Member through</th>
                <th>Backup group</th>
                <th>Next run</th>
                <th>Last run</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {g.members.map((m) => (
                <tr key={m.id} className={m.enabled ? '' : 'disabled'}>
                  <td>
                    <OnlineDot online={m.online} />
                  </td>
                  <td>
                    <Link to={`/clients/${m.client_id}`}>
                      <b>{m.client_name}</b>
                    </Link>
                    {!m.member_enabled && <span className="tag">disabled</span>}
                    {m.extra_excludes.length > 0 && (
                      <span className="tag" title={`Also excludes ${m.extra_excludes.join(', ')}`}>
                        +{m.extra_excludes.length} excludes
                      </span>
                    )}
                  </td>
                  <td>
                    {m.explicit && <span className="tag">by name</span>}
                    {m.via_tags.map((t) => (
                      <span key={t} className="tag">
                        {tagLabel(t)}
                      </span>
                    ))}
                  </td>
                  <td>
                    <code>host/{m.backup_id}</code>
                  </td>
                  <td>
                    {m.waiting ? (
                      <span className="badge info">waits: {m.waiting}</span>
                    ) : m.catch_up_pending ? (
                      <span className="badge info">catch-up pending</span>
                    ) : m.next_run ? (
                      dateTime(m.next_run)
                    ) : (
                      '—'
                    )}
                    {m.schedule && m.start_delay > 0 && (
                      <span className="tag" title="Start offset within the job's spread">
                        {delayText(m.start_delay)}
                      </span>
                    )}
                  </td>
                  <td>
                    {m.last_run ? (
                      <Link to={`/runs/${m.last_run.id}`}>
                        <StateBadge state={m.last_run.state} />{' '}
                        <span className="muted-text">{ago(m.last_run.finished_at || m.last_run.started_at || m.last_run.queued_at)}</span>
                      </Link>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="row-actions">
                    {perms.can('backups.run', { id: m.client_id }) && (
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            const r = await api.runJob(m.id)
                            setMsg(`Run #${r.run_id} on ${m.client_name} queued${m.online ? '' : ' — it starts when the PC comes online'}.`)
                            reload()
                          } catch (e) {
                            setMsg((e as Error).message)
                          }
                        }}
                      >
                        Run now
                      </button>
                    )}
                    {perms.can('jobs.manage', { id: m.client_id }) && (
                      <button className="small ghost" onClick={() => setMember(m)}>
                        Settings
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Card title="Run history">
        <RunsTable runs={data.runs} showClient progress />
      </Card>
      {editing && (
        <GroupJobEditor
          job={g}
          onClose={(_, deleted) => {
            setEditing(false)
            if (deleted) location.hash = '/jobs'
            else reload()
          }}
        />
      )}
      {member && (
        <MemberEditor
          member={member}
          groupName={g.name}
          onClose={() => {
            setMember(null)
            reload()
          }}
        />
      )}
    </>
  )
}

function what(j: { kind: string; sources: string[]; volumes: string[] }) {
  return j.kind === 'files' ? j.sources : j.volumes
}

function tagLabel(t: string) {
  return t === ALL_CLIENTS ? 'all clients' : `#${t}`
}

function delayText(s: number) {
  const m = Math.round(s / 60)
  return m >= 60 ? `+${Math.floor(m / 60)}h ${m % 60}m` : `+${m} min`
}

export function JobTags({ j }: { j: Pick<GroupJob, 'enabled' | 'encrypt' | 'lock_days'> }) {
  return (
    <>
      {!j.enabled && <span className="tag">disabled</span>}
      {j.encrypt && <span className="tag">encrypted</span>}
      {j.lock_days > 0 && (
        <span className="tag" title={`New snapshots are protected on PBS for at least ${j.lock_days} day(s), then for as long as retention keeps them`}>
          locked ≥{j.lock_days}d
        </span>
      )}
    </>
  )
}

export function ScheduleText({ j }: { j: { schedule: string; catch_up: boolean } }) {
  return (
    <>
      <code>{j.schedule || 'manual'}</code>
      {j.schedule && <span className="tag">{j.catch_up ? 'catch-up' : 'skip if missed'}</span>}
    </>
  )
}

function MemberSelection({ g }: { g: GroupJob }) {
  if (g.tags.length === 0) return null
  return (
    <span className="muted-text">
      {g.tags.map((t) => (
        <span key={t} className="tag">
          {tagLabel(t)}
        </span>
      ))}
    </span>
  )
}

function RunSummary({ members }: { members: GroupMember[] }) {
  if (members.length === 0) return <>—</>
  const count: Record<string, number> = {}
  for (const m of members) {
    const st = m.last_run?.state ?? 'never'
    count[st] = (count[st] ?? 0) + 1
  }
  return (
    <span title={members.map((m) => `${m.client_name}: ${m.last_run?.state ?? 'never run'}`).join('\n')}>
      {Object.entries(count).map(([st, n]) => (
        <span key={st} className="run-count">
          {st === 'never' ? <span className="badge muted">never</span> : <StateBadge state={st} />} {n}{' '}
        </span>
      ))}
    </span>
  )
}

export function keepText(k: Keep): string {
  const parts = Object.entries(k)
    .filter(([, v]) => v)
    .map(([key, v]) => `${v} ${key.replace('keep-', '')}`)
  return parts.length ? parts.join(', ') : 'keep all'
}

export function newGroupJob(clients: number[]): Partial<GroupJob> {
  return {
    name: 'User files',
    kind: 'files',
    backup_id: '',
    sources: ['C:\\Users'],
    excludes: [],
    volumes: ['C:'],
    use_vss: true,
    change_detection: 'metadata',
    encrypt: false,
    schedule: '0 21 * * *',
    window_minutes: 60,
    catch_up: true,
    retention: { 'keep-last': 3, 'keep-daily': 14, 'keep-weekly': 8, 'keep-monthly': 12 },
    lock_days: 14,
    daily_cap: 0,
    spread_minutes: 0,
    prevent_sleep: true,
    wake_to_run: true,
    bandwidth: {},
    on_battery: '',
    on_metered: 'defer',
    enabled: true,
    clients,
    tags: [],
  }
}

const schedulePresets: [string, string][] = [
  ['0 21 * * *', 'Daily at 21:00'],
  ['0 12,21 * * 1-5', 'Weekdays 12:00 and 21:00'],
  ['0 */4 * * *', 'Every 4 hours'],
  ['0 22 * * 0', 'Weekly, Sunday 22:00'],
  ['', 'Manual only'],
]

const keepKeys: (keyof Keep)[] = ['keep-last', 'keep-hourly', 'keep-daily', 'keep-weekly', 'keep-monthly', 'keep-yearly']

const lines = (s: string) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

type EditorTab = 'general' | 'clients' | 'source' | 'schedule' | 'retention' | 'security'

const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const weekOrder = [1, 2, 3, 4, 5, 6, 0]

export function rateText(kbit?: number): string {
  if (!kbit) return 'unlimited'
  return kbit >= 1000 ? `${kbit / 1000} Mbit/s` : `${kbit} kbit/s`
}

export const bandwidthLimited = (b?: Bandwidth) => !!b && (!!b.rate || (!!b.window_start && !!b.window_rate))

export function bandwidthText(b?: Bandwidth): string {
  if (!b) return 'unlimited'
  let s = rateText(b.rate)
  if (b.window_start) {
    const days = b.window_days?.length ? ' ' + weekOrder.filter((d) => b.window_days!.includes(d)).map((d) => weekdays[d]).join(', ') : ''
    s += `; ${rateText(b.window_rate)} ${b.window_start}–${b.window_end}${days}`
  }
  return s
}

// RateInput edits a rate in Mbit/s, stored in kbit/s (0 = unlimited).
function RateInput({ kbit, onChange }: { kbit?: number; onChange: (kbit: number) => void }) {
  const [text, setText] = useState(kbit ? String(kbit / 1000) : '')
  return (
    <input
      type="number"
      min={0}
      step="any"
      placeholder="unlimited"
      value={text}
      onChange={(e) => {
        setText(e.target.value)
        onChange(Math.max(0, Math.round(Number(e.target.value) * 1000)) || 0)
      }}
    />
  )
}

// BandwidthFields edits an upload limit, with an optional time window.
// PolicySelect picks what scheduled runs do on battery power or a metered network.
function PolicySelect({ value, onChange }: { value: Policy; onChange: (p: Policy) => void }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as Policy)}>
      <option value="">Run as usual</option>
      <option value="defer">Wait until it no longer is</option>
      <option value="stop">Wait, and stop a running backup</option>
    </select>
  )
}

export function BandwidthFields({ b, onChange }: { b: Bandwidth; onChange: (b: Bandwidth) => void }) {
  const set = (p: Partial<Bandwidth>) => onChange({ ...b, ...p })
  const days = b.window_days ?? []
  return (
    <>
      <div className="grid3">
        <Field label="Upload limit (Mbit/s)" hint="Empty = unlimited.">
          <RateInput kbit={b.rate} onChange={(rate) => set({ rate })} />
        </Field>
      </div>
      <div className="options">
        <Option
          checked={!!b.window_start}
          onChange={(on) =>
            onChange(
              on
                ? { ...b, window_start: '08:00', window_end: '18:00', window_days: [1, 2, 3, 4, 5], window_rate: b.window_rate || 10000 }
                : { rate: b.rate },
            )
          }
          title="A different limit at certain times"
        >
          In the PC's local time, e.g. a tighter limit during office hours or none at night.
        </Option>
      </div>
      {b.window_start && (
        <>
          <div className="grid3">
            <Field label="From">
              <input type="time" value={b.window_start} onChange={(e) => set({ window_start: e.target.value })} />
            </Field>
            <Field label="To" hint="Before “From” = until the next day.">
              <input type="time" value={b.window_end ?? ''} onChange={(e) => set({ window_end: e.target.value })} />
            </Field>
            <Field label="Limit then (Mbit/s)" hint="Empty = unlimited.">
              <RateInput kbit={b.window_rate} onChange={(window_rate) => set({ window_rate })} />
            </Field>
          </div>
          <Field label="On" hint="The days the window starts on; none selected = every day.">
            <div className="chips">
              {weekOrder.map((d) => (
                <button
                  type="button"
                  key={d}
                  className={`chip ${days.includes(d) ? 'on' : ''}`}
                  onClick={() => set({ window_days: days.includes(d) ? days.filter((x) => x !== d) : [...days, d] })}
                >
                  {weekdays[d]}
                </button>
              ))}
            </div>
          </Field>
        </>
      )}
    </>
  )
}

// Option is a checkbox with a title and a one-line explanation under it.
export function Option({
  checked,
  onChange,
  title,
  disabled,
  children,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  title: ReactNode
  disabled?: boolean
  children?: ReactNode
}) {
  return (
    <label className={'option' + (disabled ? ' disabled' : '')}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <b>{title}</b>
        {children && <small>{children}</small>}
      </span>
    </label>
  )
}

export function GroupJobEditor({ job, onClose }: { job: Partial<GroupJob>; onClose: (saved?: GroupJob, deleted?: boolean) => void }) {
  const [j, setJ] = useState<Partial<GroupJob>>(job)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const [tab, setTab] = useState<EditorTab>('general')
  const clients = useLoad(api.clients, [])
  const encryption = useLoad(api.encryptionSettings, [])
  // Encryption can only be turned on once a master key is set (jobs encrypted earlier keep it).
  const needsMasterKey = !job.encrypt && !!encryption.data && !encryption.data.master_pubkey
  const set = (patch: Partial<GroupJob>) => setJ({ ...j, ...patch })
  const tags = j.tags ?? []
  const chosen = j.clients ?? []
  const allClients = tags.includes(ALL_CLIENTS)
  const knownTags = [...new Set((clients.data ?? []).flatMap((c) => c.tags))].sort()
  const matching = (clients.data ?? []).filter((c) => allClients || chosen.includes(c.id) || c.tags.some((t) => tags.includes(t)))
  const shown = (clients.data ?? []).filter((c) => !filter || c.name.includes(filter.toLowerCase()) || c.tags.some((t) => t.includes(filter.toLowerCase())))
  const toggleTag = (t: string) => set({ tags: tags.includes(t) ? tags.filter((x) => x !== t) : [...tags, t] })
  const files = j.kind === 'files'
  const locked = (j.lock_days ?? 0) > 0

  const tabs: [EditorTab, string, ReactNode?][] = [
    ['general', 'General'],
    ['clients', 'Clients', matching.length],
    ['source', files ? 'Folders' : 'Volumes', what({ kind: j.kind ?? 'files', sources: j.sources ?? [], volumes: j.volumes ?? [] }).length],
    ['schedule', 'Schedule'],
    ['retention', 'Retention'],
    ['security', 'Security'],
  ]

  return (
    <Modal title={j.id ? `Edit job “${job.name}”` : 'New backup job'} onClose={() => onClose()} wide>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          if (!j.name?.trim()) {
            setTab('general')
            setError('The job needs a name.')
            return
          }
          try {
            const saved = await api.saveGroupJob(j)
            onClose(saved)
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <nav className="tabs editor-tabs">
          {tabs.map(([k, label, count]) => (
            <button type="button" key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>
              {label}
              {count !== undefined && <span className="count">{count}</span>}
            </button>
          ))}
        </nav>

        <div className="tab-panel">
          {tab === 'general' && (
            <>
              <div className="grid2">
                <Field label="Name">
                  <input value={j.name ?? ''} onChange={(e) => set({ name: e.target.value })} autoFocus />
                </Field>
                <Field label="Type" hint={j.id ? 'The type of an existing job cannot be changed.' : undefined}>
                  <select value={j.kind} onChange={(e) => set({ kind: e.target.value as GroupJob['kind'], backup_id: '' })} disabled={!!j.id}>
                    <option value="files">Files and folders (pxar)</option>
                    <option value="image">Volume image (block level)</option>
                  </select>
                </Field>
              </div>
              <Field
                label="Backup ID (PBS backup group)"
                hint={`Empty = the client's name${j.kind === 'image' ? ' plus “-image”' : ''}. Every client has its own namespace, so members never share a group.`}
              >
                <input
                  value={j.backup_id ?? ''}
                  onChange={(e) => set({ backup_id: e.target.value })}
                  placeholder={j.kind === 'image' ? '<client>-image' : '<client>'}
                />
              </Field>
              <div className="options">
                <Option checked={!!j.enabled} onChange={(v) => set({ enabled: v })} title="Enabled">
                  A disabled job never starts on its own and is skipped by “Run now on all members”.
                </Option>
              </div>
            </>
          )}

          {tab === 'clients' && (
            <>
              <p className="muted-text intro">
                Pick PCs by tag and/or by name. Clients tagged later join automatically, and new PCs join jobs for all clients. Each PC keeps its own backup
                group and history.
              </p>
              <h3>By tag</h3>
              <div className="chips">
                <button type="button" className={`chip ${allClients ? 'on' : ''}`} onClick={() => toggleTag(ALL_CLIENTS)}>
                  All clients
                </button>
                {[...new Set([...knownTags, ...tags.filter((t) => t !== ALL_CLIENTS)])].map((t) => (
                  <button type="button" key={t} className={`chip ${tags.includes(t) ? 'on' : ''}`} onClick={() => toggleTag(t)}>
                    #{t}
                  </button>
                ))}
              </div>
              <h3>By name</h3>
              {allClients ? (
                <p className="muted-text">Every client is a member of this job.</p>
              ) : (
                <>
                  <input className="member-filter" placeholder="Filter clients…" value={filter} onChange={(e) => setFilter(e.target.value)} />
                  <div className="member-list">
                    {shown.length === 0 && <span className="muted-text">No clients.</span>}
                    {shown.map((c) => {
                      const viaTag = c.tags.filter((t) => tags.includes(t))
                      return (
                        <label key={c.id} title={viaTag.length && !chosen.includes(c.id) ? `Selected through ${viaTag.map((t) => '#' + t).join(', ')}` : ''}>
                          <input
                            type="checkbox"
                            checked={chosen.includes(c.id) || viaTag.length > 0}
                            disabled={viaTag.length > 0 && !chosen.includes(c.id)}
                            onChange={(e) => set({ clients: e.target.checked ? [...chosen, c.id] : chosen.filter((x) => x !== c.id) })}
                          />
                          <OnlineDot online={c.online} /> {c.name}
                          {c.tags.map((t) => (
                            <span key={t} className="tag">
                              #{t}
                            </span>
                          ))}
                        </label>
                      )
                    })}
                  </div>
                </>
              )}
            </>
          )}

          {tab === 'source' &&
            (files ? (
              <>
                <div className="grid2">
                  <Field label="Folders to back up" hint="One absolute path per line.">
                    <textarea rows={6} value={(j.sources ?? []).join('\n')} onChange={(e) => set({ sources: lines(e.target.value) })} />
                  </Field>
                  <Field
                    label="Exclude patterns"
                    hint={
                      <>
                        One per line, e.g. <code>*.iso</code>, <code>**/Downloads</code>. Temp folders, pagefile etc. are always excluded. Members can add their
                        own.
                      </>
                    }
                  >
                    <textarea rows={6} value={(j.excludes ?? []).join('\n')} onChange={(e) => set({ excludes: lines(e.target.value) })} />
                  </Field>
                </div>
                <h3>How files are read</h3>
                <Field
                  label="Change detection"
                  hint="Unchanged files are skipped by size, timestamps and attributes. Needs PBS 3.3 or later; older servers automatically get the legacy format."
                >
                  <select value={j.change_detection ?? 'metadata'} onChange={(e) => set({ change_detection: e.target.value as GroupJob['change_detection'] })}>
                    <option value="metadata">Skip unchanged files (recommended)</option>
                    <option value="data">Read every file</option>
                    <option value="legacy">Legacy single archive (pxar v1)</option>
                  </select>
                </Field>
                <div className="options">
                  <Option checked={!!j.use_vss} onChange={(v) => set({ use_vss: v })} title="Use a VSS snapshot (recommended)">
                    Backs up a consistent point-in-time copy, including files that are open or locked.
                  </Option>
                </div>
              </>
            ) : (
              <Field label="Volumes" hint="Drive letters, one per line, e.g. C:. Each volume becomes a 4 MiB fixed-chunk image archive.">
                <textarea rows={4} value={(j.volumes ?? []).join('\n')} onChange={(e) => set({ volumes: lines(e.target.value) })} />
              </Field>
            ))}

          {tab === 'schedule' && (
            <>
              <Field
                label="When (cron, PC local time)"
                hint="minute hour day-of-month month day-of-week, or @daily / @every 6h. Empty = manual only. Each agent starts the job itself — the server only pushes this configuration."
              >
                <div className="chips presets">
                  {schedulePresets.map(([v, label]) => (
                    <button type="button" key={label} className={`chip ${j.schedule === v ? 'on' : ''}`} onClick={() => set({ schedule: v })}>
                      {label}
                    </button>
                  ))}
                </div>
                <input value={j.schedule ?? ''} onChange={(e) => set({ schedule: e.target.value })} placeholder="manual only" />
              </Field>
              {j.schedule ? (
                <>
                  <h3>Timing</h3>
                  <div className="grid3">
                    <Field label="Start window (minutes)" hint="A run may start up to this long after its time and still count as on time.">
                      <input
                        type="number"
                        min={1}
                        max={10080}
                        value={j.window_minutes ?? 60}
                        onChange={(e) => set({ window_minutes: Number(e.target.value) })}
                      />
                    </Field>
                    <Field
                      label="Start spread (minutes)"
                      hint="Each member starts at its own fixed offset within this range, so PCs don't all hit PBS at once. 0 = all at once."
                    >
                      <input
                        type="number"
                        min={0}
                        max={1440}
                        value={j.spread_minutes ?? 0}
                        onChange={(e) => set({ spread_minutes: Number(e.target.value) || 0 })}
                      />
                    </Field>
                    <Field label="If the PC misses the window" hint="Because it was off, asleep or busy.">
                      <select value={j.catch_up ? 'catch' : 'skip'} onChange={(e) => set({ catch_up: e.target.value === 'catch' })}>
                        <option value="catch">Run when available (catch-up)</option>
                        <option value="skip">Skip and record as missed</option>
                      </select>
                    </Field>
                  </div>
                </>
              ) : (
                <p className="muted-text">This job only runs when started by hand. Pick a schedule to set its timing.</p>
              )}
              <h3>Power</h3>
              <div className="options">
                <Option checked={!!j.prevent_sleep} onChange={(v) => set({ prevent_sleep: v })} title="Keep the PC awake while a backup runs">
                  Windows won't go to sleep on idle until the backup finishes.
                </Option>
                {j.schedule && (
                  <Option checked={!!j.wake_to_run} onChange={(v) => set({ wake_to_run: v })} title="Wake the PC for scheduled backups">
                    Wakes it from sleep or hibernation. Needs “Allow wake timers” in the power plan; a PC that is shut down stays off.
                  </Option>
                )}
              </div>
              {j.schedule && (
                <div className="grid3">
                  <Field label="On battery power" hint="Laptops unplugged. Runs started by hand always run.">
                    <PolicySelect value={j.on_battery ?? ''} onChange={(on_battery) => set({ on_battery })} />
                  </Field>
                  <Field label="On a metered network" hint="Set as metered in Windows (e.g. a phone hotspot), or roaming.">
                    <PolicySelect value={j.on_metered ?? ''} onChange={(on_metered) => set({ on_metered })} />
                  </Field>
                </div>
              )}
              {j.schedule && (j.on_battery || j.on_metered) && (
                <p className="muted-text small">
                  A run that waits starts as soon as the PC is plugged in or off the metered network: on time within the start window, after it as a
                  catch-up, or it is recorded as missed if catch-up is off. A stopped run starts over.
                </p>
              )}
              <h3>Bandwidth</h3>
              <p className="muted-text">Caps how fast each member uploads to PBS. A limit set on the client applies too; the lower one wins.</p>
              <BandwidthFields b={j.bandwidth ?? {}} onChange={(bandwidth) => set({ bandwidth })} />
            </>
          )}

          {tab === 'retention' && (
            <>
              <p className="muted-text intro">
                Applied by this console once a day to each member's backup group, never because a PC reported a run. Snapshots still inside their lock period,
                and ones an operator protected on PBS, are kept on top of these counts.
              </p>
              <h3>Snapshots to keep</h3>
              <div className="keep">
                {keepKeys.map((k) => (
                  <label key={k}>
                    <span>{k.replace('keep-', '')}</span>
                    <input
                      type="number"
                      min={0}
                      value={j.retention?.[k] ?? 0}
                      onChange={(e) => set({ retention: { ...j.retention, [k]: Number(e.target.value) || undefined } })}
                    />
                  </label>
                ))}
              </div>
              <p className="summary">
                Keeps <b>{keepText(j.retention ?? {})}</b>
                {keepText(j.retention ?? {}) === 'keep all' && <span className="muted-text"> — all counts are zero, nothing is ever pruned</span>}
              </p>
            </>
          )}

          {tab === 'security' && (
            <>
              <h3>Encryption</h3>
              <div className="options">
                <Option checked={!!j.encrypt} onChange={(v) => set({ encrypt: v })} title="Encrypt on the PC" disabled={needsMasterKey}>
                  AES-256-GCM with each client's own key, escrowed by this console. PBS only ever sees encrypted data.
                </Option>
              </div>
              {needsMasterKey && (
                <p className="warn-text small">
                  Set up an RSA master key in <Link to="/settings">Console Settings</Link> first. It keeps encrypted backups recoverable even if this console is
                  lost.
                </p>
              )}
              {!!j.id && !!j.encrypt !== !!job.encrypt && (
                <div className="notice">
                  {j.encrypt ? 'The next run encrypts everything' : 'The next run stores everything unencrypted'}: it reads every file and uploads all data
                  again, since chunks can't be shared between encrypted and unencrypted snapshots. Existing snapshots stay as they are and remain restorable.
                </div>
              )}
              <h3>Ransomware protection</h3>
              <div className="options">
                <Option
                  checked={locked}
                  onChange={(v) => set({ lock_days: v ? 14 : 0 })}
                  title={
                    <span className="inline-input">
                      Immutable for at least
                      <input
                        type="number"
                        min={1}
                        max={3650}
                        disabled={!locked}
                        value={j.lock_days || ''}
                        onChange={(e) => set({ lock_days: Math.max(1, Number(e.target.value) || 1) })}
                      />
                      days
                    </span>
                  }
                >
                  Each new snapshot is protected on PBS for this long, then for as long as retention keeps it: until then nothing can prune or delete it, not
                  even the PC or an operator by mistake. Set it longer than you'd take to notice an attack.
                </Option>
              </div>
              <Field
                label="Backups per day"
                hint="Only this many backups of a member per day are locked and count for retention; extra ones are removed by retention and reported as a possible ransomware sign. 0 = automatic (the scheduled runs plus 3)."
              >
                <input
                  type="number"
                  min={0}
                  max={100}
                  className="narrow"
                  value={j.daily_cap ?? 0}
                  onChange={(e) => set({ daily_cap: Number(e.target.value) || 0 })}
                />
              </Field>
            </>
          )}
        </div>

        <ErrorBox error={error} />
        <div className="buttons">
          {j.id && (
            <button
              type="button"
              className="danger left"
              onClick={async () => {
                if (!confirm(`Delete “${job.name}” for all its clients? Snapshots on PBS are kept.`)) return
                try {
                  await api.deleteGroupJob(j.id!)
                  onClose(undefined, true)
                } catch (err) {
                  setError((err as Error).message)
                }
              }}
            >
              Delete
            </button>
          )}
          <button type="button" onClick={() => onClose()}>
            Cancel
          </button>
          <button className="primary">Save</button>
        </div>
      </form>
    </Modal>
  )
}

// MemberEditor changes one client's settings in a group job.
export function MemberEditor({
  member,
  groupName,
  onClose,
}: {
  member: Job & { explicit?: boolean; via_tags?: string[] }
  groupName: string
  onClose: () => void
}) {
  const [enabled, setEnabled] = useState(member.member_enabled)
  const [extra, setExtra] = useState(member.extra_excludes.join('\n'))
  const [error, setError] = useState('')
  const detachable = member.explicit !== false && !(member.via_tags?.length ?? 0)
  return (
    <Modal title={`“${groupName}” on this client`} onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            await api.saveMember(member.id, { enabled, extra_excludes: lines(extra) })
            onClose()
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <p className="muted-text">
          The job definition is shared by all its clients; <Link to={`/jobs/${member.group_id}`}>edit it on the job page</Link>. These settings only apply to
          this client.
        </p>
        {member.kind === 'files' && (
          <Field
            label="Additional exclude patterns"
            hint={member.excludes.length ? `On top of the job's: ${member.excludes.join(', ')}` : 'One per line, on top of the job’s own.'}
          >
            <textarea rows={4} value={extra} onChange={(e) => setExtra(e.target.value)} />
          </Field>
        )}
        <div className="checks">
          <label>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled on this client
            {!member.group_enabled && <span className="muted-text"> (the job itself is disabled)</span>}
          </label>
        </div>
        <ErrorBox error={error} />
        <div className="buttons">
          <button
            type="button"
            className="danger left"
            disabled={!detachable}
            title={detachable ? '' : 'This client is selected by a tag of the job: disable it here, or change its tags'}
            onClick={async () => {
              if (!confirm(`Remove this client from “${groupName}”? Its snapshots on PBS are kept.`)) return
              try {
                await api.detachMember(member.id)
                onClose()
              } catch (err) {
                setError((err as Error).message)
              }
            }}
          >
            Remove from job
          </button>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary">Save</button>
        </div>
      </form>
    </Modal>
  )
}
