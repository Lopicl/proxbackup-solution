// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { ALL_CLIENTS, api, type GroupJob, type GroupJobView, type GroupMember, type Job, type Keep } from '../api'
import { RunsTable } from './RunsTable'
import { ago, Card, dateTime, Empty, ErrorBox, Field, Link, Modal, OnlineDot, StateBadge, useLoad } from '../ui'

// Every backup job is a group job: one definition, any number of member
// clients (chosen by name or by tag), each with its own backup group, history
// and agent-side schedule.

export function Jobs() {
  const { data, error, reload } = useLoad(api.groupJobs, [], 10000)
  const [editing, setEditing] = useState<Partial<GroupJob> | null>(null)
  const [msg, setMsg] = useState('')
  return (
    <>
      <h1>Jobs</h1>
      <ErrorBox error={error} />
      {msg && <div className="notice">{msg}</div>}
      <Card
        title={`${data?.length ?? 0} backup jobs`}
        actions={
          <button className="primary" onClick={() => setEditing(newGroupJob([]))}>
            New job
          </button>
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
                    <button className="small" disabled={g.members.length === 0} onClick={() => runGroup(g, setMsg, reload)}>
                      Run now
                    </button>
                    <button className="small ghost" onClick={() => setEditing(g)}>
                      Edit
                    </button>
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
          <button onClick={() => runGroup(g, setMsg, reload)} disabled={g.members.length === 0}>
            Run now on all members
          </button>{' '}
          <button className="primary" onClick={() => setEditing(true)}>
            Edit job
          </button>
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
                    {m.catch_up_pending ? <span className="badge info">catch-up pending</span> : m.next_run ? dateTime(m.next_run) : '—'}
                    {m.schedule && m.start_delay > 0 && <span className="tag" title="Start offset within the job's spread">{delayText(m.start_delay)}</span>}
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
                    <button className="small ghost" onClick={() => setMember(m)}>
                      Settings
                    </button>
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
        <span className="tag" title={`New snapshots are protected on PBS for ${j.lock_days} day(s)`}>
          locked {j.lock_days}d
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
    spread_minutes: 0,
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

export function GroupJobEditor({ job, onClose }: { job: Partial<GroupJob>; onClose: (saved?: GroupJob, deleted?: boolean) => void }) {
  const [j, setJ] = useState<Partial<GroupJob>>(job)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('')
  const clients = useLoad(api.clients, [])
  const set = (patch: Partial<GroupJob>) => setJ({ ...j, ...patch })
  const tags = j.tags ?? []
  const chosen = j.clients ?? []
  const allClients = tags.includes(ALL_CLIENTS)
  const knownTags = [...new Set((clients.data ?? []).flatMap((c) => c.tags))].sort()
  const matching = (clients.data ?? []).filter((c) => allClients || chosen.includes(c.id) || c.tags.some((t) => tags.includes(t)))
  const shown = (clients.data ?? []).filter((c) => !filter || c.name.includes(filter.toLowerCase()) || c.tags.some((t) => t.includes(filter.toLowerCase())))
  const toggleTag = (t: string) => set({ tags: tags.includes(t) ? tags.filter((x) => x !== t) : [...tags, t] })

  return (
    <Modal title={j.id ? `Edit job “${job.name}”` : 'New backup job'} onClose={() => onClose()} wide>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            const saved = await api.saveGroupJob(j)
            onClose(saved)
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <div className="grid2">
          <Field label="Name">
            <input value={j.name ?? ''} onChange={(e) => set({ name: e.target.value })} required />
          </Field>
          <Field label="Type">
            <select value={j.kind} onChange={(e) => set({ kind: e.target.value as GroupJob['kind'], backup_id: '' })} disabled={!!j.id}>
              <option value="files">Files and folders (pxar)</option>
              <option value="image">Volume image (block level)</option>
            </select>
          </Field>
        </div>

        <Field
          label={`Clients (${matching.length} selected)`}
          hint="Pick PCs by name and/or by tag: clients tagged later join automatically, and new PCs join jobs for all clients. Each PC keeps its own backup group and history."
        >
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
          {!allClients && (
            <>
              <input className="member-filter" placeholder="Filter clients…" value={filter} onChange={(e) => setFilter(e.target.value)} />
              <div className="member-list">
                {shown.length === 0 && <span className="muted-text">No clients.</span>}
                {shown.map((c) => {
                  const viaTag = c.tags.filter((t) => tags.includes(t))
                  return (
                    <label key={c.id}>
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
        </Field>

        {j.kind === 'files' ? (
          <div className="grid2">
            <Field label="Folders to back up" hint="One absolute path per line.">
              <textarea rows={5} value={(j.sources ?? []).join('\n')} onChange={(e) => set({ sources: lines(e.target.value) })} />
            </Field>
            <Field
              label="Exclude patterns"
              hint={
                <>
                  One per line, e.g. <code>*.iso</code>, <code>**/Downloads</code>. Temp folders, pagefile etc. are always excluded. Members can add their own.
                </>
              }
            >
              <textarea rows={5} value={(j.excludes ?? []).join('\n')} onChange={(e) => set({ excludes: lines(e.target.value) })} />
            </Field>
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
          </div>
        ) : (
          <Field label="Volumes" hint="Drive letters, one per line, e.g. C:. Each volume becomes a 4 MiB fixed-chunk image archive.">
            <textarea rows={3} value={(j.volumes ?? []).join('\n')} onChange={(e) => set({ volumes: lines(e.target.value) })} />
          </Field>
        )}
        <div className="grid2">
          <Field
            label="Schedule (cron, PC local time)"
            hint="minute hour day-of-month month day-of-week, or @daily / @every 6h. Empty = manual. Each agent starts the job itself — the server only pushes this configuration."
          >
            <input value={j.schedule ?? ''} onChange={(e) => set({ schedule: e.target.value })} placeholder="0 21 * * *" />
            <div className="chips">
              {schedulePresets.map(([v, label]) => (
                <button type="button" key={label} className={`chip ${j.schedule === v ? 'on' : ''}`} onClick={() => set({ schedule: v })}>
                  {label}
                </button>
              ))}
            </div>
          </Field>
          <Field
            label="Backup ID (PBS backup group)"
            hint={`Empty = the client's name${j.kind === 'image' ? ' plus “-image”' : ''}. Every client has its own namespace, so members never share a group.`}
          >
            <input value={j.backup_id ?? ''} onChange={(e) => set({ backup_id: e.target.value })} />
          </Field>
        </div>
        {j.schedule && (
          <div className="grid3">
            <Field label="Start window (minutes)" hint="A scheduled run may start up to this long after its time and still count as on time.">
              <input type="number" min={1} max={10080} value={j.window_minutes ?? 60} onChange={(e) => set({ window_minutes: Number(e.target.value) })} />
            </Field>
            <Field
              label="Start spread (minutes)"
              hint="Each member starts at its own fixed offset within this range after the scheduled time, so many PCs don't hit PBS at the same minute. 0 = all at once."
            >
              <input type="number" min={0} max={1440} value={j.spread_minutes ?? 0} onChange={(e) => set({ spread_minutes: Number(e.target.value) || 0 })} />
            </Field>
            <Field label="If the PC is off, asleep or busy during the window">
              <select value={j.catch_up ? 'catch' : 'skip'} onChange={(e) => set({ catch_up: e.target.value === 'catch' })}>
                <option value="catch">Run as soon as it is available again (catch-up)</option>
                <option value="skip">Skip it and record the run as missed</option>
              </select>
            </Field>
          </div>
        )}
        <Field
          label="Retention"
          hint="Applied by the server to each member's backup group after each successful run (PBS prune). All zero keeps everything. Snapshots inside the lock period are always kept, on top of these counts."
        >
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
        </Field>
        <Field
          label="Lock period (days)"
          hint="Each new snapshot is marked protected on PBS and released after this many days: until then nothing can prune or delete it, not even the PC or an operator by mistake. 0 = off."
        >
          <input type="number" min={0} max={3650} value={j.lock_days ?? 0} onChange={(e) => set({ lock_days: Number(e.target.value) || 0 })} />
        </Field>
        <div className="checks">
          {j.kind === 'files' && (
            <label>
              <input type="checkbox" checked={!!j.use_vss} onChange={(e) => set({ use_vss: e.target.checked })} /> Use VSS snapshot (recommended, consistent and
              includes open files)
            </label>
          )}
          <label>
            <input type="checkbox" checked={!!j.encrypt} onChange={(e) => set({ encrypt: e.target.checked })} /> Encrypt on the PC (AES-256-GCM with each
            client's own key, escrowed by this console)
          </label>
          <label>
            <input type="checkbox" checked={!!j.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        {!!j.id && !!j.encrypt !== !!job.encrypt && (
          <div className="notice">
            {j.encrypt ? 'The next run encrypts everything' : 'The next run stores everything unencrypted'}: it reads every file and uploads all data again, since chunks
            can't be shared between encrypted and unencrypted snapshots. Existing snapshots stay as they are and remain restorable.
          </div>
        )}
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
export function MemberEditor({ member, groupName, onClose }: { member: Job & { explicit?: boolean; via_tags?: string[] }; groupName: string; onClose: () => void }) {
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
          The job definition is shared by all its clients; <Link to={`/jobs/${member.group_id}`}>edit it on the job page</Link>. These settings only apply to this
          client.
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
