import { useState } from 'react'
import { api, type Job, type Keep, type Snapshot } from '../api'
import { RunsTable } from './RunsTable'
import { ago, bytes, Card, dateTime, Empty, ErrorBox, Field, Link, Modal, OnlineDot, useLoad } from '../ui'

export function ClientDetail({ id, tab }: { id: number; tab: string }) {
  const { data, error, reload } = useLoad(() => api.client(id), [id], 5000)
  const [editing, setEditing] = useState<Partial<Job> | null>(null)
  const [msg, setMsg] = useState('')
  if (error) return <ErrorBox error={error} />
  if (!data) return null
  const c = data.client

  const tabs = [
    ['jobs', `Jobs (${data.jobs.length})`],
    ['runs', 'History'],
    ['snapshots', 'Snapshots & restore'],
  ]
  return (
    <>
      <div className="title-row">
        <h1>
          <OnlineDot online={c.online} /> {c.name}
        </h1>
        <button
          className="danger"
          onClick={async () => {
            if (!confirm(`Revoke ${c.name}? The agent certificate and its PBS token are disabled. Existing snapshots are kept.`)) return
            await api.revokeClient(id)
            location.hash = '/clients'
          }}
        >
          Revoke client
        </button>
      </div>
      <div className="facts">
        <span>
          Host <b>{c.hostname || '—'}</b>
        </span>
        <span>
          Agent <b>{c.agent_version || '—'}</b> {c.os}
        </span>
        <span>
          Namespace <code>{c.namespace}</code>
        </span>
        <span>
          Token <code>{c.token_id}</code>
        </span>
        <span>
          Last seen <b>{ago(c.last_seen)}</b>
        </span>
        <span>
          Last success <b>{ago(c.last_success)}</b>
        </span>
        <span title="Schedules are evaluated by the agent on the PC's own clock">
          PC time zone <b>{c.time_zone || '—'}</b>
        </span>
        <span>
          Config{' '}
          {c.config_synced ? (
            <b className="ok-text">in sync</b>
          ) : (
            <b className="warn-text" title="The agent picks up the new configuration the next time it connects">pending — applied when the PC connects</b>
          )}
        </span>
      </div>
      <nav className="tabs">
        {tabs.map(([k, label]) => (
          <a key={k} href={`#/clients/${id}/${k}`} className={tab === k ? 'active' : ''}>
            {label}
          </a>
        ))}
      </nav>
      {msg && <div className="notice">{msg}</div>}

      {tab === 'jobs' && (
        <Card
          title="Backup jobs"
          actions={
            <button className="primary" onClick={() => setEditing(newJob(id, c.name))}>
              New job
            </button>
          }
        >
          {data.jobs.length === 0 ? (
            <Empty>No backup jobs. Create one to start protecting this PC.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>What</th>
                  <th>Schedule</th>
                  <th>Next run</th>
                  <th>Retention</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.jobs.map((j) => (
                  <tr key={j.id} className={j.enabled ? '' : 'disabled'}>
                    <td>
                      <b>{j.name}</b>
                      {!j.enabled && <span className="tag">disabled</span>}
                    </td>
                    <td>{j.kind === 'files' ? 'Files' : 'Volume image'}</td>
                    <td className="ellipsis" title={(j.kind === 'files' ? j.sources : j.volumes).join(', ')}>
                      {(j.kind === 'files' ? j.sources : j.volumes).join(', ')}
                    </td>
                    <td>
                      <code>{j.schedule || 'manual'}</code>
                      {j.schedule && <span className="tag">{j.catch_up ? 'catch-up' : 'skip if missed'}</span>}
                    </td>
                    <td>
                      {j.catch_up_pending ? <span className="badge info">catch-up pending</span> : j.next_run ? dateTime(j.next_run) : '—'}
                    </td>
                    <td>{keepText(j.retention)}</td>
                    <td className="row-actions">
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            const r = await api.runJob(j.id)
                            setMsg(`Run #${r.run_id} queued${c.online ? '' : ' — it starts when the PC comes online'}.`)
                            reload()
                          } catch (e) {
                            setMsg((e as Error).message)
                          }
                        }}
                      >
                        Run now
                      </button>
                      <button className="small ghost" onClick={() => setEditing(j)}>
                        Edit
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {tab === 'runs' && (
        <Card title="Run history">
          <RunsTable runs={data.runs} progress />
        </Card>
      )}

      {tab === 'snapshots' && <Snapshots clientId={id} onQueued={(r) => (location.hash = `/runs/${r}`)} />}

      {editing && (
        <JobEditor
          job={editing}
          onClose={() => {
            setEditing(null)
            reload()
          }}
        />
      )}
    </>
  )
}

function newJob(clientId: number, name: string): Partial<Job> {
  return {
    client_id: clientId,
    name: 'User files',
    kind: 'files',
    backup_id: name,
    sources: ['C:\\Users'],
    excludes: [],
    volumes: ['C:'],
    use_vss: true,
    schedule: '0 21 * * *',
    window_minutes: 60,
    catch_up: true,
    retention: { 'keep-last': 3, 'keep-daily': 14, 'keep-weekly': 8, 'keep-monthly': 12 },
    enabled: true,
  }
}

function keepText(k: Keep): string {
  const parts = Object.entries(k)
    .filter(([, v]) => v)
    .map(([key, v]) => `${v} ${key.replace('keep-', '')}`)
  return parts.length ? parts.join(', ') : 'keep all'
}

const schedulePresets: [string, string][] = [
  ['0 21 * * *', 'Daily at 21:00'],
  ['0 12,21 * * 1-5', 'Weekdays 12:00 and 21:00'],
  ['0 */4 * * *', 'Every 4 hours'],
  ['0 22 * * 0', 'Weekly, Sunday 22:00'],
  ['', 'Manual only'],
]

const keepKeys: (keyof Keep)[] = ['keep-last', 'keep-hourly', 'keep-daily', 'keep-weekly', 'keep-monthly', 'keep-yearly']

function JobEditor({ job, onClose }: { job: Partial<Job>; onClose: () => void }) {
  const [j, setJ] = useState<Partial<Job>>(job)
  const [error, setError] = useState('')
  const set = (patch: Partial<Job>) => setJ({ ...j, ...patch })
  const lines = (s: string) => s.split('\n').map((l) => l.trim()).filter(Boolean)

  return (
    <Modal title={j.id ? `Edit job “${job.name}”` : 'New backup job'} onClose={onClose} wide>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            await api.saveJob(j)
            onClose()
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
            <select value={j.kind} onChange={(e) => set({ kind: e.target.value as Job['kind'], backup_id: '' })} disabled={!!j.id}>
              <option value="files">Files and folders (pxar)</option>
              <option value="image">Volume image (block level)</option>
            </select>
          </Field>
        </div>
        {j.kind === 'files' ? (
          <div className="grid2">
            <Field label="Folders to back up" hint="One absolute path per line.">
              <textarea rows={5} value={(j.sources ?? []).join('\n')} onChange={(e) => set({ sources: lines(e.target.value) })} />
            </Field>
            <Field label="Exclude patterns" hint={<>One per line, e.g. <code>*.iso</code>, <code>**/Downloads</code>. Temp folders, pagefile etc. are always excluded.</>}>
              <textarea rows={5} value={(j.excludes ?? []).join('\n')} onChange={(e) => set({ excludes: lines(e.target.value) })} />
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
            hint="minute hour day-of-month month day-of-week, or @daily / @every 6h. Empty = manual. The agent starts the job itself — the server only pushes this configuration."
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
          <Field label="Backup ID (PBS backup group)" hint="Leave empty for the default.">
            <input value={j.backup_id ?? ''} onChange={(e) => set({ backup_id: e.target.value })} />
          </Field>
        </div>
        {j.schedule && (
          <div className="grid2">
            <Field label="Start window (minutes)" hint="A scheduled run may start up to this long after its time and still count as on time.">
              <input type="number" min={1} max={10080} value={j.window_minutes ?? 60} onChange={(e) => set({ window_minutes: Number(e.target.value) })} />
            </Field>
            <Field label="If the PC is off, asleep or busy during the window">
              <select value={j.catch_up ? 'catch' : 'skip'} onChange={(e) => set({ catch_up: e.target.value === 'catch' })}>
                <option value="catch">Run as soon as it is available again (catch-up)</option>
                <option value="skip">Skip it and record the run as missed</option>
              </select>
            </Field>
          </div>
        )}
        <Field label="Retention" hint="Applied by the server after each successful run (PBS prune). All zero keeps everything.">
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
        <div className="checks">
          {j.kind === 'files' && (
            <label>
              <input type="checkbox" checked={!!j.use_vss} onChange={(e) => set({ use_vss: e.target.checked })} /> Use VSS snapshot (recommended, consistent and
              includes open files)
            </label>
          )}
          <label>
            <input type="checkbox" checked={!!j.enabled} onChange={(e) => set({ enabled: e.target.checked })} /> Enabled
          </label>
        </div>
        <ErrorBox error={error} />
        <div className="buttons">
          {j.id && (
            <button
              type="button"
              className="danger left"
              onClick={async () => {
                if (!confirm('Delete this job? Snapshots on PBS are kept.')) return
                await api.deleteJob(j.id!)
                onClose()
              }}
            >
              Delete
            </button>
          )}
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary">Save</button>
        </div>
      </form>
    </Modal>
  )
}

function Snapshots({ clientId, onQueued }: { clientId: number; onQueued: (runId: number) => void }) {
  const { data, error } = useLoad(() => api.snapshots(clientId), [clientId])
  const [restore, setRestore] = useState<{ snap: Snapshot; archive: string } | null>(null)
  return (
    <Card title="Snapshots on PBS">
      <ErrorBox error={error} />
      {data && data.length === 0 && <Empty>No snapshots yet.</Empty>}
      {data && data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Group</th>
              <th className="num">Size</th>
              <th>Verified</th>
              <th>Archives</th>
            </tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={s['backup-id'] + s['backup-time']}>
                <td>{dateTime(s['backup-time'])}</td>
                <td>
                  <code>
                    {s['backup-type']}/{s['backup-id']}
                  </code>
                  {s.protected && <span className="tag">protected</span>}
                </td>
                <td className="num">{bytes(s.size)}</td>
                <td>{s.verification ? <span className={`badge ${s.verification.state === 'ok' ? 'ok' : 'bad'}`}>{s.verification.state}</span> : '—'}</td>
                <td className="archives">
                  {s.files
                    .filter((f) => f.filename.endsWith('.didx') || f.filename.endsWith('.fidx'))
                    .map((f) => (
                      <button key={f.filename} className="small" title={`Restore ${f.filename}`} onClick={() => setRestore({ snap: s, archive: f.filename })}>
                        ⤓ {f.filename.replace(/\.(pxar\.didx|img\.fidx)$/, '')}
                        <span className="muted-text"> {bytes(f.size)}</span>
                      </button>
                    ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {restore && <RestoreDialog clientId={clientId} {...restore} onClose={() => setRestore(null)} onQueued={onQueued} />}
    </Card>
  )
}

function RestoreDialog({
  clientId,
  snap,
  archive,
  onClose,
  onQueued,
}: {
  clientId: number
  snap: Snapshot
  archive: string
  onClose: () => void
  onQueued: (runId: number) => void
}) {
  const isImage = archive.endsWith('.img.fidx')
  const stamp = new Date(snap['backup-time'] * 1000).toISOString().slice(0, 16).replace(/[:T]/g, '-')
  const [target, setTarget] = useState(`C:\\Restore\\${stamp}`)
  const [paths, setPaths] = useState('')
  const [overwrite, setOverwrite] = useState<'skip' | 'overwrite' | 'if-newer'>('skip')
  const [error, setError] = useState('')
  return (
    <Modal title={`Restore ${archive}`} onClose={onClose}>
      <p className="muted-text">
        From snapshot {snap['backup-type']}/{snap['backup-id']} of {dateTime(snap['backup-time'])}. The agent on the PC downloads and writes the files.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            const r = await api.restore(clientId, {
              backup_id: snap['backup-id'],
              backup_time: snap['backup-time'],
              archive,
              target_dir: target,
              paths: paths.split('\n').map((p) => p.trim()).filter(Boolean),
              overwrite,
            })
            onQueued(r.run_id)
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <Field label="Restore to folder on the PC" hint={isImage ? 'The volume image is written as a .img file into this folder.' : 'Use the original location to roll back files in place.'}>
          <input value={target} onChange={(e) => setTarget(e.target.value)} required />
        </Field>
        {!isImage && (
          <>
            <Field label="Only these paths (optional)" hint={<>Archive-relative, one per line, e.g. <code>alice/Documents</code>. Empty restores everything.</>}>
              <textarea rows={3} value={paths} onChange={(e) => setPaths(e.target.value)} />
            </Field>
            <Field label="Existing files">
              <select value={overwrite} onChange={(e) => setOverwrite(e.target.value as typeof overwrite)}>
                <option value="skip">Keep existing files</option>
                <option value="if-newer">Replace if the backup is newer</option>
                <option value="overwrite">Always replace</option>
              </select>
            </Field>
          </>
        )}
        <ErrorBox error={error} />
        <div className="buttons">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary">Start restore</button>
        </div>
      </form>
      <p className="muted-text small">
        <Link to={`/clients/${clientId}/runs`}>Restore progress appears in the client history.</Link>
      </p>
    </Modal>
  )
}
