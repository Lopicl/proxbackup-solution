// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { ALL_CLIENTS, api, type GroupJob, type GroupMember, type Snapshot } from '../api'
import { RestoreBrowser } from './RestoreBrowser'
import { RunsTable } from './RunsTable'
import { GroupJobEditor, JobTags, keepText, MemberEditor, newGroupJob, ScheduleText } from './Jobs'
import { ago, bytes, Card, dateTime, Empty, ErrorBox, Field, Link, Modal, OnlineDot, StateBadge, useLoad } from '../ui'

export function ClientDetail({ id, tab }: { id: number; tab: string }) {
  const { data, error, reload } = useLoad(() => api.client(id), [id], 5000)
  const groups = useLoad(api.groupJobs, [], 5000)
  const [editing, setEditing] = useState<Partial<GroupJob> | null>(null)
  const [member, setMember] = useState<{ m: GroupMember; group: string } | null>(null)
  const [editingTags, setEditingTags] = useState(false)
  const [msg, setMsg] = useState('')
  if (error) return <ErrorBox error={error} />
  if (!data) return null
  const c = data.client
  const reloadAll = () => {
    reload()
    groups.reload()
  }
  // The group jobs this client is a member of.
  const memberships = (groups.data ?? []).flatMap((g) => g.members.filter((m) => m.client_id === id).map((m) => ({ g, m })))

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
          Agent <b>{c.agent_version || '—'}</b> {c.os}{' '}
          {c.agent_update &&
            (c.agent_update_pushed ? (
              <b className="warn-text" title="The agent installs it as soon as no backup is running">
                update to {c.agent_update} pushed{c.online ? '' : ' — applied when the PC connects'}
              </b>
            ) : (
              <button
                className="small"
                title="Install the console's agent version on this PC now, even with automatic agent updates off. It waits for running backups to finish."
                onClick={async () => {
                  try {
                    const r = await api.pushAgentUpdate(id)
                    setMsg(`Agent update to ${r.version} pushed${c.online ? '' : ' — it is installed when the PC comes online'}.`)
                    reload()
                  } catch (e) {
                    setMsg((e as Error).message)
                  }
                }}
              >
                Update agent to {c.agent_update}
              </button>
            ))}
        </span>
        <span>
          Tags{' '}
          {c.tags.length ? (
            c.tags.map((t) => (
              <span key={t} className="tag">
                #{t}
              </span>
            ))
          ) : (
            <b>none</b>
          )}{' '}
          <button className="small ghost" title="Tags group clients: jobs can target every client with a tag" onClick={() => setEditingTags(true)}>
            Edit
          </button>
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
        <span>
          Encryption{' '}
          {c.encryption_fingerprint ? (
            <>
              <code title={`Key fingerprint ${c.encryption_fingerprint}, created ${dateTime(c.encryption_created)}`}>{c.encryption_fingerprint.slice(0, 23)}…</code>{' '}
              <button
                className="small"
                title="The key is escrowed by this console. Keep a copy offline to restore with proxmox-backup-client --keyfile if the console is lost."
                onClick={async () => {
                  if (!confirm(`Download the encryption key of ${c.name}? Anyone with this file and read access to the datastore can decrypt its backups. Store it safely.`)) return
                  try {
                    await api.downloadClientKey(c)
                  } catch (e) {
                    setMsg((e as Error).message)
                  }
                }}
              >
                Download key
              </button>
            </>
          ) : (
            <b>off</b>
          )}
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
            <button className="primary" onClick={() => setEditing(newGroupJob([id]))}>
              New job
            </button>
          }
        >
          {memberships.length === 0 ? (
            <Empty>{groups.data ? 'No backup jobs. Create one, or add this PC to an existing job on the Jobs page.' : 'Loading…'}</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Job</th>
                  <th>Type</th>
                  <th>What</th>
                  <th>Schedule</th>
                  <th>Next run</th>
                  <th>Last run</th>
                  <th>Retention</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {memberships.map(({ g, m }) => (
                  <tr key={m.id} className={m.enabled ? '' : 'disabled'}>
                    <td>
                      <Link to={`/jobs/${g.id}`}>
                        <b>{g.name}</b>
                      </Link>
                      <JobTags j={g} />
                      {!m.member_enabled && <span className="tag">disabled here</span>}
                      {g.members.length > 1 && (
                        <span className="tag" title={`Shared with ${g.members.length - 1} other client(s)`}>
                          {g.members.length} clients
                        </span>
                      )}
                      {m.via_tags.map((t) => (
                        <span key={t} className="tag" title="Member through this tag">
                          {t === ALL_CLIENTS ? 'all clients' : '#' + t}
                        </span>
                      ))}
                    </td>
                    <td>{g.kind === 'files' ? 'Files' : 'Volume image'}</td>
                    <td className="ellipsis" title={(g.kind === 'files' ? g.sources : g.volumes).join(', ')}>
                      {(g.kind === 'files' ? g.sources : g.volumes).join(', ')}
                      {m.extra_excludes.length > 0 && (
                        <span className="tag" title={`Also excludes ${m.extra_excludes.join(', ')}`}>
                          +{m.extra_excludes.length} excludes
                        </span>
                      )}
                    </td>
                    <td>
                      <ScheduleText j={g} />
                    </td>
                    <td>
                      {m.catch_up_pending ? <span className="badge info">catch-up pending</span> : m.next_run ? dateTime(m.next_run) : '—'}
                    </td>
                    <td>{m.last_run ? <StateBadge state={m.last_run.state} /> : '—'}</td>
                    <td>{keepText(g.retention)}</td>
                    <td className="row-actions">
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            const r = await api.runJob(m.id)
                            setMsg(`Run #${r.run_id} queued${c.online ? '' : ' — it starts when the PC comes online'}.`)
                            reloadAll()
                          } catch (e) {
                            setMsg((e as Error).message)
                          }
                        }}
                      >
                        Run now
                      </button>
                      <button className="small ghost" onClick={() => setMember({ m, group: g.name })} title="Settings of this job on this client">
                        Settings
                      </button>
                      <button className="small ghost" onClick={() => setEditing(g)} title={g.members.length > 1 ? `Changes apply to all ${g.members.length} clients` : ''}>
                        Edit job
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

      {tab === 'snapshots' && (
        <Snapshots
          clientId={id}
          online={c.online}
          onQueued={(runs) => (location.hash = runs.length === 1 ? `/runs/${runs[0]}` : `/clients/${id}/runs`)}
        />
      )}

      {editing && (
        <GroupJobEditor
          job={editing}
          onClose={() => {
            setEditing(null)
            reloadAll()
          }}
        />
      )}
      {member && (
        <MemberEditor
          member={member.m}
          groupName={member.group}
          onClose={() => {
            setMember(null)
            reloadAll()
          }}
        />
      )}
      {editingTags && (
        <TagsEditor
          clientId={id}
          tags={c.tags}
          onClose={() => {
            setEditingTags(false)
            reloadAll()
          }}
        />
      )}
    </>
  )
}

function TagsEditor({ clientId, tags, onClose }: { clientId: number; tags: string[]; onClose: () => void }) {
  const [text, setText] = useState(tags.join(' '))
  const [error, setError] = useState('')
  return (
    <Modal title="Client tags" onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            await api.setClientTags(clientId, text.split(/[\s,]+/).filter(Boolean))
            onClose()
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <Field
          label="Tags"
          hint="Separated by spaces or commas, e.g. office laptops. Lowercase letters, digits, '.', '_' and '-'. Jobs that target a tag attach or detach this client right away."
        >
          <input value={text} onChange={(e) => setText(e.target.value.toLowerCase())} autoFocus />
        </Field>
        <ErrorBox error={error} />
        <div className="buttons">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary">Save</button>
        </div>
      </form>
    </Modal>
  )
}

function Snapshots({ clientId, online, onQueued }: { clientId: number; online: boolean; onQueued: (runIds: number[]) => void }) {
  const { data, error } = useLoad(() => api.snapshots(clientId), [clientId])
  const [restore, setRestore] = useState<{ snap: Snapshot; archive: string } | null>(null)
  const [browse, setBrowse] = useState<Snapshot | null>(null)
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
              <tr key={s.ns + s['backup-id'] + s['backup-time']}>
                <td>{dateTime(s['backup-time'])}</td>
                <td>
                  <code>
                    {s['backup-type']}/{s['backup-id']}
                  </code>
                  {s.old && (
                    <span className="tag" title="Taken before this client moved to its current namespace">
                      {s.ns}
                    </span>
                  )}
                  {s.protected && <span className="tag">protected</span>}
                  {s.files.some((f) => f['crypt-mode'] === 'encrypt') && <span className="tag">encrypted</span>}
                </td>
                <td className="num">{bytes(s.size)}</td>
                <td>{s.verification ? <span className={`badge ${s.verification.state === 'ok' ? 'ok' : 'bad'}`}>{s.verification.state}</span> : '—'}</td>
                <td className="archives">
                  {s.files.some((f) => f.filename === 'catalog.pcat1.didx') && (
                    <button className="small primary" title="Browse the files in this snapshot and restore some of them" onClick={() => setBrowse(s)}>
                      Browse files
                    </button>
                  )}
                  {s.files
                    // A split archive (.mpxar + .ppxar) is restored as one; the catalog isn't restorable.
                    .filter((f) => /\.(pxar|mpxar)\.didx$|\.img\.fidx$/.test(f.filename))
                    .map((f) => {
                      const payload = f.filename.endsWith('.mpxar.didx')
                        ? s.files.find((p) => p.filename === f.filename.replace(/\.mpxar\.didx$/, '.ppxar.didx'))
                        : undefined
                      return (
                        <button key={f.filename} className="small" title={`Restore ${f.filename}`} onClick={() => setRestore({ snap: s, archive: f.filename })}>
                          ⤓ {f.filename.replace(/\.(m?pxar\.didx|img\.fidx)$/, '')}
                          <span className="muted-text"> {bytes(f.size + (payload?.size ?? 0))}</span>
                        </button>
                      )
                    })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {restore && <RestoreDialog clientId={clientId} {...restore} onClose={() => setRestore(null)} onQueued={(r) => onQueued([r])} />}
      {browse && <RestoreBrowser clientId={clientId} snap={browse} online={online} onClose={() => setBrowse(null)} onQueued={onQueued} />}
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
              ns: snap.ns,
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
        <Field
          label="Restore to folder on the PC"
          hint={
            isImage
              ? 'Selected files keep their folder structure here. Without paths, the whole volume image is written as a .img file.'
              : 'Use the original location to roll back files in place.'
          }
        >
          <input value={target} onChange={(e) => setTarget(e.target.value)} required />
        </Field>
        <Field
          label={isImage ? 'Files or folders from the volume (optional)' : 'Only these paths (optional)'}
          hint={
            isImage ? (
              <>
                Paths on the NTFS volume, one per line, e.g. <code>Users/alice/Documents</code>; <code>/</code> restores every file. Only the
                selected files are downloaded. Empty restores the raw image.
              </>
            ) : (
              <>
                Archive-relative, one per line, e.g. <code>alice/Documents</code>. Empty restores everything.
              </>
            )
          }
        >
          <textarea rows={3} value={paths} onChange={(e) => setPaths(e.target.value)} />
        </Field>
        {(!isImage || paths.trim() !== '') && (
          <Field label="Existing files">
            <select value={overwrite} onChange={(e) => setOverwrite(e.target.value as typeof overwrite)}>
              <option value="skip">Keep existing files</option>
              <option value="if-newer">Replace if the backup is newer</option>
              <option value="overwrite">Always replace</option>
            </select>
          </Field>
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
