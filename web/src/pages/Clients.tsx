import { useState } from 'react'
import { api, type Enrollment } from '../api'
import { ago, Card, Empty, ErrorBox, Field, Link, Modal, OnlineDot, StateBadge, useLoad } from '../ui'

export function Clients() {
  const { data, error, reload } = useLoad(api.clients, [], 10000)
  const enrollments = useLoad(api.enrollments, [], 10000)
  const [adding, setAdding] = useState(false)
  const [showing, setShowing] = useState<Enrollment | null>(null)
  const [actionError, setActionError] = useState('')
  const pending = (enrollments.data ?? []).filter((e) => !e.used_at && e.expires > Date.now() / 1000)
  const reloadAll = () => {
    reload()
    enrollments.reload()
  }
  return (
    <>
      <h1>Clients</h1>
      <ErrorBox error={error || enrollments.error || actionError} />
      <Card
        title={`${data?.length ?? 0} clients` + (pending.length ? `, ${pending.length} waiting to enroll` : '')}
        actions={
          <button className="primary" onClick={() => setAdding(true)}>
            Add client
          </button>
        }
      >
        {data && data.length === 0 && pending.length === 0 ? (
          <Empty>No clients yet. Click “Add client” to generate an enrollment token for a Windows PC.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Name</th>
                <th>Hostname</th>
                <th>Agent</th>
                <th>Last seen</th>
                <th>Last successful backup</th>
                <th>Last run</th>
              </tr>
            </thead>
            <tbody>
              {pending.map((e) => (
                <tr key={'e' + e.id} className="pending">
                  <td>
                    <span className="dot pending" title="enrollment token not used yet" />
                  </td>
                  <td>
                    <b>{e.client_name}</b>
                  </td>
                  <td colSpan={4}>
                    <span className="badge info">Waiting for agent</span>{' '}
                    <span className="muted-text">
                      token created {ago(e.created_at)}, expires {ago(e.expires)}
                    </span>
                  </td>
                  <td className="row-actions">
                    <button className="small" onClick={() => setShowing(e)}>
                      Show command
                    </button>
                    <button
                      className="small ghost"
                      onClick={async () => {
                        if (!confirm(`Cancel the enrollment token for ${e.client_name}?`)) return
                        try {
                          setActionError('')
                          await api.deleteEnrollment(e.id)
                          enrollments.reload()
                        } catch (err) {
                          setActionError((err as Error).message)
                        }
                      }}
                    >
                      Cancel
                    </button>
                  </td>
                </tr>
              ))}
              {data?.map((c) => {
                const stale = !c.last_success || Date.now() / 1000 - c.last_success > 3 * 86400
                return (
                  <tr key={c.id}>
                    <td>
                      <OnlineDot online={c.online} />
                    </td>
                    <td>
                      <Link to={`/clients/${c.id}`}>
                        <b>{c.name}</b>
                      </Link>
                    </td>
                    <td>{c.hostname}</td>
                    <td className="muted-text">
                      {c.agent_version} {c.os}
                    </td>
                    <td>{ago(c.last_seen)}</td>
                    <td className={stale ? 'warn-text' : ''}>{ago(c.last_success)}</td>
                    <td>{c.last_run ? <StateBadge state={c.last_run.state} /> : '—'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Card>
      {adding && (
        <AddClient
          onClose={() => {
            setAdding(false)
            reloadAll()
          }}
        />
      )}
      {showing && <EnrollmentCommand e={showing} onClose={() => setShowing(null)} />}
    </>
  )
}

function EnrollmentCommand({ e, onClose }: { e: Enrollment; onClose: () => void }) {
  const { data, error } = useLoad(() => api.enrollmentCommand(e.id), [e.id])
  return (
    <Modal title={`Enroll ${e.client_name}`} onClose={onClose} wide>
      <ErrorBox error={error} />
      {data && <EnrollInstructions command={data.command} expires={e.expires} />}
      <div className="buttons">
        <button className="primary" onClick={onClose}>
          Done
        </button>
      </div>
    </Modal>
  )
}

function EnrollInstructions({ command, expires }: { command: string; expires: number }) {
  return (
    <>
      <p>
        On the Windows PC, copy <code>proxbackup-agent.exe</code> to a folder (e.g. <code>C:\Program Files\proxbackup</code>) and run in an elevated prompt. The token
        can be used once and expires {ago(expires)}.
      </p>
      <pre className="copy" onClick={(ev) => navigator.clipboard?.writeText((ev.target as HTMLElement).innerText)}>
        {command}
      </pre>
      <small className="muted-text">Click the command to copy it. The client appears in the list once the agent has enrolled.</small>
    </>
  )
}

function AddClient({ onClose }: { onClose: () => void }) {
  const targets = useLoad(api.targets, [])
  const [name, setName] = useState('')
  const [targetId, setTargetId] = useState(0)
  const [ttl, setTtl] = useState(24)
  const [error, setError] = useState('')
  const [result, setResult] = useState<{ client_name: string; token: string; command: string } | null>(null)
  const tid = targetId || targets.data?.[0]?.id || 0

  if (targets.data && targets.data.length === 0)
    return (
      <Modal title="Add client" onClose={onClose}>
        <p>
          Configure a <Link to="/targets">PBS server</Link> first. New clients get their own namespace and a backup-only API token on it.
        </p>
      </Modal>
    )

  return (
    <Modal title="Add client" onClose={onClose} wide={!!result}>
      {!result ? (
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            try {
              setResult(await api.createEnrollment(name, tid, ttl))
            } catch (err) {
              setError((err as Error).message)
            }
          }}
        >
          <Field label="Client name" hint="Used as PBS namespace, backup ID and token name. Lowercase letters, digits, - and _.">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. office-pc-07" autoFocus required />
          </Field>
          <Field label="PBS server">
            <select value={tid} onChange={(e) => setTargetId(Number(e.target.value))}>
              {targets.data?.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} — {t.datastore}
                  {t.root_ns ? `/${t.root_ns}` : ''}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Token valid for (hours)">
            <input type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(Number(e.target.value))} />
          </Field>
          <ErrorBox error={error} />
          <div className="buttons">
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary">Create enrollment token</button>
          </div>
        </form>
      ) : (
        <div>
          <p>
            Enrollment token for <b>{result.client_name}</b> created. Until it is used it is listed under Clients, where you can show this command again.
          </p>
          <EnrollInstructions command={result.command} expires={Date.now() / 1000 + ttl * 3600} />
          <div className="buttons">
            <button className="primary" onClick={onClose}>
              Done
            </button>
          </div>
        </div>
      )}
    </Modal>
  )
}
