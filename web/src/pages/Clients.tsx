// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { api, clientName, type Enrollment, type SetupToken, type Target } from '../api'
import { ago, Card, Empty, ErrorBox, Field, Link, Modal, OnlineDot, StateBadge, useLoad } from '../ui'

export function Clients() {
  const { data, error, reload } = useLoad(api.clients, [], 10000)
  const enrollments = useLoad(api.enrollments, [], 10000)
  const setups = useLoad(api.setupTokens, [], 10000)
  const revoked = useLoad(api.revokedClients, [], 10000)
  const targets = useLoad(api.targets, [])
  const [adding, setAdding] = useState(false)
  const [creatingSetup, setCreatingSetup] = useState(false)
  const [showing, setShowing] = useState<Enrollment | null>(null)
  const [showingSetup, setShowingSetup] = useState<SetupToken | null>(null)
  const [actionError, setActionError] = useState('')
  const pending = (enrollments.data ?? []).filter((e) => !e.used_at && e.expires > Date.now() / 1000)
  const reloadAll = () => {
    reload()
    enrollments.reload()
    setups.reload()
    revoked.reload()
  }
  const activeSetups = (setups.data ?? []).filter((t) => t.expires > Date.now() / 1000)
  return (
    <>
      <h1>Clients</h1>
      <ErrorBox error={error || enrollments.error || setups.error || revoked.error || actionError} />
      <Card
        title={`${data?.length ?? 0} clients` + (pending.length ? `, ${pending.length} waiting to enroll` : '')}
        actions={
          <>
            <button onClick={() => setCreatingSetup(true)} title="One setup for many PCs: each asks for its client name">
              Create agent setup
            </button>
            <button className="primary" onClick={() => setAdding(true)}>
              Add client
            </button>
          </>
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
                      {c.tags.map((t) => (
                        <span key={t} className="tag">
                          #{t}
                        </span>
                      ))}
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
      {activeSetups.length > 0 && (
        <Card title={`${activeSetups.length} active agent setup${activeSetups.length > 1 ? 's' : ''}`}>
          <table>
            <thead>
              <tr>
                <th>PBS server</th>
                <th>Created</th>
                <th>Expires</th>
                <th>PCs enrolled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {activeSetups.map((t) => (
                <tr key={t.id}>
                  <td>{targetLabel(targets.data, t.target_id)}</td>
                  <td>{ago(t.created_at)}</td>
                  <td>{ago(t.expires)}</td>
                  <td>{t.uses}</td>
                  <td className="row-actions">
                    <button className="small" onClick={() => setShowingSetup(t)}>
                      Download
                    </button>
                    <button
                      className="small ghost"
                      onClick={async () => {
                        if (!confirm('Revoke this agent setup? PCs it already enrolled stay.')) return
                        try {
                          setActionError('')
                          await api.deleteSetupToken(t.id)
                          setups.reload()
                        } catch (err) {
                          setActionError((err as Error).message)
                        }
                      }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      {(revoked.data?.length ?? 0) > 0 && (
        <Card title="Recently revoked">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Hostname</th>
                <th>Revoked</th>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {revoked.data!.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link to={`/clients/${c.id}`}>{clientName(c)}</Link>
                  </td>
                  <td>{c.hostname}</td>
                  <td>{ago(c.revoked_at)}</td>
                  <td>{ago(c.last_seen)}</td>
                  <td className="row-actions">
                    {c.restorable ? (
                      <button
                        className="small"
                        title="Reactivate the client: its agent reconnects with a new PBS token and its jobs are re-enabled"
                        onClick={async () => {
                          if (!confirm(`Un-revoke ${clientName(c)}? Its agent reconnects and the jobs enabled before the revocation run again.`)) return
                          try {
                            setActionError('')
                            await api.unrevokeClient(c.id)
                            reloadAll()
                          } catch (err) {
                            setActionError((err as Error).message)
                          }
                        }}
                      >
                        Un-revoke
                      </button>
                    ) : (
                      <span className="muted-text">enroll the PC again</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      {creatingSetup && (
        <CreateSetup
          targets={targets.data}
          onClose={() => {
            setCreatingSetup(false)
            reloadAll()
          }}
        />
      )}
      {showingSetup && <ShowSetup t={showingSetup} onClose={() => setShowingSetup(null)} />}
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

function targetLabel(targets: Target[] | null | undefined, id: number) {
  const t = targets?.find((t) => t.id === id)
  return t ? `${t.name} — ${t.datastore}${t.root_ns ? `/${t.root_ns}` : ''}` : `#${id}`
}

function ShowSetup({ t, onClose }: { t: SetupToken; onClose: () => void }) {
  const { data, error } = useLoad(() => api.setupToken(t.id), [t.id])
  return (
    <Modal title="Agent setup" onClose={onClose} wide>
      <ErrorBox error={error} />
      {data && <SetupInstructions id={t.id} command={data.command} expires={t.expires} />}
      <div className="buttons">
        <button className="primary" onClick={onClose}>
          Done
        </button>
      </div>
    </Modal>
  )
}

function SetupInstructions({ id, command, expires }: { id: number; command: string; expires: number }) {
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const download = async (arch: 'amd64' | 'arm64') => {
    try {
      setError('')
      setBusy(arch)
      await api.downloadSetup(id, arch)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy('')
    }
  }
  return (
    <>
      <p>
        Run the setup on each Windows PC (it asks for administrator rights). It asks for the client name, prefilled with the PC's hostname, and the ProxBackup
        host or IP, prefilled with this console's address, then enrolls the PC and installs the agent service. Any number of PCs can use it until it expires{' '}
        {ago(expires)}.
      </p>
      <div className="buttons" style={{ justifyContent: 'flex-start', marginTop: 0 }}>
        <button className="primary" disabled={!!busy} onClick={() => download('amd64')}>
          {busy === 'amd64' ? 'Downloading…' : 'Download setup (x64)'}
        </button>
        <button disabled={!!busy} onClick={() => download('arm64')}>
          {busy === 'arm64' ? 'Downloading…' : 'Download setup (ARM64)'}
        </button>
      </div>
      <ErrorBox error={error} />
      <p>
        Or run this in a prompt next to <code>proxbackup-agent.exe</code>:
      </p>
      <pre className="copy" onClick={(ev) => navigator.clipboard?.writeText((ev.target as HTMLElement).innerText)}>
        {command}
      </pre>
      <small className="muted-text">Anyone with the setup can enroll PCs until it expires; revoke it under Clients when you are done.</small>
    </>
  )
}

function CreateSetup({ targets, onClose }: { targets?: Target[] | null; onClose: () => void }) {
  const [targetId, setTargetId] = useState(0)
  const [ttl, setTtl] = useState(4)
  const [error, setError] = useState('')
  const [result, setResult] = useState<{ id: number; expires: number; command: string } | null>(null)
  const tid = targetId || targets?.[0]?.id || 0

  if (targets && targets.length === 0)
    return (
      <Modal title="Create agent setup" onClose={onClose}>
        <p>
          Configure a <Link to="/targets">PBS server</Link> first. New clients get their own namespace and a backup-only API token on it.
        </p>
      </Modal>
    )

  return (
    <Modal title="Create agent setup" onClose={onClose} wide={!!result}>
      {!result ? (
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            try {
              setResult(await api.createSetupToken(tid, ttl))
            } catch (err) {
              setError((err as Error).message)
            }
          }}
        >
          <p>A setup enrolls any number of PCs with a temporary token. Each PC chooses its own client name during setup.</p>
          <Field label="PBS server">
            <select value={tid} onChange={(e) => setTargetId(Number(e.target.value))}>
              {targets?.map((t) => (
                <option key={t.id} value={t.id}>
                  {targetLabel(targets, t.id)}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Valid for (hours)">
            <input type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(Number(e.target.value))} required />
          </Field>
          <ErrorBox error={error} />
          <div className="buttons">
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary">Create setup</button>
          </div>
        </form>
      ) : (
        <div>
          <SetupInstructions id={result.id} command={result.command} expires={result.expires} />
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
