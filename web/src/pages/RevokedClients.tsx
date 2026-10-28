// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { api, clientName, type Client } from '../api'
import { usePerms } from '../perms'
import { ago, Card, Empty, ErrorBox, Field, Link, Modal, useLoad } from '../ui'
import { EnrollInstructions } from './Clients'

// Revoked clients keep their backups. Un-revoking gives them back to the same
// PC (its agent still holds its certificate); re-enrolling gives them to the
// PC that runs a new enrollment command. Both need "Manage revoked clients".
export function RevokedClients() {
  const perms = usePerms()
  const allowed = perms.all('clients.revoked')
  const { data, error, reload } = useLoad(() => (allowed ? api.revokedClients() : Promise.resolve([])), [allowed], 10000)
  const [actionError, setActionError] = useState('')
  const [reenrolling, setReenrolling] = useState<Client | null>(null)
  const [showing, setShowing] = useState<Client | null>(null)
  if (!allowed) return <ErrorBox error="You don't have the permission: Manage revoked clients" />
  const act = async (f: () => Promise<unknown>) => {
    try {
      setActionError('')
      await f()
      reload()
    } catch (err) {
      setActionError((err as Error).message)
    }
  }
  return (
    <>
      <h1>
        <Link to="/clients">Clients</Link> › Revoked clients
      </h1>
      <ErrorBox error={error || actionError} />
      <p className="muted-text">
        Revoked clients keep their backups. <b>Un-revoke</b> reconnects the same PC. <b>Re-enroll</b> creates an enrollment command: the PC that runs it takes
        over the client with its name, backups, history and jobs.
      </p>
      <Card title={`${data?.length ?? 0} revoked clients`}>
        {data && data.length === 0 ? (
          <Empty>No revoked clients.</Empty>
        ) : (
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
              {data?.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link to={`/clients/${c.id}`}>{clientName(c)}</Link>
                  </td>
                  <td>{c.hostname}</td>
                  <td>
                    {ago(c.revoked_at)}
                    {c.revoked_reason && (
                      <>
                        {' '}
                        <span className="badge bad" title={c.revoked_reason}>
                          possible credential theft
                        </span>
                      </>
                    )}
                  </td>
                  <td>{ago(c.last_seen)}</td>
                  <td className="row-actions">
                    {c.reenroll ? (
                      <>
                        <span className="badge warn" title="The PC that runs the command takes over this client">
                          re-enrollment pending, expires {ago(c.reenroll.expires)}
                        </span>
                        <button className="small" onClick={() => setShowing(c)}>
                          Show command
                        </button>
                        <button
                          className="small ghost"
                          onClick={() => confirm(`Cancel the re-enrollment of ${clientName(c)}?`) && act(() => api.deleteReenrollment(c.id))}
                        >
                          Cancel
                        </button>
                      </>
                    ) : c.name_in_use ? (
                      <span className="muted-text" title="Revoke that client or cancel its enrollment to bring this one back">
                        name used by another client
                      </span>
                    ) : (
                      <>
                        {c.restorable && (
                          <button
                            className="small"
                            title="Reactivate the client: its agent reconnects with a new PBS token and its jobs are re-enabled"
                            onClick={() =>
                              confirm(`Un-revoke ${clientName(c)}? Its agent reconnects and the jobs enabled before the revocation run again.`) &&
                              act(() => api.unrevokeClient(c.id))
                            }
                          >
                            Un-revoke
                          </button>
                        )}
                        <button className="small" title="Give this client, with its backups, to a PC" onClick={() => setReenrolling(c)}>
                          Re-enroll…
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {reenrolling && (
        <Reenroll
          c={reenrolling}
          onClose={() => {
            setReenrolling(null)
            reload()
          }}
        />
      )}
      {showing && <ReenrollCommand c={showing} onClose={() => setShowing(null)} />}
    </>
  )
}

function Reenroll({ c, onClose }: { c: Client; onClose: () => void }) {
  const [ttl, setTtl] = useState(24)
  const [error, setError] = useState('')
  const [result, setResult] = useState<{
    command: string
    expires: number
  } | null>(null)
  const name = clientName(c)
  return (
    <Modal title={`Re-enroll ${name}`} onClose={onClose} wide={!!result}>
      {!result ? (
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            try {
              setResult(await api.createReenrollment(c.id, ttl))
            } catch (err) {
              setError((err as Error).message)
            }
          }}
        >
          <p>
            The PC that runs the enrollment command becomes <b>{name}</b>: it gets this client&apos;s backups (and can restore them), its run history, its
            encryption key and its jobs, re-enabled as they were before the revocation. Its previous certificate and PBS token stay invalid.
          </p>
          {c.revoked_reason && <p className="warn-text">The console revoked this client itself ({c.revoked_reason}). Only re-enroll it on a PC you trust.</p>}
          <Field label="Token valid for (hours)">
            <input type="number" min={1} max={720} value={ttl} onChange={(e) => setTtl(Number(e.target.value))} />
          </Field>
          <ErrorBox error={error} />
          <div className="buttons">
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary">Create re-enrollment token</button>
          </div>
        </form>
      ) : (
        <div>
          <EnrollInstructions command={result.command} expires={result.expires} />
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

function ReenrollCommand({ c, onClose }: { c: Client; onClose: () => void }) {
  const { data, error } = useLoad(() => api.reenrollmentCommand(c.id), [c.id])
  return (
    <Modal title={`Re-enroll ${clientName(c)}`} onClose={onClose} wide>
      <ErrorBox error={error} />
      {data && <EnrollInstructions command={data.command} expires={data.expires} />}
      <div className="buttons">
        <button className="primary" onClick={onClose}>
          Done
        </button>
      </div>
    </Modal>
  )
}
