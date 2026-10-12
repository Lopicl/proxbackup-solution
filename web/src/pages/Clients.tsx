import { useState } from 'react'
import { api } from '../api'
import { ago, Card, Empty, ErrorBox, Field, Link, Modal, OnlineDot, StateBadge, useLoad } from '../ui'

export function Clients() {
  const { data, error, reload } = useLoad(api.clients, [], 10000)
  const [adding, setAdding] = useState(false)
  return (
    <>
      <h1>Clients</h1>
      <ErrorBox error={error} />
      <Card
        title={`${data?.length ?? 0} clients`}
        actions={
          <button className="primary" onClick={() => setAdding(true)}>
            Add client
          </button>
        }
      >
        {data && data.length === 0 ? (
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
            reload()
          }}
        />
      )}
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
            Enrollment token for <b>{result.client_name}</b> created. It can be used once and expires in {ttl} hours.
          </p>
          <p>On the Windows PC, copy <code>pbspc-agent.exe</code> to a folder (e.g. <code>C:\Program Files\pbspc</code>) and run in an elevated prompt:</p>
          <pre className="copy" onClick={(e) => navigator.clipboard?.writeText((e.target as HTMLElement).innerText)}>
            {result.command}
          </pre>
          <small className="muted-text">Click the command to copy it. The client appears in the list once the agent has enrolled.</small>
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
