// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { api, type AuditEntry, type Client, type Perm, type PermInfo, type Role, type RoleAssignment, type User } from '../api'
import { usePerms } from '../perms'
import { ago, Card, dateTime, Empty, ErrorBox, Field, Modal, useLoad } from '../ui'

// Console users, the roles that give them permissions, and the audit log,
// shown as tabs of Console Settings.

/** Clients for scope pickers; empty if the user can't list them. */
function useClients() {
  return useLoad(() => api.clients().catch(() => [] as Client[]), [])
}

function scopeText(a: RoleAssignment, clients: Client[] | null) {
  if (a.all_clients) return 'all clients'
  const names = a.clients.map((id) => clients?.find((c) => c.id === id)?.name ?? `#${id}`)
  return [...names, ...a.tags.map((t) => '#' + t)].join(', ')
}

export function UserList() {
  const { me } = usePerms()
  const { data, error, reload } = useLoad(api.users, [])
  const roles = useLoad(api.roles, [])
  const clients = useClients()
  const [editing, setEditing] = useState<User | 'new' | null>(null)
  const [resetting, setResetting] = useState<User | null>(null)
  const [actionError, setActionError] = useState('')
  return (
    <>
      <ErrorBox error={error || roles.error || actionError} />
      <Card
        title={`${data?.length ?? 0} users`}
        actions={
          <button className="primary" onClick={() => setEditing('new')}>
            Add user
          </button>
        }
      >
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Roles</th>
              <th>Last sign-in</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {data?.map((u) => (
              <tr key={u.id} className={u.enabled ? '' : 'disabled'}>
                <td>
                  <b>{u.username}</b>
                  {u.id === me?.id && <span className="tag">you</span>}
                  {!u.enabled && <span className="badge muted">disabled</span>}
                  {u.must_change_password && (
                    <span className="tag" title="Must choose a new password at the next sign-in">
                      password change pending
                    </span>
                  )}
                </td>
                <td>
                  {u.roles.length === 0 ? (
                    <span className="muted-text">none</span>
                  ) : (
                    u.roles.map((a, i) => (
                      <div key={i}>
                        <b>{a.role_name}</b> <span className="muted-text">on {scopeText(a, clients.data)}</span>
                      </div>
                    ))
                  )}
                </td>
                <td>{ago(u.last_login)}</td>
                <td>{dateTime(u.created_at)}</td>
                <td className="row-actions">
                  <button className="small ghost" onClick={() => setEditing(u)}>
                    Edit
                  </button>
                  <button className="small ghost" onClick={() => setResetting(u)}>
                    Reset password
                  </button>
                  {u.id !== me?.id && (
                    <button
                      className="small ghost"
                      onClick={async () => {
                        if (!confirm(`Delete the user ${u.username}? Its sessions end immediately. The audit log keeps its entries.`)) return
                        try {
                          setActionError('')
                          await api.deleteUser(u.id)
                          reload()
                        } catch (e) {
                          setActionError((e as Error).message)
                        }
                      }}
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {editing && roles.data && (
        <UserEditor
          user={editing === 'new' ? null : editing}
          self={editing !== 'new' && editing.id === me?.id}
          roles={roles.data}
          clients={clients.data ?? []}
          onClose={() => {
            setEditing(null)
            reload()
          }}
        />
      )}
      {resetting && <ResetPassword user={resetting} onClose={() => setResetting(null)} />}
    </>
  )
}

function UserEditor({ user, self, roles, clients, onClose }: { user: User | null; self: boolean; roles: Role[]; clients: Client[]; onClose: () => void }) {
  const [username, setUsername] = useState(user?.username ?? '')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [enabled, setEnabled] = useState(user?.enabled ?? true)
  const [mustChange, setMustChange] = useState(true)
  const [assignments, setAssignments] = useState<RoleAssignment[]>(
    user?.roles ?? [{ role_id: roles.find((r) => r.builtin === 'readonly')?.id ?? roles[0].id, all_clients: true, clients: [], tags: [] }],
  )
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const update = (i: number, p: Partial<RoleAssignment>) => setAssignments(assignments.map((a, j) => (i === j ? { ...a, ...p } : a)))
  const allTags = [...new Set(clients.flatMap((c) => c.tags))].sort()
  return (
    <Modal title={user ? `Edit ${user.username}` : 'Add user'} onClose={onClose} wide>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setError('')
          if (!user && password !== repeat) return setError('The passwords do not match.')
          setBusy(true)
          try {
            if (user) await api.updateUser(user.id, { enabled, roles: assignments })
            else await api.createUser({ username, password, enabled, must_change_password: mustChange, roles: assignments })
            onClose()
          } catch (err) {
            setError((err as Error).message)
          } finally {
            setBusy(false)
          }
        }}
      >
        {!user && (
          <>
            <Field label="Username" hint="Letters, digits, '.', '_', '@' and '-'.">
              <input value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus autoComplete="off" />
            </Field>
            <div className="grid2">
              <Field label="Password" hint="At least 10 characters.">
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} minLength={10} required autoComplete="new-password" />
              </Field>
              <Field label="Repeat password">
                <input type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} minLength={10} required autoComplete="new-password" />
              </Field>
            </div>
          </>
        )}
        <div className="checks">
          <label title={self ? "You can't disable your own account" : ''}>
            <input type="checkbox" checked={enabled} disabled={self} onChange={(e) => setEnabled(e.target.checked)} /> Enabled — disabled users can't sign in
          </label>
          {!user && (
            <label>
              <input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} /> Must choose a new password at the first sign-in
            </label>
          )}
        </div>
        <h3>Roles</h3>
        <p className="muted-text">
          A role applies to all clients or only to some clients and tags. Console permissions (PBS servers, settings, users, audit log) only come with roles for
          all clients.
        </p>
        {assignments.length === 0 && <Empty>No roles: the user can sign in but sees nothing.</Empty>}
        {assignments.map((a, i) => (
          <div key={i} className="card">
            <div className="grid2">
              <Field label="Role">
                <select value={a.role_id} onChange={(e) => update(i, { role_id: Number(e.target.value) })}>
                  {roles.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Applies to">
                <select value={a.all_clients ? 'all' : 'some'} onChange={(e) => update(i, { all_clients: e.target.value === 'all' })}>
                  <option value="all">All clients</option>
                  <option value="some">Selected clients and tags</option>
                </select>
              </Field>
            </div>
            {!a.all_clients && (
              <>
                <span className="muted-text small">Tags (clients tagged later are included)</span>
                <div className="chips">
                  {allTags.length === 0 && <span className="muted-text small">no client has tags yet</span>}
                  {allTags.map((t) => (
                    <button
                      type="button"
                      key={t}
                      className={`chip ${a.tags.includes(t) ? 'on' : ''}`}
                      onClick={() => update(i, { tags: a.tags.includes(t) ? a.tags.filter((x) => x !== t) : [...a.tags, t] })}
                    >
                      #{t}
                    </button>
                  ))}
                </div>
                <span className="muted-text small">Clients</span>
                <div className="chips">
                  {clients.length === 0 && <span className="muted-text small">no clients yet</span>}
                  {clients.map((c) => (
                    <button
                      type="button"
                      key={c.id}
                      className={`chip ${a.clients.includes(c.id) ? 'on' : ''}`}
                      onClick={() => update(i, { clients: a.clients.includes(c.id) ? a.clients.filter((x) => x !== c.id) : [...a.clients, c.id] })}
                    >
                      {c.name}
                    </button>
                  ))}
                </div>
              </>
            )}
            <div className="buttons">
              <button type="button" className="small ghost" onClick={() => setAssignments(assignments.filter((_, j) => j !== i))}>
                Remove role
              </button>
            </div>
          </div>
        ))}
        <div className="buttons">
          <button
            type="button"
            className="left"
            onClick={() => setAssignments([...assignments, { role_id: roles[0].id, all_clients: true, clients: [], tags: [] }])}
          >
            Add role
          </button>
        </div>
        <ErrorBox error={error} />
        <div className="buttons">
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy}>
            {user ? 'Save' : 'Create user'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function ResetPassword({ user, onClose }: { user: User; onClose: () => void }) {
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [mustChange, setMustChange] = useState(true)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)
  return (
    <Modal title={`Reset the password of ${user.username}`} onClose={onClose}>
      {done ? (
        <>
          <div className="notice">Password changed. The user's other sessions were signed out.</div>
          <div className="buttons">
            <button onClick={onClose}>Close</button>
          </div>
        </>
      ) : (
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            if (password !== repeat) return setError('The passwords do not match.')
            try {
              await api.resetPassword(user.id, password, mustChange)
              setDone(true)
            } catch (err) {
              setError((err as Error).message)
            }
          }}
        >
          <Field label="New password" hint="At least 10 characters.">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              minLength={10}
              required
              autoFocus
              autoComplete="new-password"
            />
          </Field>
          <Field label="Repeat new password">
            <input type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} minLength={10} required autoComplete="new-password" />
          </Field>
          <div className="checks">
            <label>
              <input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} /> Must choose a new password at the next sign-in
            </label>
          </div>
          <ErrorBox error={error} />
          <div className="buttons">
            <button type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary">Reset password</button>
          </div>
        </form>
      )}
    </Modal>
  )
}

export function RoleList() {
  const { data, error, reload } = useLoad(api.roles, [])
  const perms = useLoad(api.permissions, [])
  const [editing, setEditing] = useState<Partial<Role> | null>(null)
  const [actionError, setActionError] = useState('')
  const label = (p: Perm) => perms.data?.find((i) => i.id === p)?.label ?? p
  return (
    <>
      <ErrorBox error={error || perms.error || actionError} />
      <Card
        title="Roles"
        actions={
          <button className="primary" onClick={() => setEditing({ name: '', description: '', permissions: ['clients.view'] })}>
            New role
          </button>
        }
      >
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Permissions</th>
              <th>Users</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {data?.map((r) => (
              <tr key={r.id}>
                <td>
                  <b>{r.name}</b>
                  {r.builtin && <span className="tag">built-in</span>}
                  <div className="muted-text small">{r.description}</div>
                </td>
                <td className="small">{r.permissions.map(label).join(', ') || '—'}</td>
                <td>{r.users}</td>
                <td className="row-actions">
                  {r.builtin ? (
                    <button
                      className="small ghost"
                      title="Create a custom role starting from this one"
                      onClick={() => setEditing({ name: `${r.name} (copy)`, description: r.description, permissions: r.permissions })}
                    >
                      Duplicate
                    </button>
                  ) : (
                    <>
                      <button className="small ghost" onClick={() => setEditing(r)}>
                        Edit
                      </button>
                      <button
                        className="small ghost"
                        disabled={r.users > 0}
                        title={r.users > 0 ? 'Assigned to users: remove it from them first' : ''}
                        onClick={async () => {
                          if (!confirm(`Delete the role ${r.name}?`)) return
                          try {
                            setActionError('')
                            await api.deleteRole(r.id)
                            reload()
                          } catch (e) {
                            setActionError((e as Error).message)
                          }
                        }}
                      >
                        Delete
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {editing && perms.data && (
        <RoleEditor
          role={editing}
          perms={perms.data}
          onClose={() => {
            setEditing(null)
            reload()
          }}
        />
      )}
    </>
  )
}

function RoleEditor({ role, perms, onClose }: { role: Partial<Role>; perms: PermInfo[]; onClose: () => void }) {
  const [r, setR] = useState(role)
  const [error, setError] = useState('')
  const has = (p: Perm) => r.permissions?.includes(p) ?? false
  const toggle = (p: Perm) => setR({ ...r, permissions: has(p) ? r.permissions!.filter((x) => x !== p) : [...(r.permissions ?? []), p] })
  return (
    <Modal title={r.id ? `Edit ${role.name}` : 'New role'} onClose={onClose} wide>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            await api.saveRole({ id: r.id, name: r.name ?? '', description: r.description ?? '', permissions: r.permissions ?? [] })
            onClose()
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <div className="grid2">
          <Field label="Name">
            <input value={r.name ?? ''} onChange={(e) => setR({ ...r, name: e.target.value })} required autoFocus />
          </Field>
          <Field label="Description">
            <input value={r.description ?? ''} onChange={(e) => setR({ ...r, description: e.target.value })} />
          </Field>
        </div>
        <h3>Permissions</h3>
        <div className="checks">
          {perms.map((p) => (
            <label key={p.id}>
              <input type="checkbox" checked={has(p.id)} onChange={() => toggle(p.id)} />
              <span>
                <b>{p.label}</b>
                {!p.client_level && <span className="tag">all clients only</span>}
                <span className="muted-text small"> {p.description}</span>
              </span>
            </label>
          ))}
        </div>
        <p className="muted-text small">Any client permission includes seeing those clients.</p>
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

const PAGE = 100

export function AuditLog() {
  const [user, setUser] = useState('')
  const [filter, setFilter] = useState('')
  const [older, setOlder] = useState<AuditEntry[]>([])
  const [more, setMore] = useState(true)
  const { data, error } = useLoad(
    () =>
      api.audit({ user: filter, limit: PAGE }).then((d) => {
        setOlder([])
        setMore(d.length === PAGE)
        return d
      }),
    [filter],
  )
  const entries = [...(data ?? []), ...older]
  return (
    <>
      <ErrorBox error={error} />
      <Card
        title="Audit log"
        actions={
          <form
            className="inline"
            onSubmit={(e) => {
              e.preventDefault()
              setFilter(user.trim())
            }}
          >
            <input value={user} onChange={(e) => setUser(e.target.value)} placeholder="Filter by user" />
          </form>
        }
      >
        {entries.length === 0 ? (
          <Empty>No entries.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>User</th>
                <th>Action</th>
                <th>Applies to</th>
                <th>Result</th>
                <th>Details</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td title={ago(e.time)}>{dateTime(e.time)}</td>
                  <td>{e.username}</td>
                  <td>{e.action}</td>
                  <td>{e.target}</td>
                  <td>
                    {e.status === 0 || e.status < 400 ? (
                      <span className="badge ok">ok</span>
                    ) : (
                      <span className="badge bad">{e.status === 403 ? 'denied' : e.status === 401 ? 'failed' : `error ${e.status}`}</span>
                    )}
                  </td>
                  <td className="ellipsis" title={e.detail}>
                    {e.detail}
                  </td>
                  <td className="muted-text">{e.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {more && entries.length > 0 && (
          <div className="buttons">
            <button
              onClick={async () => {
                const page = await api.audit({ user: filter, before: entries[entries.length - 1].id, limit: PAGE })
                setOlder([...older, ...page])
                setMore(page.length === PAGE)
              }}
            >
              Load older entries
            </button>
          </div>
        )}
      </Card>
    </>
  )
}
