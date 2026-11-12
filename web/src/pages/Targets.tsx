// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { api, type Target } from '../api'
import { usePerms } from '../perms'
import { Card, Empty, ErrorBox, Field, Modal, useLoad } from '../ui'

type Form = Partial<Target> & { admin_secret?: string }

/** The Datastores tab of Console Settings: the PBS datastores clients back up to. */
export function Targets() {
  const { data, error, reload } = useLoad(api.targets, [])
  const { me, can } = usePerms()
  const local = me?.local_pbs
  const canManage = can('targets.manage')
  const [edit, setEdit] = useState<Form | null>(null)
  return (
    <>
      <ErrorBox error={error} />
      <Card
        title="Datastores"
        actions={
          canManage && (
            <button
              className="primary"
              onClick={() =>
                setEdit({
                  pbs_user: 'proxbackup@pbs',
                  admin_auth_id: 'proxbackup@pbs',
                  root_ns: 'pcs',
                  ...(local && { host: local.host, admin_auth_id: local.auth_id }),
                })
              }
            >
              Add datastore
            </button>
          )
        }
      >
        {data && data.length === 0 ? (
          <Empty>{canManage ? 'Add the Proxmox Backup Server datastore that PCs should back up to.' : 'No datastores yet.'}</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Host</th>
                <th>Datastore / namespace</th>
                <th>PBS admin</th>
                <th>Agent user</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data?.map((t) => (
                <tr key={t.id}>
                  <td>
                    <b>{t.name}</b>
                  </td>
                  <td>
                    <code>{t.host}</code>
                    {t.console_host && (
                      <div className="muted-text">
                        console: <code>{t.console_host}</code>
                      </div>
                    )}
                  </td>
                  <td>
                    <code>
                      {t.datastore}
                      {t.root_ns ? ` / ${t.root_ns}` : ''}
                    </code>
                  </td>
                  <td>
                    <code>{t.admin_auth_id}</code>
                  </td>
                  <td>
                    <code>{t.pbs_user}</code>
                  </td>
                  <td className="row-actions">
                    {canManage && (
                      <button className="small ghost" onClick={() => setEdit(t)}>
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
      <Card title="How agents are provisioned">
        <p className="muted-text">
          When a PC enrolls, the server signs in as the PBS admin to create namespace <code>&lt;root namespace&gt;/&lt;client&gt;</code>, an API token{' '}
          <code>&lt;agent user&gt;!&lt;client&gt;</code> and grants it <b>DatastoreBackup</b> on that namespace only. Agents can create and restore their own
          snapshots, but cannot delete, prune or read other clients' backups. Retention (prune) is run by this server.
        </p>
        <p className="muted-text">
          Use the agent user itself as PBS admin, with its password, the <b>DatastoreAdmin</b> role on{' '}
          <code>/datastore/&lt;datastore&gt;/&lt;root namespace&gt;</code>, <b>DatastoreAudit</b> on <code>/datastore/&lt;datastore&gt;</code> (not propagated,
          for the usage shown on the dashboard) and nothing else: PBS lets it set ACLs only for its own tokens and never gives them more than it has, and VM
          backups in other namespaces stay out of its reach. Create the root namespace yourself. An API token as admin needs the <b>Admin</b> role on{' '}
          <code>/</code>.
        </p>
        <p className="muted-text">
          On this PBS the console's own user <code>proxbackup@pbs</code> is set up like that for you: adding a datastore here creates its root namespace and
          grants those rights. It gets rights only on a root namespace that doesn't exist yet or that it could already use.
        </p>
      </Card>
      {edit && (
        <TargetEditor
          t={edit}
          local={local}
          onClose={() => {
            setEdit(null)
            reload()
          }}
        />
      )}
    </>
  )
}

function TargetEditor({ t: init, local, onClose }: { t: Form; local?: { auth_id: string; host: string; datastores: string[] }; onClose: () => void }) {
  const [t, setT] = useState<Form>(init)
  const isLocal = init.id ? !!init.local : !!local && t.admin_auth_id === local.auth_id && t.host === local.host
  const [error, setError] = useState('')
  const [test, setTest] = useState('')
  const set = (p: Form) => setT({ ...t, ...p })
  return (
    <Modal title={t.id ? `Edit ${init.name}` : 'Add datastore'} onClose={onClose} wide>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            await api.saveTarget(t)
            onClose()
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <div className="grid2">
          <Field label="Name">
            <input value={t.name ?? ''} onChange={(e) => set({ name: e.target.value })} required placeholder="pbs-main" />
          </Field>
          <Field label="Host" hint="host or host:port (default 8007), as reachable from the PCs (and this server, unless a console address is set).">
            <input value={t.host ?? ''} onChange={(e) => set({ host: e.target.value })} required placeholder="pbs.example.lan" />
          </Field>
        </div>
        {!isLocal && (
          <Field
            label="Console address (optional)"
            hint="Where this server reaches PBS, if not at Host: e.g. pbs.example.lan:8007 when Host is the agents' reverse proxy, which refuses password sign-ins. Must serve the same certificate."
          >
            <input value={t.console_host ?? ''} onChange={(e) => set({ console_host: e.target.value })} placeholder="same as Host" />
          </Field>
        )}
        <Field
          label="Certificate fingerprint (SHA-256)"
          hint={
            isLocal
              ? 'Leave empty: read from this PBS automatically and kept up to date.'
              : 'Shown on the PBS dashboard (“Show Fingerprint”). Leave empty only if PBS has a publicly trusted certificate.'
          }
        >
          <input value={t.fingerprint ?? ''} onChange={(e) => set({ fingerprint: e.target.value })} placeholder="aa:bb:cc:…" />
        </Field>
        <div className="grid2">
          <Field label="Datastore" hint={isLocal ? 'Only for PCs: the console gets no rights on the datastores you don’t add.' : undefined}>
            <input value={t.datastore ?? ''} onChange={(e) => set({ datastore: e.target.value })} required list={isLocal ? 'local-datastores' : undefined} />
            {isLocal && (
              <datalist id="local-datastores">
                {local?.datastores.map((d) => (
                  <option key={d} value={d} />
                ))}
              </datalist>
            )}
          </Field>
          <Field
            label="Root namespace"
            hint={
              'Each client gets a child namespace below this one. Changing it creates it on PBS and moves existing clients there; their older snapshots stay restorable.' +
              (isLocal ? ' Required on this PBS: the console has rights only below it. Use a new one, not one holding other backups.' : '')
            }
          >
            <input value={t.root_ns ?? ''} onChange={(e) => set({ root_ns: e.target.value })} placeholder="pcs" required={isLocal} />
          </Field>
        </div>
        <div className="grid2">
          <Field label="PBS admin" hint="The agent user (recommended), or an API token ID (user@realm!token).">
            <input value={t.admin_auth_id ?? ''} onChange={(e) => set({ admin_auth_id: e.target.value })} required placeholder="proxbackup@pbs" />
          </Field>
          <Field
            label="Password or token secret"
            hint={
              isLocal
                ? 'Not needed: this is the PBS user created when the console was installed on this PBS.'
                : t.id
                  ? 'Leave empty to keep the stored one (enter it again when changing host, console address, fingerprint or PBS admin).'
                  : 'Stored encrypted.'
            }
          >
            <input
              type="password"
              value={t.admin_secret ?? ''}
              onChange={(e) => set({ admin_secret: e.target.value })}
              required={!t.id && !isLocal}
              autoComplete="off"
            />
          </Field>
        </div>
        <Field
          label="PBS user owning the agent tokens"
          hint="Must be the PBS admin when that is a user. With a token as admin, created if missing (without a password)."
        >
          <input value={t.pbs_user ?? ''} onChange={(e) => set({ pbs_user: e.target.value })} placeholder="proxbackup@pbs" />
        </Field>
        {test && <div className="notice">{test}</div>}
        <ErrorBox error={error} />
        <div className="buttons">
          {t.id && (
            <button
              type="button"
              className="danger left"
              onClick={async () => {
                if (!confirm('Delete this datastore?')) return
                try {
                  await api.deleteTarget(t.id!)
                  onClose()
                } catch (e) {
                  setError((e as Error).message)
                }
              }}
            >
              Delete
            </button>
          )}
          <button
            type="button"
            onClick={async () => {
              setTest('Testing…')
              setError('')
              try {
                const r = await api.testTarget(t)
                setTest(
                  `Connected to PBS ${r.version}.${r.release}. Datastores: ${r.datastores.join(', ') || 'none'}.` +
                    (r.datastore_found ? ' ✓ datastore found.' : ` ✗ datastore “${t.datastore}” not found.`),
                )
              } catch (e) {
                setTest('')
                setError((e as Error).message)
              }
            }}
          >
            Test connection
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
