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
              onClick={() => setEdit({ pbs_user: 'proxbackup@pbs', root_ns: 'pcs', ...(local && { host: local.host, admin_auth_id: local.auth_id }) })}
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
                <th>Admin token</th>
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
          When a PC enrolls, the server uses the admin token to create namespace <code>&lt;root namespace&gt;/&lt;client&gt;</code>, an API token{' '}
          <code>&lt;agent user&gt;!&lt;client&gt;</code> and grants it <b>DatastoreBackup</b> on that namespace only. Agents can create and restore their own
          snapshots, but cannot delete, prune or read other clients' backups. Retention (prune) is run by this server.
        </p>
        <p className="muted-text">
          The admin token needs permission to manage users, tokens, ACLs, namespaces and to prune and delete snapshots — e.g. a token of <code>root@pam</code>{' '}
          without privilege separation, or a dedicated user with the <b>Admin</b> role on <code>/</code>.
        </p>
      </Card>
      {edit && (
        <TargetEditor
          t={edit}
          localAuthID={local?.auth_id}
          onClose={() => {
            setEdit(null)
            reload()
          }}
        />
      )}
    </>
  )
}

function TargetEditor({ t: init, localAuthID, onClose }: { t: Form; localAuthID?: string; onClose: () => void }) {
  const isLocal = !!localAuthID && init.admin_auth_id === localAuthID
  const [t, setT] = useState<Form>(init)
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
          <Field label="Host" hint="host or host:port (default 8007), as reachable from the PCs and this server.">
            <input value={t.host ?? ''} onChange={(e) => set({ host: e.target.value })} required placeholder="pbs.example.lan" />
          </Field>
        </div>
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
          <Field label="Datastore">
            <input value={t.datastore ?? ''} onChange={(e) => set({ datastore: e.target.value })} required />
          </Field>
          <Field
            label="Root namespace"
            hint="Each client gets a child namespace below this one. Changing it creates it on PBS and moves existing clients there; their older snapshots stay restorable."
          >
            <input value={t.root_ns ?? ''} onChange={(e) => set({ root_ns: e.target.value })} placeholder="pcs" />
          </Field>
        </div>
        <div className="grid2">
          <Field label="Admin API token ID">
            <input value={t.admin_auth_id ?? ''} onChange={(e) => set({ admin_auth_id: e.target.value })} required placeholder="root@pam!proxbackup" />
          </Field>
          <Field
            label="Admin API token secret"
            hint={
              isLocal
                ? 'Not needed: this is the token created when the console was installed on this PBS.'
                : t.id
                  ? 'Leave empty to keep the stored secret.'
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
        <Field label="PBS user owning the agent tokens" hint="Created automatically if missing (no password, cannot log in).">
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
