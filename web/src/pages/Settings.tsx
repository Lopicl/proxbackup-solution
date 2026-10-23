// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react'
import { api, type EncryptionSettings, type NotifySettings, type Perm } from '../api'
import { generateMasterKeyPair } from '../masterkey'
import { Card, ErrorBox, Field } from '../ui'
import { usePerms } from '../perms'
import { UpdatesCard } from './Updates'
import { AuditLog, RoleList, UserList } from './Users'

/** The Console Settings tabs the user may open, in display order. */
export function settingsTabs(can: (p: Perm) => boolean): [string, string][] {
  const tabs: [string, string][] = []
  if (can('notifications.manage')) tabs.push(['notifications', 'Notifications'])
  if (can('encryption.manage')) tabs.push(['encryption', 'Encryption'])
  if (can('updates.manage')) tabs.push(['updates', 'Updates'])
  if (can('users.manage')) tabs.push(['users', 'Users'], ['roles', 'Roles'])
  if (can('audit.view')) tabs.push(['audit', 'Audit log'])
  tabs.push(['certificate', 'Certificate'])
  return tabs
}

export function Settings({ tab }: { tab?: string }) {
  const { can } = usePerms()
  const tabs = settingsTabs(can)
  const current = tabs.find(([k]) => k === tab)?.[0] ?? tabs[0][0]
  return (
    <>
      <h1>Console Settings</h1>
      <nav className="tabs">
        {tabs.map(([k, label]) => (
          <a key={k} href={`#/settings/${k}`} className={current === k ? 'active' : ''}>
            {label}
          </a>
        ))}
      </nav>
      {current === 'notifications' && <NotificationsCard />}
      {current === 'encryption' && <EncryptionCard />}
      {current === 'updates' && <UpdatesCard />}
      {current === 'users' && <UserList />}
      {current === 'roles' && <RoleList />}
      {current === 'audit' && <AuditLog />}
      {current === 'certificate' && <CertificateCard />}
    </>
  )
}

function CertificateCard() {
  return (
    <Card title="Server certificate authority">
      <p className="muted-text">
        Agents trust this server through its internal CA (pinned at enrollment). Import the CA into your browser or OS trust store to remove the certificate
        warning for this web UI.
      </p>
      <a className="button" href="/api/ca.pem" download="proxbackup-ca.pem">
        Download CA certificate
      </a>
    </Card>
  )
}

function NotificationsCard() {
  const [s, setS] = useState<NotifySettings | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  useEffect(() => {
    api.notifySettings().then(setS, (e: Error) => setError(e.message))
  }, [])
  if (!s) return <ErrorBox error={error} />
  const set = (p: Partial<NotifySettings>) => setS({ ...s, ...p })
  return (
    <Card title="Notifications">
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setError('')
          try {
            setS(await api.saveNotifySettings(s))
            setMsg('Saved.')
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <div className="checks">
          <label>
            <input type="checkbox" checked={s.on_failure} onChange={(e) => set({ on_failure: e.target.checked })} /> Notify when a backup fails or is lost
          </label>
          <label>
            <input type="checkbox" checked={s.on_success} onChange={(e) => set({ on_success: e.target.checked })} /> Notify on success too
          </label>
        </div>
        <Field label="Alert when a client has no successful backup for (days)" hint="0 disables the daily check.">
          <input type="number" min={0} value={s.stale_days} onChange={(e) => set({ stale_days: Number(e.target.value) })} />
        </Field>
        <h3>Webhook</h3>
        <Field
          label="URL"
          hint="Receives a JSON POST: {event, severity, subject, text, run, client}. Works with ntfy, Gotify bridges, Teams/Slack relays, n8n…"
        >
          <input value={s.webhook_url} onChange={(e) => set({ webhook_url: e.target.value })} placeholder="https://…" />
        </Field>
        <h3>Email</h3>
        <div className="grid2">
          <Field label="SMTP server">
            <input value={s.smtp_host} onChange={(e) => set({ smtp_host: e.target.value })} placeholder="smtp.example.com" />
          </Field>
          <div className="grid2">
            <Field label="Port">
              <input type="number" value={s.smtp_port} onChange={(e) => set({ smtp_port: Number(e.target.value) })} />
            </Field>
            <Field label="Security">
              <select value={s.smtp_tls} onChange={(e) => set({ smtp_tls: e.target.value })}>
                <option value="starttls">STARTTLS</option>
                <option value="tls">TLS</option>
                <option value="none">None</option>
              </select>
            </Field>
          </div>
          <Field label="Username">
            <input value={s.smtp_user} onChange={(e) => set({ smtp_user: e.target.value })} autoComplete="off" />
          </Field>
          <Field label="Password" hint={s.smtp_password_set ? 'A password is stored; leave empty to keep it.' : undefined}>
            <input type="password" value={s.smtp_password ?? ''} onChange={(e) => set({ smtp_password: e.target.value })} autoComplete="new-password" />
          </Field>
          <Field label="From">
            <input value={s.smtp_from} onChange={(e) => set({ smtp_from: e.target.value })} placeholder="backup@example.com" />
          </Field>
          <Field label="To" hint="Comma separated.">
            <input value={s.smtp_to} onChange={(e) => set({ smtp_to: e.target.value })} placeholder="it@example.com" />
          </Field>
        </div>
        {msg && <div className="notice">{msg}</div>}
        <ErrorBox error={error} />
        <div className="buttons">
          <button
            type="button"
            onClick={async () => {
              setMsg('')
              setError('')
              try {
                await api.testNotify()
                setMsg('Test notification sent.')
              } catch (e) {
                setError((e as Error).message)
              }
            }}
          >
            Send test (saved settings)
          </button>
          <button className="primary">Save</button>
        </div>
      </form>
    </Card>
  )
}

function EncryptionCard() {
  const [s, setS] = useState<EncryptionSettings | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [generating, setGenerating] = useState(false)
  useEffect(() => {
    api.encryptionSettings().then(setS, (e: Error) => setError(e.message))
  }, [])
  if (!s) return <ErrorBox error={error} />
  return (
    <Card title="Client-side encryption">
      <p className="muted-text">
        Jobs with encryption on are encrypted on the PC with a key of its own, created with the client's first encrypted job. This console keeps every key
        (sealed with its master key), sends it to the agent and uses it for restores, so a lost PC's backups stay restorable. Download a client's key on its
        page to restore with <code>proxmox-backup-client --keyfile</code>. Jobs can turn encryption on once an RSA master key is set below.
      </p>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setError('')
          setMsg('')
          try {
            setS(await api.saveEncryptionSettings(s))
            setMsg('Saved. Agents get the change with their next connection.')
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <Field
          label="RSA master public key"
          hint={
            <>
              With a master key, every encrypted snapshot also holds its key encrypted with it (<code>rsa-encrypted.key.blob</code>), recoverable without this
              console: <code>proxmox-backup-client key import-with-master-key</code>. Generate a key pair here, or create one with{' '}
              <code>proxmox-backup-client key create-master-key</code> and paste <code>master-public.pem</code>. Keep the private key offline.
            </>
          }
        >
          <textarea
            rows={4}
            value={s.master_pubkey}
            onChange={(e) => setS({ ...s, master_pubkey: e.target.value })}
            placeholder="-----BEGIN PUBLIC KEY-----"
            spellCheck={false}
          />
        </Field>
        {s.master_fingerprint && (
          <p className="muted-text small">
            RSA {s.master_bits} bits, SHA-256 <code>{s.master_fingerprint}</code>
          </p>
        )}
        {msg && <div className="notice">{msg}</div>}
        <ErrorBox error={error} />
        <div className="buttons">
          {!generating && (
            <button type="button" onClick={() => setGenerating(true)}>
              Generate key pair…
            </button>
          )}
          <button className="primary">Save</button>
        </div>
      </form>
      {generating && (
        <MasterKeyGenerator
          replacing={!!s.master_fingerprint}
          onGenerated={(pub) => {
            setS({ ...s, master_pubkey: pub, master_bits: undefined, master_fingerprint: undefined })
            setMsg('')
          }}
          onClose={() => setGenerating(false)}
        />
      )}
    </Card>
  )
}

// MasterKeyGenerator creates the RSA master key pair in the browser: the
// private key is only offered as a download, the console gets the public key.
function MasterKeyGenerator({ replacing, onGenerated, onClose }: { replacing: boolean; onGenerated: (publicPem: string) => void; onClose: () => void }) {
  const [pass, setPass] = useState('')
  const [pass2, setPass2] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [privatePem, setPrivatePem] = useState('')
  const download = (pem: string) => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([pem], { type: 'application/x-pem-file' }))
    a.download = 'master-private.pem'
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }
  if (privatePem) {
    return (
      <>
        <h3>Key pair generated</h3>
        <div className="notice">
          Your browser downloaded <code>master-private.pem</code>, encrypted with your passphrase. This console never had it: store it offline with the
          passphrase (password manager, safe), because it is the only way to recover snapshot keys without the console. The public key is filled in above; click{' '}
          <b>Save</b> to use it.
        </div>
        <div className="buttons">
          <button type="button" onClick={() => download(privatePem)}>
            Download private key again
          </button>
          <button type="button" onClick={onClose}>
            Done
          </button>
        </div>
      </>
    )
  }
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        setError('')
        if (pass.length < 8) return setError('Use a passphrase of at least 8 characters.')
        if (pass !== pass2) return setError('The passphrases do not match.')
        setBusy(true)
        try {
          const k = await generateMasterKeyPair(pass)
          download(k.privatePem)
          setPrivatePem(k.privatePem)
          setPass('')
          setPass2('')
          onGenerated(k.publicPem)
        } catch (err) {
          setError((err as Error).message)
        } finally {
          setBusy(false)
        }
      }}
    >
      <h3>Generate a master key pair</h3>
      <p className="muted-text">
        Your browser creates an RSA 4096-bit key pair. The private key is downloaded as <code>master-private.pem</code>, protected by the passphrase below, and
        never sent to this console. <code>proxmox-backup-client key import-with-master-key</code> asks for that passphrase.
      </p>
      {replacing && (
        <p className="warn-text">A master key is already set. Snapshots made so far stay recoverable only with its private key, so keep that one too.</p>
      )}
      <div className="grid2">
        <Field label="Passphrase">
          <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
        </Field>
        <Field label="Repeat passphrase">
          <input type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" />
        </Field>
      </div>
      <ErrorBox error={error} />
      <div className="buttons">
        <button type="button" onClick={onClose} disabled={busy}>
          Cancel
        </button>
        <button className="primary" disabled={busy}>
          {busy ? 'Generating…' : 'Generate and download'}
        </button>
      </div>
    </form>
  )
}
