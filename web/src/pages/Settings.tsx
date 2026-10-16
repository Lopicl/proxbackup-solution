// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react'
import { api, type EncryptionSettings, type NotifySettings } from '../api'
import { Card, ErrorBox, Field } from '../ui'
import { UpdatesCard } from './Updates'

export function Settings() {
  const [s, setS] = useState<NotifySettings | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  useEffect(() => {
    api.notifySettings().then(setS, (e: Error) => setError(e.message))
  }, [])
  if (!s) return <ErrorBox error={error} />
  const set = (p: Partial<NotifySettings>) => setS({ ...s, ...p })
  return (
    <>
      <h1>Settings</h1>
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
          <Field label="URL" hint="Receives a JSON POST: {event, severity, subject, text, run, client}. Works with ntfy, Gotify bridges, Teams/Slack relays, n8n…">
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
      <EncryptionCard />
      <UpdatesCard />
      <Card title="Server certificate authority">
        <p className="muted-text">
          Agents trust this server through its internal CA (pinned at enrollment). Import the CA into your browser or OS trust store to remove the certificate warning for this
          web UI.
        </p>
        <a className="button" href="/api/ca.pem" download="proxbackup-ca.pem">
          Download CA certificate
        </a>
      </Card>
    </>
  )
}

function EncryptionCard() {
  const [s, setS] = useState<EncryptionSettings | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  useEffect(() => {
    api.encryptionSettings().then(setS, (e: Error) => setError(e.message))
  }, [])
  if (!s) return <ErrorBox error={error} />
  return (
    <Card title="Client-side encryption">
      <p className="muted-text">
        Jobs with encryption on are encrypted on the PC with a key of its own, created with the client's first encrypted job. This console keeps every key
        (sealed with its master key), sends it to the agent and uses it for restores, so a lost PC's backups stay restorable. Download a client's key on its page
        to restore with <code>proxmox-backup-client --keyfile</code>.
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
          label="RSA master public key (optional)"
          hint={
            <>
              With a master key, every encrypted snapshot also holds its key encrypted with it (<code>rsa-encrypted.key.blob</code>), recoverable without this
              console: <code>proxmox-backup-client key import-with-master-key</code>. Create one with <code>proxmox-backup-client key create-master-key</code>{' '}
              and paste <code>master-public.pem</code>; keep the private key offline.
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
          <button className="primary">Save</button>
        </div>
      </form>
    </Card>
  )
}
