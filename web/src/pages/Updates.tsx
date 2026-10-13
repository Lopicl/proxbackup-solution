// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react'
import { api, type Updates, type UpdateSettings } from '../api'
import { ago, Card, dateTime, ErrorBox, Field } from '../ui'

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
// Shown Monday first; values are Go's time.Weekday (0 = Sunday).
const ORDER = [1, 2, 3, 4, 5, 6, 0]

export function UpdatesCard() {
  const [u, setU] = useState<Updates | null>(null)
  const [s, setS] = useState<UpdateSettings | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState('')

  const apply = (d: Updates) => {
    setU(d)
    setS(d.settings)
  }
  useEffect(() => {
    api.updates().then(apply, (e: Error) => setError(e.message))
  }, [])
  // Follow an install in progress.
  useEffect(() => {
    if (!u?.status.installing) return
    const t = setInterval(() => api.updates().then(setU, () => {}), 5000)
    return () => clearInterval(t)
  }, [u?.status.installing])

  if (!u || !s) return <ErrorBox error={error} />
  const st = u.status
  const set = (p: Partial<UpdateSettings>) => setS({ ...s, ...p })
  const setWin = (p: Partial<UpdateSettings['window']>) => set({ window: { ...s.window, ...p } })
  const toggleDay = (d: number) => setWin({ days: s.window.days.includes(d) ? s.window.days.filter((x) => x !== d) : [...s.window.days, d].sort() })

  const act = async (name: string, fn: () => Promise<Updates>, done: string) => {
    setBusy(name)
    setError('')
    setMsg('')
    try {
      apply(await fn())
      setMsg(done)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy('')
    }
  }
  const res = st.last_result

  return (
    <Card title="Updates">
      <div className="facts">
        <span>
          Installed <b>{st.current}</b>
        </span>
        <span>
          Latest release{' '}
          <b>
            {st.latest ? (
              <a href={st.latest_url} target="_blank" rel="noreferrer">
                {st.latest}
              </a>
            ) : (
              'none'
            )}
          </b>
          {st.published_at ? <span className="small"> ({dateTime(st.published_at)})</span> : null}
        </span>
        <span>Checked {ago(st.last_check)}</span>
      </div>
      {st.check_error && <ErrorBox error={`Update check failed: ${st.check_error}`} />}
      {st.mode_note && <div className="notice">{st.mode_note}</div>}
      {st.available && (
        <div className="notice">
          Version <b>{st.latest}</b> is available.{' '}
          {st.installing
            ? 'Installing…'
            : st.next_install
              ? `It will be installed automatically ${st.next_install <= Date.now() / 1000 + 60 ? 'now' : dateTime(st.next_install)}.`
              : s.auto_install
                ? 'Select at least one day to install it automatically.'
                : 'Automatic installation is off.'}
          {st.latest_notes && (
            <details>
              <summary>Release notes</summary>
              <pre className="log">{st.latest_notes}</pre>
            </details>
          )}
        </div>
      )}
      {res && (
        <p className={res.state === 'failed' ? 'bad-text' : res.state === 'success' ? 'ok-text' : 'muted-text'}>
          {res.state === 'installing' && `Installing ${res.to} (started ${ago(res.time)})…`}
          {res.state === 'success' && `Updated from ${res.from} to ${res.to} ${ago(res.time)}.`}
          {res.state === 'failed' && `Update to ${res.to} failed ${ago(res.time)}: ${res.error}`}
        </p>
      )}

      <form
        onSubmit={(e) => {
          e.preventDefault()
          act('save', () => api.saveUpdateSettings(s), 'Saved.')
        }}
      >
        <div className="checks">
          <label>
            <input type="checkbox" checked={s.auto_install} onChange={(e) => set({ auto_install: e.target.checked })} /> Install console updates automatically
          </label>
        </div>
        <div className="grid2">
          <Field label="On these days">
            <div className="chips">
              {ORDER.map((d) => (
                <button type="button" key={d} className={`chip ${s.window.days.includes(d) ? 'on' : ''}`} onClick={() => toggleDay(d)} disabled={!s.auto_install}>
                  {DAYS[d]}
                </button>
              ))}
            </div>
          </Field>
          <div className="grid2">
            <Field label="At (server time)">
              <input type="time" value={s.window.time} onChange={(e) => setWin({ time: e.target.value })} disabled={!s.auto_install} required />
            </Field>
            <Field label="Window (minutes)" hint="Install only if the console is running in this window.">
              <input type="number" min={5} max={1440} value={s.window.minutes} onChange={(e) => setWin({ minutes: Number(e.target.value) })} disabled={!s.auto_install} />
            </Field>
          </div>
        </div>
        <div className="checks">
          <label>
            <input type="checkbox" checked={s.agents} onChange={(e) => set({ agents: e.target.checked })} /> Update agents to the console's version (each PC updates itself when no backup is running)
          </label>
          <label>
            <input type="checkbox" checked={s.prerelease} onChange={(e) => set({ prerelease: e.target.checked })} /> Include pre-releases
          </label>
        </div>
        {s.agents && (
          <p className="muted-text small">
            {st.agent_version
              ? `Agent ${st.agent_version} (${st.agent_archs?.sort().join(', ')}) is ready for older agents.`
              : st.agent_cache_error
                ? `Agent binaries for ${st.current} could not be fetched: ${st.agent_cache_error}`
                : `Agent binaries for ${st.current} are fetched with the next check.`}
          </p>
        )}
        <p className="muted-text small">
          Releases come from{' '}
          <a href={`https://github.com/${st.repo}/releases`} target="_blank" rel="noreferrer">
            github.com/{st.repo}
          </a>{' '}
          and are checked every 6 hours. Downloads are verified against the release's SHA256SUMS.
        </p>
        {msg && <div className="notice">{msg}</div>}
        <ErrorBox error={error} />
        <div className="buttons">
          <button type="button" disabled={!!busy} onClick={() => act('check', api.checkUpdates, 'Checked for updates.')}>
            {busy === 'check' ? 'Checking…' : 'Check now'}
          </button>
          {st.available && st.mode && (
            <button
              type="button"
              disabled={!!busy || st.installing}
              onClick={() => {
                if (confirm(`Install ${st.latest} now? The console restarts for a few seconds.`))
                  act('install', api.installUpdate, `Installing ${st.latest}. The console restarts in a moment.`)
              }}
            >
              Install {st.latest} now
            </button>
          )}
          <button className="primary" disabled={!!busy}>
            Save
          </button>
        </div>
      </form>
    </Card>
  )
}
