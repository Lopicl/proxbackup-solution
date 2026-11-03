// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react'
import { api, type AgentSettings } from '../api'
import { Card, ErrorBox, Field, Modal } from '../ui'

// The limit on how many days in a row PC users may pause scheduled backups
// from the tray: -1 = no limit, 0 = no pauses, null = the console's default.

export function pauseDaysText(d: number): string {
  if (d < 0) return 'no limit'
  if (d === 0) return 'not allowed'
  return d === 1 ? 'up to 1 day in a row' : `up to ${d} days in a row`
}

const explanation =
  'PC users can pause scheduled backups from the ProxBackup tray icon, for up to 24 hours at a time. The limit counts from the first pause: once it is used up, pauses are refused until a scheduled backup has started again. Resuming early does not reset it.'

function PauseDaysInput({ value, onChange, defaultDays }: { value: number | null; onChange: (v: number | null) => void; defaultDays?: number }) {
  const mode = value === null ? 'default' : value < 0 ? 'unlimited' : value === 0 ? 'none' : 'days'
  return (
    <>
      <Field label="Tray pauses">
        <select
          value={mode}
          onChange={(e) => {
            const m = e.target.value
            onChange(m === 'default' ? null : m === 'unlimited' ? -1 : m === 'none' ? 0 : value && value > 0 ? value : 1)
          }}
        >
          {defaultDays !== undefined && <option value="default">Console default ({pauseDaysText(defaultDays)})</option>}
          <option value="none">Not allowed</option>
          <option value="days">Limited to a number of days in a row</option>
          <option value="unlimited">No limit</option>
        </select>
      </Field>
      {mode === 'days' && (
        <Field label="Days in a row" hint="1 to 365">
          <input type="number" min={1} max={365} required value={value ?? 1} onChange={(e) => onChange(Number(e.target.value))} />
        </Field>
      )}
    </>
  )
}

/** Console Settings → Agents: the default pause limit of every client. */
export function AgentsCard() {
  const [s, setS] = useState<AgentSettings | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  useEffect(() => {
    api.agentSettings().then(setS, (e: Error) => setError(e.message))
  }, [])
  if (!s) return <ErrorBox error={error} />
  return (
    <Card title="Pausing backups from the tray">
      <p className="muted-text">{explanation} Clients can override this default on their page.</p>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          setError('')
          setMsg('')
          try {
            setS(await api.saveAgentSettings(s))
            setMsg('Saved. Agents get the change with their next connection.')
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <PauseDaysInput value={s.pause_days} onChange={(v) => setS({ ...s, pause_days: v ?? 1 })} />
        <ErrorBox error={error} />
        {msg && <div className="notice">{msg}</div>}
        <div className="buttons">
          <button className="primary">Save</button>
        </div>
      </form>
    </Card>
  )
}

/** Sets a client's own pause limit, or makes it follow the default. */
export function PauseLimitEditor({ clientId, days, onClose }: { clientId: number; days: number | null; onClose: () => void }) {
  const [v, setV] = useState<number | null>(days)
  const [defaults, setDefaults] = useState<AgentSettings | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    api.agentSettings().then(setDefaults, (e: Error) => setError(e.message))
  }, [])
  return (
    <Modal title="Pausing backups from the tray" onClose={onClose}>
      <form
        onSubmit={async (e) => {
          e.preventDefault()
          try {
            await api.setClientPauseLimit(clientId, v)
            onClose()
          } catch (err) {
            setError((err as Error).message)
          }
        }}
      >
        <p className="muted-text">{explanation} A stricter limit also shortens a pause in effect.</p>
        {defaults && <PauseDaysInput value={v} onChange={setV} defaultDays={defaults.pause_days} />}
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
