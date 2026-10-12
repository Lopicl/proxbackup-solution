import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

// ---- formatting ----

export function bytes(n?: number): string {
  if (!n) return '0 B'
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}

export function ago(ts?: number): string {
  if (!ts) return 'never'
  const s = Math.floor(Date.now() / 1000 - ts)
  if (s < 0) return 'in ' + duration(-s)
  if (s < 60) return 'just now'
  return duration(s) + ' ago'
}

export function duration(s: number): string {
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`
}

export function dateTime(ts?: number): string {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

// ---- hooks ----

/** Loads data and optionally refreshes it every `interval` ms. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[], interval = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string>('')
  const fnRef = useRef(fn)
  fnRef.current = fn
  const reload = useCallback(() => {
    fnRef.current().then(
      (d) => {
        setData(d)
        setError('')
      },
      (e: Error) => setError(e.message),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => {
    reload()
    if (!interval) return
    const t = setInterval(reload, interval)
    return () => clearInterval(t)
  }, [reload, interval])
  return { data, error, reload }
}

// ---- components ----

const stateClass: Record<string, string> = {
  success: 'ok',
  warning: 'warn',
  failed: 'bad',
  lost: 'bad',
  missed: 'warn',
  canceled: 'muted',
  queued: 'info',
  dispatched: 'info',
  running: 'info',
}

export function StateBadge({ state }: { state: string }) {
  return <span className={`badge ${stateClass[state] ?? 'muted'}`}>{state}</span>
}

export function OnlineDot({ online }: { online: boolean }) {
  return <span className={`dot ${online ? 'on' : 'off'}`} title={online ? 'online' : 'offline'} />
}

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header>
          <h2>{title}</h2>
          <div className="actions">{actions}</div>
        </header>
      )}
      {children}
    </section>
  )
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: 'ok' | 'warn' | 'bad' }) {
  return (
    <div className={`stat ${tone ?? ''}`}>
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  )
}

export function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className={`modal ${wide ? 'wide' : ''}`} onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-label={title}>
        <header>
          <h2>{title}</h2>
          <button className="ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        {children}
      </div>
    </div>
  )
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  )
}

export function ErrorBox({ error }: { error?: string }) {
  return error ? <div className="error">{error}</div> : null
}

export function ProgressBar({ p }: { p: { bytes_read: number; bytes_total?: number } }) {
  const pct = p.bytes_total ? Math.min(100, (100 * p.bytes_read) / p.bytes_total) : undefined
  return (
    <div className={`progress ${pct === undefined ? 'indeterminate' : ''}`} title={pct !== undefined ? `${pct.toFixed(0)}%` : ''}>
      <div style={{ width: pct !== undefined ? `${pct}%` : undefined }} />
    </div>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Link({ to, children, className }: { to: string; children: ReactNode; className?: string }) {
  return (
    <a href={'#' + to} className={className}>
      {children}
    </a>
  )
}
