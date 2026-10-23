// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from 'react'
import { api, type LogLine } from '../api'
import { usePerms } from '../perms'
import { bytes, Card, dateTime, duration, ErrorBox, Link, ProgressBar, StateBadge, useLoad } from '../ui'

export function RunDetail({ id }: { id: number }) {
  const { data: r, error, reload } = useLoad(() => api.run(id), [id], 2000)
  const [logs, setLogs] = useState<LogLine[]>([])
  const lastId = useRef(0)
  const box = useRef<HTMLPreElement>(null)
  const perms = usePerms()

  useEffect(() => {
    lastId.current = 0
    setLogs([])
    let stop = false
    const poll = async () => {
      try {
        const more = await api.runLogs(id, lastId.current)
        if (more.length && !stop) {
          lastId.current = more[more.length - 1].id
          setLogs((l) => [...l, ...more])
        }
      } catch {
        /* retry on next tick */
      }
    }
    poll()
    const t = setInterval(poll, 2000)
    return () => {
      stop = true
      clearInterval(t)
    }
  }, [id])

  useEffect(() => {
    const el = box.current
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 80) el.scrollTop = el.scrollHeight
  }, [logs])

  if (error) return <ErrorBox error={error} />
  if (!r) return null
  const active = ['queued', 'dispatched', 'running'].includes(r.state)
  const end = r.finished_at || Math.floor(Date.now() / 1000)
  const p = r.progress
  return (
    <>
      <div className="title-row">
        <h1>
          Run #{r.id} <StateBadge state={r.state} />
        </h1>
        {active && !r.cancel_requested && perms.can(r.kind === 'restore' ? 'restore' : 'backups.run', { id: r.client_id }) && (
          <button
            className="danger"
            onClick={async () => {
              await api.cancelRun(r.id)
              reload()
            }}
          >
            Cancel
          </button>
        )}
      </div>
      <div className="facts">
        <span>
          Client <Link to={`/clients/${r.client_id}`}>{r.client_name}</Link>
        </span>
        <span>
          Job <b>{r.job_name || r.kind}</b> ({r.trigger})
        </span>
        <span>Queued {dateTime(r.queued_at)}</span>
        {r.started_at > 0 && <span>Duration {duration(end - r.started_at)}</span>}
        {r.snapshot && (
          <span>
            Snapshot <code>{r.snapshot}</code>
          </span>
        )}
      </div>
      {r.error && <div className="error">{r.error}</div>}
      {r.restore && (
        <div className="notice">
          Restoring <code>{r.restore.archive}</code> → <code>{r.restore.target_dir}</code>
          {r.restore.paths?.length ? ` (${r.restore.paths.join(', ')})` : ''}, existing files: {r.restore.overwrite}
        </div>
      )}
      <Card title={active ? `Progress — ${p.phase || r.state}` : 'Result'}>
        {active && <ProgressBar p={p} />}
        <div className="stats compact">
          <div className="stat">
            <div className="value">{(active ? p.files : r.result.files) ?? 0}</div>
            <div className="label">files</div>
          </div>
          <div className="stat">
            <div className="value">{bytes(active ? p.bytes_read : r.result.bytes_total)}</div>
            <div className="label">{active && p.bytes_total ? `of ${bytes(p.bytes_total)}` : 'processed'}</div>
          </div>
          <div className="stat">
            <div className="value">{bytes(active ? p.bytes_uploaded : r.result.bytes_uploaded)}</div>
            <div className="label">uploaded (new data)</div>
          </div>
          {!active && (
            <div className="stat">
              <div className="value">
                {r.result.chunks_new} / {r.result.chunks_new + r.result.chunks_reused}
              </div>
              <div className="label">new chunks</div>
            </div>
          )}
          <div className={`stat ${(active ? p.skipped : r.result.skipped) ? 'warn' : ''}`}>
            <div className="value">{(active ? p.skipped : r.result.skipped) ?? 0}</div>
            <div className="label">skipped</div>
          </div>
        </div>
        {active && p.current_archive && (
          <p className="muted-text">
            Archive <code>{p.current_archive}</code>
          </p>
        )}
      </Card>
      <Card title={`Log (${logs.length})`}>
        <pre className="log" ref={box}>
          {logs.map((l) => (
            <div key={l.id} className={`lvl-${l.level}`}>
              <span className="ts">{new Date(l.ts * 1000).toLocaleTimeString()}</span> {l.msg}
            </div>
          ))}
          {logs.length === 0 && <span className="muted-text">No log lines yet.</span>}
        </pre>
      </Card>
    </>
  )
}
