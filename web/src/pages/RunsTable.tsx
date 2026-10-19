// SPDX-License-Identifier: AGPL-3.0-or-later

import type { Run } from '../api'
import { ago, bytes, duration, Empty, Link, ProgressBar, StateBadge } from '../ui'

export function RunsTable({ runs, showClient, progress }: { runs: Run[]; showClient?: boolean; progress?: boolean }) {
  if (runs.length === 0) return <Empty>No runs yet.</Empty>
  return (
    <table>
      <thead>
        <tr>
          <th>#</th>
          {showClient && <th>Client</th>}
          <th>Job</th>
          <th>State</th>
          <th>Started</th>
          <th>Duration</th>
          <th className="num">Data</th>
          <th className="num">Uploaded</th>
          <th>Snapshot / error</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((r) => {
          const active = ['queued', 'dispatched', 'running'].includes(r.state)
          const end = r.finished_at || (active ? Math.floor(Date.now() / 1000) : 0)
          const data = active ? r.progress.bytes_read : r.result.bytes_total
          const up = active ? r.progress.bytes_uploaded : r.result.bytes_uploaded
          return (
            <tr key={r.id}>
              <td>
                <Link to={`/runs/${r.id}`}>{r.id}</Link>
              </td>
              {showClient && (
                <td>
                  <Link to={`/clients/${r.client_id}`}>{r.client_name}</Link>
                </td>
              )}
              <td>
                {r.group_id ? <Link to={`/jobs/${r.group_id}`}>{r.job_name}</Link> : r.job_name || r.kind}
                {r.trigger === 'schedule' && (
                  <span className="tag" title={r.scheduled_for ? `scheduled for ${new Date(r.scheduled_for * 1000).toLocaleString()}` : ''}>
                    sched
                  </span>
                )}
                {r.trigger === 'catch-up' && (
                  <span className="tag catchup" title={r.scheduled_for ? `missed slot ${new Date(r.scheduled_for * 1000).toLocaleString()}, run when the PC was available` : ''}>
                    catch-up
                  </span>
                )}
              </td>
              <td>
                <StateBadge state={r.state} />
                {progress && active && <ProgressBar p={r.progress} />}
              </td>
              {r.state === 'missed' && r.scheduled_for ? (
                <td title={`was scheduled for ${new Date(r.scheduled_for * 1000).toLocaleString()}`}>{ago(r.scheduled_for)}</td>
              ) : (
                <td title={new Date((r.started_at || r.queued_at) * 1000).toLocaleString()}>{ago(r.started_at || r.queued_at)}</td>
              )}
              <td>{r.started_at && end ? duration(end - r.started_at) : '—'}</td>
              <td className="num">{bytes(data)}</td>
              <td className="num">{bytes(up)}</td>
              <td className="ellipsis" title={r.error || r.snapshot}>
                {r.error ? <span className={r.state === 'missed' ? 'warn-text' : 'bad-text'}>{r.error}</span> : <code>{r.snapshot}</code>}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
