// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react'
import { api, type StorageTimeframe, type TargetStorage } from '../api'
import { BarList, UsageChart, UsageMeter } from '../charts'
import { bytes, Card, Empty, ErrorBox, Link, Stat, useLoad } from '../ui'

const timeframes: [StorageTimeframe, string][] = [
  ['day', 'Day'],
  ['week', 'Week'],
  ['month', 'Month'],
  ['year', 'Year'],
]

export function Dashboard() {
  const { data, error } = useLoad(api.dashboard, [], 5000)
  const [tf, setTf] = useState<StorageTimeframe>('week')
  const storage = useLoad(() => api.storage(tf), [tf], 60000)
  return (
    <>
      <h1>Dashboard</h1>
      <ErrorBox error={error} />
      {data && (
        <div className="stats">
          <Stat label="Clients" value={data.clients} />
          <Stat label="Online" value={data.online} tone={data.online ? 'ok' : undefined} />
          <Stat label="No backup in 3 days" value={data.stale} tone={data.stale ? 'warn' : 'ok'} />
          <Stat label="Running now" value={<Link to="/runs">{data.active_runs}</Link>} />
          <Stat label="Recent failures" value={data.failed_recent} tone={data.failed_recent ? 'bad' : 'ok'} />
        </div>
      )}
      <div className="section-head">
        <h2>Storage</h2>
        <div className="segmented" role="group" aria-label="Time range">
          {timeframes.map(([k, label]) => (
            <button key={k} className={tf === k ? 'active' : ''} onClick={() => setTf(k)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <ErrorBox error={storage.error} />
      {storage.data?.length === 0 && <Empty>No PBS servers yet.</Empty>}
      {storage.data?.map((t) => <TargetStorageCard key={t.id} t={t} timeframe={tf} />)}
    </>
  )
}

function TargetStorageCard({ t, timeframe }: { t: TargetStorage; timeframe: StorageTimeframe }) {
  const [table, setTable] = useState(false)
  return (
    <Card
      title={
        <>
          {t.name} <span className="muted-text">· {t.datastore}</span>
        </>
      }
      actions={
        !t.error && (
          <button className="small" onClick={() => setTable(!table)}>
            {table ? 'Show chart' : 'Show table'}
          </button>
        )
      }
    >
      {t.error ? (
        <div className="error">Could not read the datastore usage: {t.error}</div>
      ) : (
        <>
          <UsageMeter used={t.used} total={t.total} />
          <div className="storage-grid">
            <div>
              <h3>Usage over time</h3>
              {table ? <HistoryTable points={t.history} /> : <UsageChart points={t.history} timeframe={timeframe} />}
            </div>
            <div>
              <h3>Protected data per client</h3>
              {t.clients.length === 0 ? (
                <Empty>No clients on this server.</Empty>
              ) : (
                <BarList
                  items={t.clients.map((c) => ({
                    key: c.id,
                    label: <Link to={`/clients/${c.id}`}>{c.name}</Link>,
                    value: c.protected,
                    title: `${c.name}: ${bytes(c.protected)} in the latest backups, ${bytes(c.uploaded_30d)} new data uploaded in 30 days`,
                  }))}
                />
              )}
              <p className="muted-text small-text">Size of each client's latest backups before deduplication.</p>
            </div>
          </div>
        </>
      )}
    </Card>
  )
}

/** The history as rows, about 12 of them evenly spread. */
function HistoryTable({ points }: { points: TargetStorage['history'] }) {
  if (points.length === 0) return <Empty>No history yet.</Empty>
  const step = Math.max(1, Math.ceil(points.length / 12))
  const rows = points.filter((_, i) => i % step === 0 || i === points.length - 1)
  return (
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th className="num">Used</th>
          <th className="num">Capacity</th>
          <th className="num">Full</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((p) => (
          <tr key={p.t}>
            <td>{new Date(p.t * 1000).toLocaleString()}</td>
            <td className="num">{bytes(p.used)}</td>
            <td className="num">{bytes(p.total)}</td>
            <td className="num">{p.total ? ((100 * p.used) / p.total).toFixed(1) + '%' : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
