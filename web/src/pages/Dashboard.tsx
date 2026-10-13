// SPDX-License-Identifier: AGPL-3.0-or-later

import { api } from '../api'
import { RunsTable } from './RunsTable'
import { Card, ErrorBox, Stat, useLoad } from '../ui'

export function Dashboard() {
  const { data, error } = useLoad(api.dashboard, [], 5000)
  return (
    <>
      <h1>Dashboard</h1>
      <ErrorBox error={error} />
      {data && (
        <>
          <div className="stats">
            <Stat label="Clients" value={data.clients} />
            <Stat label="Online" value={data.online} tone={data.online ? 'ok' : undefined} />
            <Stat label="No backup in 3 days" value={data.stale} tone={data.stale ? 'warn' : 'ok'} />
            <Stat label="Running now" value={data.active_runs} />
            <Stat label="Recent failures" value={data.failed_recent} tone={data.failed_recent ? 'bad' : 'ok'} />
          </div>
          {data.active.length > 0 && (
            <Card title="Active runs">
              <RunsTable runs={data.active} showClient progress />
            </Card>
          )}
          <Card title="Recent runs">
            <RunsTable runs={data.recent_runs} showClient />
          </Card>
        </>
      )}
    </>
  )
}
