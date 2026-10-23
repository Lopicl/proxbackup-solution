// SPDX-License-Identifier: AGPL-3.0-or-later

import { api } from '../api'
import { RunsTable } from './RunsTable'
import { Card, ErrorBox, useLoad } from '../ui'

export function Runs() {
  const active = useLoad(() => api.runs({ active: true }), [], 5000)
  const recent = useLoad(() => api.runs({ limit: 100 }), [], 5000)
  return (
    <>
      <h1>Runs</h1>
      <ErrorBox error={active.error || recent.error} />
      {active.data && active.data.length > 0 && (
        <Card title="Active runs">
          <RunsTable runs={active.data} showClient progress />
        </Card>
      )}
      {recent.data && (
        <Card title="Recent runs">
          <RunsTable runs={recent.data} showClient />
        </Card>
      )}
    </>
  )
}
