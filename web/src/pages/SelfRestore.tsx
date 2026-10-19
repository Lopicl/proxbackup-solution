// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState, type ReactNode } from 'react'
import { selfRestoreApi, type Snapshot } from '../api'
import { bytes, Card, dateTime, Empty, ErrorBox, ProgressBar, StateBadge, useLoad } from '../ui'
import { RestoreBrowser, type RestoreBackend } from './RestoreBrowser'

/**
 * The restore page a PC user opens with "Restore files…" in the tray icon
 * (#/restore/<token>). It needs no console login: the token is a restore
 * session for this PC and this Windows user. Users who aren't administrators
 * of the PC only see and restore their own profile folder.
 */
export function SelfRestore({ token }: { token: string }) {
  const sr = useMemo(() => selfRestoreApi(token), [token])
  const session = useLoad(sr.session, [sr], 60000)
  const snaps = useLoad(sr.snapshots, [sr])
  const runs = useLoad(sr.runs, [sr], 3000)
  const [browse, setBrowse] = useState<Snapshot | null>(null)
  const s = session.data

  const backend = useMemo<RestoreBackend | null>(() => {
    if (!s) return null
    const home = s.scope.replace(/\\+$/, '')
    return {
      catalog: sr.catalog,
      restore: sr.restore,
      footer: 'Progress appears on this page.',
      defaultTarget: (stamp) => (s.admin ? `C:\\Restore\\${stamp}` : `${home}\\Restored\\${stamp}`),
      note: s.admin ? undefined : (
        <>
          You can restore files from your own folder <code>{s.scope}</code>, back to where they were or to another folder inside it.
        </>
      ),
    }
  }, [s, sr])

  if (session.error && !s)
    return (
      <Shell>
        <Card title="Restore files">
          <ErrorBox error={session.error} />
        </Card>
      </Shell>
    )
  if (!s || !backend) return null

  return (
    <Shell right={s.user}>
      <div className="title-row">
        <h1>Restore files on {s.hostname || s.client_name}</h1>
      </div>
      <p className="muted-text">
        Signed in on the PC as <b>{s.user}</b>
        {s.admin ? ' (administrator: every backed-up file can be restored)' : <> — you can restore files from <code>{s.scope}</code></>}.
        {!s.online && ' The PC is offline right now: restores start when it connects.'}
        {' '}This page stops working {dateTime(s.expires)} or after an hour without use; open it again from the ProxBackup tray icon.
      </p>
      {runs.data && runs.data.length > 0 && (
        <Card title="Your restores">
          <table>
            <thead>
              <tr>
                <th>Requested</th>
                <th>What</th>
                <th>To</th>
                <th>State</th>
                <th className="num">Files</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td>{dateTime(r.queued_at)}</td>
                  <td className="ellipsis" title={r.paths.join(', ')}>
                    {r.paths.length ? r.paths.join(', ') : r.archive}
                  </td>
                  <td>
                    <code>{r.target_dir}</code>
                  </td>
                  <td>
                    <StateBadge state={r.state} />
                    {r.state === 'running' && <ProgressBar p={r.progress} />}
                    {r.error && <div className="bad-text small">{r.error}</div>}
                  </td>
                  <td className="num">{r.state === 'running' ? r.progress.files : r.result.files || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      <Card title="Backups of this PC">
        <ErrorBox error={snaps.error} />
        {!snaps.data && !snaps.error && <Empty>Loading…</Empty>}
        {snaps.data && snaps.data.length === 0 && <Empty>No backups yet.</Empty>}
        {snaps.data && snaps.data.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Backup</th>
                <th className="num">Size</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {snaps.data.map((sn) => {
                const browsable = sn.files.some((f) => f.filename === 'catalog.pcat1.didx')
                return (
                  <tr key={sn.ns + sn['backup-id'] + sn['backup-time']}>
                    <td>{dateTime(sn['backup-time'])}</td>
                    <td>
                      <code>{sn['backup-id']}</code>
                    </td>
                    <td className="num">{bytes(sn.size)}</td>
                    <td className="row-actions">
                      <button
                        className="small primary"
                        disabled={!browsable}
                        title={browsable ? '' : 'This backup has no file list (it was taken by an older agent)'}
                        onClick={() => setBrowse(sn)}
                      >
                        Browse files
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Card>
      {browse && (
        <RestoreBrowser
          backend={backend}
          snap={browse}
          online={s.online}
          onClose={() => setBrowse(null)}
          onQueued={() => {
            setBrowse(null)
            runs.reload()
          }}
        />
      )}
    </Shell>
  )
}

function Shell({ right, children }: { right?: string; children: ReactNode }) {
  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="logo">▣</span> ProxBackup
        </div>
        <nav />
        {right && <div className="version">{right}</div>}
      </header>
      <main>{children}</main>
    </div>
  )
}
