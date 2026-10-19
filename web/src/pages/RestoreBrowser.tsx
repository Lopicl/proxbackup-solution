// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, type CatalogEntry, type RestoreSpec, type Snapshot } from '../api'
import { bytes, dateTime, Empty, ErrorBox, Field, Link, Modal } from '../ui'

/** Where the browser reads catalogs from and sends restores to. */
export interface RestoreBackend {
  catalog: (snap: Snapshot, path: string) => Promise<CatalogEntry[]>
  restore: (spec: RestoreSpec) => Promise<{ run_id: number }>
  /** Shown next to the buttons (where progress appears). */
  footer?: ReactNode
  /** Default for "Another folder on the PC"; stamp is the snapshot time as YYYY-MM-DD-HH-MM. */
  defaultTarget?: (stamp: string) => string
  /** Explains a restriction of what can be restored. */
  note?: ReactNode
}

/** The console admin's backend for a client. */
export function adminBackend(clientId: number): RestoreBackend {
  return {
    catalog: (snap, path) => api.catalog(clientId, snap, path),
    restore: (spec) => api.restore(clientId, spec),
    footer: <Link to={`/clients/${clientId}/runs`}>Restore progress appears in the client history.</Link>,
  }
}

// Directories with more entries show only the first ones until filtered.
const maxRows = 500

const isImage = (archive: string) => archive.endsWith('.img.fidx')
export const archiveLabel = (archive: string) => archive.replace(/\.(m?pxar\.didx|img\.fidx)$/, '')

/** Selection paths are catalog paths without the leading slash: "<archive>" or "<archive>/<rel>". */
function covers(sel: string[], p: string) {
  return sel.some((s) => p === s || p.startsWith(s + '/'))
}

/**
 * Browses a snapshot's catalog (catalog.pcat1.didx) and restores the selected
 * files and folders, one restore run per archive.
 */
export function RestoreBrowser({
  backend,
  snap,
  online,
  onClose,
  onQueued,
}: {
  backend: RestoreBackend
  snap: Snapshot
  online: boolean
  onClose: () => void
  onQueued: (runIds: number[]) => void
}) {
  const [dir, setDir] = useState('') // current folder, "" = the archives
  const [listing, setListing] = useState<{ dir: string; entries: CatalogEntry[] } | null>(null)
  const [loadError, setLoadError] = useState('')
  const [origins, setOrigins] = useState<Record<string, string>>({})
  const [filter, setFilter] = useState('')
  const [sel, setSel] = useState<string[]>([])
  const stamp = new Date(snap['backup-time'] * 1000).toISOString().slice(0, 16).replace(/[:T]/g, '-')
  const [dest, setDest] = useState<'original' | 'other'>('other')
  const [target, setTarget] = useState(backend.defaultTarget ? backend.defaultTarget(stamp) : `C:\\Restore\\${stamp}`)
  const [overwrite, setOverwrite] = useState<RestoreSpec['overwrite']>('skip')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let live = true
    setLoadError('')
    backend.catalog(snap, '/' + dir).then(
      (entries) => {
        if (!live) return
        setListing({ dir, entries })
        if (dir === '') setOrigins(Object.fromEntries(entries.filter((e) => e.origin).map((e) => [e.name, e.origin!])))
      },
      (e: Error) => live && setLoadError(e.message),
    )
    return () => {
      live = false
    }
  }, [backend, snap, dir])

  const open = (d: string) => {
    setDir(d)
    setFilter('')
  }
  const toggle = (p: string) =>
    setSel((s) => (s.includes(p) ? s.filter((x) => x !== p) : [...s.filter((x) => !x.startsWith(p + '/')), p].sort()))

  // The selection as restore runs: one per archive.
  const runs = useMemo(() => {
    const by = new Map<string, string[]>()
    for (const p of sel) {
      const [archive, ...rest] = p.split('/')
      const paths = by.get(archive) ?? []
      // A whole volume image means every file on it (an empty list would write the raw image).
      paths.push(rest.length ? rest.join('/') : isImage(archive) ? '/' : '')
      by.set(archive, paths)
    }
    return [...by].map(([archive, paths]) => ({ archive, paths: paths.includes('') ? [] : paths }))
  }, [sel])
  const missingOrigin = runs.filter((r) => !origins[r.archive]).map((r) => archiveLabel(r.archive))
  const originalOK = runs.length > 0 && missingOrigin.length === 0
  const anyOrigin = Object.keys(origins).length > 0
  useEffect(() => {
    if (dest === 'original' && runs.length > 0 && !originalOK) setDest('other')
  }, [dest, runs.length, originalOK])

  const crumbs = dir ? dir.split('/') : []
  const shown = listing && listing.dir === dir ? listing.entries.filter((e) => e.name.toLowerCase().includes(filter.toLowerCase())) : null

  const submit = async () => {
    setError('')
    setBusy(true)
    const ids: number[] = []
    try {
      for (const r of runs) {
        let dir = origins[r.archive]
        if (dest === 'other') {
          dir = target.replace(/[\\/]+$/, '')
          // Several archives each get a subfolder, so their trees don't mix.
          if (runs.length > 1) dir += '\\' + archiveLabel(r.archive)
        }
        const res = await backend.restore({
          backup_id: snap['backup-id'],
          backup_time: snap['backup-time'],
          ns: snap.ns,
          archive: r.archive,
          target_dir: dir,
          paths: r.paths,
          overwrite,
        })
        ids.push(res.run_id)
      }
      onQueued(ids)
    } catch (e) {
      setError((e as Error).message + (ids.length ? ` (run${ids.length > 1 ? 's' : ''} #${ids.join(', #')} already queued)` : ''))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={`Browse snapshot of ${dateTime(snap['backup-time'])}`} onClose={onClose} wide>
      <p className="muted-text">
        {snap['backup-type']}/{snap['backup-id']}. Tick the files and folders to restore; the agent on the PC downloads and writes them
        {online ? '' : ' when the PC comes online'}.
      </p>
      {backend.note && <p className="notice">{backend.note}</p>}
      <nav className="crumbs">
        <a onClick={() => open('')}>Archives</a>
        {crumbs.map((c, i) => (
          <span key={i}>
            {' / '}
            <a onClick={() => open(crumbs.slice(0, i + 1).join('/'))}>{i === 0 ? archiveLabel(c) : c}</a>
          </span>
        ))}
        {dir && (
          <input className="filter" placeholder="Filter this folder" value={filter} onChange={(e) => setFilter(e.target.value)} />
        )}
      </nav>
      <div className="browser">
        <ErrorBox error={loadError} />
        {!shown && !loadError && <Empty>Loading the snapshot catalog…</Empty>}
        {shown && shown.length === 0 && <Empty>{filter ? 'Nothing matches.' : 'Empty folder.'}</Empty>}
        {shown && shown.length > 0 && (
          <table>
            <thead>
              <tr>
                <th className="check"></th>
                <th>Name</th>
                <th className="num">Size</th>
                <th>Modified</th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, maxRows).map((e) => {
                const p = dir ? `${dir}/${e.name}` : e.name
                const inherited = covers(sel, p) && !sel.includes(p)
                const restorable = e.type === 'dir' || e.type === 'file' || e.type === 'symlink'
                return (
                  <tr key={e.name}>
                    <td className="check">
                      <input
                        type="checkbox"
                        checked={covers(sel, p)}
                        disabled={inherited || !restorable}
                        title={inherited ? 'Included with its parent folder' : ''}
                        onChange={() => toggle(p)}
                      />
                    </td>
                    <td className="name">
                      {e.type === 'dir' ? (
                        <a onClick={() => open(p)}>
                          <span className="icon">{dir ? '📁' : isImage(e.name) ? '💽' : '🗂'}</span>
                          {dir ? e.name : archiveLabel(e.name)}
                        </a>
                      ) : (
                        <>
                          <span className="icon">{e.type === 'symlink' ? '↪' : '📄'}</span>
                          {e.name}
                        </>
                      )}
                      {!dir && (
                        <span className="muted-text small">
                          {' '}
                          {isImage(e.name) ? 'volume image' : 'files'}
                          {e.origin && (
                            <>
                              {' '}
                              from <code>{e.origin}</code>
                            </>
                          )}
                        </span>
                      )}
                    </td>
                    <td className="num">{e.type === 'file' ? bytes(e.size) : ''}</td>
                    <td>{e.mtime ? dateTime(e.mtime) : ''}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
        {shown && shown.length > maxRows && (
          <p className="muted-text small">
            Showing {maxRows} of {shown.length} entries. Filter to find the others.
          </p>
        )}
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <Field label={`Selected (${sel.length})`}>
          {sel.length === 0 ? (
            <span className="muted-text small">Nothing selected yet. Tick an archive to restore all of it.</span>
          ) : (
            <div className="chips">
              {sel.map((p) => {
                const [a, ...rest] = p.split('/')
                return (
                  <span key={p} className="chip tag" title={p}>
                    {archiveLabel(a)}
                    {rest.length ? '/' + rest.join('/') : ' (all)'}{' '}
                    <a onClick={() => toggle(p)} aria-label={`Remove ${p}`}>
                      ✕
                    </a>
                  </span>
                )
              })}
            </div>
          )}
        </Field>
        <Field
          label="Restore to"
          hint={
            dest === 'original'
              ? 'Files go back where they were backed up from, keeping their folder structure.'
              : runs.length > 1
                ? 'Each archive gets its own subfolder here; files keep their folder structure.'
                : 'Files keep their folder structure below this folder.'
          }
        >
          <div className="checks">
            <label title={anyOrigin ? (missingOrigin.length ? `Unknown for ${missingOrigin.join(', ')}: its source is no longer in this client's jobs` : '') : "The archives' sources are no longer in this client's jobs"}>
              <input type="radio" checked={dest === 'original'} disabled={!originalOK} onChange={() => setDest('original')} />
              Original location
              {runs.length > 0 && originalOK && (
                <span className="muted-text small">{[...new Set(runs.map((r) => origins[r.archive]))].join(', ')}</span>
              )}
            </label>
            <label>
              <input type="radio" checked={dest === 'other'} onChange={() => setDest('other')} />
              Another folder on the PC
            </label>
          </div>
          {dest === 'other' && <input value={target} onChange={(e) => setTarget(e.target.value)} required />}
        </Field>
        <Field label="Existing files" hint={dest === 'original' ? 'Restoring in place: “Always replace” rolls the selected files back to this snapshot.' : undefined}>
          <select value={overwrite} onChange={(e) => setOverwrite(e.target.value as typeof overwrite)}>
            <option value="skip">Keep existing files</option>
            <option value="if-newer">Replace if the backup is newer</option>
            <option value="overwrite">Always replace</option>
          </select>
        </Field>
        <ErrorBox error={error} />
        <div className="buttons">
          <span className="left muted-text small">{backend.footer}</span>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary" disabled={busy || runs.length === 0}>
            {runs.length > 1 ? `Start ${runs.length} restores` : 'Start restore'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
