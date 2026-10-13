// SPDX-License-Identifier: AGPL-3.0-or-later

import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, setUnauthorizedHandler, type Me } from './api'
import { ErrorBox, Field, Modal } from './ui'
import { Dashboard } from './pages/Dashboard'
import { Clients } from './pages/Clients'
import { ClientDetail } from './pages/ClientDetail'
import { RunDetail } from './pages/RunDetail'
import { Targets } from './pages/Targets'
import { Settings } from './pages/Settings'
import './styles.css'

function useHashRoute(): string {
  const [route, setRoute] = useState(() => location.hash.slice(1) || '/')
  useEffect(() => {
    const h = () => setRoute(location.hash.slice(1) || '/')
    window.addEventListener('hashchange', h)
    return () => window.removeEventListener('hashchange', h)
  }, [])
  return route
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [pbsLogin, setPbsLogin] = useState(false)
  useEffect(() => {
    api.loginInfo().then((r) => setPbsLogin(r.pbs_login), () => {})
  }, [])
  return (
    <div className="login">
      <form
        className="card"
        onSubmit={async (e) => {
          e.preventDefault()
          setBusy(true)
          try {
            await api.login(username, password)
            onLogin()
          } catch (err) {
            setError((err as Error).message)
          } finally {
            setBusy(false)
          }
        }}
      >
        <h1>
          <span className="logo">▣</span> ProxBackup Console
        </h1>
        <Field label="Username" hint={pbsLogin ? 'A console account, or a PBS administrator such as root@pam.' : undefined}>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </Field>
        <Field label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus />
        </Field>
        <ErrorBox error={error} />
        <button className="primary" disabled={busy}>
          Sign in
        </button>
      </form>
    </div>
  )
}

function PasswordForm({ forced, onDone, onCancel }: { forced?: boolean; onDone: () => void; onCancel?: () => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault()
        if (next !== repeat) return setError('The new passwords do not match.')
        setBusy(true)
        setError('')
        try {
          await api.changePassword(current, next)
          onDone()
        } catch (err) {
          setError((err as Error).message)
        } finally {
          setBusy(false)
        }
      }}
    >
      {forced && <p className="muted-text">This account still has its generated initial password. Choose your own to continue.</p>}
      <Field label={forced ? 'Initial password' : 'Current password'}>
        <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" autoFocus required />
      </Field>
      <Field label="New password" hint="At least 10 characters.">
        <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" minLength={10} required />
      </Field>
      <Field label="Repeat new password">
        <input type="password" value={repeat} onChange={(e) => setRepeat(e.target.value)} autoComplete="new-password" minLength={10} required />
      </Field>
      <ErrorBox error={error} />
      <div className="buttons">
        {onCancel && (
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
        )}
        <button className="primary" disabled={busy}>
          Change password
        </button>
      </div>
    </form>
  )
}

const nav = [
  { to: '/', label: 'Dashboard' },
  { to: '/clients', label: 'Clients' },
  { to: '/targets', label: 'PBS servers' },
  { to: '/settings', label: 'Settings' },
]

function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined)
  const [changingPw, setChangingPw] = useState(false)
  const route = useHashRoute()
  const loadMe = () => api.me().then(setMe, () => setMe(null))
  useEffect(() => {
    setUnauthorizedHandler(() => setMe(null))
    loadMe()
  }, [])

  if (me === undefined) return null
  if (me === null) return <Login onLogin={loadMe} />
  if (me.must_change_password)
    return (
      <div className="login">
        <div className="card">
          <h1>
            <span className="logo">▣</span> Set your password
          </h1>
          <PasswordForm forced onDone={loadMe} />
        </div>
      </div>
    )
  const user = me.username
  const version = me.version

  const parts = route.split('/').filter(Boolean)
  let page
  if (parts[0] === 'clients' && parts[1]) page = <ClientDetail id={Number(parts[1])} tab={parts[2] ?? 'jobs'} />
  else if (parts[0] === 'clients') page = <Clients />
  else if (parts[0] === 'runs' && parts[1]) page = <RunDetail id={Number(parts[1])} />
  else if (parts[0] === 'targets') page = <Targets />
  else if (parts[0] === 'settings') page = <Settings />
  else page = <Dashboard />

  const active = '/' + (parts[0] ?? '')
  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <span className="logo">▣</span> ProxBackup Console
        </div>
        <nav>
          {nav.map((n) => (
            <a key={n.to} href={'#' + n.to} className={active === n.to || (n.to === '/clients' && active === '/runs') ? 'active' : ''}>
              {n.label}
            </a>
          ))}
        </nav>
        {version && <div className="version">v{version}</div>}
        <div className="user">
          <span title={user}>{user}</span>
          {me.local_account && (
            <button className="ghost small" onClick={() => setChangingPw(true)}>
              Password
            </button>
          )}
          <button
            className="ghost small"
            onClick={async () => {
              await api.logout()
              setMe(null)
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main>{page}</main>
      {changingPw && (
        <Modal title="Change password" onClose={() => setChangingPw(false)}>
          <PasswordForm onDone={() => setChangingPw(false)} onCancel={() => setChangingPw(false)} />
        </Modal>
      )}
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
