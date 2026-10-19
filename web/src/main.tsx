// SPDX-License-Identifier: AGPL-3.0-or-later

import { StrictMode, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, setUnauthorizedHandler, type Me } from './api'
import { ErrorBox, Field, Modal } from './ui'
import { Dashboard } from './pages/Dashboard'
import { Clients } from './pages/Clients'
import { ClientDetail } from './pages/ClientDetail'
import { JobDetail, Jobs } from './pages/Jobs'
import { RunDetail } from './pages/RunDetail'
import { Targets } from './pages/Targets'
import { Settings } from './pages/Settings'
import { SelfRestore } from './pages/SelfRestore'
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
  { to: '/jobs', label: 'Jobs' },
  { to: '/targets', label: 'PBS servers' },
]

const UserIcon = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="8" r="4" />
    <path d="M4 21c0-4 3.6-7 8-7s8 3 8 7" />
  </svg>
)

const GearIcon = () => (
  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
)

/** The profile button in the top bar and its drop-down menu. */
function ProfileMenu({ me, onSettings, onLogout }: { me: Me; onSettings: () => void; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open])
  const pick = (fn: () => void) => () => {
    setOpen(false)
    fn()
  }
  return (
    <div className="menu" ref={ref}>
      <button className={'icon-btn profile' + (open ? ' open' : '')} onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open} title={me.username}>
        <UserIcon />
        <span className="name">{me.username}</span>
      </button>
      {open && (
        <div className="menu-list" role="menu">
          <div className="menu-head">
            Signed in as <b>{me.username}</b>
          </div>
          <button role="menuitem" onClick={pick(onSettings)}>
            Profile Settings
          </button>
          <button role="menuitem" onClick={pick(onLogout)}>
            Logout
          </button>
        </div>
      )}
    </div>
  )
}

function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined)
  const [profileOpen, setProfileOpen] = useState(false)
  const route = useHashRoute()
  const loadMe = () => api.me().then(setMe, () => setMe(null))
  // A PC user's restore page from the tray icon: authenticated by its token, no login.
  const selfRestore = route.startsWith('/restore/') ? route.slice('/restore/'.length) : ''
  useEffect(() => {
    if (selfRestore) return
    setUnauthorizedHandler(() => setMe(null))
    loadMe()
  }, [selfRestore])

  if (selfRestore) return <SelfRestore token={selfRestore} />

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
  const version = me.version

  const parts = route.split('/').filter(Boolean)
  let page
  if (parts[0] === 'clients' && parts[1]) page = <ClientDetail id={Number(parts[1])} tab={parts[2] ?? 'jobs'} />
  else if (parts[0] === 'clients') page = <Clients />
  else if (parts[0] === 'jobs' && parts[1]) page = <JobDetail id={Number(parts[1])} />
  else if (parts[0] === 'jobs') page = <Jobs />
  else if (parts[0] === 'runs' && parts[1]) page = <RunDetail id={Number(parts[1])} />
  else if (parts[0] === 'targets') page = <Targets />
  else if (parts[0] === 'settings') page = <Settings />
  else page = <Dashboard />

  const active = '/' + (parts[0] ?? '')
  return (
    <div className="shell">
      <header className="topbar">
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
        <a href="#/settings" className={'icon-btn' + (active === '/settings' ? ' active' : '')} title="Console Settings" aria-label="Console Settings">
          <GearIcon />
        </a>
        <ProfileMenu
          me={me}
          onSettings={() => setProfileOpen(true)}
          onLogout={async () => {
            await api.logout()
            setMe(null)
          }}
        />
      </header>
      <main>{page}</main>
      {profileOpen && (
        <Modal title="Profile Settings" onClose={() => setProfileOpen(false)}>
          <h3>Change password</h3>
          {me.local_account ? (
            <PasswordForm onDone={() => setProfileOpen(false)} onCancel={() => setProfileOpen(false)} />
          ) : (
            <p className="muted-text">
              <b>{me.username}</b> signs in through Proxmox Backup Server. Change its password on the PBS server.
            </p>
          )}
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
