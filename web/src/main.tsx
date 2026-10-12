import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { api, setUnauthorizedHandler } from './api'
import { ErrorBox, Field } from './ui'
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

function Login({ onLogin }: { onLogin: (u: string) => void }) {
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
            const r = await api.login(username, password)
            onLogin(r.username)
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

const nav = [
  { to: '/', label: 'Dashboard' },
  { to: '/clients', label: 'Clients' },
  { to: '/targets', label: 'PBS servers' },
  { to: '/settings', label: 'Settings' },
]

function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined)
  const [version, setVersion] = useState('')
  const route = useHashRoute()
  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null))
    api.me().then(
      (m) => {
        setUser(m.username)
        setVersion(m.version)
      },
      () => setUser(null),
    )
  }, [])

  if (user === undefined) return null
  if (user === null)
    return (
      <Login
        onLogin={(u) => {
          setUser(u)
          api.me().then((m) => setVersion(m.version), () => {})
        }}
      />
    )

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
          {user}
          <button
            className="ghost small"
            onClick={async () => {
              await api.logout()
              setUser(null)
            }}
          >
            Sign out
          </button>
        </div>
      </aside>
      <main>{page}</main>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
