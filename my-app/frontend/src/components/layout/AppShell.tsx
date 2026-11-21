import { type ReactNode, useEffect, useRef, useState } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { Home, Inbox, ListChecks, BookOpen, ScrollText, Settings, Search, Bell, Plus, Shield, LogOut, Upload, ChevronDown } from 'lucide-react'
import { useAuthStore } from '../../store/authStore'
import { usersApi } from '../../api/users'
import { dashboardApi } from '../../api/dashboard'
import { Avatar, Toaster } from '../ui'
import NewIncidentModal from '../NewIncidentModal'
import { ROLE_LABELS } from '../../utils/constants'
import { useLiveUpdates } from '../../useLiveUpdates'

const NAV = [
  { to: '/', label: 'Home', icon: Home, end: true },
  { to: '/incidents', label: 'Incidents', icon: Inbox },
  { to: '/actions', label: 'Action queue', icon: ListChecks, badge: true },
  { to: '/playbooks', label: 'Playbooks', icon: BookOpen },
  { to: '/logs', label: 'Logs', icon: ScrollText },
]

function useOutsideClose(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) close() }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open, close])
  return ref
}

function RailLink({ to, label, icon: Icon, end, badge }: { to: string; label: string; icon: any; end?: boolean; badge?: number }) {
  return (
    <NavLink
      to={to}
      end={end}
      title={label}
      aria-label={label}
      className={({ isActive }) => clsx(
        'relative group flex items-center justify-center h-11 w-full text-white/80 hover:bg-rail-hover hover:text-white',
        isActive && 'bg-rail-active text-white',
      )}
    >
      <Icon className="w-[18px] h-[18px]" strokeWidth={2} />
      {!!badge && (
        <span className="absolute top-1.5 right-2 min-w-[16px] h-4 px-1 rounded-full bg-[#ffb648] text-[#703b15] text-[10px] font-bold flex items-center justify-center">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
      <span className="pointer-events-none absolute left-full ml-2 z-50 hidden group-hover:block whitespace-nowrap rounded bg-ink px-2 py-1 text-xs text-white shadow">
        {label}
      </span>
    </NavLink>
  )
}

export default function AppShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate()
  const location = useLocation()
  const { user, setUser, logout } = useAuthStore()
  const [search, setSearch] = useState('')
  const [addOpen, setAddOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)
  const [newIncident, setNewIncident] = useState(false)
  useLiveUpdates()
  const addRef = useOutsideClose(addOpen, () => setAddOpen(false))
  const userRef = useOutsideClose(userOpen, () => setUserOpen(false))

  // The signed-in user survives a page reload: tokens are stored, the profile is fetched.
  const me = useQuery({ queryKey: ['me'], queryFn: () => usersApi.me().then((r) => r.data), staleTime: 5 * 60_000 })
  useEffect(() => { if (me.data) setUser(me.data) }, [me.data, setUser])

  const overview = useQuery({
    queryKey: ['dashboard', 'overview'],
    queryFn: () => dashboardApi.overview().then((r) => r.data),
    refetchInterval: 60_000,
  })
  const pending = overview.data?.pending_actions || 0

  useEffect(() => {
    setSearch(location.pathname === '/incidents' ? new URLSearchParams(location.search).get('search') || '' : '')
  }, [location.pathname, location.search])

  return (
    <div className="h-screen flex overflow-hidden bg-white">
      {/* Icon rail */}
      <aside className="w-[52px] shrink-0 bg-rail flex flex-col items-center">
        <NavLink to="/" className="h-12 w-full flex items-center justify-center text-white" title="Cane AI" aria-label="Cane AI home">
          <Shield className="w-6 h-6" fill="currentColor" strokeWidth={0} />
        </NavLink>
        <nav className="w-full flex-1">
          {NAV.map((item) => (
            <RailLink key={item.to} {...item} badge={item.badge ? pending : undefined} />
          ))}
        </nav>
        <div className="w-full pb-2">
          <RailLink to="/settings" label="Settings" icon={Settings} />
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-12 shrink-0 border-b border-line flex items-center gap-3 px-3 bg-white">
          <div className="relative" ref={addRef}>
            <button className="btn text-ink hover:bg-surface-sunken px-2" onClick={() => setAddOpen((o) => !o)}>
              <Plus className="w-4 h-4" /> Add
            </button>
            {addOpen && (
              <div className="absolute left-0 top-9 z-40 w-48 bg-white border border-line rounded shadow-lg py-1 text-[13px]">
                <button className="w-full flex items-center gap-2 px-3 h-8 hover:bg-brand-50 text-left" onClick={() => { setAddOpen(false); setNewIncident(true) }}>
                  <Inbox className="w-4 h-4 text-ink-muted" /> Incident
                </button>
                <button className="w-full flex items-center gap-2 px-3 h-8 hover:bg-brand-50 text-left" onClick={() => { setAddOpen(false); navigate('/logs?upload=1') }}>
                  <Upload className="w-4 h-4 text-ink-muted" /> Log file
                </button>
              </div>
            )}
          </div>

          <div className="flex-1" />

          <form
            className="relative w-72"
            onSubmit={(e) => { e.preventDefault(); navigate(search.trim() ? `/incidents?view=open&search=${encodeURIComponent(search.trim())}` : '/incidents') }}
          >
            <Search className="w-4 h-4 absolute left-2.5 top-2 text-ink-faint" />
            <input className="input pl-8" placeholder="Search incidents" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search incidents" />
          </form>

          <button className="relative w-8 h-8 flex items-center justify-center rounded text-ink-muted hover:bg-surface-sunken" onClick={() => navigate('/actions')} title={`${pending} action${pending === 1 ? '' : 's'} awaiting approval`} aria-label="Actions awaiting approval">
            <Bell className="w-[18px] h-[18px]" />
            {pending > 0 && <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-severity-critical" />}
          </button>

          <div className="relative" ref={userRef}>
            <button className="flex items-center gap-1 rounded hover:bg-surface-sunken p-1" onClick={() => setUserOpen((o) => !o)} aria-label="Account menu">
              <Avatar name={user?.full_name || user?.email} size={28} />
              <ChevronDown className="w-3.5 h-3.5 text-ink-muted" />
            </button>
            {userOpen && (
              <div className="absolute right-0 top-10 z-40 w-60 bg-white border border-line rounded shadow-lg text-[13px]">
                <div className="px-3 py-3 border-b border-line">
                  <div className="font-semibold truncate">{user?.full_name || '—'}</div>
                  <div className="text-ink-muted truncate">{user?.email}</div>
                  {user?.role && <div className="tag mt-1.5">{ROLE_LABELS[user.role] || user.role}</div>}
                </div>
                <button className="w-full flex items-center gap-2 px-3 h-9 hover:bg-brand-50 text-left" onClick={() => { setUserOpen(false); navigate('/settings') }}>
                  <Settings className="w-4 h-4 text-ink-muted" /> Settings
                </button>
                <button className="w-full flex items-center gap-2 px-3 h-9 hover:bg-brand-50 text-left border-t border-line" onClick={logout}>
                  <LogOut className="w-4 h-4 text-ink-muted" /> Sign out
                </button>
              </div>
            )}
          </div>
        </header>

        <main className="flex-1 min-h-0 flex">{children}</main>
      </div>

      {newIncident && <NewIncidentModal onClose={() => setNewIncident(false)} />}
      <Toaster />
    </div>
  )
}
