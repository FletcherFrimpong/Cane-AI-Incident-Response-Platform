import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '../../store/authStore'
import {
  LayoutDashboard,
  AlertTriangle,
  Brain,
  BookOpen,
  ScrollText,
  Settings,
  LogOut,
  Shield,
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Incidents', href: '/incidents', icon: AlertTriangle },
  { name: 'AI Triage', href: '/triage', icon: Brain },
  { name: 'Playbooks', href: '/playbooks', icon: BookOpen },
  { name: 'Logs', href: '/logs', icon: ScrollText },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export default function AppShell({ children }: { children: ReactNode }) {
  const location = useLocation()
  const logout = useAuthStore((s) => s.logout)
  const user = useAuthStore((s) => s.user)

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-64 bg-brand-950 text-white flex flex-col">
        <div className="flex items-center gap-2 px-6 py-5 border-b border-brand-800">
          <Shield className="h-8 w-8 text-brand-400" />
          <span className="text-xl font-bold">Cane AI</span>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {navigation.map((item) => {
            const isActive =
              item.href === '/'
                ? location.pathname === '/'
                : location.pathname.startsWith(item.href)
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-brand-800 text-white'
                    : 'text-brand-200 hover:bg-brand-900 hover:text-white'
                }`}
              >
                <item.icon className="h-5 w-5" />
                {item.name}
              </Link>
            )
          })}
        </nav>

        <div className="px-3 py-4 border-t border-brand-800">
          <div className="px-3 py-2 text-sm text-brand-300 truncate">
            {user?.email || 'User'}
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-brand-200 hover:bg-brand-900 hover:text-white transition-colors w-full"
          >
            <LogOut className="h-5 w-5" />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">{children}</div>
      </main>
    </div>
  )
}
