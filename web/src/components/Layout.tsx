import { useState } from 'react'
import { Outlet, useLocation, useNavigate, Link } from 'react-router-dom'
import { ChevronRight, LogOut } from 'lucide-react'
import { Sidebar } from './Sidebar'
import { useQueryClient } from '@tanstack/react-query'
import { cookieLogout } from '../api/client'

function Breadcrumb() {
  const location = useLocation()
  const parts = location.pathname.split('/').filter(Boolean)

  const crumbs = parts.map((part, i) => ({
    label: decodeURIComponent(part),
    to: '/' + parts.slice(0, i + 1).join('/'),
  }))

  return (
    <nav className="flex items-center gap-1 text-sm text-muted">
      {crumbs.map((crumb, i) => (
        <span key={crumb.to} className="flex items-center gap-1">
          {i > 0 && <ChevronRight size={12} className="text-border" />}
          {i === crumbs.length - 1 ? (
            <span className="text-txt font-medium capitalize">{crumb.label}</span>
          ) : (
            <Link
              to={crumb.to}
              className="hover:text-txt capitalize transition-colors"
            >
              {crumb.label}
            </Link>
          )}
        </span>
      ))}
    </nav>
  )
}

export default function Layout() {
  const [sidebarExpanded, setSidebarExpanded] = useState(true)
  const navigate = useNavigate()
  const qc = useQueryClient()

  const handleLogout = () => {
    void cookieLogout()
    qc.clear()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <div
        onMouseEnter={() => setSidebarExpanded(true)}
        onMouseLeave={() => setSidebarExpanded(false)}
        className="flex-shrink-0"
        style={{ width: sidebarExpanded ? 224 : 64, transition: 'width 200ms ease' }}
      >
        <Sidebar expanded={sidebarExpanded} />
      </div>

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between px-6 py-3 border-b border-border bg-surface flex-shrink-0 h-12">
          <Breadcrumb />
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 text-xs text-muted hover:text-danger transition-colors"
            title="Logout"
          >
            <LogOut size={14} />
            <span>Logout</span>
          </button>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto bg-bg">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
