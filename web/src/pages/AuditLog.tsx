import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ScrollText, Search, Loader2, AlertCircle } from 'lucide-react'
import { listAuditEvents } from '../api/client'
import { EmptyState } from '../components/EmptyState'
import { Badge } from '../components/Badge'

const ACTION_COLORS: Record<string, 'success' | 'danger' | 'warn' | 'accent' | 'muted'> = {
  read: 'success',
  write: 'accent',
  delete: 'danger',
  login: 'warn',
  logout: 'muted',
}

function actionBadgeVariant(action: string): 'success' | 'danger' | 'warn' | 'accent' | 'muted' | 'default' {
  const lower = action.toLowerCase()
  for (const [key, val] of Object.entries(ACTION_COLORS)) {
    if (lower.includes(key)) return val
  }
  return 'default'
}

export default function AuditLog() {
  const [search, setSearch] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')

  const { data, isLoading, error } = useQuery({
    queryKey: ['audit'],
    queryFn: listAuditEvents,
    retry: false,
  })

  const events = (data?.events ?? []).filter((e) => {
    if (search) {
      const q = search.toLowerCase()
      if (
        !e.action.toLowerCase().includes(q) &&
        !e.actor.toLowerCase().includes(q) &&
        !e.resource.toLowerCase().includes(q)
      ) {
        return false
      }
    }
    if (startDate && new Date(e.timestamp) < new Date(startDate)) return false
    if (endDate && new Date(e.timestamp) > new Date(endDate)) return false
    return true
  })

  return (
    <div>
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <h2 className="text-sm font-semibold text-txt">Audit Log</h2>
        <Badge variant="muted">{events.length} events</Badge>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 px-6 py-3 border-b border-border bg-surface">
        <div className="relative flex-1 max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by action, actor, resource…"
            className="w-full bg-bg border border-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-txt placeholder:text-muted focus:outline-none focus:border-accent"
          />
        </div>
        <div className="flex items-center gap-2 text-xs text-muted">
          <span>From</span>
          <input
            type="date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="bg-bg border border-border rounded-lg px-2 py-1.5 text-xs text-txt focus:outline-none focus:border-accent"
          />
          <span>to</span>
          <input
            type="date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="bg-bg border border-border rounded-lg px-2 py-1.5 text-xs text-txt focus:outline-none focus:border-accent"
          />
        </div>
        {(search || startDate || endDate) && (
          <button
            onClick={() => { setSearch(''); setStartDate(''); setEndDate('') }}
            className="text-xs text-muted hover:text-txt"
          >
            Clear
          </button>
        )}
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center gap-2 text-muted text-sm p-8">
          <Loader2 size={16} className="animate-spin" />
          Loading audit events…
        </div>
      ) : error ? (
        <div className="px-6 py-8">
          <div className="flex items-start gap-3 bg-surface border border-border rounded-xl p-5">
            <AlertCircle size={16} className="text-muted flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-txt">No audit events yet</p>
              <p className="text-xs text-muted mt-1">
                Audit logging activates after authentication is configured. Once enabled, all secret
                reads, writes, deletes, and login events will appear here with actor, IP address, and
                resource details.
              </p>
            </div>
          </div>
        </div>
      ) : events.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No audit events"
          description="Audit logging activates after authentication is configured."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td className="text-xs font-mono text-muted whitespace-nowrap">
                    {new Date(event.timestamp).toLocaleString()}
                  </td>
                  <td className="text-xs font-mono">
                    {event.actor}
                  </td>
                  <td>
                    <Badge variant={actionBadgeVariant(event.action)}>
                      {event.action}
                    </Badge>
                  </td>
                  <td className="text-xs font-mono text-muted max-w-xs truncate">
                    {event.resource}
                  </td>
                  <td className="text-xs font-mono text-muted">
                    {event.ip}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
