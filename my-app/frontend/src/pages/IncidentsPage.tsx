import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Search, Bell } from 'lucide-react'
import { incidentsApi } from '../api/incidents'
import { SEVERITY_COLORS, STATUS_COLORS, SEVERITY_BORDER } from '../utils/constants'
import { formatRelative } from '../utils/formatters'
import type { Incident } from '../types/incident'

const QUEUE_FILTERS = [
  { label: 'Needs Attention', status: 'awaiting_analyst' },
  { label: 'New', status: 'new' },
  { label: 'In Progress', status: 'in_progress' },
  { label: 'All Open', status: '' },
  { label: 'Closed', status: 'closed' },
]

export default function IncidentsPage() {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['incidents', severityFilter, statusFilter],
    queryFn: () =>
      incidentsApi
        .list({
          severity: severityFilter || undefined,
          status: statusFilter || undefined,
          page_size: 100,
        })
        .then((r) => r.data),
  })

  const incidents: Incident[] = data?.items || []
  const total = data?.total || 0
  const filtered = incidents.filter(
    (i) =>
      !search ||
      i.title.toLowerCase().includes(search.toLowerCase()) ||
      i.id.includes(search) ||
      i.attack_type?.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Incidents</h1>
          <p className="text-sm text-gray-500 mt-1">{total} total incidents</p>
        </div>
      </div>

      {/* Queue filters */}
      <div className="flex gap-2 mb-4">
        {QUEUE_FILTERS.map((f) => (
          <button
            key={f.label}
            onClick={() => setStatusFilter(f.status)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              statusFilter === f.status
                ? 'bg-brand-600 text-white'
                : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="card mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search by title, ID, or attack type..."
              className="input pl-9"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            className="input w-auto"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading incidents...</div>
      ) : isError ? (
        <div className="card text-center py-12 text-red-600">
          Failed to load incidents. Please try again.
        </div>
      ) : filtered.length === 0 ? (
        <div className="card text-center py-12 text-gray-500">
          No incidents found.
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((incident) => (
            <Link
              key={incident.id}
              to={`/incidents/${incident.id}`}
              className={`card block hover:shadow-md transition-shadow border-l-4 ${SEVERITY_BORDER[incident.severity] || 'border-l-gray-300'}`}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`badge text-xs ${SEVERITY_COLORS[incident.severity] || ''}`}>
                      {incident.severity}
                    </span>
                    <span className={`badge text-xs ${STATUS_COLORS[incident.status] || ''}`}>
                      {incident.status.replace(/_/g, ' ')}
                    </span>
                    {incident.status === 'awaiting_analyst' && (
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-amber-700">
                        <Bell className="h-3 w-3" />
                        Action Required
                      </span>
                    )}
                    {incident.attack_type && (
                      <span className="badge text-xs bg-purple-50 text-purple-700">
                        {incident.attack_type}
                      </span>
                    )}
                  </div>
                  <h3 className="font-medium truncate">{incident.title}</h3>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {incident.id.slice(0, 8)} &middot; {formatRelative(incident.created_at)}
                  </p>
                </div>
                <div className="flex items-center gap-4 ml-4 shrink-0">
                  {incident.confidence_score != null && incident.confidence_score > 0 && (
                    <div className="text-right">
                      <div className="text-xs text-gray-500">Confidence</div>
                      <div className="font-semibold text-sm">
                        {Math.round(incident.confidence_score * 100)}%
                      </div>
                    </div>
                  )}
                  {incident.mitre_tactics && incident.mitre_tactics.length > 0 && (
                    <div className="text-right hidden md:block">
                      <div className="text-xs text-gray-500">MITRE</div>
                      <div className="text-xs font-medium text-purple-700">
                        {incident.mitre_tactics.length} tactic{incident.mitre_tactics.length > 1 ? 's' : ''}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
