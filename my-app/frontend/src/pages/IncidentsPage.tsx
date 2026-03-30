import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, Search } from 'lucide-react'
import { incidentsApi } from '../api/incidents'
import { SEVERITY_COLORS, STATUS_COLORS } from '../utils/constants'
import { formatRelative } from '../utils/formatters'
import type { Incident } from '../types/incident'

export default function IncidentsPage() {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['incidents', severityFilter, statusFilter],
    queryFn: () =>
      incidentsApi
        .list({
          severity: severityFilter || undefined,
          status: statusFilter || undefined,
        })
        .then((r) => r.data),
  })

  const incidents: Incident[] = data || []
  const filtered = incidents.filter(
    (i) =>
      !search ||
      i.title.toLowerCase().includes(search.toLowerCase()) ||
      i.id.includes(search),
  )

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Incidents</h1>
        <button className="btn-primary flex items-center gap-2">
          <Plus className="h-4 w-4" />
          New Incident
        </button>
      </div>

      <div className="card mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search incidents..."
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
          <select
            className="input w-auto"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="triaging">Triaging</option>
            <option value="in_progress">In Progress</option>
            <option value="containment">Containment</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading incidents...</div>
      ) : filtered.length === 0 ? (
        <div className="card text-center py-12 text-gray-500">
          No incidents found.
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((incident) => (
            <Link
              key={incident.id}
              to={`/incidents/${incident.id}`}
              className="card block hover:shadow-md transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span
                      className={`badge ${SEVERITY_COLORS[incident.severity] || ''}`}
                    >
                      {incident.severity}
                    </span>
                    <span
                      className={`badge ${STATUS_COLORS[incident.status] || ''}`}
                    >
                      {incident.status.replace('_', ' ')}
                    </span>
                    <h3 className="font-medium">{incident.title}</h3>
                  </div>
                  <p className="text-sm text-gray-500">
                    {incident.id.slice(0, 8)} &middot;{' '}
                    {formatRelative(incident.created_at)}
                    {incident.attack_type && ` · ${incident.attack_type}`}
                  </p>
                </div>
                {incident.confidence_score !== null && (
                  <div className="text-right">
                    <div className="text-sm text-gray-500">Confidence</div>
                    <div className="font-semibold">
                      {Math.round(incident.confidence_score * 100)}%
                    </div>
                  </div>
                )}
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
