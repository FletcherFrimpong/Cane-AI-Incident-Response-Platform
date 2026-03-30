import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { incidentsApi } from '../api/incidents'
import { SEVERITY_COLORS, STATUS_COLORS } from '../utils/constants'
import { formatDate } from '../utils/formatters'
import type { Incident, TimelineEntry } from '../types/incident'

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()

  const { data: incident, isLoading } = useQuery({
    queryKey: ['incident', id],
    queryFn: () => incidentsApi.get(id!).then((r) => r.data as Incident),
    enabled: !!id,
  })

  const { data: timeline } = useQuery({
    queryKey: ['incident-timeline', id],
    queryFn: () =>
      incidentsApi.getTimeline(id!).then((r) => r.data as TimelineEntry[]),
    enabled: !!id,
  })

  if (isLoading || !incident) {
    return <div className="text-gray-500">Loading incident...</div>
  }

  return (
    <div>
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <span className={`badge ${SEVERITY_COLORS[incident.severity] || ''}`}>
            {incident.severity}
          </span>
          <span className={`badge ${STATUS_COLORS[incident.status] || ''}`}>
            {incident.status.replace('_', ' ')}
          </span>
        </div>
        <h1 className="text-2xl font-bold">{incident.title}</h1>
        <p className="text-sm text-gray-500 mt-1">
          ID: {incident.id} &middot; Created: {formatDate(incident.created_at)}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main content */}
        <div className="lg:col-span-2 space-y-6">
          <div className="card">
            <h2 className="text-lg font-semibold mb-3">Description</h2>
            <p className="text-gray-700 whitespace-pre-wrap">
              {incident.description || 'No description provided.'}
            </p>
          </div>

          {incident.mitre_tactics && incident.mitre_tactics.length > 0 && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-3">MITRE ATT&CK</h2>
              <div className="flex flex-wrap gap-2">
                {incident.mitre_tactics.map((t) => (
                  <span key={t} className="badge bg-purple-100 text-purple-800">
                    {t}
                  </span>
                ))}
                {incident.mitre_techniques?.map((t) => (
                  <span key={t} className="badge bg-indigo-100 text-indigo-800">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="card">
            <h2 className="text-lg font-semibold mb-3">Timeline</h2>
            {timeline && timeline.length > 0 ? (
              <div className="space-y-4">
                {timeline.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex gap-3 border-l-2 border-gray-200 pl-4"
                  >
                    <div className="flex-1">
                      <p className="text-sm font-medium">{entry.description}</p>
                      <p className="text-xs text-gray-500">
                        {entry.actor} &middot; {formatDate(entry.timestamp)}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No timeline entries yet.</p>
            )}
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <div className="card">
            <h2 className="text-lg font-semibold mb-3">Details</h2>
            <dl className="space-y-3 text-sm">
              <div>
                <dt className="text-gray-500">Attack Type</dt>
                <dd className="font-medium">{incident.attack_type || 'Unknown'}</dd>
              </div>
              <div>
                <dt className="text-gray-500">Confidence</dt>
                <dd className="font-medium">
                  {incident.confidence_score !== null
                    ? `${Math.round(incident.confidence_score * 100)}%`
                    : 'N/A'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Assigned To</dt>
                <dd className="font-medium">
                  {incident.assigned_to || 'Unassigned'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Last Updated</dt>
                <dd className="font-medium">
                  {formatDate(incident.updated_at)}
                </dd>
              </div>
            </dl>
          </div>

          <div className="card space-y-2">
            <h2 className="text-lg font-semibold mb-3">Actions</h2>
            <button className="btn-primary w-full">Run AI Triage</button>
            <button className="btn-secondary w-full">Assign</button>
            <button className="btn-secondary w-full">Escalate</button>
            <button className="btn-danger w-full">Close Incident</button>
          </div>
        </div>
      </div>
    </div>
  )
}
