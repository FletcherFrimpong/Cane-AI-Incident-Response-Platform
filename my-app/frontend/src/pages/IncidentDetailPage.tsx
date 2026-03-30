import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  RefreshCw, ArrowUpRight, XCircle, CheckCircle, Clock, Brain,
  AlertTriangle, Shield, MessageSquare, Loader2,
} from 'lucide-react'
import { incidentsApi } from '../api/incidents'
import { triageApi } from '../api/triage'
import { actionsApi } from '../api/actions'
import { SEVERITY_COLORS, STATUS_COLORS, ACTION_STATUS_COLORS, TIMELINE_COLORS } from '../utils/constants'
import { formatDate, formatRelative } from '../utils/formatters'
import type { Incident, TimelineEntry } from '../types/incident'

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const queryClient = useQueryClient()
  const [closeNote, setCloseNote] = useState('')
  const [showClose, setShowClose] = useState(false)
  const [noteText, setNoteText] = useState('')
  const [rejectReason, setRejectReason] = useState('')
  const [rejectingId, setRejectingId] = useState<string | null>(null)

  // Queries
  const { data: incident, isLoading } = useQuery({
    queryKey: ['incident', id],
    queryFn: () => incidentsApi.get(id!).then((r) => r.data as Incident),
    enabled: !!id,
  })

  const { data: timeline } = useQuery({
    queryKey: ['incident-timeline', id],
    queryFn: () => incidentsApi.getTimeline(id!).then((r) => r.data as TimelineEntry[]),
    enabled: !!id,
  })

  const { data: triageResults } = useQuery({
    queryKey: ['triage-results', id],
    queryFn: () => triageApi.getResults(id!).then((r) => r.data).catch(() => []),
    enabled: !!id,
  })

  const { data: actions } = useQuery({
    queryKey: ['incident-actions', id],
    queryFn: () => actionsApi.history({ incident_id: id }).then((r) => r.data).catch(() => []),
    enabled: !!id,
  })

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ['incident', id] })
    queryClient.invalidateQueries({ queryKey: ['incident-timeline', id] })
    queryClient.invalidateQueries({ queryKey: ['triage-results', id] })
    queryClient.invalidateQueries({ queryKey: ['incident-actions', id] })
  }

  // Mutations
  const triageMutation = useMutation({
    mutationFn: () => triageApi.analyze(id!),
    onSuccess: invalidateAll,
  })

  const escalateMutation = useMutation({
    mutationFn: () => incidentsApi.escalate(id!),
    onSuccess: invalidateAll,
  })

  const closeMutation = useMutation({
    mutationFn: (note: string) => incidentsApi.close(id!, note),
    onSuccess: () => { invalidateAll(); setShowClose(false); setCloseNote('') },
  })

  const noteMutation = useMutation({
    mutationFn: (content: string) => incidentsApi.addNote(id!, content),
    onSuccess: () => { invalidateAll(); setNoteText('') },
  })

  const approveMutation = useMutation({
    mutationFn: (actionId: string) => actionsApi.approve(actionId),
    onSuccess: invalidateAll,
  })

  const rejectMutation = useMutation({
    mutationFn: ({ actionId, reason }: { actionId: string; reason: string }) =>
      actionsApi.reject(actionId, reason),
    onSuccess: () => { invalidateAll(); setRejectingId(null); setRejectReason('') },
  })

  if (isLoading || !incident) {
    return <div className="text-gray-500">Loading incident...</div>
  }

  const latestTriage = triageResults?.[0]
  const analysis = latestTriage?.output
  const pendingActions = (actions || []).filter((a: any) => a.status === 'pending_approval')
  const completedActions = (actions || []).filter((a: any) => a.status !== 'pending_approval')
  const isClosed = incident.status === 'closed' || incident.status === 'false_positive'

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-2 flex-wrap">
          <span className={`badge ${SEVERITY_COLORS[incident.severity] || ''}`}>
            {incident.severity}
          </span>
          <span className={`badge ${STATUS_COLORS[incident.status] || ''}`}>
            {incident.status.replace(/_/g, ' ')}
          </span>
          {incident.attack_type && (
            <span className="badge bg-purple-100 text-purple-800">{incident.attack_type}</span>
          )}
          {incident.confidence_score != null && incident.confidence_score > 0 && (
            <span className="badge bg-brand-100 text-brand-800">
              {Math.round(incident.confidence_score * 100)}% confidence
            </span>
          )}
        </div>
        <h1 className="text-2xl font-bold">{incident.title}</h1>
        <p className="text-sm text-gray-500 mt-1">
          ID: {incident.id} &middot; Created: {formatDate(incident.created_at)}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main column */}
        <div className="lg:col-span-2 space-y-6">

          {/* AI Analysis Card */}
          {analysis && (
            <div className="card border-l-4 border-l-violet-400">
              <div className="flex items-center gap-2 mb-4">
                <Brain className="h-5 w-5 text-violet-600" />
                <h2 className="text-lg font-semibold">AI Analysis</h2>
                <span className="text-xs text-gray-500 ml-auto">
                  {latestTriage.provider} &middot; {latestTriage.model} &middot; {formatRelative(latestTriage.created_at)}
                </span>
              </div>

              {analysis.summary && (
                <p className="text-gray-700 mb-4">{analysis.summary}</p>
              )}

              {analysis.requires_human_review && (
                <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg mb-4 flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-amber-800">Human Review Required</p>
                    <p className="text-sm text-amber-700">{analysis.human_review_reason}</p>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                <div className="bg-gray-50 rounded-lg p-3">
                  <div className="text-xs text-gray-500">Severity</div>
                  <div className="font-semibold capitalize">{analysis.severity}</div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <div className="text-xs text-gray-500">Confidence</div>
                  <div className="font-semibold">{Math.round((analysis.confidence_score || 0) * 100)}%</div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <div className="text-xs text-gray-500">Kill Chain</div>
                  <div className="font-semibold text-sm capitalize">{analysis.kill_chain_phase || 'N/A'}</div>
                </div>
                <div className="bg-gray-50 rounded-lg p-3">
                  <div className="text-xs text-gray-500">Attack Type</div>
                  <div className="font-semibold text-sm capitalize">{analysis.attack_type || 'Unknown'}</div>
                </div>
              </div>

              {/* MITRE ATT&CK */}
              {(incident.mitre_tactics?.length > 0 || incident.mitre_techniques?.length > 0) && (
                <div className="mb-4">
                  <h3 className="text-sm font-medium text-gray-700 mb-2">MITRE ATT&CK</h3>
                  <div className="flex flex-wrap gap-1.5">
                    {incident.mitre_tactics?.map((t: string) => (
                      <span key={t} className="badge text-xs bg-purple-100 text-purple-800">{t}</span>
                    ))}
                    {incident.mitre_techniques?.map((t: string) => (
                      <span key={t} className="badge text-xs bg-indigo-100 text-indigo-800">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {/* IOCs */}
              {analysis.indicators_of_compromise && (
                <div>
                  <h3 className="text-sm font-medium text-gray-700 mb-2">Indicators of Compromise</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                    {Object.entries(analysis.indicators_of_compromise).map(([type, values]: [string, any]) =>
                      values?.length > 0 && (
                        <div key={type} className="bg-red-50 rounded-lg p-2">
                          <div className="text-xs font-medium text-red-700 uppercase mb-1">{type}</div>
                          {values.map((v: string) => (
                            <div key={v} className="font-mono text-xs text-red-900 truncate">{v}</div>
                          ))}
                        </div>
                      )
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Pending Actions */}
          {pendingActions.length > 0 && (
            <div className="card border-l-4 border-l-amber-400">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Clock className="h-5 w-5 text-amber-600" />
                Pending Actions ({pendingActions.length})
              </h2>
              <div className="space-y-3">
                {pendingActions.map((action: any) => (
                  <div key={action.id} className="p-3 bg-amber-50 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <span className="font-medium text-sm capitalize">
                          {action.action_type.replace(/_/g, ' ')}
                        </span>
                        {action.action_params && (
                          <span className="text-xs text-gray-500 ml-2">
                            {Object.entries(action.action_params).map(([k, v]) => `${k}: ${v}`).join(', ')}
                          </span>
                        )}
                      </div>
                      <span className="text-xs text-gray-500">{action.requested_by}</span>
                    </div>
                    {rejectingId === action.id ? (
                      <div className="flex gap-2 mt-2">
                        <input
                          className="input text-sm flex-1"
                          placeholder="Reason for rejection..."
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                        />
                        <button
                          className="btn-danger text-sm px-3"
                          disabled={!rejectReason || rejectMutation.isPending}
                          onClick={() => rejectMutation.mutate({ actionId: action.id, reason: rejectReason })}
                        >
                          Confirm
                        </button>
                        <button
                          className="btn-secondary text-sm px-3"
                          onClick={() => { setRejectingId(null); setRejectReason('') }}
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <div className="flex gap-2 mt-2">
                        <button
                          className="flex items-center gap-1 px-3 py-1.5 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 disabled:opacity-50"
                          disabled={approveMutation.isPending}
                          onClick={() => approveMutation.mutate(action.id)}
                        >
                          <CheckCircle className="h-3.5 w-3.5" />
                          Approve
                        </button>
                        <button
                          className="flex items-center gap-1 px-3 py-1.5 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700"
                          onClick={() => setRejectingId(action.id)}
                        >
                          <XCircle className="h-3.5 w-3.5" />
                          Reject
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions from AI (if no formal actions created yet) */}
          {analysis?.recommended_actions?.length > 0 && pendingActions.length === 0 && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-brand-600" />
                AI Recommended Actions
              </h2>
              <div className="space-y-2">
                {analysis.recommended_actions.map((rec: any, i: number) => (
                  <div key={i} className="p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-medium text-sm capitalize">
                          {rec.action?.replace(/_/g, ' ')}
                        </span>
                        <span className="text-xs text-gray-500 ml-2">Target: {rec.target}</span>
                      </div>
                      <span className={`badge text-xs ${
                        rec.priority === 'immediate' ? 'bg-red-100 text-red-800' :
                        rec.priority === 'high' ? 'bg-orange-100 text-orange-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {rec.priority}
                      </span>
                    </div>
                    {rec.reason && (
                      <p className="text-xs text-gray-600 mt-1">{rec.reason}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Action History */}
          {completedActions.length > 0 && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Action History</h2>
              <div className="space-y-2">
                {completedActions.map((action: any) => (
                  <div key={action.id} className="flex items-center justify-between p-2 bg-gray-50 rounded-lg text-sm">
                    <div>
                      <span className="font-medium capitalize">{action.action_type.replace(/_/g, ' ')}</span>
                      <span className="text-xs text-gray-500 ml-2">{action.requested_by}</span>
                    </div>
                    <span className={`badge text-xs ${ACTION_STATUS_COLORS[action.status] || ''}`}>
                      {action.status.replace(/_/g, ' ')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Description */}
          {incident.description && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-3">Description</h2>
              <p className="text-gray-700 whitespace-pre-wrap">{incident.description}</p>
            </div>
          )}

          {/* Timeline */}
          <div className="card">
            <h2 className="text-lg font-semibold mb-4">Timeline</h2>
            {timeline && timeline.length > 0 ? (
              <div className="space-y-3">
                {[...timeline].reverse().map((entry) => (
                  <div
                    key={entry.id}
                    className={`border-l-2 pl-4 py-1 ${TIMELINE_COLORS[entry.event_type] || 'border-l-gray-200'}`}
                  >
                    <p className="text-sm">{entry.description}</p>
                    <p className="text-xs text-gray-500">
                      {entry.actor} &middot; {formatRelative(entry.timestamp)}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No timeline entries yet.</p>
            )}

            {/* Add note */}
            <div className="mt-4 pt-4 border-t flex gap-2">
              <input
                className="input flex-1 text-sm"
                placeholder="Add analyst note..."
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && noteText && noteMutation.mutate(noteText)}
              />
              <button
                className="btn-secondary text-sm flex items-center gap-1"
                disabled={!noteText || noteMutation.isPending}
                onClick={() => noteMutation.mutate(noteText)}
              >
                <MessageSquare className="h-3.5 w-3.5" />
                Add
              </button>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Details */}
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
                  {incident.confidence_score != null
                    ? `${Math.round(incident.confidence_score * 100)}%`
                    : 'N/A'}
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Status</dt>
                <dd>
                  <span className={`badge text-xs ${STATUS_COLORS[incident.status] || ''}`}>
                    {incident.status.replace(/_/g, ' ')}
                  </span>
                </dd>
              </div>
              <div>
                <dt className="text-gray-500">Assigned To</dt>
                <dd className="font-medium">{incident.assigned_to || 'Unassigned'}</dd>
              </div>
              {incident.correlation_id && (
                <div>
                  <dt className="text-gray-500">Correlation ID</dt>
                  <dd className="font-mono text-xs truncate">{incident.correlation_id}</dd>
                </div>
              )}
              {incident.source_entities && (
                <>
                  {incident.source_entities.ips?.length > 0 && (
                    <div>
                      <dt className="text-gray-500">Source IPs</dt>
                      <dd className="font-mono text-xs space-y-0.5">
                        {incident.source_entities.ips.slice(0, 5).map((ip: string) => (
                          <div key={ip}>{ip}</div>
                        ))}
                        {incident.source_entities.ips.length > 5 && (
                          <div className="text-gray-400">+{incident.source_entities.ips.length - 5} more</div>
                        )}
                      </dd>
                    </div>
                  )}
                </>
              )}
              <div>
                <dt className="text-gray-500">Last Updated</dt>
                <dd className="font-medium">{formatDate(incident.updated_at)}</dd>
              </div>
            </dl>
          </div>

          {/* Actions */}
          <div className="card space-y-2">
            <h2 className="text-lg font-semibold mb-3">Actions</h2>
            <button
              className="btn-primary w-full flex items-center justify-center gap-2"
              disabled={triageMutation.isPending}
              onClick={() => triageMutation.mutate()}
            >
              {triageMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
              {triageMutation.isPending ? 'Analyzing...' : 'Re-run AI Triage'}
            </button>
            {triageMutation.isError && (
              <p className="text-xs text-red-600">
                {(triageMutation.error as any)?.response?.data?.detail || 'Triage failed. Check API key in Settings.'}
              </p>
            )}
            <button
              className="btn-secondary w-full flex items-center justify-center gap-2"
              disabled={isClosed || escalateMutation.isPending}
              onClick={() => escalateMutation.mutate()}
            >
              <ArrowUpRight className="h-4 w-4" />
              Escalate
            </button>

            {!showClose ? (
              <button
                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 disabled:opacity-50"
                disabled={isClosed}
                onClick={() => setShowClose(true)}
              >
                <XCircle className="h-4 w-4" />
                Close Incident
              </button>
            ) : (
              <div className="space-y-2 p-3 bg-red-50 rounded-lg">
                <input
                  className="input text-sm"
                  placeholder="Closing notes..."
                  value={closeNote}
                  onChange={(e) => setCloseNote(e.target.value)}
                />
                <div className="flex gap-2">
                  <button
                    className="btn-danger text-sm flex-1"
                    disabled={!closeNote || closeMutation.isPending}
                    onClick={() => closeMutation.mutate(closeNote)}
                  >
                    Confirm Close
                  </button>
                  <button
                    className="btn-secondary text-sm"
                    onClick={() => setShowClose(false)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Playbook */}
          {incident.playbook_id && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-3">Playbook</h2>
              <p className="text-sm text-gray-700">
                Playbook attached &middot; Step {(incident.current_playbook_step || 0) + 1}
              </p>
              <p className="text-xs text-gray-500 mt-1 font-mono truncate">
                {incident.playbook_id}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
