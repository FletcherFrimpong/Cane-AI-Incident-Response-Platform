import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { CheckCircle, XCircle, Clock, ListChecks } from 'lucide-react'
import { actionsApi } from '../api/actions'
import { ACTION_STATUS_COLORS } from '../utils/constants'
import { formatRelative } from '../utils/formatters'

export default function ActionsQueuePage() {
  const queryClient = useQueryClient()
  const [rejectingId, setRejectingId] = useState<string | null>(null)
  const [rejectReason, setRejectReason] = useState('')
  const [tab, setTab] = useState<'pending' | 'history'>('pending')

  const { data: pending, isLoading: pendingLoading } = useQuery({
    queryKey: ['actions-pending'],
    queryFn: () => actionsApi.pending().then((r) => r.data),
    refetchInterval: 10000,
  })

  const { data: history, isLoading: historyLoading } = useQuery({
    queryKey: ['actions-history'],
    queryFn: () => actionsApi.history({ page_size: 50 }).then((r) => r.data),
    enabled: tab === 'history',
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['actions-pending'] })
    queryClient.invalidateQueries({ queryKey: ['actions-history'] })
  }

  const approveMutation = useMutation({
    mutationFn: (actionId: string) => actionsApi.approve(actionId),
    onSuccess: invalidate,
  })

  const rejectMutation = useMutation({
    mutationFn: ({ actionId, reason }: { actionId: string; reason: string }) =>
      actionsApi.reject(actionId, reason),
    onSuccess: () => { invalidate(); setRejectingId(null); setRejectReason('') },
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Action Queue</h1>
          <p className="text-sm text-gray-500 mt-1">
            {pending?.length || 0} actions awaiting approval
          </p>
        </div>
      </div>

      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setTab('pending')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === 'pending' ? 'bg-brand-600 text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
          }`}
        >
          <span className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Pending ({pending?.length || 0})
          </span>
        </button>
        <button
          onClick={() => setTab('history')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            tab === 'history' ? 'bg-brand-600 text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
          }`}
        >
          <span className="flex items-center gap-2">
            <ListChecks className="h-4 w-4" />
            History
          </span>
        </button>
      </div>

      {tab === 'pending' && (
        pendingLoading ? (
          <div className="text-gray-500">Loading...</div>
        ) : !pending || pending.length === 0 ? (
          <div className="card text-center py-12">
            <CheckCircle className="h-12 w-12 text-green-300 mx-auto mb-3" />
            <h3 className="text-lg font-medium text-gray-900 mb-1">All clear</h3>
            <p className="text-gray-500 text-sm">No actions awaiting approval.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {pending.map((action: any) => (
              <div key={action.id} className="card border-l-4 border-l-amber-400">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <span className="font-semibold capitalize">
                      {action.action_type.replace(/_/g, ' ')}
                    </span>
                    {action.action_params && (
                      <span className="text-sm text-gray-500 ml-2">
                        {Object.entries(action.action_params).map(([k, v]) => `${k}: ${v}`).join(', ')}
                      </span>
                    )}
                  </div>
                  <div className="text-right text-sm text-gray-500">
                    <div>{action.requested_by}</div>
                    <div>{formatRelative(action.created_at)}</div>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <Link
                    to={`/incidents/${action.incident_id}`}
                    className="text-sm text-brand-600 hover:text-brand-800 font-medium"
                  >
                    View Incident &rarr;
                  </Link>
                  {rejectingId === action.id ? (
                    <div className="flex gap-2">
                      <input
                        className="input text-sm w-48"
                        placeholder="Reason..."
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
                    <div className="flex gap-2">
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
              </div>
            ))}
          </div>
        )
      )}

      {tab === 'history' && (
        historyLoading ? (
          <div className="text-gray-500">Loading...</div>
        ) : !history || history.length === 0 ? (
          <div className="card text-center py-12 text-gray-500">No action history yet.</div>
        ) : (
          <div className="card overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-gray-500">
                  <th className="pb-3 pr-4">Action</th>
                  <th className="pb-3 pr-4">Status</th>
                  <th className="pb-3 pr-4">Requested By</th>
                  <th className="pb-3 pr-4">Time</th>
                  <th className="pb-3">Incident</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {history.map((action: any) => (
                  <tr key={action.id} className="hover:bg-gray-50">
                    <td className="py-2 pr-4 font-medium capitalize">
                      {action.action_type.replace(/_/g, ' ')}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`badge text-xs ${ACTION_STATUS_COLORS[action.status] || ''}`}>
                        {action.status.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="py-2 pr-4">{action.requested_by}</td>
                    <td className="py-2 pr-4 whitespace-nowrap">{formatRelative(action.created_at)}</td>
                    <td className="py-2">
                      <Link
                        to={`/incidents/${action.incident_id}`}
                        className="text-brand-600 hover:text-brand-800"
                      >
                        {action.incident_id.slice(0, 8)}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  )
}
