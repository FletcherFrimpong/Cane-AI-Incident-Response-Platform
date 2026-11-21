import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, ListChecks, RefreshCw, X } from 'lucide-react'
import { actionsApi } from '../api/actions'
import { useAuthStore } from '../store/authStore'
import { ActionPill, EmptyState, ErrorNote, Loading, Modal, Severity, ViewsSidebar, notify } from '../components/ui'
import { ACTION_LABELS, ACTION_PARAM_KEYS, hasRole } from '../utils/constants'
import { errorMessage, formatQueueTime, shortId } from '../utils/formatters'

const VIEWS = [
  { key: 'pending_approval', label: 'Awaiting approval' },
  { key: 'completed', label: 'Completed' },
  { key: 'failed', label: 'Failed' },
  { key: 'rejected', label: 'Rejected' },
  { key: 'all', label: 'All actions' },
]
const TITLES: Record<string, string> = {
  pending_approval: 'Actions awaiting approval', completed: 'Completed actions', failed: 'Failed actions', rejected: 'Rejected actions', all: 'All actions',
}
const targetOf = (a: any) => String(a.action_params?.[ACTION_PARAM_KEYS[a.action_type]] ?? Object.values(a.action_params || {})[0] ?? '')

export default function ActionsQueuePage() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const canAct = hasRole(useAuthStore((s) => s.user)?.role, 'tier2_analyst')
  const [view, setView] = useState('pending_approval')
  const [rejecting, setRejecting] = useState<any | null>(null)
  const [reason, setReason] = useState('')

  const history = useQuery({ queryKey: ['actions', 'history'], queryFn: () => actionsApi.history({ page_size: 200 }).then((r) => r.data as any[]), refetchInterval: 60_000 })
  const all = history.data || []
  const rows = view === 'all' ? all : all.filter((a) => a.status === view)
  const count = (key: string) => (key === 'all' ? all.length : all.filter((a) => a.status === key).length)

  const refresh = () => { qc.invalidateQueries({ queryKey: ['actions'] }); qc.invalidateQueries({ queryKey: ['dashboard'] }); qc.invalidateQueries({ queryKey: ['incident'] }) }
  const approve = useMutation({
    mutationFn: (id: string) => actionsApi.approve(id),
    onSuccess: (res) => {
      refresh()
      res.data.status === 'completed'
        ? notify.success(res.data.result?.dry_run ? 'Action simulated (dry run)' : 'Action executed')
        : notify.error('Action failed', res.data.error_message)
    },
    onError: (e) => notify.error('Could not approve the action', errorMessage(e)),
  })
  const reject = useMutation({
    mutationFn: () => actionsApi.reject(rejecting.id, reason.trim()),
    onSuccess: () => { refresh(); setRejecting(null); setReason('') },
    onError: (e) => notify.error('Could not reject the action', errorMessage(e)),
  })

  return (
    <div className="flex-1 flex min-w-0">
      <ViewsSidebar
        title="Action queue"
        active={view}
        onSelect={setView}
        sections={[{ items: VIEWS.slice(0, 1).map((v) => ({ ...v, count: count(v.key) })) }, { items: VIEWS.slice(1).map((v) => ({ ...v, count: count(v.key), muted: true })) }]}
        footer={<>Containment actions the AI proposes wait here until a tier 2 analyst or above approves them.</>}
      />
      <section className="flex-1 min-w-0 flex flex-col">
        <div className="px-5 pt-5 pb-3 shrink-0 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold">{TITLES[view]}</h1>
            <div className="text-[13px] text-ink-muted mt-1">{rows.length} action{rows.length === 1 ? '' : 's'}</div>
          </div>
          <button className="btn-basic px-2" onClick={() => history.refetch()} title="Refresh" aria-label="Refresh"><RefreshCw className={`w-4 h-4 ${history.isFetching ? 'animate-spin' : ''}`} /></button>
        </div>
        <div className="flex-1 min-h-0 overflow-auto border-t border-line">
          {history.isLoading ? <Loading />
            : history.isError ? <div className="p-5"><ErrorNote>Could not load actions.</ErrorNote></div>
            : rows.length === 0
              ? <EmptyState icon={<ListChecks className="w-8 h-8" />} title={view === 'pending_approval' ? 'Nothing is waiting for approval' : 'No actions here'}>
                  {view === 'pending_approval' ? 'When AI triage recommends a containment action that needs a person, it appears here.' : 'Actions in this state will be listed here.'}
                </EmptyState>
              : (
                <table className="table-queue min-w-[1080px]">
                  <thead>
                    <tr>
                      <th className="w-24">Status</th>
                      <th className="w-48">Action</th>
                      <th className="w-[22%]">Target</th>
                      <th>Incident</th>
                      <th className="w-28">Severity</th>
                      <th className="w-32">Requested by</th>
                      <th className="w-36">Requested</th>
                      <th className="w-44" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((a) => (
                      <tr key={a.id} className="row" onClick={() => navigate(`/incidents/${a.incident_id}`)}>
                        <td><ActionPill status={a.status} /></td>
                        <td className="font-medium whitespace-nowrap">{ACTION_LABELS[a.action_type] || a.action_type}</td>
                        <td className="max-w-0"><div className="truncate font-mono text-xs" title={targetOf(a)}>{targetOf(a)}</div></td>
                        <td className="max-w-0">
                          <div className="truncate" title={a.incident_title || ''}><span className="text-ink-muted">{shortId(a.incident_id)}</span> {a.incident_title}</div>
                          {a.error_message && <div className="truncate text-xs text-[#8c232c]" title={a.error_message}>{a.error_message}</div>}
                        </td>
                        <td>{a.incident_severity ? <Severity value={a.incident_severity} /> : '-'}</td>
                        <td className="text-ink-soft truncate">{a.source === 'ai_recommended' && a.requested_by === 'system' ? 'Cane AI' : a.requested_by.split('@')[0]}</td>
                        <td className="text-ink-soft whitespace-nowrap">{formatQueueTime(a.created_at)}</td>
                        <td className="text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          {a.status === 'pending_approval' && canAct && (
                            <>
                              <button className="btn-primary btn-sm mr-1.5" disabled={approve.isPending} onClick={() => approve.mutate(a.id)}><Check className="w-3.5 h-3.5" /> Approve</button>
                              <button className="btn-basic btn-sm" onClick={() => setRejecting(a)}><X className="w-3.5 h-3.5" /> Reject</button>
                            </>
                          )}
                          {a.status === 'completed' && a.result?.dry_run && <span className="tag">Dry run</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
        </div>
      </section>

      {rejecting && (
        <Modal
          title="Reject action"
          onClose={() => setRejecting(null)}
          footer={<>
            <button className="btn-basic" onClick={() => setRejecting(null)}>Cancel</button>
            <button className="btn-danger" disabled={!reason.trim() || reject.isPending} onClick={() => reject.mutate()}>Reject action</button>
          </>}
        >
          <div className="text-[13px] mb-3"><span className="font-semibold">{ACTION_LABELS[rejecting.action_type] || rejecting.action_type}</span> on <span className="font-mono text-xs">{targetOf(rejecting)}</span> will not run.</div>
          <label className="label">Reason</label>
          <textarea className="input" rows={3} autoFocus value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded on the incident timeline" />
        </Modal>
      )}
    </div>
  )
}
