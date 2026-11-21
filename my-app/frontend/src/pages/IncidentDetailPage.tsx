import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { ArrowLeft, Bot, Check, ChevronDown, ExternalLink, Radar, Sparkles, X, AlertTriangle, ShieldCheck } from 'lucide-react'
import { incidentsApi } from '../api/incidents'
import { triageApi } from '../api/triage'
import { actionsApi } from '../api/actions'
import { playbooksApi } from '../api/playbooks'
import { useAuthStore } from '../store/authStore'
import { useAssignableUsers } from '../hooks'
import { ActionPill, Avatar, ErrorNote, Loading, Modal, Severity, Spinner, StatusPill, notify } from '../components/ui'
import {
  ACTION_LABELS, ACTION_PARAM_KEYS, PHASE_LABELS, SEVERITIES, SEVERITY_META, STATUS_OPTIONS, STEP_TYPE_LABELS, VERDICT_META, hasRole,
} from '../utils/constants'
import { errorMessage, formatDate, formatQueueTime, shortId, titleCase } from '../utils/formatters'
import type { Incident, TimelineEntry } from '../types/incident'

const SUBMIT_OPTIONS = [
  { key: 'note', label: 'Internal note', hint: 'Add the note and leave the status as it is' },
  { key: 'escalate', label: 'Escalated', hint: 'Flag for a senior analyst' },
  { key: 'closed', label: 'Closed', hint: 'Resolved. The note becomes the closing summary' },
  { key: 'false_positive', label: 'False positive', hint: 'Not a real incident. The note says why' },
] as const
type SubmitKey = (typeof SUBMIT_OPTIONS)[number]['key']

const actorLabel = (actor: string) => (actor === 'system' || actor === 'ai' ? 'Cane AI' : actor)
const targetOf = (action: any) => action.action_params?.[ACTION_PARAM_KEYS[action.action_type]] ?? Object.values(action.action_params || {})[0] ?? ''

function Field({ label, children, action }: { label: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-1">
        <div className="text-xs font-semibold">{label}</div>
        {action}
      </div>
      {children}
    </div>
  )
}

function Tags({ values, empty = '-' }: { values?: string[] | null; empty?: string }) {
  if (!values?.length) return <div className="text-[13px] text-ink-faint">{empty}</div>
  return <div className="flex flex-wrap gap-1">{values.map((v) => <span key={v} className="tag font-mono text-[11px] max-w-full truncate" title={v}>{v}</span>)}</div>
}

export default function IncidentDetailPage() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const me = useAuthStore((s) => s.user)
  const canAct = hasRole(me?.role, 'tier2_analyst')
  const { users, names } = useAssignableUsers()

  const [tab, setTab] = useState<'conversation' | 'evidence' | 'playbook'>('conversation')
  const [note, setNote] = useState('')
  const [submitAs, setSubmitAs] = useState<SubmitKey>('note')
  const [submitMenu, setSubmitMenu] = useState(false)
  const [rejecting, setRejecting] = useState<any | null>(null)
  const [rejectReason, setRejectReason] = useState('')
  const [manualType, setManualType] = useState('block_ip')
  const [manualTarget, setManualTarget] = useState('')
  const [decision, setDecision] = useState('')
  const streamEnd = useRef<HTMLDivElement>(null)

  const incident = useQuery({ queryKey: ['incident', id], queryFn: () => incidentsApi.get(id).then((r) => r.data as Incident), refetchInterval: 60_000 })
  const timeline = useQuery({ queryKey: ['incident', id, 'timeline'], queryFn: () => incidentsApi.getTimeline(id).then((r) => r.data as TimelineEntry[]), refetchInterval: 60_000 })
  const evidence = useQuery({ queryKey: ['incident', id, 'evidence'], queryFn: () => incidentsApi.getEvidence(id).then((r) => r.data as any[]) })
  const analyses = useQuery({ queryKey: ['incident', id, 'triage'], queryFn: () => triageApi.getResults(id).then((r) => r.data as any[]), refetchInterval: 60_000 })
  const actions = useQuery({ queryKey: ['incident', id, 'actions'], queryFn: () => actionsApi.history({ incident_id: id }).then((r) => r.data as any[]), refetchInterval: 60_000 })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: () => playbooksApi.list().then((r) => r.data as any[]) })
  const playbookId = incident.data?.playbook_id
  const playbook = useQuery({ queryKey: ['playbook', playbookId], queryFn: () => playbooksApi.get(playbookId!).then((r) => r.data), enabled: !!playbookId })

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['incident', id] })
    qc.invalidateQueries({ queryKey: ['incidents'] })
    qc.invalidateQueries({ queryKey: ['incident-views'] })
    qc.invalidateQueries({ queryKey: ['dashboard'] })
    qc.invalidateQueries({ queryKey: ['actions'] })
  }
  const fail = (title: string) => (err: any) => notify.error(title, errorMessage(err))

  const update = useMutation({ mutationFn: (data: any) => incidentsApi.update(id, data), onSuccess: refresh, onError: fail('Could not update the incident') })
  const assign = useMutation({ mutationFn: (userId: string | null) => incidentsApi.assign(id, userId), onSuccess: refresh, onError: fail('Could not assign the incident') })
  const triage = useMutation({
    mutationFn: () => triageApi.analyze(id),
    onSuccess: (res) => {
      refresh()
      res.data.analysis_type?.endsWith('_failed')
        ? notify.error('AI triage could not complete', res.data.output?.error)
        : notify.success('AI triage complete')
    },
    onError: fail('AI triage failed'),
  })
  const approve = useMutation({
    mutationFn: (actionId: string) => actionsApi.approve(actionId),
    onSuccess: (res) => {
      refresh()
      res.data.status === 'completed'
        ? notify.success(res.data.result?.dry_run ? 'Action simulated (dry run)' : 'Action executed')
        : notify.error('Action failed', res.data.error_message)
    },
    onError: fail('Could not approve the action'),
  })
  const reject = useMutation({
    mutationFn: ({ actionId, reason }: { actionId: string; reason: string }) => actionsApi.reject(actionId, reason),
    onSuccess: () => { refresh(); setRejecting(null); setRejectReason('') },
    onError: fail('Could not reject the action'),
  })
  const execute = useMutation({
    mutationFn: () => actionsApi.execute({ incident_id: id, action_type: manualType, action_params: { [ACTION_PARAM_KEYS[manualType]]: manualTarget.trim() } }),
    onSuccess: (res) => {
      refresh(); setManualTarget('')
      res.data.status === 'completed'
        ? notify.success(res.data.result?.dry_run ? 'Action simulated (dry run)' : 'Action executed')
        : notify.error('Action failed', res.data.error_message)
    },
    onError: fail('Could not run the action'),
  })
  const enrich = useMutation({
    mutationFn: () => incidentsApi.enrich(id),
    onSuccess: () => { refresh(); notify.success('Lookups complete') },
    onError: fail('Could not run lookups'),
  })
  const startPlaybook = useMutation({ mutationFn: (pbId: string) => playbooksApi.execute(pbId, id), onSuccess: () => { refresh(); setTab('playbook') }, onError: fail('Could not start the playbook') })
  const advance = useMutation({ mutationFn: () => playbooksApi.advance(id, decision.trim() || undefined), onSuccess: () => { refresh(); setDecision('') }, onError: fail('Could not advance the playbook') })
  const submit = useMutation({
    mutationFn: async () => {
      const text = note.trim()
      if (submitAs === 'note') return incidentsApi.addNote(id, text)
      if (submitAs === 'escalate') { if (text) await incidentsApi.addNote(id, text); return incidentsApi.escalate(id) }
      return incidentsApi.close(id, text, submitAs === 'false_positive')
    },
    onSuccess: () => { refresh(); setNote(''); setSubmitAs('note') },
    onError: fail('Could not submit'),
  })

  useEffect(() => { streamEnd.current?.scrollIntoView({ block: 'end' }) }, [timeline.data?.length, tab])

  if (incident.isLoading) return <div className="flex-1"><Loading /></div>
  if (incident.isError || !incident.data) {
    return <div className="flex-1 p-6"><ErrorNote>This incident could not be loaded. It may have been deleted. <Link className="link" to="/incidents">Back to incidents</Link></ErrorNote></div>
  }

  const inc = incident.data
  const closed = ['closed', 'false_positive'].includes(inc.status)
  const latest = (analyses.data || []).find((a) => ['triage', 'auto_triage'].includes(a.analysis_type))
  const failed = (analyses.data || [])[0]?.analysis_type?.endsWith('_failed') ? (analyses.data || [])[0] : null
  const out = latest?.output
  const entities = inc.source_entities || {}
  const pending = (actions.data || []).filter((a) => a.status === 'pending_approval')
  const done = (actions.data || []).filter((a) => a.status !== 'pending_approval')
  const dropped = (out?.action_decisions || []).filter((d: any) => d.disposition === 'skip')
  const steps: any[] = playbook.data?.steps || []
  const currentStep = steps.find((s) => s.step_order === inc.current_playbook_step)
  const enrichment: any = (inc as any).enrichment
  const tickets: any[] = Object.values(((inc as any).external_refs || {}).tickets || {})
  const needsNote = submitAs !== 'escalate'
  const submitLabel = SUBMIT_OPTIONS.find((o) => o.key === submitAs)!.label

  return (
    <div className="flex-1 flex flex-col min-w-0">
      {/* Ticket strip */}
      <div className="h-10 shrink-0 border-b border-line bg-surface flex items-center gap-2 px-3 text-[13px]">
        <Link to="/incidents" className="btn btn-sm text-ink-soft hover:bg-line-soft px-1.5"><ArrowLeft className="w-4 h-4" /> Incidents</Link>
        <span className="tag bg-white"><StatusPill status={inc.status} /><span className="ml-1.5">Incident {shortId(inc.id)}</span></span>
        <span className="tag bg-white"><Severity value={inc.severity} /></span>
        {inc.attack_type && <span className="tag bg-white">{titleCase(inc.attack_type)}</span>}
        <div className="flex-1" />
        <span className="text-ink-muted">Opened {formatDate(inc.created_at)}</span>
      </div>

      <div className="flex-1 min-h-0 flex">
        {/* Properties */}
        <aside className="w-72 shrink-0 border-r border-line bg-surface overflow-y-auto px-4 py-4">
          <Field
            label="Assignee"
            action={me && inc.assigned_to !== me.id && !closed && <button className="link text-xs" onClick={() => assign.mutate(me.id)}>take it</button>}
          >
            <select className="input" value={inc.assigned_to || ''} disabled={assign.isPending} onChange={(e) => assign.mutate(e.target.value || null)}>
              <option value="">Unassigned</option>
              {users.map((u) => <option key={u.id} value={u.id}>{u.full_name}</option>)}
              {inc.assigned_to && !names[inc.assigned_to] && <option value={inc.assigned_to}>Former user</option>}
            </select>
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Severity">
              <select className="input" value={inc.severity} onChange={(e) => update.mutate({ severity: e.target.value })}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_META[s].label}</option>)}
              </select>
            </Field>
            <Field label="Status">
              <select className="input" value={inc.status} onChange={(e) => update.mutate({ status: e.target.value })}>
                {STATUS_OPTIONS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </Field>
          </div>
          <Field label="Playbook">
            <select className="input" value={inc.playbook_id || ''} disabled={startPlaybook.isPending} onChange={(e) => e.target.value && startPlaybook.mutate(e.target.value)}>
              <option value="">None attached</option>
              {(playbooks.data || []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            {inc.playbook_id && (
              <button className="link text-xs mt-1" onClick={() => setTab('playbook')}>
                {currentStep ? `On step ${currentStep.step_order} of ${steps.length}: ${currentStep.title}` : steps.length ? 'Playbook complete' : 'View playbook'}
              </button>
            )}
          </Field>
          <Field label="AI confidence">
            <div className="text-[13px]">{inc.confidence_score != null ? `${Math.round(inc.confidence_score * 100)}%` : <span className="text-ink-faint">Not triaged yet</span>}</div>
          </Field>
          <Field label="Source IPs"><Tags values={entities.ips} /></Field>
          <Field label="Hosts"><Tags values={entities.hosts} /></Field>
          <Field label="Accounts"><Tags values={entities.users} /></Field>
          <Field label="MITRE ATT&CK"><Tags values={[...(inc.mitre_tactics || []), ...(inc.mitre_techniques || [])]} /></Field>
          {tickets.length > 0 && (
            <Field label="Tickets">
              <div className="space-y-1">
                {tickets.map((t, i) => (
                  <div key={i} className="text-[13px] flex items-center gap-1.5">
                    {t.ticket_url && !t.dry_run
                      ? <a className="link inline-flex items-center gap-1" href={t.ticket_url} target="_blank" rel="noreferrer">{t.label || t.ticket_id} <ExternalLink className="w-3 h-3" /></a>
                      : <span>{t.label || t.ticket_id}</span>}
                    <span className="text-ink-muted">{t.integration}</span>
                    {t.dry_run && <span className="tag">Dry run</span>}
                    {t.closed && <span className="tag">Closed</span>}
                  </div>
                ))}
              </div>
            </Field>
          )}
          <Field label="Correlation ID">
            <div className="text-[12px] font-mono text-ink-soft break-all">{inc.correlation_id || <span className="text-ink-faint font-sans">None (single event)</span>}</div>
          </Field>
        </aside>

        {/* Conversation */}
        <section className="flex-1 min-w-0 flex flex-col">
          <div className="px-5 pt-4 shrink-0">
            <h1 className="text-lg font-semibold leading-6">{inc.title}</h1>
            {inc.description && <p className="text-[13px] text-ink-muted mt-0.5">{inc.description}</p>}
            <div className="flex gap-5 mt-3 border-b border-line text-[13px]">
              {([['conversation', 'Conversation'], ['evidence', `Evidence (${evidence.data?.length ?? 0})`], ['playbook', 'Playbook']] as const).map(([key, label]) => (
                <button key={key} onClick={() => setTab(key)} className={clsx('pb-2 -mb-px border-b-2', tab === key ? 'border-brand-500 text-brand-500 font-semibold' : 'border-transparent text-ink-soft hover:text-ink')}>
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto px-5 py-4">
            {tab === 'conversation' && (
              <div className="space-y-3 max-w-3xl">
                {timeline.isLoading && <Loading />}
                {(timeline.data || []).map((entry) => {
                  const isNote = entry.event_type === 'analyst_note'
                  const isAi = ['auto_triage', 'ai_analysis', 'ai_analysis_failed'].includes(entry.event_type)
                  if (isNote || isAi) {
                    return (
                      <div key={entry.id} className="flex gap-3">
                        {isAi
                          ? <span className="w-7 h-7 rounded-full bg-[#eadcf4] text-[#6a27b8] flex items-center justify-center shrink-0"><Bot className="w-4 h-4" /></span>
                          : <Avatar name={entry.actor} size={28} />}
                        <div className="min-w-0 flex-1">
                          <div className="text-[13px]">
                            <span className="font-semibold">{isAi ? 'Cane AI' : entry.actor}</span>
                            <span className="text-ink-faint"> · {formatQueueTime(entry.timestamp)}</span>
                            {isNote && <span className="tag ml-2 bg-[#fff8ed] border-[#fcdba9] text-[#8a4b0b]">Internal note</span>}
                          </div>
                          <div className={clsx('mt-1 rounded border px-3 py-2 text-[13px] leading-5 whitespace-pre-wrap break-words',
                            isNote ? 'bg-[#fff8ed] border-[#fcdba9]' : entry.event_type === 'ai_analysis_failed' ? 'bg-[#fff0f1] border-[#f5b5ba]' : 'bg-[#f7f2fb] border-[#dcc6ee]')}>
                            {entry.description.replace(/^AI triage completed: /, '')}
                            {isAi && entry.extra_data?.model && (
                              <div className="text-xs text-ink-muted mt-1.5">
                                {entry.extra_data.provider} · {entry.extra_data.model}
                                {entry.extra_data.confidence != null && ` · ${Math.round(entry.extra_data.confidence * 100)}% confidence`}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    )
                  }
                  return (
                    <div key={entry.id} className="flex items-start gap-3 text-[13px] text-ink-soft pl-[7px]">
                      <span className={clsx('w-3.5 h-3.5 mt-1 rounded-full border-2 bg-white shrink-0',
                        entry.event_type.includes('failed') || entry.event_type.includes('rejected') ? 'border-severity-critical'
                          : entry.event_type === 'action_executed' ? 'border-[#038153]' : 'border-line')} />
                      <div className="ml-[7px] min-w-0">
                        <span className="break-words">{entry.description}</span>
                        <span className="text-ink-faint"> · {actorLabel(entry.actor)} · {formatQueueTime(entry.timestamp)}</span>
                      </div>
                    </div>
                  )
                })}
                <div ref={streamEnd} />
              </div>
            )}

            {tab === 'evidence' && (
              evidence.isLoading ? <Loading />
                : !evidence.data?.length ? <div className="text-[13px] text-ink-muted">No log events are linked to this incident.</div>
                : (
                  <div className="border border-line rounded overflow-auto">
                    <table className="table-queue">
                      <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Summary</th><th>Source IP</th><th>Host</th><th>Account</th></tr></thead>
                      <tbody>
                        {evidence.data.map((e) => (
                          <tr key={e.id}>
                            <td className="whitespace-nowrap text-ink-soft">{formatDate(e.time_generated)}</td>
                            <td><Severity value={e.severity} /></td>
                            <td className="whitespace-nowrap">{e.log_type}</td>
                            <td className="max-w-[320px]"><div className="truncate" title={e.summary || ''}>{e.summary || '-'}</div></td>
                            <td className="font-mono text-xs">{e.source_ip || '-'}</td>
                            <td className="text-ink-soft">{e.host || '-'}</td>
                            <td className="text-ink-soft">{e.user_identity || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )
            )}

            {tab === 'playbook' && (
              !inc.playbook_id ? <div className="text-[13px] text-ink-muted">No playbook is attached. Choose one under <span className="font-semibold text-ink">Playbook</span> on the left to start a guided response.</div>
                : playbook.isLoading ? <Loading />
                : (
                  <div className="max-w-3xl">
                    <div className="font-semibold">{playbook.data?.name}</div>
                    <div className="text-[13px] text-ink-muted mb-3">{inc.current_playbook_step == null && steps.length ? 'All steps complete.' : `${steps.length} steps, following NIST SP 800-61.`}</div>
                    <ol className="border border-line rounded divide-y divide-line-soft">
                      {steps.map((step) => {
                        const isCurrent = step.step_order === inc.current_playbook_step
                        const isDone = inc.current_playbook_step == null || step.step_order < inc.current_playbook_step
                        return (
                          <li key={step.id} className={clsx('px-3 py-2.5', isCurrent && 'bg-brand-50')}>
                            <div className="flex items-start gap-3">
                              <span className={clsx('w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold shrink-0',
                                isDone ? 'bg-[#038153] text-white' : isCurrent ? 'bg-brand-500 text-white' : 'bg-surface-sunken text-ink-muted border border-line')}>
                                {isDone ? <Check className="w-3.5 h-3.5" /> : step.step_order}
                              </span>
                              <div className="min-w-0 flex-1">
                                <div className="flex flex-wrap items-center gap-2 text-[13px]">
                                  <span className="font-semibold">{step.title}</span>
                                  <span className="tag">{PHASE_LABELS[step.phase] || step.phase}</span>
                                  <span className="tag">{STEP_TYPE_LABELS[step.step_type] || step.step_type}</span>
                                  {step.auto_action_type && <span className="tag">{ACTION_LABELS[step.auto_action_type] || step.auto_action_type}</span>}
                                </div>
                                {isCurrent && (
                                  <>
                                    <div className="text-[13px] text-ink-soft mt-1.5 whitespace-pre-wrap leading-5">{step.description}</div>
                                    <div className="flex items-center gap-2 mt-2.5">
                                      {step.step_type === 'human_decision' && (
                                        <input className="input w-56" placeholder="Decision, e.g. CONFIRMED" value={decision} onChange={(e) => setDecision(e.target.value)} />
                                      )}
                                      <button className="btn-primary btn-sm" disabled={advance.isPending} onClick={() => advance.mutate()}>
                                        {advance.isPending ? 'Saving…' : 'Mark step done'}
                                      </button>
                                    </div>
                                  </>
                                )}
                              </div>
                            </div>
                          </li>
                        )
                      })}
                    </ol>
                  </div>
                )
            )}
          </div>

          {/* Composer */}
          <div className="shrink-0 border-t border-line">
            <div className="px-5 pt-3">
              <div className="text-xs font-semibold text-[#8a4b0b] mb-1">Internal note</div>
              <textarea
                className="input bg-[#fff8ed] border-[#fcdba9] focus:border-[#e0a04a] focus:ring-[#fcdba9]"
                rows={3}
                placeholder={submitAs === 'closed' ? 'How was this resolved?' : submitAs === 'false_positive' ? 'Why is this not a real incident?' : 'Add what you found, for the next analyst…'}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2 px-5 py-2.5">
              <button className="btn-basic" disabled={triage.isPending} onClick={() => triage.mutate()} title="Analyse this incident's evidence with the configured AI model. Recommended actions are queued for approval, never run automatically.">
                {triage.isPending ? <Spinner /> : <Sparkles className="w-4 h-4 text-[#6a27b8]" />}
                {triage.isPending ? 'Analysing…' : latest ? 'Re-run AI triage' : 'Run AI triage'}
              </button>
              <div className="flex-1" />
              <div className="relative flex">
                <button
                  className="btn bg-ink text-white hover:bg-black rounded-r-none"
                  disabled={submit.isPending || (needsNote && !note.trim())}
                  onClick={() => submit.mutate()}
                  title={needsNote && !note.trim() ? 'Write a note first' : undefined}
                >
                  {submit.isPending ? 'Submitting…' : <>Submit as <span className="font-bold">{submitLabel}</span></>}
                </button>
                <button className="btn bg-ink text-white hover:bg-black rounded-l-none border-l border-white/25 px-1.5" onClick={() => setSubmitMenu((o) => !o)} aria-label="Choose how to submit">
                  <ChevronDown className="w-4 h-4" />
                </button>
                {submitMenu && (
                  <div className="absolute right-0 bottom-9 z-30 w-72 bg-white border border-line rounded shadow-lg py-1">
                    {SUBMIT_OPTIONS.map((opt) => (
                      <button key={opt.key} className={clsx('w-full text-left px-3 py-1.5 hover:bg-brand-50', submitAs === opt.key && 'bg-brand-50')} onClick={() => { setSubmitAs(opt.key); setSubmitMenu(false) }}>
                        <div className="text-[13px]">Submit as <span className="font-semibold">{opt.label}</span></div>
                        <div className="text-xs text-ink-muted">{opt.hint}</div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* Context: AI analysis + response actions */}
        <aside className="w-80 shrink-0 border-l border-line overflow-y-auto">
          <div className="px-4 py-4 border-b border-line">
            <div className="flex items-center gap-1.5 panel-title mb-2"><Sparkles className="w-3.5 h-3.5 text-[#6a27b8]" /> AI analysis</div>
            {failed && (
              <div className="mb-3"><ErrorNote><span className="font-semibold">Last triage attempt failed.</span> {failed.output?.error}</ErrorNote></div>
            )}
            {!out ? (
              <div className="text-[13px] text-ink-muted">
                {analyses.isLoading ? 'Loading…' : 'This incident has not been triaged by AI yet. Use “Run AI triage” below the conversation.'}
              </div>
            ) : (
              <div className="text-[13px] space-y-3">
                <p className="leading-5">{out.summary}</p>
                <div className="grid grid-cols-2 gap-2">
                  <div><div className="text-xs text-ink-muted">Assessed severity</div><Severity value={out.severity} /></div>
                  <div><div className="text-xs text-ink-muted">Confidence</div><span className="font-semibold">{Math.round((out.confidence_score || 0) * 100)}%</span></div>
                  <div><div className="text-xs text-ink-muted">Attack type</div>{out.attack_type ? titleCase(out.attack_type) : '-'}</div>
                  <div><div className="text-xs text-ink-muted">Kill chain</div>{out.kill_chain_phase ? titleCase(out.kill_chain_phase) : '-'}</div>
                </div>
                {out.requires_human_review ? (
                  <div className="flex gap-2 rounded border border-[#fcdba9] bg-[#fff8ed] px-2.5 py-2 text-[#703b15]">
                    <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                    <div><span className="font-semibold">Needs human review.</span> {out.human_review_reason}</div>
                  </div>
                ) : (
                  <div className="flex gap-2 rounded border border-[#aecfc2] bg-[#edf8f4] px-2.5 py-2 text-[#186146]">
                    <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0" /> The model did not ask for human review.
                  </div>
                )}
                {Object.entries(out.indicators_of_compromise || {}).some(([, v]: any) => v?.length) && (
                  <div>
                    <div className="text-xs text-ink-muted mb-1">Indicators of compromise</div>
                    <Tags values={Object.values(out.indicators_of_compromise).flat() as string[]} />
                  </div>
                )}
                <div className="text-xs text-ink-faint">{latest.provider} · {latest.model} · {formatQueueTime(latest.created_at)}</div>
              </div>
            )}
          </div>

          <div className="px-4 py-4 border-b border-line">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5 panel-title"><Radar className="w-3.5 h-3.5 text-brand-500" /> Threat intel & context</div>
              <button className="link text-xs" disabled={enrich.isPending} onClick={() => enrich.mutate()}>{enrich.isPending ? 'Looking up…' : enrichment ? 'Refresh' : 'Look up'}</button>
            </div>
            {!enrichment ? (
              <div className="text-[13px] text-ink-muted">Not looked up yet. Lookups run automatically on new incidents once a threat-intelligence or directory integration is connected.</div>
            ) : (enrichment.indicators?.length || 0) + (enrichment.context?.length || 0) === 0 ? (
              <div className="text-[13px] text-ink-muted">Connected sources had nothing on this incident's indicators.</div>
            ) : (
              <div className="space-y-2.5 text-[13px]">
                {(enrichment.indicators || []).map((ind: any) => (
                  <div key={`${ind.kind}:${ind.value}`}>
                    <div className="flex items-center gap-1.5">
                      <span className={clsx('pill', (VERDICT_META[ind.verdict] || VERDICT_META.unknown).cls)}>{(VERDICT_META[ind.verdict] || VERDICT_META.unknown).label}</span>
                      <span className="font-mono text-xs break-all">{ind.value}</span>
                    </div>
                    {ind.sources?.length
                      ? <ul className="mt-1 space-y-0.5">{ind.sources.map((src: any, i: number) => (
                          <li key={i} className="text-xs text-ink-soft border-l-2 border-line pl-2"><span className="font-medium text-ink">{src.source}:</span> {src.summary || src.verdict}</li>
                        ))}</ul>
                      : <div className="text-xs text-ink-faint mt-0.5">No source had a record of it.</div>}
                  </div>
                ))}
                {(enrichment.context || []).map((ctx: any) => (
                  <div key={`${ctx.kind}:${ctx.value}`} className="rounded border border-line p-2">
                    <div className="text-xs text-ink-muted">{ctx.kind === 'user' ? 'Account' : 'Host'}</div>
                    <div className="font-mono text-xs break-all mb-1">{ctx.value}</div>
                    {ctx.sources.map((src: any, i: number) => (
                      <div key={i} className="text-xs">
                        <div className="font-medium">{src.source}</div>
                        <dl className="grid grid-cols-[96px_1fr] gap-x-2 text-ink-soft">
                          {Object.entries(src).filter(([k, v]) => !['source', 'platform'].includes(k) && v !== null && v !== '' && typeof v !== 'object').slice(0, 8).map(([k, v]) => (
                            <div key={k} className="contents"><dt className="text-ink-muted truncate">{titleCase(k)}</dt><dd className="break-words">{String(v)}</dd></div>
                          ))}
                        </dl>
                      </div>
                    ))}
                  </div>
                ))}
                <div className="text-xs text-ink-faint">{(enrichment.sources || []).join(', ') || 'No sources answered'} · {formatQueueTime(enrichment.generated_at)}</div>
              </div>
            )}
          </div>

          <div className="px-4 py-4">
            <div className="panel-title mb-2">Response actions</div>
            {pending.length === 0 && done.length === 0 && <div className="text-[13px] text-ink-muted mb-3">No actions yet. AI triage proposes them; an analyst approves.</div>}

            {pending.map((action) => (
              <div key={action.id} className="border border-[#fcdba9] bg-[#fff8ed] rounded p-2.5 mb-2 text-[13px]">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold">{ACTION_LABELS[action.action_type] || action.action_type}</span>
                  <ActionPill status={action.status} />
                </div>
                <div className="font-mono text-xs break-all mt-0.5">{String(targetOf(action))}</div>
                <div className="text-xs text-ink-muted mt-1">Proposed by {action.source === 'ai_recommended' ? 'Cane AI' : action.requested_by.startsWith('playbook:') ? 'the playbook' : action.requested_by}</div>
                {canAct ? (
                  <div className="flex gap-2 mt-2">
                    <button className="btn-primary btn-sm flex-1" disabled={approve.isPending} onClick={() => approve.mutate(action.id)}><Check className="w-3.5 h-3.5" /> Approve & run</button>
                    <button className="btn-basic btn-sm" onClick={() => setRejecting(action)}><X className="w-3.5 h-3.5" /> Reject</button>
                  </div>
                ) : <div className="text-xs text-ink-muted mt-2">A tier 2 analyst or above must approve this.</div>}
              </div>
            ))}

            {done.map((action) => (
              <div key={action.id} className="border border-line rounded p-2.5 mb-2 text-[13px]">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{ACTION_LABELS[action.action_type] || action.action_type}</span>
                  <span className="flex items-center gap-1">{action.result?.dry_run && <span className="tag">Dry run</span>}<ActionPill status={action.status} /></span>
                </div>
                <div className="font-mono text-xs break-all mt-0.5 text-ink-soft">{String(targetOf(action))}</div>
                {action.error_message && <div className="text-xs text-[#8c232c] mt-1 break-words">{action.error_message}</div>}
                {action.status === 'completed' && (action.result?.results || []).map((r: any, i: number) => (
                  <div key={i} className={clsx('text-xs mt-0.5', r.success ? 'text-ink-muted' : 'text-[#8c232c]')}>
                    {r.success ? '✓' : '✕'} {r.integration}{r.dry_run ? ' (simulated)' : ''}{!r.success && r.message ? `: ${r.message}` : ''}
                  </div>
                ))}
              </div>
            ))}

            {dropped.length > 0 && (
              <details className="text-[13px] mb-3">
                <summary className="cursor-pointer text-ink-muted">{dropped.length} AI suggestion{dropped.length === 1 ? '' : 's'} not turned into actions</summary>
                <ul className="mt-1.5 space-y-1.5">
                  {dropped.map((d: any, i: number) => (
                    <li key={i} className="text-xs text-ink-soft border-l-2 border-line pl-2">
                      <span className="font-medium">{ACTION_LABELS[d.action] || d.action}</span>{d.target ? ` on ${d.target}` : ''}: {d.reason}
                    </li>
                  ))}
                </ul>
              </details>
            )}

            {canAct && !closed && (
              <div className="border-t border-line pt-3 mt-3">
                <div className="text-xs font-semibold mb-1.5">Run an action yourself</div>
                <select className="input mb-2" value={manualType} onChange={(e) => setManualType(e.target.value)}>
                  {Object.keys(ACTION_LABELS).filter((k) => !['run_kql_query', 'purge_email'].includes(k)).map((k) => <option key={k} value={k}>{ACTION_LABELS[k]}</option>)}
                </select>
                <input className="input mb-2 font-mono text-xs" placeholder={titleCase(ACTION_PARAM_KEYS[manualType])} value={manualTarget} onChange={(e) => setManualTarget(e.target.value)} />
                <button className="btn-secondary btn-sm w-full" disabled={!manualTarget.trim() || execute.isPending} onClick={() => execute.mutate()}>
                  {execute.isPending ? 'Running…' : 'Run now'}
                </button>
              </div>
            )}
          </div>
        </aside>
      </div>

      {rejecting && (
        <Modal
          title="Reject action"
          onClose={() => setRejecting(null)}
          footer={
            <>
              <button className="btn-basic" onClick={() => setRejecting(null)}>Cancel</button>
              <button className="btn-danger" disabled={!rejectReason.trim() || reject.isPending} onClick={() => reject.mutate({ actionId: rejecting.id, reason: rejectReason.trim() })}>Reject action</button>
            </>
          }
        >
          <div className="text-[13px] mb-3">
            <span className="font-semibold">{ACTION_LABELS[rejecting.action_type] || rejecting.action_type}</span> on <span className="font-mono text-xs">{String(targetOf(rejecting))}</span> will not run.
          </div>
          <label className="label">Reason</label>
          <textarea className="input" rows={3} autoFocus value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} placeholder="Recorded on the incident timeline" />
        </Modal>
      )}
    </div>
  )
}
