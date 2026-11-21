import { Fragment, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BookOpen, Plus, Trash2 } from 'lucide-react'
import { playbooksApi } from '../api/playbooks'
import { useAuthStore } from '../store/authStore'
import { EmptyState, ErrorNote, Loading, Modal, ViewsSidebar, notify } from '../components/ui'
import { ACTION_LABELS, PHASE_LABELS, STEP_TYPE_LABELS, hasRole } from '../utils/constants'
import { errorMessage, titleCase } from '../utils/formatters'

const PHASES = Object.keys(PHASE_LABELS)

export default function PlaybooksPage() {
  const qc = useQueryClient()
  const canManage = hasRole(useAuthStore((s) => s.user)?.role, 'manager')
  const [selected, setSelected] = useState('')
  const [creating, setCreating] = useState(false)
  const [addingStep, setAddingStep] = useState(false)
  const [form, setForm] = useState({ name: '', description: '', attack_types: '' })
  const [step, setStep] = useState({ title: '', description: '', phase: 'containment', step_type: 'human_action' })

  const list = useQuery({ queryKey: ['playbooks'], queryFn: () => playbooksApi.list().then((r) => r.data as any[]) })
  useEffect(() => { if (!selected && list.data?.length) setSelected(list.data[0].id) }, [list.data, selected])
  const detail = useQuery({ queryKey: ['playbook', selected], queryFn: () => playbooksApi.get(selected).then((r) => r.data), enabled: !!selected })

  const create = useMutation({
    mutationFn: () => playbooksApi.create({
      name: form.name.trim(), description: form.description.trim() || null,
      attack_types: form.attack_types.split(',').map((s) => s.trim().toLowerCase().replace(/\s+/g, '_')).filter(Boolean),
    }),
    onSuccess: (res) => { qc.invalidateQueries({ queryKey: ['playbooks'] }); setSelected(res.data.id); setCreating(false); setForm({ name: '', description: '', attack_types: '' }) },
    onError: (e) => notify.error('Could not create the playbook', errorMessage(e)),
  })
  const addStep = useMutation({
    mutationFn: () => playbooksApi.addStep(selected, { ...step, title: step.title.trim(), description: step.description.trim(), step_order: (detail.data?.steps?.length || 0) + 1 }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['playbook', selected] }); qc.invalidateQueries({ queryKey: ['playbooks'] }); setAddingStep(false); setStep({ title: '', description: '', phase: 'containment', step_type: 'human_action' }) },
    onError: (e) => notify.error('Could not add the step', errorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: () => playbooksApi.delete(selected),
    onSuccess: () => { setSelected(''); qc.invalidateQueries({ queryKey: ['playbooks'] }) },
    onError: (e) => notify.error('Could not delete the playbook', errorMessage(e)),
  })

  const all = list.data || []
  const builtin = all.filter((p) => p.is_builtin).map((p) => ({ key: p.id, label: p.name.replace(/ Playbook$/, ''), count: p.steps_count }))
  const custom = all.filter((p) => !p.is_builtin).map((p) => ({ key: p.id, label: p.name, count: p.steps_count }))
  const pb = detail.data
  const steps: any[] = pb?.steps || []

  return (
    <div className="flex-1 flex min-w-0">
      <ViewsSidebar
        title="Playbooks"
        active={selected}
        onSelect={setSelected}
        sections={[{ heading: 'Built-in (NIST 800-61)', items: builtin }, ...(custom.length ? [{ heading: 'Custom', items: custom }] : [])]}
        footer={<>The number beside each playbook is its step count.</>}
      />
      <section className="flex-1 min-w-0 overflow-y-auto">
        {list.isLoading ? <Loading />
          : list.isError ? <div className="p-5"><ErrorNote>Could not load playbooks.</ErrorNote></div>
          : !pb ? (detail.isLoading ? <Loading /> : <EmptyState icon={<BookOpen className="w-8 h-8" />} title="No playbooks yet">Built-in playbooks are loaded when the backend starts.</EmptyState>)
          : (
            <>
              <div className="px-5 pt-5 pb-4 border-b border-line flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h1 className="text-xl font-semibold">{pb.name}</h1>
                  <p className="text-[13px] text-ink-muted mt-1 max-w-3xl">{pb.description}</p>
                  <div className="flex flex-wrap items-center gap-1.5 mt-2.5 text-[13px]">
                    <span className="tag">{pb.is_builtin ? 'Built-in' : 'Custom'}</span>
                    <span className="tag">{pb.framework === 'nist_800_61' ? 'NIST SP 800-61' : titleCase(pb.framework)}</span>
                    <span className="text-ink-muted ml-1">Used for:</span>
                    {(pb.attack_types || []).map((a: string) => <span key={a} className="tag">{titleCase(a)}</span>)}
                  </div>
                </div>
                {canManage && (
                  <div className="flex gap-2 shrink-0">
                    {!pb.is_builtin && <button className="btn-basic" onClick={() => window.confirm(`Delete "${pb.name}"?`) && remove.mutate()}><Trash2 className="w-4 h-4" /> Delete</button>}
                    <button className="btn-secondary" onClick={() => setCreating(true)}><Plus className="w-4 h-4" /> New playbook</button>
                  </div>
                )}
              </div>
              <div className="px-5 py-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-[13px] font-semibold">{steps.length} step{steps.length === 1 ? '' : 's'}</div>
                  {canManage && !pb.is_builtin && <button className="btn-ghost btn-sm" onClick={() => setAddingStep(true)}><Plus className="w-3.5 h-3.5" /> Add step</button>}
                </div>
                {steps.length === 0 ? <div className="text-[13px] text-ink-muted border border-line rounded p-4">This playbook has no steps yet.</div> : (
                  <div className="border border-line rounded overflow-hidden">
                    <table className="table-queue">
                      <thead><tr><th className="w-12">#</th><th>Step</th><th className="w-32">Type</th><th className="w-44">Automated action</th><th className="w-28">Approval</th></tr></thead>
                      <tbody>
                        {PHASES.filter((ph) => steps.some((s) => s.phase === ph)).map((ph) => (
                          <Fragment key={ph}>
                            <tr className="group-row"><td colSpan={5}>Phase: <span className="font-semibold text-ink">{PHASE_LABELS[ph]}</span></td></tr>
                            {steps.filter((s) => s.phase === ph).map((s) => (
                              <tr key={s.id}>
                                <td className="text-ink-muted tabular-nums !align-top !py-2.5">{s.step_order}</td>
                                <td className="!py-2.5 !h-auto !align-top">
                                  <div className="font-medium">{s.title}</div>
                                  <div className="text-ink-soft whitespace-pre-wrap leading-5 mt-0.5 max-w-3xl">{s.description}</div>
                                </td>
                                <td className="!align-top !py-2.5"><span className="tag">{STEP_TYPE_LABELS[s.step_type] || s.step_type}</span></td>
                                <td className="!align-top !py-2.5 text-ink-soft">{s.auto_action_type ? ACTION_LABELS[s.auto_action_type] || s.auto_action_type : '-'}</td>
                                <td className="!align-top !py-2.5 text-ink-soft">{s.requires_approval ? 'Required' : '-'}</td>
                              </tr>
                            ))}
                          </Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </>
          )}
      </section>

      {creating && (
        <Modal title="New playbook" onClose={() => setCreating(false)} footer={<>
          <button className="btn-basic" onClick={() => setCreating(false)}>Cancel</button>
          <button className="btn-primary" disabled={!form.name.trim() || create.isPending} onClick={() => create.mutate()}>Create playbook</button>
        </>}>
          <div className="space-y-3">
            <div><label className="label">Name</label><input className="input" autoFocus value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
            <div><label className="label">Description</label><textarea className="input" rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
            <div>
              <label className="label">Attack types</label>
              <input className="input" value={form.attack_types} onChange={(e) => setForm({ ...form, attack_types: e.target.value })} placeholder="e.g. sql_injection, web_shell" />
              <div className="hint">Comma-separated. AI triage attaches this playbook to incidents it classifies as one of these.</div>
            </div>
          </div>
        </Modal>
      )}
      {addingStep && (
        <Modal title="Add step" onClose={() => setAddingStep(false)} footer={<>
          <button className="btn-basic" onClick={() => setAddingStep(false)}>Cancel</button>
          <button className="btn-primary" disabled={!step.title.trim() || !step.description.trim() || addStep.isPending} onClick={() => addStep.mutate()}>Add step</button>
        </>}>
          <div className="space-y-3">
            <div><label className="label">Title</label><input className="input" autoFocus value={step.title} onChange={(e) => setStep({ ...step, title: e.target.value })} /></div>
            <div><label className="label">Instructions</label><textarea className="input" rows={4} value={step.description} onChange={(e) => setStep({ ...step, description: e.target.value })} /></div>
            <div className="grid grid-cols-2 gap-3">
              <div><label className="label">Phase</label><select className="input" value={step.phase} onChange={(e) => setStep({ ...step, phase: e.target.value })}>{PHASES.map((p) => <option key={p} value={p}>{PHASE_LABELS[p]}</option>)}</select></div>
              <div><label className="label">Type</label><select className="input" value={step.step_type} onChange={(e) => setStep({ ...step, step_type: e.target.value })}>{['human_action', 'human_decision', 'info'].map((t) => <option key={t} value={t}>{STEP_TYPE_LABELS[t]}</option>)}</select></div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
