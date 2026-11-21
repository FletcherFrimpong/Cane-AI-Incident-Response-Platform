import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { incidentsApi } from '../api/incidents'
import { Modal, ErrorNote } from './ui'
import { SEVERITIES, SEVERITY_META } from '../utils/constants'
import { errorMessage } from '../utils/formatters'

export default function NewIncidentModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [attackType, setAttackType] = useState('')

  const create = useMutation({
    mutationFn: () => incidentsApi.create({ title: title.trim(), description: description.trim() || null, severity, attack_type: attackType.trim() || null }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-views'] })
      onClose()
      navigate(`/incidents/${res.data.id}`)
    },
  })

  return (
    <Modal
      title="New incident"
      onClose={onClose}
      footer={
        <>
          <button className="btn-basic" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!title.trim() || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? 'Creating…' : 'Create incident'}
          </button>
        </>
      }
    >
      <div className="space-y-3">
        {create.isError && <ErrorNote>{errorMessage(create.error)}</ErrorNote>}
        <div>
          <label className="label">Subject</label>
          <input className="input" autoFocus value={title} onChange={(e) => setTitle(e.target.value)} placeholder="What happened?" />
        </div>
        <div>
          <label className="label">Description</label>
          <textarea className="input" rows={4} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What was observed, where, and how it was reported" />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Severity</label>
            <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_META[s].label}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Attack type</label>
            <input className="input" value={attackType} onChange={(e) => setAttackType(e.target.value)} placeholder="e.g. phishing" />
          </div>
        </div>
      </div>
    </Modal>
  )
}
