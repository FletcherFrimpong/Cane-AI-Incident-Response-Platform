export interface Incident {
  id: string
  tenant_id: string
  title: string
  description: string | null
  severity: string
  status: string
  attack_type: string | null
  confidence_score: number | null
  correlation_id: string | null
  assigned_to: string | null
  playbook_id: string | null
  current_playbook_step: number | null
  mitre_tactics: string[] | null
  mitre_techniques: string[] | null
  source_entities: Record<string, string[]> | null
  created_at: string
  updated_at: string
  resolved_at: string | null
}

export interface TimelineEntry {
  id: string
  event_type: string
  actor: string
  description: string
  metadata: Record<string, any> | null
  timestamp: string
}
