export interface LogEvent {
  id: string
  tenant_id: string
  time_generated: string
  source_system: string
  log_type: string
  schema_id: string
  correlation_id: string | null
  severity: string
  summary: string | null
  source_ip: string | null
  destination_ip: string | null
  user_identity: string | null
  host: string | null
  incident_id: string | null
  created_at: string
}

export interface LogEventDetail extends LogEvent {
  raw_data: Record<string, any>
}
