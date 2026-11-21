// Solid status pills, as in a help-desk queue: colour says where the work is.
export const STATUS_META: Record<string, { label: string; cls: string }> = {
  new: { label: 'New', cls: 'bg-[#ffb648] text-[#703b15]' },
  triaging: { label: 'Triaging', cls: 'bg-[#3091ec] text-white' },
  awaiting_analyst: { label: 'Open', cls: 'bg-severity-critical text-white' },
  in_progress: { label: 'In progress', cls: 'bg-[#1f73b7] text-white' },
  containment: { label: 'Containment', cls: 'bg-[#d2680d] text-white' },
  eradication: { label: 'Eradication', cls: 'bg-[#8a4fb5] text-white' },
  recovery: { label: 'Recovery', cls: 'bg-[#038153] text-white' },
  closed: { label: 'Closed', cls: 'bg-[#87929d] text-white' },
  false_positive: { label: 'False positive', cls: 'bg-[#c2c8cc] text-ink' },
}

export const STATUS_OPTIONS = Object.entries(STATUS_META).map(([value, m]) => ({
  value,
  label: value === 'awaiting_analyst' ? 'Open (awaiting analyst)' : m.label,
}))

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

export const SEVERITY_META: Record<string, { label: string; dot: string; text: string }> = {
  critical: { label: 'Critical', dot: 'bg-severity-critical', text: 'text-severity-critical' },
  high: { label: 'High', dot: 'bg-severity-high', text: 'text-severity-high' },
  medium: { label: 'Medium', dot: 'bg-severity-medium', text: 'text-severity-medium' },
  low: { label: 'Low', dot: 'bg-severity-low', text: 'text-severity-low' },
  info: { label: 'Info', dot: 'bg-severity-info', text: 'text-ink-muted' },
}

export const ACTION_STATUS_META: Record<string, { label: string; cls: string }> = {
  pending_approval: { label: 'Pending', cls: 'bg-[#ffb648] text-[#703b15]' },
  approved: { label: 'Approved', cls: 'bg-[#3091ec] text-white' },
  executing: { label: 'Running', cls: 'bg-[#3091ec] text-white' },
  completed: { label: 'Done', cls: 'bg-[#038153] text-white' },
  failed: { label: 'Failed', cls: 'bg-severity-critical text-white' },
  rejected: { label: 'Rejected', cls: 'bg-[#87929d] text-white' },
}

export const ACTION_LABELS: Record<string, string> = {
  block_ip: 'Block IP address',
  block_url: 'Block URL',
  block_file_hash: 'Block file hash',
  isolate_host: 'Isolate host',
  release_host: 'Release host',
  run_av_scan: 'Run antivirus scan',
  disable_account: 'Disable account',
  enable_account: 'Enable account',
  revoke_sessions: 'Revoke sessions',
  force_password_reset: 'Force password reset',
  purge_email: 'Remove email from mailboxes',
  run_kql_query: 'Run KQL query',
}

// The parameter that names each action's target (mirrors the backend)
export const ACTION_PARAM_KEYS: Record<string, string> = {
  block_ip: 'ip_address',
  block_url: 'url',
  block_file_hash: 'file_hash',
  isolate_host: 'machine_id',
  release_host: 'machine_id',
  run_av_scan: 'machine_id',
  disable_account: 'user_principal_name',
  enable_account: 'user_principal_name',
  revoke_sessions: 'user_principal_name',
  force_password_reset: 'user_principal_name',
  purge_email: 'internet_message_id',
  run_kql_query: 'query',
}

export const ROLE_LABELS: Record<string, string> = {
  tier1_analyst: 'Tier 1 analyst',
  tier2_analyst: 'Tier 2 analyst',
  manager: 'Manager',
  admin: 'Admin',
}

export const PHASE_LABELS: Record<string, string> = {
  preparation: 'Preparation',
  detection_analysis: 'Detection & analysis',
  containment: 'Containment',
  eradication: 'Eradication',
  recovery: 'Recovery',
  post_incident: 'Post-incident',
}

export const STEP_TYPE_LABELS: Record<string, string> = {
  automated: 'Automated',
  human_decision: 'Decision',
  human_action: 'Analyst task',
  info: 'Guidance',
}

const ROLE_RANK: Record<string, number> = { tier1_analyst: 1, tier2_analyst: 2, manager: 3, admin: 4 }
export const hasRole = (role: string | undefined, min: keyof typeof ROLE_RANK | string) =>
  (ROLE_RANK[role || ''] || 0) >= (ROLE_RANK[min] || 99)

export const VERDICT_META: Record<string, { label: string; cls: string }> = {
  malicious: { label: 'Malicious', cls: 'bg-severity-critical text-white' },
  suspicious: { label: 'Suspicious', cls: 'bg-[#ffb648] text-[#703b15]' },
  benign: { label: 'Benign', cls: 'bg-[#038153] text-white' },
  unknown: { label: 'No verdict', cls: 'bg-[#c2c8cc] text-ink' },
}

export const INTEGRATION_CATEGORIES: { key: string; label: string; blurb: string }[] = [
  { key: 'response', label: 'Response', blurb: 'Tools that carry out containment actions: block, isolate, disable.' },
  { key: 'enrichment', label: 'Threat intelligence', blurb: 'Reputation and context lookups for the indicators in an incident.' },
  { key: 'notification', label: 'Notifications & paging', blurb: 'Where people hear about serious incidents and approvals.' },
  { key: 'ticketing', label: 'Ticketing', blurb: 'Keeps a ticket in your system of record in step with each serious incident.' },
  { key: 'source', label: 'Log & alert sources', blurb: 'Polled every minute for new events, which flow through normal ingestion.' },
]
