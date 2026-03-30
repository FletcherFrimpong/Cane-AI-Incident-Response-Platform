export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  info: 'bg-gray-100 text-gray-800 border-gray-200',
}

export const STATUS_COLORS: Record<string, string> = {
  new: 'bg-purple-100 text-purple-800',
  triaging: 'bg-blue-100 text-blue-800',
  awaiting_analyst: 'bg-yellow-100 text-yellow-800',
  in_progress: 'bg-cyan-100 text-cyan-800',
  containment: 'bg-orange-100 text-orange-800',
  eradication: 'bg-red-100 text-red-800',
  recovery: 'bg-green-100 text-green-800',
  closed: 'bg-gray-100 text-gray-800',
  false_positive: 'bg-gray-100 text-gray-500',
}

export const SEVERITY_BORDER: Record<string, string> = {
  critical: 'border-l-red-500',
  high: 'border-l-orange-500',
  medium: 'border-l-yellow-500',
  low: 'border-l-blue-500',
  info: 'border-l-gray-300',
}

export const ACTION_STATUS_COLORS: Record<string, string> = {
  pending_approval: 'bg-amber-100 text-amber-800',
  approved: 'bg-green-100 text-green-800',
  rejected: 'bg-red-100 text-red-800',
  executing: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
}

export const TIMELINE_COLORS: Record<string, string> = {
  incident_created: 'border-l-purple-400',
  auto_triage: 'border-l-violet-400',
  ai_analysis: 'border-l-violet-400',
  action_executed: 'border-l-green-400',
  action_failed: 'border-l-red-400',
  action_rejected: 'border-l-red-400',
  assignment: 'border-l-blue-400',
  escalation: 'border-l-orange-400',
  status_change: 'border-l-cyan-400',
  incident_closed: 'border-l-gray-400',
  analyst_note: 'border-l-gray-300',
}

export const ROLE_LABELS: Record<string, string> = {
  tier1_analyst: 'Tier 1 Analyst',
  tier2_analyst: 'Tier 2 Analyst',
  manager: 'Manager',
  admin: 'Admin',
}
