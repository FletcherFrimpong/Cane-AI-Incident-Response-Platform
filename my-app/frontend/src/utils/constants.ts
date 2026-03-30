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

export const ROLE_LABELS: Record<string, string> = {
  tier1_analyst: 'Tier 1 Analyst',
  tier2_analyst: 'Tier 2 Analyst',
  manager: 'Manager',
  admin: 'Admin',
}
