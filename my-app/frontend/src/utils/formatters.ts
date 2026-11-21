import { format, formatDistanceToNow, isToday, isYesterday, differenceInDays } from 'date-fns'

export function formatDate(date: string | Date): string {
  return format(new Date(date), 'MMM d, yyyy HH:mm')
}

export function formatRelative(date: string | Date): string {
  return formatDistanceToNow(new Date(date), { addSuffix: true })
}

/** Queue-style timestamp: "12 minutes ago", "Yesterday 22:44", "Thursday 09:08", "Mar 30". */
export function formatQueueTime(date: string | Date): string {
  const d = new Date(date)
  if (isToday(d)) return formatDistanceToNow(d, { addSuffix: true })
  if (isYesterday(d)) return `Yesterday ${format(d, 'HH:mm')}`
  if (differenceInDays(new Date(), d) < 7) return format(d, 'EEEE HH:mm')
  return format(d, d.getFullYear() === new Date().getFullYear() ? 'MMM d' : 'MMM d, yyyy')
}

export function truncate(str: string, len: number = 100): string {
  return str.length > len ? str.slice(0, len) + '...' : str
}

/** Short, readable incident reference from its UUID. */
export const shortId = (id: string) => `#${id.slice(0, 6).toUpperCase()}`

const ACRONYMS: Record<string, string> = { ddos: 'DDoS', sql: 'SQL', ip: 'IP', url: 'URL', av: 'AV', kql: 'KQL', id: 'ID', api: 'API', apt: 'APT' }

export const titleCase = (s: string | null | undefined) =>
  (s || '')
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((word, i) => ACRONYMS[word.toLowerCase()] || (i === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word))
    .join(' ')

/** Human-readable message from an axios error. */
export function errorMessage(err: any, fallback = 'Something went wrong'): string {
  const detail = err?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail.length) {
    return detail.map((d: any) => `${(d.loc || []).slice(1).join('.')}: ${d.msg}`).join('; ')
  }
  return err?.message || fallback
}
