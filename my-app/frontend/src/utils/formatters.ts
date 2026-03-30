import { format, formatDistanceToNow } from 'date-fns'

export function formatDate(date: string | Date): string {
  return format(new Date(date), 'MMM d, yyyy HH:mm')
}

export function formatRelative(date: string | Date): string {
  return formatDistanceToNow(new Date(date), { addSuffix: true })
}

export function truncate(str: string, len: number = 100): string {
  return str.length > len ? str.slice(0, len) + '...' : str
}
