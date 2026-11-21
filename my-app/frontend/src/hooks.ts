import { useQuery } from '@tanstack/react-query'
import { usersApi } from './api/users'

export interface Assignable { id: string; full_name: string; role: string }

/** Active analysts, plus an id -> name lookup for table cells. */
export function useAssignableUsers() {
  const query = useQuery({
    queryKey: ['users', 'assignable'],
    queryFn: () => usersApi.assignable().then((r) => r.data as Assignable[]),
    staleTime: 60_000,
  })
  const users = query.data || []
  const names: Record<string, string> = {}
  users.forEach((u) => { names[u.id] = u.full_name })
  return { users, names }
}
