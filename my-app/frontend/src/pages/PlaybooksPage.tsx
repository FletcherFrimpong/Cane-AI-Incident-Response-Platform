import { useQuery } from '@tanstack/react-query'
import { Plus, BookOpen } from 'lucide-react'
import { playbooksApi } from '../api/playbooks'

export default function PlaybooksPage() {
  const { data: playbooks, isLoading } = useQuery({
    queryKey: ['playbooks'],
    queryFn: () => playbooksApi.list().then((r) => r.data),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Playbooks</h1>
        <button className="btn-primary flex items-center gap-2">
          <Plus className="h-4 w-4" />
          New Playbook
        </button>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading playbooks...</div>
      ) : !playbooks || playbooks.length === 0 ? (
        <div className="card text-center py-12">
          <BookOpen className="h-12 w-12 text-gray-300 mx-auto mb-3" />
          <h3 className="text-lg font-medium text-gray-900 mb-1">
            No playbooks yet
          </h3>
          <p className="text-gray-500 text-sm">
            Create your first playbook to automate incident response.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {playbooks.map((pb: any) => (
            <div key={pb.id} className="card hover:shadow-md transition-shadow">
              <h3 className="font-semibold mb-1">{pb.name}</h3>
              <p className="text-sm text-gray-500 mb-3">
                {pb.description || 'No description'}
              </p>
              <div className="flex items-center justify-between text-sm">
                <span className="badge bg-brand-100 text-brand-800">
                  {pb.trigger_type}
                </span>
                <span className="text-gray-400">
                  {pb.steps_count || 0} steps
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
