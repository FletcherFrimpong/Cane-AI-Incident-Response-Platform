import { useQuery } from '@tanstack/react-query'
import { dashboardApi } from '../api/dashboard'
import { AlertTriangle, Shield, Clock, CheckCircle } from 'lucide-react'

export default function DashboardPage() {
  const { data: overview, isLoading, isError } = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: () => dashboardApi.overview().then((r) => r.data),
  })

  if (isLoading) {
    return <div className="text-gray-500">Loading dashboard...</div>
  }

  if (isError) {
    return <div className="card text-center py-12 text-red-600">Failed to load dashboard. Please try again.</div>
  }

  const stats = [
    {
      name: 'Open Incidents',
      value: overview?.open_incidents ?? 0,
      icon: AlertTriangle,
      color: 'text-red-600 bg-red-100',
    },
    {
      name: 'Critical Alerts',
      value: overview?.critical_incidents ?? 0,
      icon: Shield,
      color: 'text-orange-600 bg-orange-100',
    },
    {
      name: 'Avg Response Time',
      value: overview?.mean_time_to_respond_minutes != null
        ? `${overview.mean_time_to_respond_minutes}m`
        : 'N/A',
      icon: Clock,
      color: 'text-blue-600 bg-blue-100',
    },
    {
      name: 'Incidents Today',
      value: overview?.incidents_today ?? 0,
      icon: CheckCircle,
      color: 'text-green-600 bg-green-100',
    },
  ]

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat) => (
          <div key={stat.name} className="card flex items-center gap-4">
            <div className={`p-3 rounded-lg ${stat.color}`}>
              <stat.icon className="h-6 w-6" />
            </div>
            <div>
              <p className="text-sm text-gray-500">{stat.name}</p>
              <p className="text-2xl font-bold">{stat.value}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Recent Threats</h2>
          <p className="text-gray-500 text-sm">
            Threat data will appear here once incidents are created.
          </p>
        </div>
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Activity Timeline</h2>
          <p className="text-gray-500 text-sm">
            Recent activity will appear here.
          </p>
        </div>
      </div>
    </div>
  )
}
