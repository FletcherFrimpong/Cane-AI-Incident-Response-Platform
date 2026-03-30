import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Upload } from 'lucide-react'
import { logsApi } from '../api/logs'
import { formatDate } from '../utils/formatters'
import { SEVERITY_COLORS } from '../utils/constants'
import type { LogEvent } from '../types/log'

export default function LogsPage() {
  const [search, setSearch] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['logs', sourceFilter],
    queryFn: () =>
      logsApi
        .list({
          source_system: sourceFilter || undefined,
          limit: 100,
        })
        .then((r) => r.data),
  })

  const logs: LogEvent[] = data || []
  const filtered = logs.filter(
    (l) =>
      !search ||
      l.summary?.toLowerCase().includes(search.toLowerCase()) ||
      l.source_ip?.includes(search) ||
      l.user_identity?.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Log Events</h1>
        <button className="btn-secondary flex items-center gap-2">
          <Upload className="h-4 w-4" />
          Upload Logs
        </button>
      </div>

      <div className="card mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search logs..."
              className="input pl-9"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            className="input w-auto"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
          >
            <option value="">All Sources</option>
            <option value="microsoft_defender">Microsoft Defender</option>
            <option value="sentinel">Microsoft Sentinel</option>
            <option value="syslog">Syslog</option>
            <option value="custom">Custom</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="text-gray-500">Loading logs...</div>
      ) : filtered.length === 0 ? (
        <div className="card text-center py-12 text-gray-500">
          No log events found.
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-gray-500">
                <th className="pb-3 pr-4">Time</th>
                <th className="pb-3 pr-4">Severity</th>
                <th className="pb-3 pr-4">Source</th>
                <th className="pb-3 pr-4">Summary</th>
                <th className="pb-3 pr-4">Source IP</th>
                <th className="pb-3">User</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {filtered.map((log) => (
                <tr key={log.id} className="hover:bg-gray-50">
                  <td className="py-2 pr-4 whitespace-nowrap">
                    {formatDate(log.time_generated)}
                  </td>
                  <td className="py-2 pr-4">
                    <span
                      className={`badge ${SEVERITY_COLORS[log.severity] || ''}`}
                    >
                      {log.severity}
                    </span>
                  </td>
                  <td className="py-2 pr-4">{log.source_system}</td>
                  <td className="py-2 pr-4 max-w-xs truncate">
                    {log.summary || '-'}
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs">
                    {log.source_ip || '-'}
                  </td>
                  <td className="py-2">{log.user_identity || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
