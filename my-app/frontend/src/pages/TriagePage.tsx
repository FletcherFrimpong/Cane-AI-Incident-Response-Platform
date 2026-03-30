import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Brain, Loader2 } from 'lucide-react'
import { triageApi } from '../api/triage'
import { incidentsApi } from '../api/incidents'
import type { Incident } from '../types/incident'

export default function TriagePage() {
  const [selectedIncident, setSelectedIncident] = useState('')
  const [provider, setProvider] = useState('claude')

  const { data: incidents } = useQuery({
    queryKey: ['incidents-for-triage'],
    queryFn: () =>
      incidentsApi.list({ status: 'new' }).then((r) => r.data as Incident[]),
  })

  const analyzeMutation = useMutation({
    mutationFn: () => triageApi.analyze(selectedIncident, provider),
  })

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">AI Triage</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Analyze Incident</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Select Incident
              </label>
              <select
                className="input"
                value={selectedIncident}
                onChange={(e) => setSelectedIncident(e.target.value)}
              >
                <option value="">Choose an incident...</option>
                {incidents?.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.title} ({i.severity})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                AI Provider
              </label>
              <select
                className="input"
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
              >
                <option value="claude">Claude (Anthropic)</option>
                <option value="openai">OpenAI GPT-4</option>
                <option value="gemini">Google Gemini</option>
              </select>
            </div>
            <button
              className="btn-primary flex items-center gap-2"
              disabled={!selectedIncident || analyzeMutation.isPending}
              onClick={() => analyzeMutation.mutate()}
            >
              {analyzeMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Brain className="h-4 w-4" />
              )}
              {analyzeMutation.isPending ? 'Analyzing...' : 'Run Analysis'}
            </button>
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Analysis Results</h2>
          {analyzeMutation.isSuccess ? (
            <pre className="text-sm bg-gray-50 p-4 rounded-lg overflow-auto max-h-96">
              {JSON.stringify(analyzeMutation.data?.data, null, 2)}
            </pre>
          ) : analyzeMutation.isError ? (
            <div className="p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
              Analysis failed. Please try again.
            </div>
          ) : (
            <p className="text-gray-500 text-sm">
              Select an incident and run analysis to see AI triage results.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
