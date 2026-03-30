import api from './client'

export const triageApi = {
  analyze: (incidentId: string, provider?: string, model?: string) =>
    api.post('/triage/analyze', {
      incident_id: incidentId,
      provider: provider || 'claude',
      model,
    }),

  getResults: (incidentId: string) =>
    api.get(`/triage/${incidentId}`),

  getRecommendations: (incidentId: string) =>
    api.get(`/triage/${incidentId}/recommendations`),

  correlate: (correlationId: string, provider?: string) =>
    api.post('/triage/correlate', {
      correlation_id: correlationId,
      provider: provider || 'claude',
    }),
}
