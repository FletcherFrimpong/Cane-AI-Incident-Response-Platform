import api from './client'

export const actionsApi = {
  pending: () => api.get('/actions/pending'),

  execute: (data: { incident_id: string; action_type: string; action_params?: any }) =>
    api.post('/actions/execute', data),

  approve: (actionId: string, notes?: string) =>
    api.post(`/actions/${actionId}/approve`, { notes }),

  reject: (actionId: string, reason: string) =>
    api.post(`/actions/${actionId}/reject`, { reason }),

  history: (params?: Record<string, any>) =>
    api.get('/actions/history', { params }),
}
