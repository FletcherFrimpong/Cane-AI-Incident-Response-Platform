import api from './client'

export const integrationsApi = {
  platforms: () => api.get('/integrations/platforms'),

  list: () => api.get('/integrations/'),

  get: (id: string) => api.get(`/integrations/${id}`),

  create: (data: any) => api.post('/integrations/', data),

  update: (id: string, data: any) => api.put(`/integrations/${id}`, data),

  delete: (id: string) => api.delete(`/integrations/${id}`),

  test: (id: string) => api.post(`/integrations/${id}/test`),

  health: (id: string) => api.get(`/integrations/${id}/health`),
}
