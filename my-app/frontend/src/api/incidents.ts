import api from './client'

export const incidentsApi = {
  list: (params?: Record<string, any>) =>
    api.get('/incidents/', { params }),

  get: (id: string) =>
    api.get(`/incidents/${id}`),

  create: (data: any) =>
    api.post('/incidents/', data),

  update: (id: string, data: any) =>
    api.put(`/incidents/${id}`, data),

  assign: (id: string, userId: string) =>
    api.put(`/incidents/${id}/assign`, { user_id: userId }),

  escalate: (id: string) =>
    api.put(`/incidents/${id}/escalate`),

  close: (id: string, content: string) =>
    api.put(`/incidents/${id}/close`, { content }),

  getTimeline: (id: string) =>
    api.get(`/incidents/${id}/timeline`),

  getEvidence: (id: string) =>
    api.get(`/incidents/${id}/evidence`),

  addNote: (id: string, content: string) =>
    api.post(`/incidents/${id}/notes`, { content }),
}
