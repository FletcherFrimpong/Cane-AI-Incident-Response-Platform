import api from './client'

export const playbooksApi = {
  list: (params?: Record<string, any>) =>
    api.get('/playbooks/', { params }),

  get: (id: string) =>
    api.get(`/playbooks/${id}`),

  create: (data: any) =>
    api.post('/playbooks/', data),

  update: (id: string, data: any) =>
    api.put(`/playbooks/${id}`, data),

  delete: (id: string) =>
    api.delete(`/playbooks/${id}`),

  getSteps: (id: string) =>
    api.get(`/playbooks/${id}/steps`),

  addStep: (id: string, data: any) =>
    api.post(`/playbooks/${id}/steps`, data),

  updateStep: (playbookId: string, stepId: string, data: any) =>
    api.put(`/playbooks/${playbookId}/steps/${stepId}`, data),

  deleteStep: (playbookId: string, stepId: string) =>
    api.delete(`/playbooks/${playbookId}/steps/${stepId}`),

  execute: (playbookId: string, incidentId: string) =>
    api.post(`/playbooks/${playbookId}/execute/${incidentId}`),
}
