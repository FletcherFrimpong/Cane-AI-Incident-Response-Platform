import api from './client'

export const dashboardApi = {
  overview: () => api.get('/dashboard/overview'),
  threats: () => api.get('/dashboard/threats'),
  geo: () => api.get('/dashboard/geo'),
  timeline: (limit?: number) => api.get('/dashboard/timeline', { params: { limit } }),
}
