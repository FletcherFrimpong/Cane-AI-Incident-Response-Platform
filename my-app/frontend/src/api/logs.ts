import api from './client'

export const logsApi = {
  list: (params?: Record<string, any>) =>
    api.get('/logs/', { params }),

  get: (id: string) =>
    api.get(`/logs/${id}`),

  ingest: (schemaId: string, data: any) =>
    api.post('/logs/ingest', { schemaId, data }),

  batchIngest: (events: any[]) =>
    api.post('/logs/batch', { events }),

  upload: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/logs/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },

  getSchemas: () =>
    api.get('/logs/schemas'),
}
