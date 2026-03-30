import api from './client'

export const usersApi = {
  me: () => api.get('/users/me'),

  updateMe: (data: any) => api.put('/users/me', data),

  list: () => api.get('/users/'),

  updateRole: (userId: string, role: string) =>
    api.put(`/users/${userId}/role`, { role }),

  addApiKey: (data: { provider: string; api_key: string; label: string; is_default?: boolean }) =>
    api.post('/users/me/api-keys', data),

  listApiKeys: () => api.get('/users/me/api-keys'),

  deleteApiKey: (keyId: string) => api.delete(`/users/me/api-keys/${keyId}`),
}
