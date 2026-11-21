import api from './client'

export const usersApi = {
  me: () => api.get('/users/me'),

  updateMe: (data: any) => api.put('/users/me', data),

  list: () => api.get('/users/'),

  assignable: () => api.get('/users/assignable'),

  create: (data: { email: string; password: string; full_name: string; role: string }) =>
    api.post('/users/', data),

  setActive: (userId: string, isActive: boolean) =>
    api.put(`/users/${userId}/active`, { is_active: isActive }),

  updateRole: (userId: string, role: string) =>
    api.put(`/users/${userId}/role`, { role }),

  addApiKey: (data: { provider: string; api_key: string; label: string; is_default?: boolean }) =>
    api.post('/users/me/api-keys', data),

  listApiKeys: () => api.get('/users/me/api-keys'),

  deleteApiKey: (keyId: string) => api.delete(`/users/me/api-keys/${keyId}`),
}
