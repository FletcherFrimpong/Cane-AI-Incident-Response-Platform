import api from './client'

export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),

  register: (email: string, password: string, full_name: string, role: string = 'tier1_analyst') =>
    api.post('/auth/register', { email, password, full_name, role }),

  refresh: (refresh_token: string) =>
    api.post('/auth/refresh', { refresh_token }),
}
