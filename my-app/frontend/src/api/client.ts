import axios from 'axios'
import { useAuthStore } from '../store/authStore'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = useAuthStore.getState().refreshToken
      if (refreshToken) {
        try {
          const res = await axios.post('/api/v1/auth/refresh', {
            refresh_token: refreshToken,
          })
          useAuthStore.getState().setTokens(
            res.data.access_token,
            res.data.refresh_token,
          )
          error.config.headers.Authorization = `Bearer ${res.data.access_token}`
          return api(error.config)
        } catch {
          useAuthStore.getState().logout()
        }
      } else {
        useAuthStore.getState().logout()
      }
    }
    return Promise.reject(error)
  },
)

export default api
