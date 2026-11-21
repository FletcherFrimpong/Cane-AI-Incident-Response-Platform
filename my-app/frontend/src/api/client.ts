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

// One refresh at a time: parallel requests that all hit 401 share the same attempt.
let refreshing: Promise<string> | null = null

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config || {}
    const isAuthCall = typeof original.url === 'string' && original.url.startsWith('/auth/')
    // A 401 from login/refresh is an answer ("wrong password"), not an expired session.
    if (error.response?.status !== 401 || isAuthCall || original._retried) {
      return Promise.reject(error)
    }
    const refreshToken = useAuthStore.getState().refreshToken
    if (!refreshToken) {
      useAuthStore.getState().logout()
      return Promise.reject(error)
    }
    try {
      refreshing =
        refreshing ||
        axios.post('/api/v1/auth/refresh', { refresh_token: refreshToken }).then((res) => {
          useAuthStore.getState().setTokens(res.data.access_token, res.data.refresh_token)
          return res.data.access_token as string
        })
      const token = await refreshing
      original._retried = true
      original.headers = { ...(original.headers || {}), Authorization: `Bearer ${token}` }
      return api(original)
    } catch {
      useAuthStore.getState().logout()
      return Promise.reject(error)
    } finally {
      refreshing = null
    }
  },
)

export default api
