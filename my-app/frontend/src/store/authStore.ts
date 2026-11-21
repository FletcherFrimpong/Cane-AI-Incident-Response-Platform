import { create } from 'zustand'

export interface CurrentUser {
  id: string
  email: string
  full_name: string
  role: string
  is_active: boolean
}

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  user: CurrentUser | null
  setTokens: (access: string, refresh: string) => void
  setUser: (user: CurrentUser | null) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: localStorage.getItem('cane_access_token'),
  refreshToken: localStorage.getItem('cane_refresh_token'),
  user: null,
  setTokens: (access, refresh) => {
    localStorage.setItem('cane_access_token', access)
    localStorage.setItem('cane_refresh_token', refresh)
    set({ accessToken: access, refreshToken: refresh })
  },
  setUser: (user) => set({ user }),
  logout: () => {
    localStorage.removeItem('cane_access_token')
    localStorage.removeItem('cane_refresh_token')
    set({ accessToken: null, refreshToken: null, user: null })
    if (window.location.pathname !== '/login') window.location.href = '/login'
  },
}))
