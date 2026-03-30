import { create } from 'zustand'

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  user: any | null
  setTokens: (access: string, refresh: string) => void
  setUser: (user: any) => void
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
    window.location.href = '/login'
  },
}))
