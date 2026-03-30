import { create } from 'zustand'

interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message?: string
  timestamp: Date
}

interface NotificationState {
  notifications: Notification[]
  add: (notification: Omit<Notification, 'id' | 'timestamp'>) => void
  remove: (id: string) => void
  clear: () => void
}

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],
  add: (notification) =>
    set((state) => ({
      notifications: [
        { ...notification, id: crypto.randomUUID(), timestamp: new Date() },
        ...state.notifications,
      ].slice(0, 50),
    })),
  remove: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),
  clear: () => set({ notifications: [] }),
}))
