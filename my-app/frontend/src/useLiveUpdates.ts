import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from './store/authStore'

/**
 * Keeps every open page current. The server streams a tiny message whenever an
 * incident or the action queue changes; we answer by refreshing the queries that
 * could be showing it. Pages still poll slowly, so a dropped stream only means
 * slower updates, never stale ones.
 *
 * Uses fetch rather than EventSource so the access token travels in a header
 * instead of the URL (where it would end up in logs and history).
 */
export function useLiveUpdates() {
  const qc = useQueryClient()
  const token = useAuthStore((s) => s.accessToken)

  useEffect(() => {
    if (!token) return
    const controller = new AbortController()
    let stopped = false
    let pending: ReturnType<typeof setTimeout> | null = null
    const touched = new Set<string>()
    let actionsTouched = false

    // Bursts (a batch ingest touches many incidents) collapse into one refresh.
    const flush = () => {
      pending = null
      touched.forEach((id) => qc.invalidateQueries({ queryKey: ['incident', id] }))
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-views'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      if (actionsTouched) qc.invalidateQueries({ queryKey: ['actions'] })
      touched.clear()
      actionsTouched = false
    }
    const handle = (raw: string) => {
      try {
        const msg = JSON.parse(raw)
        if (msg.type === 'incident' && msg.incident_id) touched.add(msg.incident_id)
        if (msg.type === 'actions') actionsTouched = true
        if (!pending) pending = setTimeout(flush, 400)
      } catch { /* ignore malformed frames */ }
    }

    const run = async () => {
      let delay = 1000
      while (!stopped) {
        try {
          const res = await fetch('/api/v1/events/stream', {
            headers: { Authorization: `Bearer ${useAuthStore.getState().accessToken}`, Accept: 'text/event-stream' },
            signal: controller.signal,
          })
          if (res.status === 401) return // the regular API client handles re-login
          if (!res.ok || !res.body) throw new Error(`stream ${res.status}`)
          delay = 1000
          const reader = res.body.getReader()
          const decoder = new TextDecoder()
          let buffer = ''
          for (;;) {
            const { value, done } = await reader.read()
            if (done) break
            buffer += decoder.decode(value, { stream: true })
            let cut: number
            while ((cut = buffer.indexOf('\n\n')) >= 0) {
              const frame = buffer.slice(0, cut)
              buffer = buffer.slice(cut + 2)
              frame.split('\n').forEach((line) => { if (line.startsWith('data: ')) handle(line.slice(6)) })
            }
          }
        } catch {
          if (stopped) return
        }
        await new Promise((r) => setTimeout(r, delay))
        delay = Math.min(delay * 2, 15000)
      }
    }
    run()
    return () => { stopped = true; controller.abort(); if (pending) clearTimeout(pending) }
  }, [token, qc])
}
