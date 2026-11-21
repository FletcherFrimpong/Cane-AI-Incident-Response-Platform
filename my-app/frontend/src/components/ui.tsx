import { type ReactNode, useEffect } from 'react'
import { clsx } from 'clsx'
import { X, CheckCircle2, AlertCircle, Info, Loader2, ChevronLeft, ChevronRight } from 'lucide-react'
import { STATUS_META, SEVERITY_META, ACTION_STATUS_META } from '../utils/constants'
import { useNotificationStore } from '../store/notificationStore'

export function StatusPill({ status }: { status: string }) {
  const meta = STATUS_META[status] || { label: status, cls: 'bg-surface-sunken text-ink' }
  return <span className={clsx('pill', meta.cls)}>{meta.label}</span>
}

export function ActionPill({ status }: { status: string }) {
  const meta = ACTION_STATUS_META[status] || { label: status, cls: 'bg-surface-sunken text-ink' }
  return <span className={clsx('pill', meta.cls)}>{meta.label}</span>
}

export function Severity({ value, plain = false }: { value: string; plain?: boolean }) {
  const meta = SEVERITY_META[value] || SEVERITY_META.info
  return (
    <span className={clsx('inline-flex items-center gap-1.5 whitespace-nowrap', !plain && meta.text, !plain && value !== 'info' && 'font-medium')}>
      <span className={clsx('w-2 h-2 rounded-full shrink-0', meta.dot)} />
      {meta.label}
    </span>
  )
}

export function Avatar({ name, size = 24 }: { name?: string | null; size?: number }) {
  const initials = (name || '?').split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0]?.toUpperCase()).join('')
  return (
    <span
      className="inline-flex items-center justify-center rounded-full bg-[#c2c8cc] text-white font-semibold shrink-0 select-none"
      style={{ width: size, height: size, fontSize: Math.max(9, size * 0.4) }}
    >
      {initials || '?'}
    </span>
  )
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={clsx('animate-spin text-ink-faint', className || 'w-4 h-4')} />
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-ink-muted text-[13px]">
      <Spinner /> {label}
    </div>
  )
}

export function EmptyState({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-16 px-6">
      {icon && <div className="text-ink-faint mb-3">{icon}</div>}
      <div className="font-semibold text-ink">{title}</div>
      {children && <div className="text-[13px] text-ink-muted mt-1 max-w-md">{children}</div>}
    </div>
  )
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2 px-3 py-2 rounded border border-[#f5b5ba] bg-[#fff0f1] text-[13px] text-[#8c232c]">
      <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
      <div>{children}</div>
    </div>
  )
}

/** Left "Views" column shared by every queue page. */
export interface ViewItem { key: string; label: string; count?: number | null; muted?: boolean; danger?: boolean }

export function ViewsSidebar({
  title, sections, active, onSelect, footer,
}: {
  title: string
  sections: { heading?: string; items: ViewItem[] }[]
  active: string
  onSelect: (key: string) => void
  footer?: ReactNode
}) {
  return (
    <aside className="w-60 shrink-0 border-r border-line bg-surface flex flex-col min-h-0">
      <div className="px-4 pt-5 pb-3 text-[15px] font-semibold">{title}</div>
      <nav className="flex-1 overflow-y-auto px-2 pb-3">
        {sections.map((section, i) => (
          <div key={i} className={clsx(i > 0 && 'mt-3 pt-3 border-t border-line')}>
            {section.heading && <div className="px-2 pb-1 panel-title">{section.heading}</div>}
            {section.items.map((item) => (
              <button
                key={item.key}
                onClick={() => onSelect(item.key)}
                className={clsx(
                  'w-full flex items-center justify-between gap-2 px-2 h-8 rounded text-[13px] text-left',
                  active === item.key ? 'bg-brand-100 font-semibold text-ink' : 'hover:bg-line-soft',
                  item.muted && active !== item.key && 'text-ink-muted',
                  item.danger && 'text-severity-critical',
                )}
              >
                <span className="truncate">{item.label}</span>
                {item.count != null && <span className="tabular-nums text-ink-soft">{item.count.toLocaleString()}</span>}
              </button>
            ))}
          </div>
        ))}
      </nav>
      {footer && <div className="border-t border-line px-4 py-3 text-xs text-ink-muted">{footer}</div>}
    </aside>
  )
}

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-center gap-1 py-3 text-[13px]">
      <button className="btn-basic btn-sm px-1.5" disabled={page <= 1} onClick={() => onPage(page - 1)} aria-label="Previous page">
        <ChevronLeft className="w-4 h-4" />
      </button>
      <span className="px-3 text-ink-soft tabular-nums">Page {page} of {pages.toLocaleString()}</span>
      <button className="btn-basic btn-sm px-1.5" disabled={page >= pages} onClick={() => onPage(page + 1)} aria-label="Next page">
        <ChevronRight className="w-4 h-4" />
      </button>
    </div>
  )
}

export function Modal({
  title, children, onClose, footer, width = 'max-w-lg',
}: { title: string; children: ReactNode; onClose: () => void; footer?: ReactNode; width?: string }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-4 bg-[#2f3941]/50" onMouseDown={onClose}>
      <div className={clsx('bg-white rounded-md shadow-xl w-full flex flex-col max-h-[80vh]', width)} onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 h-12 border-b border-line shrink-0">
          <div className="font-semibold text-[15px]">{title}</div>
          <button onClick={onClose} className="text-ink-muted hover:text-ink" aria-label="Close"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-5 py-4 overflow-y-auto">{children}</div>
        {footer && <div className="flex justify-end gap-2 px-5 py-3 border-t border-line bg-surface rounded-b-md shrink-0">{footer}</div>}
      </div>
    </div>
  )
}

/** Label-left form row, as in an admin centre. */
export function FormRow({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[180px_1fr] gap-4 py-3 items-start">
      <div className="text-[13px] font-semibold pt-1.5">{label}</div>
      <div className="max-w-md">
        {children}
        {hint && <div className="hint">{hint}</div>}
      </div>
    </div>
  )
}

export function Toaster() {
  const { notifications, remove } = useNotificationStore()
  useEffect(() => {
    if (!notifications.length) return
    const timers = notifications.map((n) => setTimeout(() => remove(n.id), n.type === 'error' ? 8000 : 4500))
    return () => timers.forEach(clearTimeout)
  }, [notifications, remove])
  return (
    <div className="fixed top-14 right-4 z-[60] flex flex-col gap-2 w-80">
      {notifications.slice(0, 4).map((n) => (
        <div key={n.id} className="flex items-start gap-2 bg-white border border-line rounded shadow-lg px-3 py-2.5 text-[13px]">
          {n.type === 'success' ? <CheckCircle2 className="w-4 h-4 mt-0.5 text-[#038153] shrink-0" />
            : n.type === 'error' ? <AlertCircle className="w-4 h-4 mt-0.5 text-severity-critical shrink-0" />
            : <Info className="w-4 h-4 mt-0.5 text-brand-500 shrink-0" />}
          <div className="flex-1 min-w-0">
            <div className="font-medium">{n.title}</div>
            {n.message && <div className="text-ink-muted break-words">{n.message}</div>}
          </div>
          <button onClick={() => remove(n.id)} className="text-ink-faint hover:text-ink" aria-label="Dismiss"><X className="w-3.5 h-3.5" /></button>
        </div>
      ))}
    </div>
  )
}

export const notify = {
  success: (title: string, message?: string) => useNotificationStore.getState().add({ type: 'success', title, message }),
  error: (title: string, message?: string) => useNotificationStore.getState().add({ type: 'error', title, message }),
  info: (title: string, message?: string) => useNotificationStore.getState().add({ type: 'info', title, message }),
}
