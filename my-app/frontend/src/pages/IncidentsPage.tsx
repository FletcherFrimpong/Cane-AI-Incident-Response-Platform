import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { Filter, Inbox, RefreshCw, Plus, X } from 'lucide-react'
import { incidentsApi } from '../api/incidents'
import IncidentTable from '../components/IncidentTable'
import NewIncidentModal from '../components/NewIncidentModal'
import { EmptyState, ErrorNote, Loading, Pager, ViewsSidebar, type ViewItem } from '../components/ui'
import { useAssignableUsers } from '../hooks'
import { SEVERITIES, SEVERITY_META } from '../utils/constants'

const PAGE_SIZE = 50

export default function IncidentsPage() {
  const [params, setParams] = useSearchParams()
  const view = params.get('view') || 'attention'
  const search = params.get('search') || ''
  const severity = params.get('severity') || ''
  const page = Number(params.get('page') || 1)
  const [showFilters, setShowFilters] = useState(!!(search || severity))
  const [searchDraft, setSearchDraft] = useState(search)
  const [creating, setCreating] = useState(false)
  const { names } = useAssignableUsers()

  useEffect(() => { setSearchDraft(search); if (search) setShowFilters(true) }, [search])

  const update = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params)
    Object.entries(changes).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)))
    if (!('page' in changes)) next.delete('page')
    setParams(next)
  }

  const views = useQuery({ queryKey: ['incident-views'], queryFn: () => incidentsApi.views().then((r) => r.data as ViewItem[]), refetchInterval: 60_000 })
  const list = useQuery({
    queryKey: ['incidents', view, page, search, severity],
    queryFn: () => incidentsApi.list({ view, page, page_size: PAGE_SIZE, search: search || undefined, severity: severity || undefined }).then((r) => r.data),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  })

  const all = views.data || []
  const label = all.find((v) => v.key === view)?.label || 'Incidents'
  const main = all.filter((v) => !['closed', 'false_positive', 'low'].includes(v.key))
  const rest = all.filter((v) => ['low', 'closed', 'false_positive'].includes(v.key)).map((v) => ({ ...v, muted: true }))

  return (
    <div className="flex-1 flex min-w-0">
      <ViewsSidebar
        title="Views"
        active={view}
        onSelect={(key) => setParams({ view: key })}
        sections={[{ items: main }, { items: rest }]}
        footer={<>Views update live.</>}
      />

      <section className="flex-1 min-w-0 flex flex-col">
        <div className="px-5 pt-5 pb-3 shrink-0">
          <div className="flex items-center justify-between gap-3">
            <h1 className="text-xl font-semibold truncate">{label}</h1>
            <div className="flex items-center gap-2">
              <button className="btn-basic px-2" onClick={() => { views.refetch(); list.refetch() }} title="Refresh" aria-label="Refresh">
                <RefreshCw className={`w-4 h-4 ${list.isFetching ? 'animate-spin' : ''}`} />
              </button>
              <button className="btn-secondary" onClick={() => setCreating(true)}><Plus className="w-4 h-4" /> New incident</button>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <button className={showFilters ? 'btn-secondary bg-brand-50' : 'btn-secondary'} onClick={() => setShowFilters((s) => !s)}>
              <Filter className="w-3.5 h-3.5" /> Filter
            </button>
            {showFilters && (
              <>
                <form onSubmit={(e) => { e.preventDefault(); update({ search: searchDraft.trim() || null }) }} className="w-64">
                  <input className="input" placeholder="Subject, ID, attack type… then Enter" value={searchDraft} onChange={(e) => setSearchDraft(e.target.value)} aria-label="Search this view" />
                </form>
                <select className="input w-40" value={severity} onChange={(e) => update({ severity: e.target.value || null })} aria-label="Severity">
                  <option value="">Any severity</option>
                  {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_META[s].label}</option>)}
                </select>
                {(search || severity) && (
                  <button className="btn-ghost" onClick={() => { setSearchDraft(''); update({ search: null, severity: null }) }}><X className="w-3.5 h-3.5" /> Clear</button>
                )}
              </>
            )}
          </div>
          <div className="text-[13px] text-ink-muted mt-3">
            {list.data ? `${list.data.total.toLocaleString()} incident${list.data.total === 1 ? '' : 's'}` : ' '}
            {search && <> matching "<span className="text-ink">{search}</span>"</>}
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-auto border-t border-line">
          {list.isLoading ? <Loading />
            : list.isError ? <div className="p-5"><ErrorNote>Could not load incidents. Check that the backend is running.</ErrorNote></div>
            : list.data.items.length === 0
              ? <EmptyState icon={<Inbox className="w-8 h-8" />} title="No incidents in this view">{search || severity ? 'Try clearing the filters.' : 'Incidents that match this view will show up here.'}</EmptyState>
              : (
                <>
                  <IncidentTable incidents={list.data.items} users={names} grouped={view !== 'recent'} />
                  <Pager page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) })} />
                </>
              )}
        </div>
      </section>

      {creating && <NewIncidentModal onClose={() => setCreating(false)} />}
    </div>
  )
}
