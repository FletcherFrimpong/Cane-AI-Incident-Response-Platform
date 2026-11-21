import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { RefreshCw, ScrollText, Upload, X } from 'lucide-react'
import { logsApi } from '../api/logs'
import { EmptyState, ErrorNote, Loading, Pager, Severity, ViewsSidebar, notify } from '../components/ui'
import { errorMessage, formatDate, shortId } from '../utils/formatters'

const PAGE_SIZE = 100
const SEVERITY_VIEWS = [
  { key: 'all', label: 'All events' },
  { key: 'sev:critical', label: 'Critical' },
  { key: 'sev:high', label: 'High' },
  { key: 'sev:medium', label: 'Medium' },
  { key: 'sev:low', label: 'Low' },
  { key: 'sev:info', label: 'Informational' },
]
const TYPE_NAMES: Record<string, string> = {
  securityalert: 'SecurityAlert', securityevent: 'SecurityEvent', signinlogs: 'SignInLogs', commonsecuritylog: 'CommonSecurityLog',
  emailevents: 'EmailEvents', emailattachmentinfo: 'EmailAttachmentInfo', emailurlinfo: 'EmailUrlInfo', dnsevents: 'DNSEvents',
  appservicehttplogs: 'AppServiceHTTPLogs', auditlogs: 'AuditLogs', officeactivity: 'OfficeActivity', awscloudtrail: 'AWSCloudTrail',
  event: 'Event', heartbeat: 'Heartbeat',
}

export default function LogsPage() {
  const qc = useQueryClient()
  const [params, setParams] = useSearchParams()
  const [view, setView] = useState('all')
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [draft, setDraft] = useState('')
  const [openId, setOpenId] = useState<string | null>(null)
  const [result, setResult] = useState<any | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (params.get('upload')) { fileInput.current?.click(); params.delete('upload'); setParams(params, { replace: true }) }
  }, [params, setParams])

  const schemas = useQuery({ queryKey: ['log-schemas'], queryFn: () => logsApi.getSchemas().then((r) => r.data.schemas as string[]), staleTime: Infinity })
  const filters = view.startsWith('sev:') ? { severity: view.slice(4) } : view.startsWith('type:') ? { log_type: TYPE_NAMES[view.slice(5)] || view.slice(5) } : {}
  const list = useQuery({
    queryKey: ['logs', view, page, search],
    queryFn: () => logsApi.list({ page, page_size: PAGE_SIZE, search: search || undefined, ...filters }).then((r) => r.data),
    placeholderData: keepPreviousData,
  })
  const detail = useQuery({ queryKey: ['log', openId], queryFn: () => logsApi.get(openId!).then((r) => r.data), enabled: !!openId })

  const upload = useMutation({
    mutationFn: (file: File) => logsApi.upload(file).then((r) => r.data),
    onSuccess: (data) => {
      setResult(data)
      qc.invalidateQueries({ queryKey: ['logs'] }); qc.invalidateQueries({ queryKey: ['incidents'] }); qc.invalidateQueries({ queryKey: ['incident-views'] }); qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
    onError: (e) => notify.error('Upload failed', errorMessage(e)),
  })

  const select = (key: string) => { setView(key); setPage(1) }
  const title = view === 'all' ? 'All events' : view.startsWith('sev:') ? `${SEVERITY_VIEWS.find((v) => v.key === view)?.label} events` : TYPE_NAMES[view.slice(5)] || view.slice(5)

  return (
    <div className="flex-1 flex min-w-0">
      <ViewsSidebar
        title="Logs"
        active={view}
        onSelect={select}
        sections={[
          { heading: 'Severity', items: SEVERITY_VIEWS },
          { heading: 'Log type', items: (schemas.data || []).map((s) => ({ key: `type:${s}`, label: TYPE_NAMES[s] || s })) },
        ]}
      />
      <section className="flex-1 min-w-0 flex flex-col">
        <div className="px-5 pt-5 pb-3 shrink-0">
          <div className="flex items-center justify-between gap-3">
            <h1 className="text-xl font-semibold truncate">{title}</h1>
            <div className="flex items-center gap-2">
              <button className="btn-basic px-2" onClick={() => list.refetch()} title="Refresh" aria-label="Refresh"><RefreshCw className={`w-4 h-4 ${list.isFetching ? 'animate-spin' : ''}`} /></button>
              <input ref={fileInput} type="file" accept=".json,application/json" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload.mutate(f); e.target.value = '' }} />
              <button className="btn-secondary" disabled={upload.isPending} onClick={() => fileInput.current?.click()}><Upload className="w-4 h-4" /> {upload.isPending ? 'Uploading…' : 'Upload log file'}</button>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-3">
            <form className="w-80 shrink-0" onSubmit={(e) => { e.preventDefault(); setSearch(draft.trim()); setPage(1) }}>
              <input className="input" placeholder="Search summary, host, account, correlation ID… then Enter" value={draft} onChange={(e) => setDraft(e.target.value)} aria-label="Search logs" />
            </form>
            {search && <button className="btn-ghost" onClick={() => { setDraft(''); setSearch(''); setPage(1) }}><X className="w-3.5 h-3.5" /> Clear</button>}
            <div className="text-[13px] text-ink-muted ml-1">{list.data ? `${list.data.total.toLocaleString()} event${list.data.total === 1 ? '' : 's'}` : ''}</div>
          </div>
          {result && (
            <div className="mt-3 flex items-start justify-between gap-3 rounded border border-[#aecfc2] bg-[#edf8f4] px-3 py-2 text-[13px] text-[#186146]">
              <div>
                <span className="font-semibold">{result.filename}</span>: {result.ingested.toLocaleString()} events ingested, {result.incidents_created} incident{result.incidents_created === 1 ? '' : 's'} opened
                {result.errors > 0 && <span className="text-[#8c232c]">, {result.errors} rejected ({result.error_details?.[0]?.error})</span>}.
                {result.incidents_created > 0 && <> <Link className="link" to="/incidents?view=recent">View incidents</Link></>}
              </div>
              <button onClick={() => setResult(null)} aria-label="Dismiss"><X className="w-4 h-4" /></button>
            </div>
          )}
        </div>
        <div className="flex-1 min-h-0 overflow-auto border-t border-line">
          {list.isLoading ? <Loading />
            : list.isError ? <div className="p-5"><ErrorNote>Could not load log events.</ErrorNote></div>
            : list.data.items.length === 0
              ? <EmptyState icon={<ScrollText className="w-8 h-8" />} title="No log events">{search ? 'Nothing matches that search.' : 'Upload a JSON log file, or point your Sentinel webhook at /api/v1/logs/ingest.'}</EmptyState>
              : (
                <>
                  <table className="table-queue min-w-[980px]">
                    <thead><tr><th className="w-40">Time</th><th className="w-28">Severity</th><th className="w-44">Type</th><th>Summary</th><th className="w-36">Source IP</th><th className="w-44">Host</th><th className="w-24">Incident</th></tr></thead>
                    <tbody>
                      {list.data.items.map((e: any) => (
                        <tr key={e.id} className="row" onClick={() => setOpenId(e.id)}>
                          <td className="whitespace-nowrap text-ink-soft tabular-nums">{formatDate(e.time_generated)}</td>
                          <td><Severity value={e.severity} /></td>
                          <td className="whitespace-nowrap">{e.log_type}</td>
                          <td className="max-w-0"><div className="truncate" title={e.summary || ''}>{e.summary || '-'}</div></td>
                          <td className="font-mono text-xs">{e.source_ip || '-'}</td>
                          <td className="max-w-0 text-ink-soft"><div className="truncate">{e.host || '-'}</div></td>
                          <td onClick={(ev) => ev.stopPropagation()}>{e.incident_id ? <Link className="link" to={`/incidents/${e.incident_id}`}>{shortId(e.incident_id)}</Link> : <span className="text-ink-faint">-</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <Pager page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={setPage} />
                </>
              )}
        </div>
      </section>

      {openId && (
        <aside className="w-[420px] shrink-0 border-l border-line flex flex-col bg-white">
          <div className="h-12 shrink-0 flex items-center justify-between px-4 border-b border-line">
            <div className="font-semibold text-[13px]">Event detail</div>
            <button onClick={() => setOpenId(null)} aria-label="Close"><X className="w-4 h-4 text-ink-muted" /></button>
          </div>
          <div className="flex-1 overflow-y-auto p-4 text-[13px]">
            {detail.isLoading ? <Loading /> : detail.isError || !detail.data ? <ErrorNote>Could not load this event.</ErrorNote> : (
              <>
                <div className="font-semibold mb-1">{detail.data.summary || detail.data.log_type}</div>
                <div className="grid grid-cols-[110px_1fr] gap-y-1.5 text-[13px] mb-4">
                  <div className="text-ink-muted">Time</div><div>{formatDate(detail.data.time_generated)}</div>
                  <div className="text-ink-muted">Type</div><div>{detail.data.log_type}</div>
                  <div className="text-ink-muted">Severity</div><div><Severity value={detail.data.severity} /></div>
                  <div className="text-ink-muted">Source system</div><div className="break-all">{detail.data.source_system}</div>
                  <div className="text-ink-muted">Source IP</div><div className="font-mono text-xs">{detail.data.source_ip || '-'}</div>
                  <div className="text-ink-muted">Destination IP</div><div className="font-mono text-xs">{detail.data.destination_ip || '-'}</div>
                  <div className="text-ink-muted">Host</div><div className="break-all">{detail.data.host || '-'}</div>
                  <div className="text-ink-muted">Account</div><div className="break-all">{detail.data.user_identity || '-'}</div>
                  <div className="text-ink-muted">Correlation ID</div><div className="font-mono text-xs break-all">{detail.data.correlation_id || '-'}</div>
                  <div className="text-ink-muted">Incident</div><div>{detail.data.incident_id ? <Link className="link" to={`/incidents/${detail.data.incident_id}`}>{shortId(detail.data.incident_id)}</Link> : 'Not linked'}</div>
                </div>
                <div className="panel-title mb-1.5">Raw event</div>
                <pre className="bg-surface-sunken border border-line rounded p-3 text-[11px] leading-4 overflow-x-auto whitespace-pre-wrap break-all">{JSON.stringify(detail.data.raw_data, null, 2)}</pre>
              </>
            )}
          </div>
        </aside>
      )}
    </div>
  )
}
