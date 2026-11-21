import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Inbox } from 'lucide-react'
import { dashboardApi } from '../api/dashboard'
import { incidentsApi } from '../api/incidents'
import IncidentTable from '../components/IncidentTable'
import { Avatar, EmptyState, ErrorNote, Loading } from '../components/ui'
import { useAssignableUsers } from '../hooks'
import { formatQueueTime, titleCase } from '../utils/formatters'

const VERBS: Record<string, string> = {
  incident_created: 'opened',
  auto_triage: 'triaged',
  ai_analysis: 'triaged',
  ai_analysis_failed: 'could not triage',
  action_proposed: 'proposed an action on',
  action_executed: 'ran an action on',
  action_failed: 'failed an action on',
  action_rejected: 'rejected an action on',
  assignment: 'reassigned',
  escalation: 'escalated',
  status_change: 'updated',
  severity_raised: 'raised the severity of',
  incident_closed: 'closed',
  analyst_note: 'commented on',
  playbook_attached: 'attached a playbook to',
  playbook_step_advanced: 'advanced the playbook on',
  playbook_completed: 'completed the playbook on',
}

const actorName = (actor: string) => (actor === 'system' ? 'Cane AI' : actor === 'ai' ? 'Cane AI' : actor.split('@')[0])

function Stat({ value, label, onClick }: { value: number | string; label: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} disabled={!onClick} className="flex-1 min-w-[84px] px-3 py-2 text-center border-r border-line last:border-r-0 enabled:hover:bg-brand-50 disabled:cursor-default">
      <div className="text-lg font-semibold tabular-nums leading-6">{value}</div>
      <div className="text-2xs font-semibold text-ink-muted uppercase tracking-wide">{label}</div>
    </button>
  )
}

function StatGroup({ title, note, children }: { title: string; note: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs mb-1"><span className="font-semibold">{title}</span> <span className="text-ink-muted">({note})</span></div>
      <div className="flex border border-line rounded bg-white">{children}</div>
    </div>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const { names } = useAssignableUsers()

  const overview = useQuery({ queryKey: ['dashboard', 'overview'], queryFn: () => dashboardApi.overview().then((r) => r.data), refetchInterval: 60_000 })
  const feed = useQuery({ queryKey: ['dashboard', 'timeline'], queryFn: () => dashboardApi.timeline(30).then((r) => r.data), refetchInterval: 60_000 })
  const threats = useQuery({ queryKey: ['dashboard', 'threats'], queryFn: () => dashboardApi.threats().then((r) => r.data) })
  const attention = useQuery({
    queryKey: ['incidents', 'attention', 1],
    queryFn: () => incidentsApi.list({ view: 'attention', page_size: 50 }).then((r) => r.data),
    refetchInterval: 60_000,
  })

  const o = overview.data
  const mttr = o?.mean_time_to_respond_minutes
  const mttrLabel = mttr == null ? '-' : mttr < 60 ? `${Math.round(mttr)}m` : mttr < 1440 ? `${(mttr / 60).toFixed(1)}h` : `${(mttr / 1440).toFixed(1)}d`
  const topThreats = (threats.data || []).slice(0, 6)
  const threatMax = Math.max(1, ...topThreats.map((t: any) => t.count))

  return (
    <div className="flex-1 flex min-w-0">
      {/* Updates feed */}
      <aside className="w-[300px] shrink-0 border-r border-line bg-surface flex flex-col min-h-0">
        <div className="px-4 pt-4 pb-2 text-[13px] font-semibold">Updates to your incidents</div>
        <div className="flex-1 overflow-y-auto px-3 pb-3 space-y-2">
          {feed.isLoading && <Loading />}
          {feed.isError && <ErrorNote>Could not load updates.</ErrorNote>}
          {feed.data?.length === 0 && <div className="text-[13px] text-ink-muted px-1 py-6 text-center">No activity yet. Updates appear here as incidents are opened, triaged and worked.</div>}
          {(feed.data || []).map((entry: any) => (
            <Link key={entry.id} to={`/incidents/${entry.incident_id}`} className="block bg-white border border-line rounded p-2.5 hover:border-brand-300">
              <div className="flex gap-2">
                <Avatar name={actorName(entry.actor)} size={22} />
                <div className="min-w-0 text-[13px] leading-[18px]">
                  <div>
                    <span className="font-semibold">{actorName(entry.actor)}</span>{' '}
                    <span className="text-ink-soft">{VERBS[entry.event_type] || 'updated'}</span>{' '}
                    <span className="text-ink">"{entry.incident_title || 'an incident'}"</span>
                  </div>
                  {['analyst_note', 'incident_closed', 'auto_triage', 'ai_analysis'].includes(entry.event_type) && (
                    <div className="text-ink-soft mt-1 line-clamp-2">{entry.description.replace(/^AI triage completed: /, '')}</div>
                  )}
                  <div className="text-xs text-ink-faint mt-1">{formatQueueTime(entry.timestamp)}</div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </aside>

      <section className="flex-1 min-w-0 overflow-y-auto">
        <div className="px-5 pt-4 pb-3 flex flex-wrap gap-5 items-end border-b border-line">
          <StatGroup title="Open incidents" note="current">
            <Stat value={o?.assigned_to_me ?? '-'} label="You" onClick={() => navigate('/incidents?view=mine')} />
            <Stat value={o?.awaiting_analyst ?? '-'} label="Awaiting" onClick={() => navigate('/incidents?view=attention')} />
            <Stat value={o?.open_incidents?.toLocaleString() ?? '-'} label="All" onClick={() => navigate('/incidents?view=open')} />
          </StatGroup>
          <StatGroup title="By severity" note="open">
            <Stat value={o?.critical_incidents ?? '-'} label="Critical" />
            <Stat value={o?.high_incidents ?? '-'} label="High" />
            <Stat value={o?.medium_incidents ?? '-'} label="Medium" />
          </StatGroup>
          <StatGroup title="Incident statistics" note="this week">
            <Stat value={o?.incidents_this_week ?? '-'} label="New" />
            <Stat value={o?.closed_this_week ?? '-'} label="Closed" onClick={() => navigate('/incidents?view=closed')} />
            <Stat value={mttrLabel} label="Avg resolve" />
          </StatGroup>
          <StatGroup title="Response actions" note="awaiting approval">
            <Stat value={o?.pending_actions ?? '-'} label="Pending" onClick={() => navigate('/actions')} />
          </StatGroup>
        </div>

        <div className="px-5 pt-4">
          <div className="flex items-baseline justify-between mb-2">
            <div className="text-[13px] font-semibold">
              Incidents requiring your attention ({attention.data?.total ?? 0}){' '}
              <span className="font-normal text-ink-muted" title="Incidents waiting on an analyst, plus critical and high incidents nobody has picked up yet.">· awaiting an analyst, or serious and not yet picked up</span>
            </div>
            <Link to="/incidents?view=attention" className="link text-[13px]">Open view</Link>
          </div>
          <div className="border border-line rounded overflow-x-auto">
            {attention.isLoading ? <Loading />
              : attention.isError ? <div className="p-4"><ErrorNote>Could not load incidents.</ErrorNote></div>
              : attention.data.items.length === 0
                ? <EmptyState icon={<Inbox className="w-8 h-8" />} title="Nothing needs your attention">No incident is waiting on an analyst right now.</EmptyState>
                : <IncidentTable incidents={attention.data.items} users={names} />}
          </div>
        </div>

        <div className="px-5 py-5">
          <div className="text-[13px] font-semibold mb-2">Attack types <span className="font-normal text-ink-muted">(all incidents)</span></div>
          <div className="border border-line rounded p-4 max-w-2xl">
            {topThreats.length === 0
              ? <div className="text-[13px] text-ink-muted">No classified incidents yet.</div>
              : (
                <div className="space-y-2">
                  {topThreats.map((t: any) => (
                    <div key={t.attack_type} className="grid grid-cols-[150px_1fr_40px] items-center gap-3 text-[13px]">
                      <div className="truncate">{titleCase(t.attack_type)}</div>
                      <div className="h-2 bg-surface-sunken rounded-sm overflow-hidden">
                        <div className="h-full bg-brand-500 rounded-sm" style={{ width: `${(t.count / threatMax) * 100}%` }} />
                      </div>
                      <div className="text-right tabular-nums text-ink-soft">{t.count}</div>
                    </div>
                  ))}
                </div>
              )}
          </div>
        </div>
      </section>
    </div>
  )
}
