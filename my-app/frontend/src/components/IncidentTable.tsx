import { Fragment } from 'react'
import { useNavigate } from 'react-router-dom'
import type { Incident } from '../types/incident'
import { StatusPill, Severity, Avatar } from './ui'
import { SEVERITIES, SEVERITY_META } from '../utils/constants'
import { formatQueueTime, shortId, titleCase } from '../utils/formatters'

/** The queue table: one row per incident, grouped under a severity heading. */
export default function IncidentTable({
  incidents, users, grouped = true,
}: { incidents: Incident[]; users: Record<string, string>; grouped?: boolean }) {
  const navigate = useNavigate()
  const groups = grouped
    ? SEVERITIES.map((s) => ({ key: s as string, rows: incidents.filter((i) => i.severity === s) })).filter((g) => g.rows.length)
    : [{ key: '', rows: incidents }]

  return (
    <table className="table-queue min-w-[860px]">
      <thead>
        <tr>
          <th className="w-24">Status</th>
          <th className="w-20">ID</th>
          <th>Subject</th>
          <th className="w-36">Attack type</th>
          <th className="w-24">Severity</th>
          <th className="w-36">Updated</th>
          <th className="w-36">Assignee</th>
        </tr>
      </thead>
      <tbody>
        {groups.map((group) => (
          <Fragment key={group.key || 'all'}>
            {grouped && (
              <tr className="group-row">
                <td colSpan={7}>Severity: <span className="font-semibold text-ink">{SEVERITY_META[group.key].label}</span></td>
              </tr>
            )}
            {group.rows.map((incident) => (
              <tr key={incident.id} className="row" onClick={() => navigate(`/incidents/${incident.id}`)}>
                <td><StatusPill status={incident.status} /></td>
                <td className="text-ink-muted tabular-nums">{shortId(incident.id)}</td>
                <td className="max-w-0"><div className="truncate" title={incident.title}>{incident.title}</div></td>
                <td className="text-ink-soft">{incident.attack_type ? titleCase(incident.attack_type) : <span className="text-ink-faint">-</span>}</td>
                <td><Severity value={incident.severity} /></td>
                <td className="text-ink-soft whitespace-nowrap">{formatQueueTime(incident.updated_at)}</td>
                <td>
                  {incident.assigned_to
                    ? <span className="inline-flex items-center gap-1.5"><Avatar name={users[incident.assigned_to]} size={18} /><span className="truncate">{users[incident.assigned_to] || 'Unknown'}</span></span>
                    : <span className="text-ink-faint">-</span>}
                </td>
              </tr>
            ))}
          </Fragment>
        ))}
      </tbody>
    </table>
  )
}
