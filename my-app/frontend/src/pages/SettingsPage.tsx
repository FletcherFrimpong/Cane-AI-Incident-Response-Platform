import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { AlertTriangle, CheckCircle2, Plus, Trash2, XCircle } from 'lucide-react'
import { usersApi } from '../api/users'
import { integrationsApi } from '../api/integrations'
import { useAuthStore } from '../store/authStore'
import { ErrorNote, FormRow, Loading, Modal, notify } from '../components/ui'
import { INTEGRATION_CATEGORIES, ROLE_LABELS, hasRole } from '../utils/constants'
import { errorMessage, formatDate, formatQueueTime, titleCase } from '../utils/formatters'

type Section = 'profile' | 'api-keys' | 'integrations' | 'team'
const PROVIDERS = [{ value: 'claude', label: 'Anthropic Claude' }, { value: 'openai', label: 'OpenAI' }, { value: 'azure_openai', label: 'Azure OpenAI' }]

function SectionTitle({ title, children, action }: { title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 pb-3 mb-1 border-b border-line">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {children && <p className="text-[13px] text-ink-muted mt-1 max-w-2xl">{children}</p>}
      </div>
      {action}
    </div>
  )
}

function Profile() {
  const qc = useQueryClient()
  const { user, setUser } = useAuthStore()
  const [name, setName] = useState(user?.full_name || '')
  // The profile arrives after first render on a fresh page load
  useEffect(() => { if (user?.full_name) setName(user.full_name) }, [user?.full_name])
  const save = useMutation({
    mutationFn: () => usersApi.updateMe({ full_name: name.trim() }),
    onSuccess: (res) => { setUser(res.data); qc.invalidateQueries({ queryKey: ['me'] }); qc.invalidateQueries({ queryKey: ['users'] }); notify.success('Profile saved') },
    onError: (e) => notify.error('Could not save your profile', errorMessage(e)),
  })
  if (!user) return <Loading />
  return (
    <>
      <SectionTitle title="Profile">How you appear to other analysts on incidents and notes.</SectionTitle>
      <div className="divide-y divide-line-soft">
        <FormRow label="Display name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></FormRow>
        <FormRow label="Email" hint="Your sign-in. Ask an administrator to change it."><div className="pt-1.5 text-[13px]">{user.email}</div></FormRow>
        <FormRow label="Role" hint="Tier 2 and above can approve containment actions. Managers edit playbooks. Admins manage integrations and people.">
          <div className="pt-1"><span className="tag">{ROLE_LABELS[user.role] || user.role}</span></div>
        </FormRow>
      </div>
      <div className="pt-4 border-t border-line flex gap-2">
        <button className="btn-primary" disabled={!name.trim() || name.trim() === user.full_name || save.isPending} onClick={() => save.mutate()}>Save changes</button>
        <button className="btn-basic" disabled={name === user.full_name} onClick={() => setName(user.full_name)}>Revert</button>
      </div>
    </>
  )
}

function ApiKeys() {
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ provider: 'claude', label: '', api_key: '' })
  const keys = useQuery({ queryKey: ['api-keys'], queryFn: () => usersApi.listApiKeys().then((r) => r.data as any[]) })
  const add = useMutation({
    mutationFn: () => usersApi.addApiKey({ provider: form.provider, label: form.label.trim() || 'My key', api_key: form.api_key.trim(), is_default: true }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['api-keys'] }); setAdding(false); setForm({ provider: 'claude', label: '', api_key: '' }); notify.success('API key saved') },
    onError: (e) => notify.error('Could not save the key', errorMessage(e)),
  })
  const del = useMutation({
    mutationFn: (id: string) => usersApi.deleteApiKey(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
    onError: (e) => notify.error('Could not delete the key', errorMessage(e)),
  })
  return (
    <>
      <SectionTitle title="API keys" action={<button className="btn-secondary shrink-0" onClick={() => setAdding(true)}><Plus className="w-4 h-4" /> Add key</button>}>
        Your own LLM key, used when you run AI triage on an incident. The most recent key is your default. Without one, triage falls back to the platform's system key if an administrator has configured it.
      </SectionTitle>
      {keys.isLoading ? <Loading /> : keys.isError ? <ErrorNote>Could not load your keys.</ErrorNote> : keys.data!.length === 0
        ? <div className="text-[13px] text-ink-muted py-6">You have not added a key.</div>
        : (
          <table className="table-queue mt-2">
            <thead><tr><th>Label</th><th>Provider</th><th>Key</th><th>Added</th><th className="w-12" /></tr></thead>
            <tbody>
              {keys.data!.map((k) => (
                <tr key={k.id}>
                  <td className="font-medium">{k.label} {k.is_default && <span className="tag ml-1">Default</span>}</td>
                  <td>{PROVIDERS.find((p) => p.value === k.provider)?.label || k.provider}</td>
                  <td className="font-mono text-xs">{k.masked_key}</td>
                  <td className="text-ink-soft">{formatDate(k.created_at)}</td>
                  <td><button className="text-ink-muted hover:text-severity-critical" onClick={() => window.confirm(`Delete the key "${k.label}"?`) && del.mutate(k.id)} aria-label="Delete key"><Trash2 className="w-4 h-4" /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      {adding && (
        <Modal title="Add API key" onClose={() => setAdding(false)} footer={<>
          <button className="btn-basic" onClick={() => setAdding(false)}>Cancel</button>
          <button className="btn-primary" disabled={form.api_key.trim().length < 8 || add.isPending} onClick={() => add.mutate()}>Save key</button>
        </>}>
          <div className="space-y-3">
            <div><label className="label">Provider</label><select className="input" value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })}>{PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}</select></div>
            <div><label className="label">Label</label><input className="input" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="e.g. Work key" /></div>
            <div><label className="label">API key</label><input className="input font-mono" type="password" autoComplete="off" value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} /><div className="hint">Stored encrypted. Only the first and last characters are ever shown again.</div></div>
          </div>
        </Modal>
      )}
    </>
  )
}

function Integrations({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient()
  const [adding, setAdding] = useState<any | null>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [name, setName] = useState('')
  const [tests, setTests] = useState<Record<string, { success: boolean; message: string }>>({})
  const platforms = useQuery({ queryKey: ['platforms'], queryFn: () => integrationsApi.platforms().then((r) => r.data as any[]) })
  const list = useQuery({ queryKey: ['integrations'], queryFn: () => integrationsApi.list().then((r) => r.data as any[]) })
  const refresh = () => qc.invalidateQueries({ queryKey: ['integrations'] })

  const create = useMutation({
    mutationFn: () => {
      const credentials: Record<string, string> = {}
      const config: Record<string, string> = {}
      adding.required_credentials.forEach((k: string) => { credentials[k] = (values[k] || '').trim() })
      ;(adding.optional_credentials || []).forEach((k: string) => { if (values[k]?.trim()) credentials[k] = values[k].trim() })
      adding.optional_config.forEach((k: string) => { if (values[k]?.trim()) config[k] = values[k].trim() })
      return integrationsApi.create({ platform: adding.platform, display_name: name.trim() || adding.display_name, auth_type: adding.auth_type, credentials, config, dry_run: true })
    },
    onSuccess: () => { refresh(); setAdding(null); setValues({}); setName(''); notify.success('Integration added in dry-run mode', 'It will simulate actions until you switch it to live.') },
    onError: (e) => notify.error('Could not add the integration', errorMessage(e)),
  })
  const patch = useMutation({ mutationFn: ({ id, data }: { id: string; data: any }) => integrationsApi.update(id, data), onSuccess: refresh, onError: (e) => notify.error('Could not update the integration', errorMessage(e)) })
  const del = useMutation({ mutationFn: (id: string) => integrationsApi.delete(id), onSuccess: refresh, onError: (e) => notify.error('Could not remove the integration', errorMessage(e)) })
  const test = useMutation({
    mutationFn: (id: string) => integrationsApi.test(id).then((r) => ({ id, ...r.data })),
    onSuccess: (res) => { setTests((t) => ({ ...t, [res.id]: res })); refresh() },
    onError: (e, id) => setTests((t) => ({ ...t, [id]: { success: false, message: errorMessage(e) } })),
  })

  const configured = list.data || []
  const goLive = (i: any) => window.confirm(`Switch "${i.display_name}" to LIVE?\n\nApproved and auto-executed actions will then change real systems (block addresses, isolate hosts, disable accounts).`) && patch.mutate({ id: i.id, data: { dry_run: false } })

  return (
    <>
      <SectionTitle title="Integrations">
        Connections to the tools Cane AI acts through, looks things up in, notifies, and pulls events from. New integrations start in <span className="font-semibold text-ink">dry-run</span>: actions are logged as if they ran, but nothing is changed.
      </SectionTitle>
      {!isAdmin && <div className="mt-3"><ErrorNote>Only administrators can add or change integrations. You can see what is connected.</ErrorNote></div>}

      <div className="text-[13px] font-semibold mt-4 mb-2">Connected</div>
      {list.isLoading ? <Loading /> : configured.length === 0
        ? <div className="text-[13px] text-ink-muted border border-line rounded p-4">Nothing connected yet. Until a response tool is connected, approved actions fail with “no connected integration can run this”.</div>
        : (
          <div className="border border-line rounded divide-y divide-line-soft">
            {configured.map((i) => (
              <div key={i.id} className="p-3 flex items-start gap-3 text-[13px]">
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold">{i.display_name}</span>
                    <span className="tag">{titleCase(i.platform)}</span>
                    {i.dry_run
                      ? <span className="pill bg-[#ffb648] text-[#703b15]">DRY RUN</span>
                      : <span className="pill bg-severity-critical text-white">LIVE</span>}
                    {!i.is_active && <span className="pill bg-[#87929d] text-white">DISABLED</span>}
                  </div>
                  <div className="text-ink-muted mt-1">
                    Health: {titleCase(i.health_status)}{i.last_health_check ? ` · checked ${formatQueueTime(i.last_health_check)}` : ' · never checked'}
                    {i.state?.last_poll && <> · last polled {formatQueueTime(i.state.last_poll)} ({i.state.last_count ?? 0} new)</>}
                  </div>
                  {i.state?.last_error && <div className="text-[#8c232c] mt-1 break-words">Last poll failed: {i.state.last_error}</div>}
                  {tests[i.id] && (
                    <div className={clsx('flex items-start gap-1.5 mt-1.5', tests[i.id].success ? 'text-[#186146]' : 'text-[#8c232c]')}>
                      {tests[i.id].success ? <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" /> : <XCircle className="w-4 h-4 shrink-0 mt-0.5" />}
                      <span className="break-words min-w-0">{tests[i.id].success ? 'Connection works' : 'Connection failed'}: {tests[i.id].message}</span>
                    </div>
                  )}
                </div>
                {isAdmin && (
                  <div className="flex flex-wrap justify-end gap-1.5 shrink-0">
                    <button className="btn-basic btn-sm" disabled={test.isPending} onClick={() => test.mutate(i.id)}>Test connection</button>
                    {i.dry_run
                      ? <button className="btn-basic btn-sm" onClick={() => goLive(i)}>Go live</button>
                      : <button className="btn-basic btn-sm" onClick={() => patch.mutate({ id: i.id, data: { dry_run: true } })}>Back to dry run</button>}
                    <button className="btn-basic btn-sm" onClick={() => patch.mutate({ id: i.id, data: { is_active: !i.is_active } })}>{i.is_active ? 'Disable' : 'Enable'}</button>
                    <button className="btn-basic btn-sm text-severity-critical" onClick={() => window.confirm(`Remove "${i.display_name}"? Its stored credentials are deleted.`) && del.mutate(i.id)} aria-label="Remove"><Trash2 className="w-3.5 h-3.5" /></button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

      {INTEGRATION_CATEGORIES.filter((cat) => (platforms.data || []).some((p) => p.category === cat.key)).map((cat) => (
        <div key={cat.key}>
          <div className="mt-6 mb-2">
            <div className="text-[13px] font-semibold">{cat.label}</div>
            <div className="text-xs text-ink-muted">{cat.blurb}</div>
          </div>
          <div className="border border-line rounded divide-y divide-line-soft">
            {(platforms.data || []).filter((p) => p.category === cat.key).map((p) => (
              <div key={p.platform} className="p-3 flex items-start gap-3 text-[13px]">
                <div className="flex-1 min-w-0">
                  <div className="font-semibold">{p.display_name}{configured.some((c) => c.platform === p.platform) && <span className="tag ml-2">Connected</span>}</div>
                  <div className="text-ink-muted">{p.description}</div>
                  <div className="flex flex-wrap gap-1 mt-1.5">{p.capabilities.slice(0, 8).map((c: string) => <span key={c} className="tag">{titleCase(c)}</span>)}</div>
                </div>
                {isAdmin && <button className="btn-secondary btn-sm shrink-0" onClick={() => { setAdding(p); setValues({}); setName(p.display_name) }}><Plus className="w-3.5 h-3.5" /> Connect</button>}
              </div>
            ))}
          </div>
        </div>
      ))}

      {adding && (
        <Modal title={`Connect ${adding.display_name}`} onClose={() => setAdding(null)} footer={<>
          <button className="btn-basic" onClick={() => setAdding(null)}>Cancel</button>
          <button className="btn-primary" disabled={create.isPending || adding.required_credentials.some((k: string) => !values[k]?.trim())} onClick={() => create.mutate()}>Connect in dry-run mode</button>
        </>}>
          <div className="space-y-3">
            <div className="flex gap-2 rounded border border-[#fcdba9] bg-[#fff8ed] px-2.5 py-2 text-[13px] text-[#703b15]">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
              <div>Starts in dry-run mode. Test the connection, watch a few simulated actions, then choose <span className="font-semibold">Go live</span>.</div>
            </div>
            <div><label className="label">Name</label><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
            {adding.required_credentials.map((k: string) => (
              <div key={k}><label className="label">{titleCase(k)}</label><input className="input font-mono" type={/secret|key|password/.test(k) ? 'password' : 'text'} autoComplete="off" value={values[k] || ''} onChange={(e) => setValues({ ...values, [k]: e.target.value })} /></div>
            ))}
            {(adding.optional_credentials || []).map((k: string) => (
              <div key={k}><label className="label">{titleCase(k)} <span className="font-normal text-ink-muted">(optional)</span></label><input className="input font-mono" type="password" autoComplete="off" value={values[k] || ''} onChange={(e) => setValues({ ...values, [k]: e.target.value })} /></div>
            ))}
            {adding.optional_config.map((k: string) => (
              <div key={k}><label className="label">{titleCase(k)} <span className="font-normal text-ink-muted">(optional)</span></label><input className="input" value={values[k] || ''} onChange={(e) => setValues({ ...values, [k]: e.target.value })} /></div>
            ))}
            {adding.required_credentials.length + (adding.optional_credentials || []).length > 0
              ? <div className="hint">Credentials are encrypted before they are stored and are never shown again.</div>
              : <div className="hint">This source needs no credentials.</div>}
          </div>
        </Modal>
      )}
    </>
  )
}

function Team() {
  const qc = useQueryClient()
  const me = useAuthStore((s) => s.user)
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ full_name: '', email: '', password: '', role: 'tier1_analyst' })
  const users = useQuery({ queryKey: ['users', 'all'], queryFn: () => usersApi.list().then((r) => r.data as any[]) })
  const refresh = () => qc.invalidateQueries({ queryKey: ['users'] })
  const create = useMutation({
    mutationFn: () => usersApi.create({ ...form, full_name: form.full_name.trim(), email: form.email.trim() }),
    onSuccess: () => { refresh(); setAdding(false); setForm({ full_name: '', email: '', password: '', role: 'tier1_analyst' }); notify.success('Account created', 'Share the temporary password with them directly.') },
    onError: (e) => notify.error('Could not create the account', errorMessage(e)),
  })
  const setRole = useMutation({ mutationFn: ({ id, role }: { id: string; role: string }) => usersApi.updateRole(id, role), onSuccess: refresh, onError: (e) => notify.error('Could not change the role', errorMessage(e)) })
  const setActive = useMutation({ mutationFn: ({ id, active }: { id: string; active: boolean }) => usersApi.setActive(id, active), onSuccess: refresh, onError: (e) => notify.error('Could not update the account', errorMessage(e)) })

  return (
    <>
      <SectionTitle title="Team" action={<button className="btn-secondary shrink-0" onClick={() => setAdding(true)}><Plus className="w-4 h-4" /> Add person</button>}>
        People who can sign in. Accounts are created here, not by self-registration. Deactivating someone signs them out everywhere and keeps their history.
      </SectionTitle>
      {users.isLoading ? <Loading /> : users.isError ? <ErrorNote>Could not load the team.</ErrorNote> : (
        <table className="table-queue mt-2">
          <thead><tr><th>Name</th><th>Email</th><th className="w-44">Role</th><th className="w-28">Status</th><th className="w-36">Joined</th><th className="w-28" /></tr></thead>
          <tbody>
            {users.data!.map((u) => (
              <tr key={u.id} className={clsx(!u.is_active && 'text-ink-faint')}>
                <td className="font-medium">{u.full_name}{u.id === me?.id && <span className="tag ml-2">You</span>}</td>
                <td>{u.email}</td>
                <td>
                  <select className="input h-7" value={u.role} disabled={u.id === me?.id || setRole.isPending} onChange={(e) => setRole.mutate({ id: u.id, role: e.target.value })} aria-label={`Role for ${u.full_name}`}>
                    {Object.entries(ROLE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                  </select>
                </td>
                <td>{u.is_active ? <span className="pill bg-[#038153] text-white">ACTIVE</span> : <span className="pill bg-[#87929d] text-white">DEACTIVATED</span>}</td>
                <td className="text-ink-soft">{formatQueueTime(u.created_at)}</td>
                <td className="text-right">
                  {u.id !== me?.id && (
                    <button className="btn-basic btn-sm" disabled={setActive.isPending} onClick={() => (u.is_active ? window.confirm(`Deactivate ${u.full_name}? They will be signed out and unable to sign in.`) : true) && setActive.mutate({ id: u.id, active: !u.is_active })}>
                      {u.is_active ? 'Deactivate' : 'Reactivate'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {adding && (
        <Modal title="Add person" onClose={() => setAdding(false)} footer={<>
          <button className="btn-basic" onClick={() => setAdding(false)}>Cancel</button>
          <button className="btn-primary" disabled={!form.full_name.trim() || !form.email.trim() || form.password.length < 10 || create.isPending} onClick={() => create.mutate()}>Create account</button>
        </>}>
          <div className="space-y-3">
            <div><label className="label">Full name</label><input className="input" autoFocus value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></div>
            <div><label className="label">Email</label><input className="input" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
            <div><label className="label">Temporary password</label><input className="input font-mono" type="text" autoComplete="off" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /><div className="hint">At least 10 characters.</div></div>
            <div><label className="label">Role</label><select className="input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{Object.entries(ROLE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div>
          </div>
        </Modal>
      )}
    </>
  )
}

export default function SettingsPage() {
  const role = useAuthStore((s) => s.user)?.role
  const isAdmin = hasRole(role, 'admin')
  const [section, setSection] = useState<Section>('profile')
  const nav: { heading: string; items: { key: Section; label: string }[] }[] = [
    { heading: 'Personal', items: [{ key: 'profile', label: 'Profile' }, { key: 'api-keys', label: 'API keys' }] },
    { heading: 'Workspace', items: [{ key: 'integrations', label: 'Integrations' }, ...(isAdmin ? [{ key: 'team' as Section, label: 'Team' }] : [])] },
  ]
  return (
    <div className="flex-1 flex min-w-0">
      <aside className="w-60 shrink-0 border-r border-line bg-surface overflow-y-auto">
        <div className="px-4 pt-5 pb-3 text-[15px] font-semibold">Settings</div>
        <nav className="px-2 pb-4">
          {nav.map((group) => (
            <div key={group.heading} className="mb-3">
              <div className="px-2 pb-1 panel-title">{group.heading}</div>
              {group.items.map((item) => (
                <button key={item.key} onClick={() => setSection(item.key)} className={clsx('w-full text-left px-2 h-8 rounded text-[13px]', section === item.key ? 'bg-brand-100 font-semibold' : 'hover:bg-line-soft')}>
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>
      <section className="flex-1 min-w-0 overflow-y-auto">
        <div className="max-w-5xl px-8 py-6">
          {section === 'profile' && <Profile />}
          {section === 'api-keys' && <ApiKeys />}
          {section === 'integrations' && <Integrations isAdmin={isAdmin} />}
          {section === 'team' && isAdmin && <Team />}
        </div>
      </section>
    </div>
  )
}
