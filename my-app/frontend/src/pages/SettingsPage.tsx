import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '../store/authStore'
import { usersApi } from '../api/users'
import { integrationsApi } from '../api/integrations'
import { Key, Plug, User } from 'lucide-react'

export default function SettingsPage() {
  const user = useAuthStore((s) => s.user)
  const [activeTab, setActiveTab] = useState<'profile' | 'apikeys' | 'integrations'>('profile')

  const tabs = [
    { id: 'profile' as const, label: 'Profile', icon: User },
    { id: 'apikeys' as const, label: 'API Keys', icon: Key },
    { id: 'integrations' as const, label: 'Integrations', icon: Plug },
  ]

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Settings</h1>

      <div className="flex gap-2 mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-brand-600 text-white'
                : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
            }`}
          >
            <tab.icon className="h-4 w-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'profile' && <ProfileSection />}
      {activeTab === 'apikeys' && <ApiKeysSection />}
      {activeTab === 'integrations' && <IntegrationsSection />}
    </div>
  )
}

function ProfileSection() {
  const user = useAuthStore((s) => s.user)

  return (
    <div className="card max-w-lg">
      <h2 className="text-lg font-semibold mb-4">Profile</h2>
      <dl className="space-y-3 text-sm">
        <div>
          <dt className="text-gray-500">Email</dt>
          <dd className="font-medium">{user?.email || '-'}</dd>
        </div>
        <div>
          <dt className="text-gray-500">Name</dt>
          <dd className="font-medium">{user?.full_name || '-'}</dd>
        </div>
        <div>
          <dt className="text-gray-500">Role</dt>
          <dd className="font-medium">{user?.role || '-'}</dd>
        </div>
      </dl>
    </div>
  )
}

function ApiKeysSection() {
  const queryClient = useQueryClient()
  const [provider, setProvider] = useState('claude')
  const [apiKey, setApiKey] = useState('')
  const [label, setLabel] = useState('')

  const { data: keys, isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => usersApi.listApiKeys().then((r) => r.data),
  })

  const addMutation = useMutation({
    mutationFn: () =>
      usersApi.addApiKey({ provider, api_key: apiKey, label, is_default: true }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
      setApiKey('')
      setLabel('')
    },
  })

  return (
    <div className="space-y-6">
      <div className="card max-w-lg">
        <h2 className="text-lg font-semibold mb-4">Add API Key</h2>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Provider
            </label>
            <select
              className="input"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
            >
              <option value="claude">Anthropic (Claude)</option>
              <option value="openai">OpenAI</option>
              <option value="azure_openai">Azure OpenAI</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Label
            </label>
            <input
              className="input"
              placeholder="e.g., Production Key"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              API Key
            </label>
            <input
              className="input"
              type="password"
              placeholder="sk-..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
          <button
            className="btn-primary"
            disabled={!apiKey || !label || addMutation.isPending}
            onClick={() => addMutation.mutate()}
          >
            {addMutation.isPending ? 'Saving...' : 'Save Key'}
          </button>
        </div>
      </div>

      <div className="card max-w-lg">
        <h2 className="text-lg font-semibold mb-4">Saved Keys</h2>
        {isLoading ? (
          <p className="text-gray-500 text-sm">Loading...</p>
        ) : !keys || keys.length === 0 ? (
          <p className="text-gray-500 text-sm">No API keys configured.</p>
        ) : (
          <div className="space-y-2">
            {keys.map((k: any) => (
              <div
                key={k.id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
              >
                <div>
                  <p className="font-medium text-sm">{k.label}</p>
                  <p className="text-xs text-gray-500">{k.provider}</p>
                </div>
                <button
                  className="text-sm text-red-600 hover:text-red-800"
                  onClick={() => usersApi.deleteApiKey(k.id)}
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function IntegrationsSection() {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [selectedPlatform, setSelectedPlatform] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [credentials, setCredentials] = useState<Record<string, string>>({})
  const [config, setConfig] = useState<Record<string, string>>({})
  const [testingId, setTestingId] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null)

  const { data: integrations, isLoading } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => integrationsApi.list().then((r) => r.data),
  })

  const { data: platforms } = useQuery({
    queryKey: ['integration-platforms'],
    queryFn: () => integrationsApi.platforms().then((r) => r.data),
  })

  const currentPlatform = platforms?.find((p: any) => p.platform === selectedPlatform)

  const addMutation = useMutation({
    mutationFn: (data: any) => integrationsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      resetForm()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
    },
  })

  function resetForm() {
    setShowForm(false)
    setSelectedPlatform('')
    setDisplayName('')
    setCredentials({})
    setConfig({})
  }

  function handlePlatformChange(platform: string) {
    setSelectedPlatform(platform)
    setCredentials({})
    setConfig({})
    const p = platforms?.find((pl: any) => pl.platform === platform)
    if (p) setDisplayName(p.display_name)
  }

  function handleSubmit() {
    if (!currentPlatform) return
    addMutation.mutate({
      platform: selectedPlatform,
      display_name: displayName,
      auth_type: currentPlatform.auth_type,
      credentials,
      config: Object.keys(config).length > 0 ? config : undefined,
    })
  }

  async function handleTest(id: string) {
    setTestingId(id)
    setTestResult(null)
    try {
      const res = await integrationsApi.test(id)
      setTestResult({ id, ok: true, msg: res.data?.message || 'Connection successful' })
    } catch (err: any) {
      setTestResult({ id, ok: false, msg: err.response?.data?.detail || 'Connection failed' })
    } finally {
      setTestingId(null)
    }
  }

  const allCredsFilled = currentPlatform?.required_credentials?.every(
    (k: string) => credentials[k]?.trim()
  )

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Add Integration */}
      {!showForm ? (
        <button
          className="btn-primary flex items-center gap-2"
          onClick={() => setShowForm(true)}
        >
          <Plug className="h-4 w-4" />
          Add Integration
        </button>
      ) : (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Add Integration</h2>
            <button className="text-sm text-gray-500 hover:text-gray-700" onClick={resetForm}>
              Cancel
            </button>
          </div>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Platform</label>
              <select
                className="input"
                value={selectedPlatform}
                onChange={(e) => handlePlatformChange(e.target.value)}
              >
                <option value="">Select a platform...</option>
                {platforms?.map((p: any) => (
                  <option key={p.platform} value={p.platform}>
                    {p.display_name}
                  </option>
                ))}
              </select>
              {currentPlatform && (
                <p className="text-xs text-gray-500 mt-1">{currentPlatform.description}</p>
              )}
            </div>

            {currentPlatform && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
                  <input
                    className="input"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                  />
                </div>

                <div className="border-t pt-4">
                  <h3 className="text-sm font-medium text-gray-700 mb-3">Credentials</h3>
                  <div className="space-y-3">
                    {currentPlatform.required_credentials.map((field: string) => (
                      <div key={field}>
                        <label className="block text-xs font-medium text-gray-600 mb-1">
                          {field.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                          <span className="text-red-500 ml-0.5">*</span>
                        </label>
                        <input
                          className="input"
                          type={field.includes('secret') || field.includes('key') ? 'password' : 'text'}
                          placeholder={field}
                          value={credentials[field] || ''}
                          onChange={(e) =>
                            setCredentials((prev) => ({ ...prev, [field]: e.target.value }))
                          }
                        />
                      </div>
                    ))}
                  </div>
                </div>

                {currentPlatform.optional_config?.length > 0 && (
                  <div className="border-t pt-4">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">
                      Optional Configuration
                    </h3>
                    <div className="space-y-3">
                      {currentPlatform.optional_config.map((field: string) => (
                        <div key={field}>
                          <label className="block text-xs font-medium text-gray-600 mb-1">
                            {field.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase())}
                          </label>
                          <input
                            className="input"
                            placeholder={field}
                            value={config[field] || ''}
                            onChange={(e) =>
                              setConfig((prev) => ({ ...prev, [field]: e.target.value }))
                            }
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {currentPlatform.capabilities?.length > 0 && (
                  <div className="border-t pt-4">
                    <h3 className="text-sm font-medium text-gray-700 mb-2">Capabilities</h3>
                    <div className="flex flex-wrap gap-1.5">
                      {currentPlatform.capabilities.map((cap: string) => (
                        <span key={cap} className="badge bg-brand-50 text-brand-700 text-xs">
                          {cap.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {addMutation.isError && (
                  <div className="p-3 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
                    {(addMutation.error as any)?.response?.data?.detail || 'Failed to add integration.'}
                  </div>
                )}

                <button
                  className="btn-primary w-full"
                  disabled={!allCredsFilled || !displayName || addMutation.isPending}
                  onClick={handleSubmit}
                >
                  {addMutation.isPending ? 'Saving...' : 'Save Integration'}
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {/* Configured Integrations */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Configured Integrations</h2>
        {isLoading ? (
          <p className="text-gray-500 text-sm">Loading...</p>
        ) : !integrations || integrations.length === 0 ? (
          <p className="text-gray-500 text-sm">
            No integrations configured yet. Add one above to connect to security platforms.
          </p>
        ) : (
          <div className="space-y-3">
            {integrations.map((int: any) => (
              <div
                key={int.id}
                className="p-4 bg-gray-50 rounded-lg"
              >
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <p className="font-medium">{int.display_name}</p>
                    <p className="text-xs text-gray-500">{int.platform}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`badge ${
                        int.health_status === 'healthy'
                          ? 'bg-green-100 text-green-800'
                          : int.health_status === 'error'
                          ? 'bg-red-100 text-red-800'
                          : 'bg-gray-100 text-gray-500'
                      }`}
                    >
                      {int.health_status || 'unknown'}
                    </span>
                    <span
                      className={`badge ${
                        int.is_active
                          ? 'bg-green-100 text-green-800'
                          : 'bg-gray-100 text-gray-500'
                      }`}
                    >
                      {int.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                </div>
                {testResult?.id === int.id && (
                  <div
                    className={`mb-2 p-2 rounded text-sm ${
                      testResult.ok
                        ? 'bg-green-50 text-green-700 border border-green-200'
                        : 'bg-red-50 text-red-700 border border-red-200'
                    }`}
                  >
                    {testResult.msg}
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    className="text-sm text-brand-600 hover:text-brand-800 font-medium"
                    disabled={testingId === int.id}
                    onClick={() => handleTest(int.id)}
                  >
                    {testingId === int.id ? 'Testing...' : 'Test Connection'}
                  </button>
                  <button
                    className="text-sm text-red-600 hover:text-red-800 font-medium"
                    onClick={() => deleteMutation.mutate(int.id)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
