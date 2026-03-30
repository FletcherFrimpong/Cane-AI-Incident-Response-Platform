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
              <option value="gemini">Google (Gemini)</option>
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
  const { data: integrations, isLoading } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => integrationsApi.list().then((r) => r.data),
  })

  return (
    <div className="card max-w-lg">
      <h2 className="text-lg font-semibold mb-4">Integrations</h2>
      {isLoading ? (
        <p className="text-gray-500 text-sm">Loading...</p>
      ) : !integrations || integrations.length === 0 ? (
        <p className="text-gray-500 text-sm">No integrations configured.</p>
      ) : (
        <div className="space-y-2">
          {integrations.map((int: any) => (
            <div
              key={int.id}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
            >
              <div>
                <p className="font-medium text-sm">{int.name}</p>
                <p className="text-xs text-gray-500">{int.platform_type}</p>
              </div>
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
          ))}
        </div>
      )}
    </div>
  )
}
