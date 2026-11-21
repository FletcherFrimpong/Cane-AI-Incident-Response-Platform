import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { ErrorNote } from '../components/ui'
import { errorMessage } from '../utils/formatters'

export default function LoginPage() {
  const navigate = useNavigate()
  const setTokens = useAuthStore((s) => s.setTokens)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await authApi.login(email, password)
      setTokens(res.data.access_token, res.data.refresh_token)
      navigate('/')
    } catch (err: any) {
      setError(err?.response ? errorMessage(err, 'Sign-in failed') : 'Cannot reach the server. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex">
      <div className="hidden md:flex w-[42%] bg-rail text-white flex-col justify-between p-10">
        <div className="flex items-center gap-2.5 text-lg font-semibold">
          <Shield className="w-7 h-7" fill="currentColor" strokeWidth={0} /> Cane AI
        </div>
        <div>
          <div className="text-3xl font-semibold leading-tight">Every incident, in one queue.</div>
          <p className="mt-3 text-white/70 text-[15px] leading-6 max-w-sm">
            Logs come in, AI triages them, and anything that needs a person lands in front of an analyst with the evidence attached.
          </p>
        </div>
        <div className="text-white/50 text-xs">Incident response platform</div>
      </div>

      <div className="flex-1 flex items-center justify-center p-6 bg-surface">
        <form onSubmit={handleSubmit} className="w-full max-w-sm bg-white border border-line rounded-md p-7">
          <h1 className="text-xl font-semibold">Sign in</h1>
          <p className="text-[13px] text-ink-muted mt-1 mb-5">Use the account your administrator created for you.</p>
          {error && <div className="mb-4"><ErrorNote>{error}</ErrorNote></div>}
          <label className="label" htmlFor="email">Email</label>
          <input id="email" type="email" className="input mb-3" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" autoFocus required />
          <label className="label" htmlFor="password">Password</label>
          <input id="password" type="password" className="input mb-5" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          <button type="submit" className="btn-primary w-full h-9" disabled={loading}>{loading ? 'Signing in…' : 'Sign in'}</button>
        </form>
      </div>
    </div>
  )
}
