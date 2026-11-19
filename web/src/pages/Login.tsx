import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Lock, ArrowRight, AlertCircle } from 'lucide-react'
import { checkHealth } from '../api/client'

export default function Login() {
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!token.trim()) return

    setLoading(true)
    setError('')

    try {
      localStorage.setItem('secretd_token', token.trim())
      await checkHealth()
      navigate('/secrets')
    } catch (err) {
      localStorage.removeItem('secretd_token')
      setError('Could not connect to secretd. Check the server is running and the token is valid.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-accent-dim border border-accent/20 flex items-center justify-center mb-4 shadow-lg shadow-accent/10">
            <Lock size={24} className="text-accent" />
          </div>
          <h1 className="font-mono text-2xl font-bold text-txt tracking-tight">
            secretd
          </h1>
          <p className="text-sm text-muted mt-2 text-center">
            Self-hosted secrets. No cloud required.
          </p>
        </div>

        {/* Card */}
        <div className="bg-surface border border-border rounded-xl p-6 shadow-2xl">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted mb-1.5 uppercase tracking-wider">
                Access Token
              </label>
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Paste your access token"
                className="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-sm text-txt font-mono placeholder:text-muted focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 transition-colors"
                autoFocus
                autoComplete="current-password"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 text-xs text-danger bg-danger/10 border border-danger/20 rounded-lg p-3">
                <AlertCircle size={14} className="flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !token.trim()}
              className="w-full flex items-center justify-center gap-2 bg-accent hover:bg-accent/90 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg px-4 py-2.5 text-sm font-medium transition-colors"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Connecting…
                </span>
              ) : (
                <>
                  Connect
                  <ArrowRight size={15} />
                </>
              )}
            </button>
          </form>
        </div>

        <p className="text-xs text-muted text-center mt-6">
          secretd v0.1 — open source password manager
        </p>
      </div>
    </div>
  )
}
