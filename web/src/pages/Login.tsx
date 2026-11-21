import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Lock, ArrowRight, AlertCircle } from 'lucide-react'
import { cookieLogin, confirmSession, listRedirectProviders, type RedirectProvider } from '../api/client'

// Reasons the server gives on /login?oidc_error=… (see src/api/native/oidc.rs).
const OIDC_ERRORS: Record<string, string> = {
  denied: 'Sign-in was denied.',
  no_account: 'No account here matches that identity. Ask an administrator to invite you.',
  unverified_email: 'Your provider has not verified your email address, so it cannot be matched to an account.',
  expired: 'That sign-in expired or was started in another browser. Try again.',
  unavailable: 'The sign-in provider is unreachable. Try again shortly.',
  failed: 'Sign-in failed. Try again, or use another method.',
}

export default function Login() {
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [providers, setProviders] = useState<RedirectProvider[]>([])
  const [params] = useSearchParams()
  const navigate = useNavigate()

  useEffect(() => {
    listRedirectProviders().then(setProviders)
  }, [])

  // Back from an external provider: either a session cookie was set, or an error code.
  useEffect(() => {
    const code = params.get('oidc_error')
    if (code) {
      setError(OIDC_ERRORS[code] ?? OIDC_ERRORS.failed)
    } else if (params.get('oidc') === 'ok') {
      confirmSession().then((ok) => {
        if (ok) navigate('/secrets', { replace: true })
        else setError(OIDC_ERRORS.failed)
      })
    }
  }, [params, navigate])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!token.trim()) return

    setLoading(true)
    setError('')

    try {
      await cookieLogin(token.trim())
      navigate('/secrets')
    } catch (err) {
      setError('Invalid token, or the server is unreachable. Check the server is running and the token is valid.')
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

        {providers.length > 0 && (
          <div className="mt-4 space-y-2">
            <div className="text-center text-xs text-muted uppercase tracking-wider">or</div>
            {providers.map((p) => (
              // A full navigation, not fetch: the browser is sent to the provider.
              <a
                key={p.id}
                href={p.url}
                className="w-full flex items-center justify-center gap-2 bg-surface hover:bg-bg border border-border text-txt rounded-lg px-4 py-2.5 text-sm font-medium transition-colors"
              >
                Sign in with {p.display_name}
                <ArrowRight size={15} />
              </a>
            ))}
          </div>
        )}

        <p className="text-xs text-muted text-center mt-6">
          secretd v0.1 — open source password manager
        </p>
      </div>
    </div>
  )
}
