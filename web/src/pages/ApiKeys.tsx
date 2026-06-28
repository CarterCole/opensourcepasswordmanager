import { Fingerprint, Info } from 'lucide-react'
import { Badge } from '../components/Badge'

export default function ApiKeys() {
  return (
    <div>
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <h2 className="text-sm font-semibold text-txt">API Keys</h2>
        <button
          disabled
          className="flex items-center gap-1.5 bg-accent/30 text-accent/50 rounded-lg px-3 py-1.5 text-xs font-medium cursor-not-allowed"
          title="Requires auth setup"
        >
          <Fingerprint size={13} />
          Generate Key
        </button>
      </div>

      <div className="px-6 py-4">
        {/* Info banner */}
        <div className="flex items-start gap-3 bg-accent-dim/40 border border-accent/20 rounded-xl p-4 mb-6">
          <Info size={16} className="text-accent flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-txt">API key management requires auth setup</p>
            <p className="text-xs text-muted mt-1">
              Full API key generation, scoping, and rotation will be available after the authentication
              layer is configured (Phase 2). Once enabled, you can create scoped tokens with expiry,
              view usage, and revoke them here.
            </p>
          </div>
        </div>

        {/* Preview table */}
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Prefix</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan={6} className="text-center py-12">
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-10 h-10 rounded-xl bg-surface-2 border border-border flex items-center justify-center">
                      <Fingerprint size={18} className="text-muted" />
                    </div>
                    <p className="text-sm font-medium text-txt">No API keys yet</p>
                    <p className="text-xs text-muted">
                      API key management activates after authentication is configured.
                    </p>
                    <Badge variant="warn">Phase 2 feature</Badge>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Feature overview */}
        <div className="mt-6 grid grid-cols-3 gap-4">
          {[
            {
              title: 'Scoped Access',
              desc: 'Limit each key to specific mounts, paths, or operations (read/write/delete).',
            },
            {
              title: 'Expiring Tokens',
              desc: 'Set TTLs from minutes to years. Keys auto-revoke when they expire.',
            },
            {
              title: 'Usage Audit',
              desc: 'Every API key request is logged to the audit trail with actor, IP, and resource.',
            },
          ].map((f) => (
            <div
              key={f.title}
              className="bg-surface border border-border rounded-xl p-4"
            >
              <p className="text-sm font-semibold text-txt mb-1">{f.title}</p>
              <p className="text-xs text-muted">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
