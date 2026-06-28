import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Plus, Trash2, X, ChevronDown, Loader2 } from 'lucide-react'
import { listSyncConfigs, createSyncConfig, deleteSyncConfig } from '../api/client'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { useToast } from '../components/Toast'

type Provider = 'aws' | 'gcp' | 'azure' | 'vault'
type Direction = 'push' | 'pull' | 'bidirectional'

const PROVIDERS: { value: Provider; label: string }[] = [
  { value: 'aws', label: 'AWS Secrets Manager' },
  { value: 'gcp', label: 'GCP Secret Manager' },
  { value: 'azure', label: 'Azure Key Vault' },
  { value: 'vault', label: 'HashiCorp Vault / OpenBao' },
]

const DIRECTIONS: { value: Direction; label: string }[] = [
  { value: 'push', label: 'Push (secretd → remote)' },
  { value: 'pull', label: 'Pull (remote → secretd)' },
  { value: 'bidirectional', label: 'Bidirectional (sync both ways)' },
]

const directionBadge: Record<Direction, 'accent' | 'success' | 'warn'> = {
  push: 'accent',
  pull: 'success',
  bidirectional: 'warn',
}

const providerBadge: Record<Provider, 'default' | 'warn' | 'accent' | 'success'> = {
  aws: 'warn',
  gcp: 'success',
  azure: 'accent',
  vault: 'default',
}

interface CredentialField {
  key: string
  label: string
  placeholder: string
  type?: 'password' | 'text'
}

const CREDENTIAL_FIELDS: Record<Provider, CredentialField[]> = {
  aws: [
    { key: 'endpoint_url', label: 'Endpoint URL', placeholder: 'https://secretsmanager.us-east-1.amazonaws.com' },
    { key: 'access_key_id', label: 'Access Key ID', placeholder: 'AKIAIOSFODNN7EXAMPLE' },
    { key: 'secret_access_key', label: 'Secret Access Key', placeholder: '••••••••', type: 'password' },
    { key: 'region', label: 'Region', placeholder: 'us-east-1' },
  ],
  gcp: [
    { key: 'project_id', label: 'Project ID', placeholder: 'my-gcp-project' },
    { key: 'service_account_token', label: 'Service Account Token', placeholder: '••••••••', type: 'password' },
  ],
  azure: [
    { key: 'vault_url', label: 'Vault URL', placeholder: 'https://my-vault.vault.azure.net' },
    { key: 'client_id', label: 'Client ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'client_secret', label: 'Client Secret', placeholder: '••••••••', type: 'password' },
    { key: 'tenant_id', label: 'Tenant ID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
  ],
  vault: [
    { key: 'address', label: 'Vault Address', placeholder: 'https://vault.example.com:8200' },
    { key: 'token', label: 'Token', placeholder: '••••••••', type: 'password' },
    { key: 'mount', label: 'Mount Path', placeholder: 'secret' },
  ],
}

function AddSyncForm({ onClose }: { onClose: () => void }) {
  const [provider, setProvider] = useState<Provider>('aws')
  const [direction, setDirection] = useState<Direction>('push')
  const [pathFilter, setPathFilter] = useState('')
  const [creds, setCreds] = useState<Record<string, string>>({})
  const { toast } = useToast()
  const qc = useQueryClient()

  const mutation = useMutation({
    mutationFn: () =>
      createSyncConfig({ provider, direction, path_filter: pathFilter || undefined, credentials: creds }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-configs'] })
      toast('Sync configured (will activate in Phase 4)', 'info')
      onClose()
    },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const updateCred = (key: string, val: string) =>
    setCreds((c) => ({ ...c, [key]: val }))

  return (
    <div className="bg-surface border border-border rounded-xl p-5 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-txt">Add Sync Configuration</h3>
        <button onClick={onClose} className="text-muted hover:text-txt">
          <X size={16} />
        </button>
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          {/* Provider */}
          <div>
            <label className="block text-xs text-muted mb-1.5">Provider</label>
            <div className="relative">
              <select
                value={provider}
                onChange={(e) => { setProvider(e.target.value as Provider); setCreds({}) }}
                className="w-full appearance-none bg-bg border border-border rounded-lg px-3 py-2 text-sm text-txt focus:outline-none focus:border-accent pr-8"
              >
                {PROVIDERS.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
              <ChevronDown size={13} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
            </div>
          </div>

          {/* Direction */}
          <div>
            <label className="block text-xs text-muted mb-1.5">Direction</label>
            <div className="relative">
              <select
                value={direction}
                onChange={(e) => setDirection(e.target.value as Direction)}
                className="w-full appearance-none bg-bg border border-border rounded-lg px-3 py-2 text-sm text-txt focus:outline-none focus:border-accent pr-8"
              >
                {DIRECTIONS.map((d) => (
                  <option key={d.value} value={d.value}>{d.label}</option>
                ))}
              </select>
              <ChevronDown size={13} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted pointer-events-none" />
            </div>
          </div>
        </div>

        {/* Path filter */}
        <div>
          <label className="block text-xs text-muted mb-1.5">Path Filter (optional)</label>
          <input
            value={pathFilter}
            onChange={(e) => setPathFilter(e.target.value)}
            placeholder="secret/production/*"
            className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm font-mono text-txt placeholder:text-muted focus:outline-none focus:border-accent"
          />
        </div>

        {/* Provider credentials */}
        <div>
          <p className="text-xs font-medium text-muted mb-2 uppercase tracking-wider">
            {PROVIDERS.find((p) => p.value === provider)?.label} Credentials
          </p>
          <div className="space-y-2">
            {CREDENTIAL_FIELDS[provider].map((field) => (
              <div key={field.key}>
                <label className="block text-xs text-muted mb-1">{field.label}</label>
                <input
                  type={field.type ?? 'text'}
                  value={creds[field.key] ?? ''}
                  onChange={(e) => updateCred(field.key, e.target.value)}
                  placeholder={field.placeholder}
                  className="w-full bg-bg border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-txt placeholder:text-muted focus:outline-none focus:border-accent"
                />
              </div>
            ))}
          </div>
        </div>

        <div className="flex gap-2 pt-1">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="flex items-center gap-1.5 bg-accent hover:bg-accent/90 disabled:opacity-50 text-white rounded-lg px-3 py-1.5 text-xs font-medium transition-colors"
          >
            {mutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <RefreshCw size={12} />
            )}
            Configure Sync
          </button>
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-xs text-muted hover:text-txt border border-border rounded-lg transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Sync() {
  const [showAdd, setShowAdd] = useState(false)
  const { toast } = useToast()
  const qc = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['sync-configs'],
    queryFn: listSyncConfigs,
    retry: false,
  })

  const deleteMutation = useMutation({
    mutationFn: deleteSyncConfig,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-configs'] })
      toast('Sync configuration removed', 'success')
    },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const configs = data?.configs ?? []

  return (
    <div>
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <h2 className="text-sm font-semibold text-txt">Sync</h2>
        <button
          onClick={() => setShowAdd((s) => !s)}
          className="flex items-center gap-1.5 bg-accent text-white rounded-lg px-3 py-1.5 text-xs font-medium hover:bg-accent/90 transition-colors"
        >
          <Plus size={13} />
          Add Sync
        </button>
      </div>

      <div className="px-6 py-4">
        {showAdd && <AddSyncForm onClose={() => setShowAdd(false)} />}

        {isLoading ? (
          <div className="flex items-center gap-2 text-muted text-sm py-8">
            <Loader2 size={16} className="animate-spin" />
            Loading sync configs…
          </div>
        ) : configs.length === 0 ? (
          <EmptyState
            icon={RefreshCw}
            title="No sync configurations"
            description="Configure sync to automatically mirror secrets to AWS, GCP, Azure, or another Vault instance."
            action={
              <button
                onClick={() => setShowAdd(true)}
                className="flex items-center gap-1.5 bg-accent text-white rounded-lg px-4 py-2 text-sm font-medium hover:bg-accent/90 transition-colors"
              >
                <Plus size={15} />
                Add Sync
              </button>
            }
          />
        ) : (
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Direction</th>
                  <th>Path Filter</th>
                  <th>Last Synced</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {configs.map((cfg) => (
                  <tr key={cfg.id} className="group">
                    <td>
                      <Badge variant={providerBadge[cfg.provider as Provider] ?? 'default'}>
                        {cfg.provider.toUpperCase()}
                      </Badge>
                    </td>
                    <td>
                      <Badge variant={directionBadge[cfg.direction as Direction] ?? 'default'}>
                        {cfg.direction}
                      </Badge>
                    </td>
                    <td className="font-mono text-xs text-muted">
                      {cfg.path_filter ?? '—'}
                    </td>
                    <td className="text-xs text-muted">
                      {cfg.last_synced ? new Date(cfg.last_synced).toLocaleString() : 'Never'}
                    </td>
                    <td>
                      <button
                        onClick={() => deleteMutation.mutate(cfg.id)}
                        disabled={deleteMutation.isPending}
                        className="text-muted hover:text-danger opacity-0 group-hover:opacity-100 transition-all"
                        title="Remove sync"
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
