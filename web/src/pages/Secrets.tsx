import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Trash2,
  ChevronDown,
  ChevronRight,
  Key,
  FolderOpen,
  Loader2,
  AlertCircle,
  Save,
  X,
  RotateCcw,
  ShieldOff,
  History,
} from 'lucide-react'
import {
  listMounts,
  listSecrets,
  readSecret,
  writeSecret,
  deleteSecret,
  readSecretMetadata,
  readSecretVersion,
  softDeleteVersions,
  undeleteVersions,
  destroyVersions,
  type VersionMeta,
} from '../api/client'
import { SecretValue } from '../components/SecretValue'
import { Badge } from '../components/Badge'
import { EmptyState } from '../components/EmptyState'
import { useToast } from '../components/Toast'

// ── New secret form ───────────────────────────────────────────────────────────

interface KVPair {
  key: string
  value: string
}

interface NewSecretFormProps {
  mount: string
  basePath: string
  onClose: () => void
  onSaved: () => void
}

type SecretMode = 'kv' | 'plaintext'

function NewSecretForm({ mount, basePath, onClose, onSaved }: NewSecretFormProps) {
  const [path, setPath] = useState(basePath ? `${basePath}/` : '')
  const [mode, setMode] = useState<SecretMode>('kv')
  const [pairs, setPairs] = useState<KVPair[]>([{ key: '', value: '' }])
  const [plaintext, setPlaintext] = useState('')
  const { toast } = useToast()
  const qc = useQueryClient()

  const mutation = useMutation({
    mutationFn: async () => {
      const secretPath = path.replace(/^\/|\/$/g, '')
      if (!secretPath) throw new Error('Path is required')
      if (mode === 'plaintext') {
        if (!plaintext.trim()) throw new Error('Secret value is required')
        return writeSecret(mount, secretPath, { value: plaintext })
      }
      const data: Record<string, string> = {}
      for (const { key, value } of pairs) {
        if (key.trim()) data[key.trim()] = value
      }
      if (Object.keys(data).length === 0) throw new Error('Add at least one key-value pair')
      return writeSecret(mount, secretPath, data)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['secrets-list'] })
      toast('Secret saved', 'success')
      onSaved()
    },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const addPair = () => setPairs((p) => [...p, { key: '', value: '' }])
  const removePair = (i: number) => setPairs((p) => p.filter((_, j) => j !== i))
  const updatePair = (i: number, field: 'key' | 'value', val: string) => {
    setPairs((p) => p.map((pair, j) => (j === i ? { ...pair, [field]: val } : pair)))
  }

  return (
    <div className="bg-surface border border-border rounded-xl p-5 mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-txt">New Secret</h3>
        <button onClick={onClose} className="text-muted hover:text-txt">
          <X size={16} />
        </button>
      </div>

      <div className="space-y-3">
        <div>
          <label className="block text-xs text-muted mb-1">Path</label>
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder={`${mount}/my-service/api-key`}
            className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm font-mono text-txt placeholder:text-muted focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30"
          />
        </div>

        {/* Mode toggle */}
        <div className="flex gap-1 p-0.5 bg-bg rounded-lg w-fit border border-border">
          {(['kv', 'plaintext'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-3 py-1 text-xs rounded-md transition-colors ${
                mode === m
                  ? 'bg-surface-2 text-txt font-medium shadow-sm'
                  : 'text-muted hover:text-txt'
              }`}
            >
              {m === 'kv' ? 'Key / Value' : 'Plaintext'}
            </button>
          ))}
        </div>

        {mode === 'kv' ? (
          <div>
            <label className="block text-xs text-muted mb-2">Fields</label>
            <div className="space-y-2">
              {pairs.map((pair, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    value={pair.key}
                    onChange={(e) => updatePair(i, 'key', e.target.value)}
                    placeholder="KEY"
                    className="flex-1 bg-bg border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-txt placeholder:text-muted focus:outline-none focus:border-accent"
                  />
                  <input
                    value={pair.value}
                    onChange={(e) => updatePair(i, 'value', e.target.value)}
                    placeholder="value"
                    type="password"
                    className="flex-1 bg-bg border border-border rounded-lg px-3 py-1.5 text-xs font-mono text-txt placeholder:text-muted focus:outline-none focus:border-accent"
                  />
                  <button
                    onClick={() => removePair(i)}
                    disabled={pairs.length === 1}
                    className="text-muted hover:text-danger disabled:opacity-30 transition-colors"
                  >
                    <X size={14} />
                  </button>
                </div>
              ))}
            </div>
            <button
              onClick={addPair}
              className="mt-2 text-xs text-accent hover:text-accent/80 flex items-center gap-1"
            >
              <Plus size={12} />
              Add field
            </button>
          </div>
        ) : (
          <div>
            <label className="block text-xs text-muted mb-2">Value</label>
            <textarea
              value={plaintext}
              onChange={(e) => setPlaintext(e.target.value)}
              placeholder="Paste your secret here…"
              rows={4}
              className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-xs font-mono text-txt placeholder:text-muted focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/30 resize-y"
            />
          </div>
        )}

        <div className="flex gap-2 pt-1">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="flex items-center gap-1.5 bg-accent hover:bg-accent/90 disabled:opacity-50 text-white rounded-lg px-3 py-1.5 text-xs font-medium transition-colors"
          >
            {mutation.isPending ? (
              <Loader2 size={12} className="animate-spin" />
            ) : (
              <Save size={12} />
            )}
            Save Secret
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

// ── Version status helpers ────────────────────────────────────────────────────

function versionStatus(v: VersionMeta): 'active' | 'deleted' | 'destroyed' {
  if (v.destroyed) return 'destroyed'
  if (v.deletion_time) return 'deleted'
  return 'active'
}

// ── Secret row ────────────────────────────────────────────────────────────────

interface SecretRowProps {
  mount: string
  secretPath: string
  name: string
}

function SecretRow({ mount, secretPath, name }: SecretRowProps) {
  const [expanded, setExpanded] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null)
  const { toast } = useToast()
  const qc = useQueryClient()

  const fullPath = secretPath ? `${secretPath}/${name}` : name

  const { data, isLoading } = useQuery({
    queryKey: ['secret', mount, fullPath],
    queryFn: () => readSecret(mount, fullPath),
    enabled: expanded,
    retry: false,
  })

  const { data: metaData, isLoading: metaLoading } = useQuery({
    queryKey: ['secret-meta', mount, fullPath],
    queryFn: () => readSecretMetadata(mount, fullPath),
    enabled: expanded,
    retry: false,
  })

  const { data: versionData, isLoading: versionLoading } = useQuery({
    queryKey: ['secret-version', mount, fullPath, selectedVersion],
    queryFn: () => readSecretVersion(mount, fullPath, selectedVersion!),
    enabled: expanded && selectedVersion !== null,
    retry: false,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['secret', mount, fullPath] })
    qc.invalidateQueries({ queryKey: ['secret-meta', mount, fullPath] })
    qc.invalidateQueries({ queryKey: ['secret-version', mount, fullPath] })
  }

  const deleteMutation = useMutation({
    mutationFn: () => deleteSecret(mount, fullPath),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['secrets-list', mount] })
      toast('Secret deleted', 'success')
      setConfirming(false)
    },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const softDeleteMutation = useMutation({
    mutationFn: (v: number) => softDeleteVersions(mount, fullPath, [v]),
    onSuccess: () => { invalidate(); toast('Version soft-deleted', 'success') },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const undeleteMutation = useMutation({
    mutationFn: (v: number) => undeleteVersions(mount, fullPath, [v]),
    onSuccess: () => { invalidate(); toast('Version restored', 'success') },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const destroyMutation = useMutation({
    mutationFn: (v: number) => destroyVersions(mount, fullPath, [v]),
    onSuccess: () => { invalidate(); toast('Version permanently destroyed', 'success') },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const restoreMutation = useMutation({
    mutationFn: async (v: number) => {
      const res = await readSecretVersion(mount, fullPath, v)
      const secretData = res?.data?.data ?? {}
      return writeSecret(mount, fullPath, secretData)
    },
    onSuccess: () => {
      invalidate()
      qc.invalidateQueries({ queryKey: ['secrets-list', mount] })
      setSelectedVersion(null)
      toast('Secret restored as new version', 'success')
    },
    onError: (err: Error) => toast(err.message, 'error'),
  })

  const currentMeta = data?.data?.metadata
  const secretData = data?.data?.data ?? {}

  const previewData = selectedVersion !== null
    ? (versionData?.data?.data ?? {})
    : secretData

  const sortedVersions = metaData
    ? Object.values(metaData.versions).sort((a, b) => b.version - a.version)
    : []

  return (
    <>
      <tr className="group">
        <td>
          <button
            onClick={() => setExpanded((e) => !e)}
            className="flex items-center gap-2 text-txt hover:text-accent transition-colors text-left"
          >
            {expanded ? (
              <ChevronDown size={14} className="text-accent flex-shrink-0" />
            ) : (
              <ChevronRight size={14} className="text-muted flex-shrink-0" />
            )}
            <Key size={13} className="text-muted flex-shrink-0" />
            <span className="font-mono text-xs">{name}</span>
          </button>
        </td>
        <td>
          <Badge variant="accent">kv-v2</Badge>
        </td>
        <td className="text-muted text-xs">
          {currentMeta?.updated_time
            ? new Date(currentMeta.updated_time).toLocaleString()
            : currentMeta?.created_time
              ? new Date(currentMeta.created_time).toLocaleString()
              : '—'}
        </td>
        <td>
          <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
            {confirming ? (
              <span className="flex items-center gap-1.5 text-xs">
                <span className="text-muted">Delete all?</span>
                <button
                  onClick={() => deleteMutation.mutate()}
                  disabled={deleteMutation.isPending}
                  className="text-danger hover:text-danger/80 font-medium"
                >
                  {deleteMutation.isPending ? '…' : 'Yes'}
                </button>
                <button
                  onClick={() => setConfirming(false)}
                  className="text-muted hover:text-txt"
                >
                  No
                </button>
              </span>
            ) : (
              <button
                onClick={() => setConfirming(true)}
                className="text-muted hover:text-danger transition-colors"
                title="Delete secret"
              >
                <Trash2 size={14} />
              </button>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={4} className="p-0">
            <div className="bg-bg border-t border-b border-border px-8 py-4 space-y-5">

              {/* ── Current / preview data ── */}
              {isLoading || (selectedVersion !== null && versionLoading) ? (
                <div className="flex items-center gap-2 text-muted text-xs">
                  <Loader2 size={13} className="animate-spin" />
                  Loading…
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-xs font-medium text-muted uppercase tracking-wide">
                    {selectedVersion !== null
                      ? `Version ${selectedVersion}`
                      : `Current (v${currentMeta?.version ?? '?'})`}
                  </p>
                  {Object.keys(previewData).length === 0 ? (
                    <p className="text-xs text-muted italic">
                      {selectedVersion !== null && versionStatus(metaData?.versions[selectedVersion] ?? { destroyed: false, deletion_time: '', created_time: '', version: selectedVersion }) === 'destroyed'
                        ? 'This version has been permanently destroyed.'
                        : 'No data found'}
                    </p>
                  ) : (
                    Object.entries(previewData).map(([k, v]) => (
                      <div key={k} className="flex items-center gap-3">
                        <span className="font-mono text-xs text-muted w-32 truncate flex-shrink-0">{k}</span>
                        <SecretValue value={String(v)} />
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* ── Version history ── */}
              <div>
                <div className="flex items-center gap-1.5 mb-2">
                  <History size={12} className="text-muted" />
                  <p className="text-xs font-medium text-muted uppercase tracking-wide">Version History</p>
                </div>
                {metaLoading ? (
                  <div className="flex items-center gap-2 text-muted text-xs">
                    <Loader2 size={13} className="animate-spin" />
                    Loading history…
                  </div>
                ) : sortedVersions.length === 0 ? (
                  <p className="text-xs text-muted italic">No versions found</p>
                ) : (
                  <div className="space-y-1">
                    {sortedVersions.map((v) => {
                      const status = versionStatus(v)
                      const isCurrent = v.version === metaData?.current_version
                      const isSelected = selectedVersion === v.version
                      return (
                        <div
                          key={v.version}
                          className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs transition-colors ${
                            isSelected
                              ? 'bg-surface-2 border border-accent/30'
                              : 'hover:bg-surface cursor-pointer'
                          }`}
                          onClick={() => setSelectedVersion(isSelected ? null : v.version)}
                        >
                          <span className="font-mono text-txt font-medium w-6 flex-shrink-0">
                            v{v.version}
                          </span>
                          <span className="text-muted flex-1">
                            {new Date(v.created_time).toLocaleString()}
                          </span>
                          {isCurrent && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-accent/10 text-accent">
                              current
                            </span>
                          )}
                          {status === 'deleted' && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-warn/10 text-warn">
                              deleted
                            </span>
                          )}
                          {status === 'destroyed' && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-danger/10 text-danger">
                              destroyed
                            </span>
                          )}
                          {/* Actions */}
                          <div className="flex items-center gap-1.5 ml-1" onClick={(e) => e.stopPropagation()}>
                            {!isCurrent && status === 'active' && (
                              <>
                                <button
                                  onClick={() => restoreMutation.mutate(v.version)}
                                  disabled={restoreMutation.isPending}
                                  className="flex items-center gap-1 text-muted hover:text-accent transition-colors"
                                  title="Restore as new version"
                                >
                                  <RotateCcw size={12} />
                                </button>
                                <button
                                  onClick={() => softDeleteMutation.mutate(v.version)}
                                  disabled={softDeleteMutation.isPending}
                                  className="flex items-center gap-1 text-muted hover:text-danger transition-colors"
                                  title="Soft-delete this version"
                                >
                                  <Trash2 size={12} />
                                </button>
                              </>
                            )}
                            {status === 'deleted' && (
                              <>
                                <button
                                  onClick={() => undeleteMutation.mutate(v.version)}
                                  disabled={undeleteMutation.isPending}
                                  className="flex items-center gap-1 text-muted hover:text-accent transition-colors"
                                  title="Undelete this version"
                                >
                                  <RotateCcw size={12} />
                                </button>
                                <button
                                  onClick={() => destroyMutation.mutate(v.version)}
                                  disabled={destroyMutation.isPending}
                                  className="flex items-center gap-1 text-muted hover:text-danger transition-colors"
                                  title="Permanently destroy this version"
                                >
                                  <ShieldOff size={12} />
                                </button>
                              </>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Secrets list ──────────────────────────────────────────────────────────────

interface SecretsListProps {
  mount: string
  path: string
}

function SecretsList({ mount, path }: SecretsListProps) {
  const [showNew, setShowNew] = useState(false)

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['secrets-list', mount, path],
    queryFn: () => listSecrets(mount, path),
    retry: false,
  })

  const keys = (data?.data?.keys ?? []).filter((k) => !k.endsWith('/'))
  const folders = (data?.data?.keys ?? []).filter((k) => k.endsWith('/'))

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-muted text-sm p-8">
        <Loader2 size={16} className="animate-spin" />
        Loading secrets…
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center gap-3 text-sm p-8 text-muted">
        <AlertCircle size={16} className="text-warn" />
        <span>{(error as Error).message}</span>
        <button onClick={() => refetch()} className="text-accent hover:underline text-xs">
          Retry
        </button>
      </div>
    )
  }

  return (
    <div>
      {/* New secret form */}
      {showNew && (
        <div className="px-6 pt-4">
          <NewSecretForm
            mount={mount}
            basePath={path}
            onClose={() => setShowNew(false)}
            onSaved={() => { setShowNew(false); refetch() }}
          />
        </div>
      )}

      {/* Folders */}
      {folders.length > 0 && (
        <div className="px-6 py-3 flex flex-wrap gap-2">
          {folders.map((folder) => (
            <a
              key={folder}
              href={`/secrets/${mount}/${path ? `${path}/` : ''}${folder.replace(/\/$/, '')}`}
              className="flex items-center gap-1.5 text-xs text-muted hover:text-txt bg-surface border border-border hover:border-accent/30 rounded-lg px-3 py-1.5 transition-colors"
            >
              <FolderOpen size={12} />
              {folder}
            </a>
          ))}
        </div>
      )}

      {/* Secrets table */}
      {keys.length > 0 ? (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Engine</th>
              <th>Modified</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <SecretRow key={key} mount={mount} secretPath={path} name={key} />
            ))}
          </tbody>
        </table>
      ) : folders.length === 0 ? (
        <EmptyState
          icon={Key}
          title="No secrets here"
          description="Create your first secret to get started."
          action={
            <button
              onClick={() => setShowNew(true)}
              className="flex items-center gap-1.5 bg-accent text-white rounded-lg px-4 py-2 text-sm font-medium hover:bg-accent/90 transition-colors"
            >
              <Plus size={15} />
              New Secret
            </button>
          }
        />
      ) : null}
    </div>
  )
}

// ── Mount picker ──────────────────────────────────────────────────────────────

function MountPicker({ onSelect }: { onSelect: (mount: string) => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ['mounts'],
    queryFn: listMounts,
  })

  const mounts = Object.keys(data ?? {}).filter(
    (k) => !k.startsWith('sys/') && !k.startsWith('identity/') && !k.startsWith('cubbyhole/')
  )

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-muted text-sm p-8">
        <Loader2 size={16} className="animate-spin" />
        Loading mounts…
      </div>
    )
  }

  if (mounts.length === 0) {
    return (
      <EmptyState
        icon={Key}
        title="No secret mounts found"
        description="Enable a KV secrets engine to get started."
      />
    )
  }

  return (
    <div className="p-6 grid grid-cols-2 md:grid-cols-3 gap-3">
      {mounts.map((mount) => (
        <button
          key={mount}
          onClick={() => onSelect(mount.replace(/\/$/, ''))}
          className="flex items-center gap-3 bg-surface border border-border hover:border-accent/40 hover:bg-surface-2 rounded-xl p-4 text-left transition-colors"
        >
          <div className="w-9 h-9 rounded-lg bg-accent-dim flex items-center justify-center flex-shrink-0">
            <Key size={16} className="text-accent" />
          </div>
          <div className="min-w-0">
            <p className="font-mono text-sm text-txt truncate">{mount.replace(/\/$/, '')}</p>
            <p className="text-xs text-muted mt-0.5">kv-v2</p>
          </div>
        </button>
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Secrets() {
  const { mount: mountParam, '*': pathParam } = useParams()
  const navigate = useNavigate()
  const [showNew, setShowNew] = useState(false)
  const qc = useQueryClient()

  const mount = mountParam ?? ''
  const path = pathParam ?? ''

  if (!mount) {
    return (
      <div>
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h2 className="text-sm font-semibold text-txt">Secrets</h2>
        </div>
        <MountPicker onSelect={(m) => navigate(`/secrets/${m}`)} />
      </div>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between px-6 py-4 border-b border-border">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-txt">
            <span className="font-mono text-accent">{mount}</span>
            {path && <span className="text-muted font-mono">/{path}</span>}
          </h2>
        </div>
        <button
          onClick={() => setShowNew((s) => !s)}
          className="flex items-center gap-1.5 bg-accent text-white rounded-lg px-3 py-1.5 text-xs font-medium hover:bg-accent/90 transition-colors"
        >
          <Plus size={13} />
          New Secret
        </button>
      </div>

      {showNew && (
        <div className="px-6 pt-4">
          <NewSecretForm
            mount={mount}
            basePath={path}
            onClose={() => setShowNew(false)}
            onSaved={() => {
              setShowNew(false)
              qc.invalidateQueries({ queryKey: ['secrets-list', mount] })
            }}
          />
        </div>
      )}

      <SecretsList mount={mount} path={path} />
    </div>
  )
}
