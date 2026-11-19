const BASE = ''

function getToken(): string {
  return localStorage.getItem('secretd_token') ?? ''
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-Vault-Token': token,
      ...(options.headers ?? {}),
    },
  })

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`HTTP ${res.status}: ${text}`)
  }

  // Some DELETE endpoints return empty body
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

// ── Health ────────────────────────────────────────────────────────────────────

export interface HealthResponse {
  initialized: boolean
  sealed: boolean
  cluster_name?: string
  version?: string
}

export function checkHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/v1/sys/health')
}

// ── Mounts ───────────────────────────────────────────────────────────────────

export interface MountInfo {
  type: string
  description: string
  options?: Record<string, string>
}

export type MountsResponse = Record<string, MountInfo>

interface MountsApiResponse {
  request_id: string
  data: MountsResponse
}

export function listMounts(): Promise<MountsResponse> {
  return request<MountsApiResponse>('/v1/sys/mounts').then((r) => r.data)
}

// ── Secrets ───────────────────────────────────────────────────────────────────

export interface ListSecretsResponse {
  data: {
    keys: string[]
  }
}

export function listSecrets(mount: string, path: string): Promise<ListSecretsResponse> {
  const p = path ? `/${path}` : ''
  return request<ListSecretsResponse>(`/v1/${mount}/metadata${p}?list=true`)
}

export interface SecretData {
  data: {
    data: Record<string, string>
    metadata: {
      created_time: string
      updated_time?: string
      version: number
      destroyed: boolean
    }
  }
}

export function readSecret(mount: string, path: string): Promise<SecretData> {
  return request<SecretData>(`/v1/${mount}/data/${path}`)
}

export function writeSecret(mount: string, path: string, data: Record<string, string>): Promise<unknown> {
  return request<unknown>(`/v1/${mount}/data/${path}`, {
    method: 'POST',
    body: JSON.stringify({ data }),
  })
}

export function deleteSecret(mount: string, path: string): Promise<unknown> {
  return request<unknown>(`/v1/${mount}/data/${path}`, {
    method: 'DELETE',
  })
}

export interface VersionMeta {
  created_time: string
  deletion_time: string
  destroyed: boolean
  version: number
}

export interface SecretMetadata {
  current_version: number
  oldest_version: number
  versions: Record<string, VersionMeta>
}

interface MetadataApiResponse {
  data: SecretMetadata
}

export function readSecretMetadata(mount: string, path: string): Promise<SecretMetadata> {
  return request<MetadataApiResponse>(`/v1/${mount}/metadata/${path}`).then((r) => r.data)
}

export function readSecretVersion(mount: string, path: string, version: number): Promise<SecretData> {
  return request<SecretData>(`/v1/${mount}/data/${path}?version=${version}`)
}

export function softDeleteVersions(mount: string, path: string, versions: number[]): Promise<unknown> {
  return request<unknown>(`/v1/${mount}/delete/${path}`, {
    method: 'POST',
    body: JSON.stringify({ versions }),
  })
}

export function undeleteVersions(mount: string, path: string, versions: number[]): Promise<unknown> {
  return request<unknown>(`/v1/${mount}/undelete/${path}`, {
    method: 'POST',
    body: JSON.stringify({ versions }),
  })
}

export function destroyVersions(mount: string, path: string, versions: number[]): Promise<unknown> {
  return request<unknown>(`/v1/${mount}/destroy/${path}`, {
    method: 'PUT',
    body: JSON.stringify({ versions }),
  })
}

// ── Audit ─────────────────────────────────────────────────────────────────────

export interface AuditEvent {
  id: string
  timestamp: string
  actor: string
  action: string
  resource: string
  ip: string
}

export interface AuditResponse {
  events: AuditEvent[]
}

export function listAuditEvents(): Promise<AuditResponse> {
  return request<AuditResponse>('/api/v1/audit')
}

// ── Sync configs ──────────────────────────────────────────────────────────────

export interface SyncConfig {
  id: string
  provider: string
  direction: string
  path_filter?: string
  last_synced?: string
  created_at: string
}

export interface SyncListResponse {
  configs: SyncConfig[]
}

export function listSyncConfigs(): Promise<SyncListResponse> {
  return request<SyncListResponse>('/api/v1/sync')
}

export interface CreateSyncConfig {
  provider: string
  direction: string
  path_filter?: string
  credentials: Record<string, string>
}

export function createSyncConfig(cfg: CreateSyncConfig): Promise<unknown> {
  return request<unknown>('/api/v1/sync', {
    method: 'POST',
    body: JSON.stringify(cfg),
  })
}

export function deleteSyncConfig(id: string): Promise<unknown> {
  return request<unknown>(`/api/v1/sync/${id}`, {
    method: 'DELETE',
  })
}
