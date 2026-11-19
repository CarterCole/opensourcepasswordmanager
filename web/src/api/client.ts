const BASE = ''

// The session token lives in an httpOnly cookie the server sets at login, so it
// is never readable by JS (XSS can't exfiltrate it). We keep only a
// non-sensitive "are we logged in" flag in localStorage to drive routing.
const AUTHED_FLAG = 'secretd_authed'

export function isAuthed(): boolean {
  try {
    return localStorage.getItem(AUTHED_FLAG) === '1'
  } catch {
    return false
  }
}

function setAuthed(v: boolean) {
  try {
    if (v) localStorage.setItem(AUTHED_FLAG, '1')
    else localStorage.removeItem(AUTHED_FLAG)
  } catch {
    /* ignore storage errors (private mode, etc.) */
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    credentials: 'include', // send the httpOnly session cookie
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  })

  if (res.status === 401 || res.status === 403) {
    // Session is gone/invalid — drop the local flag so routing sends us to login.
    setAuthed(false)
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`HTTP ${res.status}: ${text}`)
  }

  // Some DELETE endpoints return empty body
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

// ── Session ───────────────────────────────────────────────────────────────────

/** Exchange a token for an httpOnly session cookie. Validated server-side. */
export async function cookieLogin(token: string): Promise<void> {
  const res = await fetch(`${BASE}/v1/auth/cookie/login`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  if (!res.ok) {
    setAuthed(false)
    throw new Error('Invalid token')
  }
  setAuthed(true)
}

/** Clear the session cookie and local flag. */
export async function cookieLogout(): Promise<void> {
  try {
    await fetch(`${BASE}/v1/auth/cookie/logout`, { method: 'POST', credentials: 'include' })
  } catch {
    /* ignore network errors on logout */
  }
  setAuthed(false)
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
