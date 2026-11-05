// Typed client for the Flask API. By default it is same origin: nginx serves
// this app and proxies /api, /files and /health to gunicorn.
//
// VITE_API_BASE (build time) points a hosted copy of the UI at the private API,
// e.g. https://app.securevpn.internal. It only works from a browser on the VPN,
// and the API must list the UI's origin in VAULT_ALLOWED_ORIGINS.
export const API_BASE = (import.meta.env.VITE_API_BASE ?? '').replace(/\/$/, '')
const credentials: RequestCredentials = API_BASE ? 'include' : 'same-origin'

export const apiUrl = (path: string) => `${API_BASE}${path}`

export type Instance = {
  instance_id?: string
  instance_type?: string
  availability_zone?: string
  private_ip?: string
  public_ip?: string
  imds?: string
}

export type Session = {
  csrf_token: string
  project: string
  environment: string
  fqdn: string
  hostname: string
  client_ip: string
  instance: Instance
  kms_key_configured: boolean
  max_upload_bytes: number
}

export type VaultFile = { name: string; size: number; modified: string }

export type FileInfo = {
  file: string
  size: number
  server_side_encryption: string | null
  kms_key_id: string | null
  bucket_key_enabled: boolean
  version_id: string | null
  last_modified: string | null
}

export type Posture = {
  bucket: string
  instance: Instance
  default_encryption?: { algorithm: string; kms_key: string | null; bucket_key_enabled: boolean }
  public_access_block?: Record<string, boolean>
  all_public_access_blocked?: boolean
  versioning?: string
  error?: string
  transport: { scheme: string; tls_protocol: string | null; tls_cipher: string | null }
}

export type Health = {
  status: 'ok' | 'degraded'
  checks: Record<string, string>
  uptime_seconds: number
  environment: string
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

let csrfToken = ''

async function request<T>(path: string, init: RequestInit = {}, okStatuses: number[] = []): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.method && init.method !== 'GET') headers.set('X-CSRF-Token', csrfToken)
  const res = await fetch(apiUrl(path), { credentials, ...init, headers })
  const body = await res.json().catch(() => ({}))
  if (!res.ok && !okStatuses.includes(res.status)) {
    throw new ApiError(body.error ?? `Request failed (HTTP ${res.status})`, res.status)
  }
  return body as T
}

export const api = {
  async session(): Promise<Session> {
    const s = await request<Session>('/api/session')
    csrfToken = s.csrf_token
    return s
  },
  files: () => request<{ files: VaultFile[] }>('/api/files').then((r) => r.files),
  info: (name: string) => request<FileInfo>(`/files/${encodeURIComponent(name)}/info`),
  remove: (name: string) => request<{ deleted: boolean }>(`/api/files/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  posture: () => request<Posture>('/api/security'),
  // 503 still carries a JSON body describing which check failed.
  health: () => request<Health>('/health', {}, [503]),

  // XHR rather than fetch: fetch has no upload progress events.
  upload(file: File, onProgress: (fraction: number) => void): Promise<void> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      const form = new FormData()
      form.append('file', file)
      xhr.open('POST', apiUrl('/api/files'))
      xhr.withCredentials = Boolean(API_BASE)
      xhr.setRequestHeader('X-CSRF-Token', csrfToken)
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total)
      xhr.onload = () => {
        if (xhr.status === 201) return resolve()
        let message = `Upload failed (HTTP ${xhr.status})`
        try {
          message = JSON.parse(xhr.responseText).error ?? message
        } catch {
          /* non-JSON error page */
        }
        reject(new ApiError(message, xhr.status))
      }
      xhr.onerror = () => reject(new ApiError('Network error during upload', 0))
      xhr.send(form)
    })
  },
}
