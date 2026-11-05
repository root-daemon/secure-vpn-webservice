import { Moon, ShieldCheck, Sun, X } from '@phosphor-icons/react'
import { useCallback, useEffect, useState } from 'react'
import { api, API_BASE, type Health, type Posture as PostureData, type Session, type VaultFile } from './api'
import { AccessPath } from './components/AccessPath'
import { Documents } from './components/Documents'
import { FileDrawer } from './components/FileDrawer'
import { Posture } from './components/Posture'
import { ServerPanel } from './components/ServerPanel'
import { Badge, Skeleton, StatusIcon, type Tone } from './components/ui'

type Theme = 'light' | 'dark'
type Toast = { id: number; tone: Tone; message: string }

const HEALTH_POLL_MS = 30_000

function initialTheme(): Theme {
  const fromUrl = new URLSearchParams(location.search).get('theme')
  if (fromUrl === 'light' || fromUrl === 'dark') return fromUrl
  try {
    const saved = localStorage.getItem('vault-theme')
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    /* storage blocked */
  }
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const [session, setSession] = useState<Session | null>(null)
  const [fatal, setFatal] = useState<string | null>(null)
  const [files, setFiles] = useState<VaultFile[] | null>(null)
  const [filesError, setFilesError] = useState<string | null>(null)
  const [posture, setPosture] = useState<PostureData | null>(null)
  const [postureError, setPostureError] = useState<string | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('vault-theme', theme)
    } catch {
      /* storage blocked */
    }
  }, [theme])

  const notify = useCallback((tone: Tone, message: string) => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, tone, message }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 5000)
  }, [])

  const loadFiles = useCallback(() => {
    api.files().then(
      (f) => {
        setFiles(f)
        setFilesError(null)
      },
      (e: Error) => setFilesError(e.message),
    )
  }, [])

  const loadPosture = useCallback(() => {
    setPosture(null)
    setPostureError(null)
    api.posture().then(setPosture, (e: Error) => setPostureError(e.message))
  }, [])

  useEffect(() => {
    api.session().then(
      (s) => {
        setSession(s)
        loadFiles()
        loadPosture()
      },
      (e: Error) => setFatal(e.message),
    )
    const poll = () => api.health().then(setHealth, () => setHealth({ status: 'degraded', checks: { app: 'unreachable', storage: 'unknown' }, uptime_seconds: 0, environment: '' }))
    poll()
    const timer = setInterval(poll, HEALTH_POLL_MS)
    return () => clearInterval(timer)
  }, [loadFiles, loadPosture])

  const closeDrawer = useCallback(() => setSelected(null), [])

  return (
    <div className="flex min-h-[100dvh] flex-col">
      <header className="sticky top-0 z-10 border-b border-line bg-surface/90 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-7xl items-center gap-4 px-4 sm:px-6">
          <span className="grid size-9 place-items-center rounded-md bg-accent text-on-accent">
            <ShieldCheck size={20} weight="bold" aria-hidden />
          </span>
          <div className="min-w-0 flex-1">
            <h1 className="text-[15px] leading-tight font-semibold tracking-tight">Secure Vault</h1>
            <p className="truncate font-mono text-xs text-muted">{session?.fqdn ?? 'connecting'}</p>
          </div>
          {session && <Badge tone="neutral">{session.environment}</Badge>}
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            className="rounded-md p-2 text-muted transition hover:bg-sunken hover:text-ink"
          >
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:py-8">
        {fatal ? (
          <div className="mx-auto max-w-lg rounded-lg border border-line bg-surface p-6">
            <h2 className="font-semibold">Cannot reach the vault service</h2>
            <p className="mt-2 text-sm text-muted">{fatal}. Check that you are connected to the VPN, then reload.</p>
            {API_BASE && (
              <ol className="mt-4 list-decimal space-y-1.5 pl-5 text-sm text-muted">
                <li>Connect the AWS Client VPN profile.</li>
                <li>
                  Trust the project CA, or open{' '}
                  <a className="font-mono text-accent underline" href={API_BASE} target="_blank" rel="noreferrer">
                    {API_BASE.replace('https://', '')}
                  </a>{' '}
                  once and accept its certificate.
                </li>
                <li>If the browser asks to access devices on your local network, allow it.</li>
              </ol>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-6 lg:grid-cols-[minmax(0,1fr)_380px]">
            <div className="space-y-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-2xl font-semibold tracking-tight">Encrypted documents</h2>
                  <p className="mt-1 text-sm text-muted">Each request passes through these four hops. None of them is reachable from the internet.</p>
                </div>
                <AccessPath posture={posture} />
              </div>
              <Documents
                files={files}
                error={filesError}
                maxBytes={session?.max_upload_bytes ?? 10 * 1024 * 1024}
                onChanged={loadFiles}
                onInfo={setSelected}
                notify={notify}
              />
            </div>
            <div className="space-y-6">
              <Posture data={posture} error={postureError} onRefresh={loadPosture} />
              {session ? <ServerPanel session={session} health={health} /> : <Skeleton className="h-48" />}
            </div>
          </div>
        )}
      </main>

      <footer className="border-t border-line">
        <p className="mx-auto max-w-7xl px-4 py-4 text-xs text-muted sm:px-6">
          Internal use only. nginx logs every request, and CloudTrail records every S3 object access.
        </p>
      </footer>

      {selected && <FileDrawer key={selected} name={selected} onClose={closeDrawer} />}

      <div className="pointer-events-none fixed right-4 bottom-4 z-30 flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className="enter pointer-events-auto flex items-start gap-3 rounded-lg border border-line bg-surface px-4 py-3 text-sm shadow-[0_8px_30px_rgba(27,36,48,0.14)]">
            <StatusIcon tone={t.tone} />
            <span className="flex-1">{t.message}</span>
            <button
              onClick={() => setToasts((all) => all.filter((x) => x.id !== t.id))}
              aria-label="Dismiss notification"
              className="-m-1 rounded-md p-1 text-muted hover:bg-sunken hover:text-ink"
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
