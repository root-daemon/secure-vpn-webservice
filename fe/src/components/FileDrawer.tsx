import { Check, Copy, DownloadSimple, X } from '@phosphor-icons/react'
import { useEffect, useState } from 'react'
import { api, apiUrl, type FileInfo } from '../api'
import { formatBytes } from '../format'
import { Badge, Skeleton } from './ui'

// Side sheet with the live head_object metadata for one file: proves the
// object really is SSE-KMS under the project key, not just labelled so.
export function FileDrawer({ name, onClose }: { name: string; onClose: () => void }) {
  const [info, setInfo] = useState<FileInfo | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    let live = true
    api.info(name).then(
      (i) => live && setInfo(i),
      (e: Error) => live && setError(e.message),
    )
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => {
      live = false
      window.removeEventListener('keydown', onKey)
    }
  }, [name, onClose])

  async function copyKey() {
    if (!info?.kms_key_id) return
    await navigator.clipboard?.writeText(info.kms_key_id)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const rows: { k: string; v: React.ReactNode }[] = info
    ? [
        { k: 'Server-side encryption', v: <Badge tone={info.server_side_encryption === 'aws:kms' ? 'ok' : 'err'}>{info.server_side_encryption ?? 'none'}</Badge>},
        {
          k: 'KMS key',
          v: info.kms_key_id ? (
            <span className="flex items-start gap-2">
              <span className="font-mono text-[12.5px] break-all">{info.kms_key_id}</span>
              <button onClick={copyKey} aria-label="Copy KMS key ARN" className="shrink-0 rounded-md p-1 text-muted hover:bg-sunken hover:text-ink">
                {copied ? <Check size={14} /> : <Copy size={14} />}
              </button>
            </span>
          ) : (
            <span className="text-muted">Not reported</span>
          ),
        },
        { k: 'S3 Bucket Key', v: info.bucket_key_enabled ? 'Enabled' : 'Disabled'},
        { k: 'Version ID', v: <span className="font-mono text-[12.5px] break-all">{info.version_id ?? 'null'}</span>},
        { k: 'Size', v: formatBytes(info.size)},
        { k: 'Last modified', v: <span className="font-mono text-[12.5px]">{info.last_modified}</span>},
      ]
    : []

  return (
    <div className="fixed inset-0 z-20 flex justify-end" role="dialog" aria-modal="true" aria-label={`Details for ${name}`}>
      <button className="absolute inset-0 bg-ink/30 backdrop-blur-[2px]" aria-label="Close details" onClick={onClose} />
      <aside className="enter relative flex h-full w-full max-w-md flex-col border-l border-line bg-surface shadow-[0_0_40px_rgba(27,36,48,0.18)]">
        <header className="flex items-start justify-between gap-4 border-b border-line px-6 py-5">
          <div className="min-w-0">
            <p className="text-xs text-muted">Object metadata from S3</p>
            <h2 className="mt-0.5 truncate text-lg font-semibold tracking-tight">{name}</h2>
          </div>
          <button onClick={onClose} aria-label="Close" className="rounded-md p-1.5 text-muted hover:bg-sunken hover:text-ink">
            <X size={18} />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {error && <p className="rounded-md bg-err-soft px-4 py-3 text-sm text-err">{error}</p>}
          {!info && !error && (
            <div className="space-y-4">
              {[0, 1, 2, 3, 4].map((i) => (
                <Skeleton key={i} className="h-10" />
              ))}
            </div>
          )}
          {info && (
            <dl className="space-y-4 text-sm">
              {rows.map(({ k, v }) => (
                <div key={k}>
                  <dt className="text-xs text-muted">{k}</dt>
                  <dd className="mt-1">{v}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
        <footer className="border-t border-line px-6 py-4">
          <a
            href={apiUrl(`/files/${encodeURIComponent(name)}`)}
            download
            className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-on-accent transition hover:bg-accent-hover active:translate-y-px"
          >
            <DownloadSimple size={16} weight="bold" />
            Download
          </a>
        </footer>
      </aside>
    </div>
  )
}
