import {
  CloudArrowUp,
  DownloadSimple,
  File,
  FileCsv,
  FileImage,
  FilePdf,
  FileText,
  FileXls,
  FileZip,
  Info,
  LockKey,
  MagnifyingGlass,
  Trash,
} from '@phosphor-icons/react'
import { useRef, useState, type DragEvent } from 'react'
import { api, apiUrl, type VaultFile } from '../api'
import { formatBytes } from '../format'
import { Badge, Panel, Skeleton, type Tone } from './ui'

const FILE_ICONS: Record<string, typeof File> = {
  pdf: FilePdf,
  txt: FileText,
  md: FileText,
  docx: FileText,
  csv: FileCsv,
  xlsx: FileXls,
  png: FileImage,
  jpg: FileImage,
  jpeg: FileImage,
  zip: FileZip,
}

function iconFor(name: string) {
  return FILE_ICONS[name.split('.').pop()?.toLowerCase() ?? ''] ?? File
}

type Props = {
  files: VaultFile[] | null
  error: string | null
  maxBytes: number
  onChanged: () => void
  onInfo: (name: string) => void
  notify: (tone: Tone, message: string) => void
}

export function Documents({ files, error, maxBytes, onChanged, onInfo, notify }: Props) {
  const input = useRef<HTMLInputElement>(null)
  const [progress, setProgress] = useState<{ name: string; fraction: number } | null>(null)
  const [dragging, setDragging] = useState(false)
  const [confirming, setConfirming] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  async function upload(file: File) {
    if (file.size > maxBytes) {
      notify('err', `${file.name} is ${formatBytes(file.size)}. The limit is ${formatBytes(maxBytes)}.`)
      return
    }
    setProgress({ name: file.name, fraction: 0 })
    try {
      await api.upload(file, (fraction) => setProgress({ name: file.name, fraction }))
      notify('ok', `${file.name} uploaded and encrypted with SSE-KMS.`)
      onChanged()
    } catch (e) {
      notify('err', (e as Error).message)
    } finally {
      setProgress(null)
      if (input.current) input.current.value = ''
    }
  }

  async function remove(name: string) {
    setConfirming(null)
    try {
      await api.remove(name)
      notify('ok', `${name} deleted. Previous versions are kept for 30 days.`)
      onChanged()
    } catch (e) {
      notify('err', (e as Error).message)
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) void upload(file)
  }

  const shown = files?.filter((f) => f.name.toLowerCase().includes(query.trim().toLowerCase())) ?? null
  const count = files?.length ?? 0
  const total = files?.reduce((sum, f) => sum + f.size, 0) ?? 0

  return (
    <Panel
      title="Documents"
      action={
        files && (
          <div className="flex items-center gap-4">
            <span className="hidden font-mono text-xs text-muted sm:inline">
              {count} {count === 1 ? 'file' : 'files'}, {formatBytes(total)}
            </span>
            {count > 0 && (
              <label className="relative block">
                <span className="sr-only">Filter documents by name</span>
                <MagnifyingGlass size={15} className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-muted" aria-hidden />
                <input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter"
                  className="h-8 w-36 rounded-md border border-line bg-surface pr-2 pl-8 text-sm placeholder:text-muted focus:border-accent focus:outline-none sm:w-44"
                />
              </label>
            )}
          </div>
        )
      }
    >
      <div className="p-5 pb-3">
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`relative flex flex-col items-start gap-4 overflow-hidden rounded-lg border border-dashed px-5 py-4 transition-colors sm:flex-row sm:items-center ${
            dragging ? 'border-accent bg-accent-soft' : 'border-line bg-sunken'
          }`}
        >
          <CloudArrowUp size={28} className="shrink-0 text-accent" aria-hidden />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">{progress ? `Uploading ${progress.name}` : 'Drop a file here to upload'}</p>
            <p className="text-[13px] text-muted">
              Up to {formatBytes(maxBytes)}. Encrypted with the project KMS key before it is written to S3.
            </p>
          </div>
          <input ref={input} type="file" className="sr-only" id="file-input" onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
          <label
            htmlFor="file-input"
            className={`inline-flex cursor-pointer items-center gap-2 rounded-md bg-accent px-3.5 py-2 text-sm font-semibold whitespace-nowrap text-on-accent transition hover:bg-accent-hover active:translate-y-px ${
              progress ? 'pointer-events-none opacity-60' : ''
            }`}
          >
            Choose file
          </label>
          {progress && (
            <div className="absolute inset-x-0 bottom-0 h-0.5" role="progressbar" aria-valuenow={Math.round(progress.fraction * 100)} aria-valuemin={0} aria-valuemax={100}>
              <div className="h-full bg-accent transition-[width] duration-200" style={{ width: `${progress.fraction * 100}%` }} />
            </div>
          )}
        </div>
      </div>

      {error ? (
        <p className="mx-5 mb-5 rounded-md bg-err-soft px-4 py-3 text-sm text-err">{error}</p>
      ) : files === null ? (
        <div className="space-y-3 px-5 pb-5">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-9" />
          ))}
        </div>
      ) : files.length === 0 ? (
        <div className="px-5 pt-6 pb-10 text-center">
          <LockKey size={32} className="mx-auto text-muted" aria-hidden />
          <p className="mt-3 text-sm font-medium">The vault is empty</p>
          <p className="mt-1 text-[13px] text-muted">Upload a document above. It is stored in S3 under SSE-KMS and versioned.</p>
        </div>
      ) : (
        <div className="relative overflow-x-auto pb-2">
          <table className="w-full min-w-[620px] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-5 py-2 font-medium">Name</th>
                <th className="px-3 py-2 text-right font-medium">Size</th>
                <th className="px-3 py-2 font-medium">Modified</th>
                <th className="px-3 py-2 font-medium">Encryption</th>
                <th className="px-5 py-2">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line border-t border-line">
              {shown!.map((f) => {
                const Icon = iconFor(f.name)
                return (
                  <tr key={f.name} className="group transition-colors hover:bg-sunken">
                    <td className="px-5 py-2.5">
                      <span className="flex items-center gap-2.5 font-medium">
                        <Icon size={18} className="shrink-0 text-muted" aria-hidden />
                        <span className="truncate">{f.name}</span>
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-right font-mono text-[13px] whitespace-nowrap text-muted tabular-nums">{formatBytes(f.size)}</td>
                    <td className="px-3 py-2.5 font-mono text-[13px] whitespace-nowrap text-muted">{f.modified}</td>
                    <td className="px-3 py-2.5">
                      <Badge tone="ok">
                        <LockKey size={12} weight="bold" aria-hidden />
                        SSE-KMS
                      </Badge>
                    </td>
                    <td className="px-5 py-2.5">
                      {confirming === f.name ? (
                        <span className="flex items-center justify-end gap-2 whitespace-nowrap">
                          <span className="text-xs text-muted">Delete?</span>
                          <button onClick={() => remove(f.name)} className="rounded-md bg-err px-2.5 py-1 text-xs font-semibold text-surface">
                            Delete
                          </button>
                          <button onClick={() => setConfirming(null)} className="rounded-md px-2.5 py-1 text-xs font-medium text-muted hover:text-ink">
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <span className="flex items-center justify-end gap-1 text-muted">
                          <IconButton label={`Encryption details for ${f.name}`} onClick={() => onInfo(f.name)}>
                            <Info size={18} />
                          </IconButton>
                          <a
                            href={apiUrl(`/files/${encodeURIComponent(f.name)}`)}
                            download
                            aria-label={`Download ${f.name}`}
                            className="rounded-md p-1.5 transition hover:bg-line hover:text-ink"
                          >
                            <DownloadSimple size={18} />
                          </a>
                          <IconButton label={`Delete ${f.name}`} onClick={() => setConfirming(f.name)} danger>
                            <Trash size={18} />
                          </IconButton>
                        </span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {shown!.length === 0 && <p className="border-t border-line px-5 py-6 text-center text-sm text-muted">No documents match “{query}”.</p>}
        </div>
      )}
    </Panel>
  )
}

function IconButton({ label, onClick, danger, children }: { label: string; onClick: () => void; danger?: boolean; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className={`rounded-md p-1.5 transition hover:bg-line active:translate-y-px ${danger ? 'hover:text-err' : 'hover:text-ink'}`}
    >
      {children}
    </button>
  )
}
