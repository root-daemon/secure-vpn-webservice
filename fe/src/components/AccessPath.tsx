import { CaretRight, Database, HardDrives, Key, LockSimple } from '@phosphor-icons/react'
import type { Posture } from '../api'

type Hop = { icon: typeof Key; name: string; detail: string; live?: string | null }

// The route every request takes. Static facts come from the Terraform design;
// the "live" line on each hop is read from /api/security when it is available.
function hops(p: Posture | null): Hop[] {
  const enc = p?.default_encryption
  const tls = p?.transport.tls_protocol
  return [
    { icon: Key, name: 'AWS Client VPN', detail: 'Mutual TLS, per-user certificate' },
    {
      icon: LockSimple,
      name: 'nginx',
      detail: 'HTTPS, private CA, TLS 1.2+',
      live: p ? (tls ?? 'TLS not observed') : null,
    },
    { icon: HardDrives, name: 'Vault API', detail: 'CSRF checks, audit log' },
    {
      icon: Database,
      name: 'S3 bucket',
      detail: 'Only via the VPC endpoint',
      live: p ? (enc ? `${enc.algorithm}${p.versioning === 'Enabled' ? ', versioned' : ''}` : 'Encryption not reported') : null,
    },
  ]
}

export function AccessPath({ posture }: { posture: Posture | null }) {
  const list = hops(posture)
  return (
    <ol className="grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-2 xl:grid-cols-4" aria-label="Request path">
      {list.map((h, i) => {
        const Icon = h.icon
        return (
          <li key={h.name} className="relative flex gap-3 bg-surface px-4 py-3.5">
            <span className="grid size-8 shrink-0 place-items-center rounded-md bg-accent-soft text-accent">
              <Icon size={17} weight="bold" aria-hidden />
            </span>
            <div className="min-w-0">
              <p className="text-sm font-semibold tracking-tight">{h.name}</p>
              <p className="text-[12.5px] leading-snug text-muted">{h.detail}</p>
              {h.live !== undefined && (
                <p className={`mt-1 font-mono text-[11.5px] ${h.live === null ? 'text-muted' : 'text-ok'}`}>{h.live ?? 'checking'}</p>
              )}
            </div>
            {i < list.length - 1 && (
              <CaretRight
                size={14}
                weight="bold"
                className="absolute top-1/2 -right-[7px] z-[1] hidden -translate-y-1/2 rounded-full bg-surface text-muted xl:block"
                aria-hidden
              />
            )}
          </li>
        )
      })}
    </ol>
  )
}
