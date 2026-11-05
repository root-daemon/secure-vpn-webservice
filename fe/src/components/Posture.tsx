import { ArrowClockwise } from '@phosphor-icons/react'
import type { Posture as PostureData } from '../api'
import { shortArn } from '../format'
import { Panel, Skeleton, StatusIcon, type Tone } from './ui'

type Check = { label: string; value: string; tone: Tone; group: 'Storage' | 'Host and transport' }

// Every row is computed from the live /api/security response. Checks that do
// not apply (e.g. instance metadata when running off EC2) show as neutral.
function checks(p: PostureData): Check[] {
  const enc = p.default_encryption
  const t = p.transport
  const imds = p.instance.imds
  return [
    {
      label: 'Bucket encryption', group: 'Storage',
      value: enc ? `${enc.algorithm}${enc.kms_key ? `, key ${shortArn(enc.kms_key)}` : ''}` : 'Unavailable',
      tone: enc?.algorithm === 'aws:kms' ? 'ok' : 'err',
    },
    { label: 'S3 Bucket Key', group: 'Storage', value: enc?.bucket_key_enabled ? 'Enabled' : 'Disabled', tone: enc?.bucket_key_enabled ? 'ok' : 'warn' },
    {
      label: 'Public access block', group: 'Storage',
      value: p.public_access_block ? `${Object.values(p.public_access_block).filter(Boolean).length} of 4 on` : 'Unavailable',
      tone: p.all_public_access_blocked ? 'ok' : 'err',
    },
    { label: 'Object versioning', group: 'Storage', value: p.versioning ?? 'Unavailable', tone: p.versioning === 'Enabled' ? 'ok' : 'warn' },
    {
      label: 'Transport', group: 'Host and transport',
      value: t.tls_protocol ? `${t.tls_protocol}, ${t.tls_cipher}` : t.scheme === 'https' ? 'HTTPS' : 'Plain HTTP (not behind nginx)',
      tone: t.tls_protocol || t.scheme === 'https' ? 'ok' : 'warn',
    },
    { label: 'Instance metadata', group: 'Host and transport', value: imds ? `IMDS${imds}` : 'Not running on EC2', tone: imds ? 'ok' : 'neutral' },
    {
      label: 'Public IP address', group: 'Host and transport',
      value: p.instance.public_ip ? p.instance.public_ip : 'Not running on EC2',
      tone: !p.instance.public_ip ? 'neutral' : p.instance.public_ip === 'none' ? 'ok' : 'err',
    },
  ]
}

export function Posture({ data, error, onRefresh }: { data: PostureData | null; error: string | null; onRefresh: () => void }) {
  const list = data ? checks(data) : []
  const applicable = list.filter((c) => c.tone !== 'neutral')
  const passing = applicable.filter((c) => c.tone === 'ok').length

  return (
    <Panel
      title="Security posture"
      action={
        <button onClick={onRefresh} aria-label="Re-check security posture" className="rounded-md p-1.5 text-muted transition hover:bg-sunken hover:text-ink">
          <ArrowClockwise size={16} />
        </button>
      }
    >
      {error && <p className="m-5 rounded-md bg-err-soft px-4 py-3 text-sm text-err">{error}</p>}
      {!data && !error && (
        <div className="space-y-3 p-5">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-8" />
          ))}
        </div>
      )}
      {data && (
        <>
          <div className="flex items-baseline gap-2 px-5 pt-4">
            <span className="font-mono text-3xl font-semibold tracking-tight tabular-nums">
              {passing}/{applicable.length}
            </span>
            <span className="text-sm text-muted">
              checks pass{list.length > applicable.length && `, ${list.length - applicable.length} not applicable here`}
            </span>
          </div>
          {(['Storage', 'Host and transport'] as const).map((group) => (
            <div key={group} className="px-5 pt-4">
              <h3 className="text-xs font-medium text-muted">{group}</h3>
              <ul className="mt-1">
                {list
                  .filter((c) => c.group === group)
                  .map((c) => (
                    <li key={c.label} className="flex items-start gap-3 py-1.5">
                      <StatusIcon tone={c.tone} />
                      <div className="flex min-w-0 flex-1 flex-wrap items-baseline justify-between gap-x-3">
                        <p className="text-sm font-medium">{c.label}</p>
                        <p className="font-mono text-[12px] break-words text-muted">{c.value}</p>
                      </div>
                    </li>
                  ))}
              </ul>
            </div>
          ))}
          <div className="h-4" />
          <p className="border-t border-line px-5 py-3 font-mono text-xs text-muted">s3://{data.bucket}</p>
        </>
      )}
    </Panel>
  )
}
