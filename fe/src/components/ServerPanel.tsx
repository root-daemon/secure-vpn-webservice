import type { Health, Session } from '../api'
import { formatUptime } from '../format'
import { Badge, Panel, Skeleton } from './ui'

export function ServerPanel({ session, health }: { session: Session; health: Health | null }) {
  const inst = session.instance
  const onEc2 = Boolean(inst.instance_id)
  const rows: [string, string][] = onEc2
    ? [
        ['Instance', `${inst.instance_id} (${inst.instance_type})`],
        ['Availability zone', inst.availability_zone ?? ''],
        ['Private IP', inst.private_ip ?? ''],
        ['Host', session.hostname],
        ['Your address', session.client_ip],
      ]
    : [
        ['Host', session.hostname],
        ['Your address', session.client_ip],
      ]

  return (
    <Panel
      title="Server"
      action={
        health ? (
          <Badge tone={health.status === 'ok' ? 'ok' : 'err'}>{health.status === 'ok' ? 'Healthy' : 'Degraded'}</Badge>
        ) : (
          <Skeleton className="h-5 w-16" />
        )
      }
    >
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 px-5 py-4 text-sm">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="truncate text-right font-mono text-[13px]">{v}</dd>
          </div>
        ))}
        {health && (
          <>
            <dt className="text-muted">Storage check</dt>
            <dd className={`text-right font-mono text-[13px] ${health.checks.storage === 'ok' ? 'text-ok' : 'text-err'}`}>{health.checks.storage}</dd>
            <dt className="text-muted">Uptime</dt>
            <dd className="text-right font-mono text-[13px] tabular-nums">{formatUptime(health.uptime_seconds)}</dd>
          </>
        )}
      </dl>
      {!onEc2 && (
        <p className="border-t border-line px-5 py-3 text-[13px] text-muted">
          Running outside EC2. When deployed, the instance identity is read here through IMDSv2.
        </p>
      )}
    </Panel>
  )
}
