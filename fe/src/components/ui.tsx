import { CheckCircle, MinusCircle, WarningCircle, XCircle } from '@phosphor-icons/react'
import type { ReactNode } from 'react'

export type Tone = 'ok' | 'warn' | 'err' | 'neutral'

const toneText: Record<Tone, string> = {
  ok: 'text-ok',
  warn: 'text-warn',
  err: 'text-err',
  neutral: 'text-muted',
}
const toneSoft: Record<Tone, string> = {
  ok: 'bg-ok-soft text-ok',
  warn: 'bg-warn-soft text-warn',
  err: 'bg-err-soft text-err',
  neutral: 'bg-sunken text-muted',
}
const toneIcon: Record<Tone, typeof CheckCircle> = {
  ok: CheckCircle,
  warn: WarningCircle,
  err: XCircle,
  neutral: MinusCircle,
}

export function Panel({ title, action, children, className = '' }: { title: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`enter rounded-lg border border-line bg-surface ${className}`}>
      <header className="flex items-center justify-between gap-4 border-b border-line px-5 py-3.5">
        <h2 className="text-[15px] font-semibold tracking-tight">{title}</h2>
        {action}
      </header>
      {children}
    </section>
  )
}

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${toneSoft[tone]}`}>{children}</span>
}

export function StatusIcon({ tone }: { tone: Tone }) {
  const Icon = toneIcon[tone]
  return <Icon className={`shrink-0 ${toneText[tone]}`} weight="fill" size={18} aria-hidden />
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`shimmer rounded-md ${className}`} aria-hidden />
}
