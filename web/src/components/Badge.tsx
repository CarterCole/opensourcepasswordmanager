interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'success' | 'warn' | 'danger' | 'accent' | 'muted'
}

const variants: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'bg-surface-2 text-txt border-border',
  success: 'bg-success/10 text-success border-success/30',
  warn: 'bg-warn/10 text-warn border-warn/30',
  danger: 'bg-danger/10 text-danger border-danger/30',
  accent: 'bg-accent-dim text-accent border-accent/30',
  muted: 'bg-surface text-muted border-border',
}

export function Badge({ children, variant = 'default' }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${variants[variant]}`}
    >
      {children}
    </span>
  )
}
