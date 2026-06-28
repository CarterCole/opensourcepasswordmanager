import { useState } from 'react'
import { Eye, EyeOff, Copy } from 'lucide-react'
import { useToast } from './Toast'

interface SecretValueProps {
  value: string
  label?: string
}

export function SecretValue({ value, label }: SecretValueProps) {
  const [revealed, setRevealed] = useState(false)
  const { toast } = useToast()

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      toast('Copied to clipboard', 'success')
    } catch {
      toast('Failed to copy', 'error')
    }
  }

  return (
    <span className="inline-flex items-center gap-2">
      {label && (
        <span className="font-mono text-xs text-muted mr-1">{label}:</span>
      )}
      {revealed ? (
        <span
          className="secret-revealed text-sm cursor-pointer select-all"
          onClick={handleCopy}
          title="Click to copy"
        >
          {value}
        </span>
      ) : (
        <span className="secret-redacted text-sm">
          {'•'.repeat(Math.min(value.length || 12, 20))}
        </span>
      )}
      <button
        onClick={() => setRevealed((r) => !r)}
        className="text-muted hover:text-txt transition-colors flex-shrink-0"
        title={revealed ? 'Hide value' : 'Reveal value'}
        type="button"
      >
        {revealed ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
      {revealed && (
        <button
          onClick={handleCopy}
          className="text-muted hover:text-accent transition-colors flex-shrink-0"
          title="Copy to clipboard"
          type="button"
        >
          <Copy size={13} />
        </button>
      )}
    </span>
  )
}
