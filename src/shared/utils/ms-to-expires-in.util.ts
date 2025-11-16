import { StringValue } from 'ms'

export function msToExpiresIn(ms: number): StringValue {
  if (ms < 1000) return '1s'

  const seconds = Math.round(ms / 1000)

  if (seconds < 60) return `${seconds}s`

  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m`

  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h`

  const days = Math.round(hours / 24)
  return `${days}d`
}
