export function normalizeInputUrl(raw: string): string {
  const trimmed = raw.trim()
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  return new URL(withScheme).toString()
}

export function parseMaybeUrl(raw: string): URL | null {
  try {
    return new URL(normalizeInputUrl(raw))
  } catch {
    return null
  }
}
