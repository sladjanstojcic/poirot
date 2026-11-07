type H = Array<[string, string]>

export function nextHopUrl(currentUrl: string, status: number, headers: H): string | null {
  if (status < 300 || status >= 400) return null
  const loc = headers.find(([k]) => k.toLowerCase() === "location")?.[1]
  if (!loc) return null
  try {
    return new URL(loc, currentUrl).toString()
  } catch {
    return null
  }
}

export function detectRedirectLoop(chain: string[], next: string): boolean {
  return chain.includes(next)
}

export function isHttpsDowngrade(from: string, to: string): boolean {
  try {
    return new URL(from).protocol === "https:" && new URL(to).protocol === "http:"
  } catch {
    return false
  }
}

export function isCrossOrigin(from: string, to: string): boolean {
  try {
    return new URL(from).host !== new URL(to).host
  } catch {
    return false
  }
}
