export function toALabel(hostname: string): string {
  // node:url performs IDN via `new URL()`. Using dummy scheme to reuse it.
  try {
    const url = new URL(`http://${hostname}`)
    return url.hostname.toLowerCase()
  } catch {
    return hostname.toLowerCase()
  }
}
