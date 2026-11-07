// Best-effort check against hstspreload.org API. 3-second timeout; never fails the run.
export async function hstsPreloadStatus(
  domain: string,
  signal: AbortSignal,
): Promise<"preloaded" | "pending" | "rejected" | "unknown" | null> {
  try {
    const res = await fetch(`https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(domain)}`, {
      signal: AbortSignal.any([signal, AbortSignal.timeout(3000)]),
    })
    if (!res.ok) return null
    const j: any = await res.json()
    return j.status ?? null
  } catch {
    return null
  }
}
