import type { Trace } from "../types/index.js"

function getByPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((current, part) => (current as any)?.[part], obj)
}

export function collectAlertables(trace: Trace): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  const put = (prefix: string, probeResult: any) => {
    for (const path of probeResult?.alertable_fields ?? []) {
      out[`${prefix}.${path}`] = getByPath(probeResult.data, path)
    }
  }

  put("domain.rdap", trace.domain.rdap)
  put("domain.dns", trace.domain.dns)
  put("domain.email", trace.domain.email)

  for (const [index, request] of trace.requests.entries()) {
    for (const stack of ["v4", "v6"] as const) {
      const attempt = request.attempts[stack]
      if (!attempt) continue
      put(`requests[${index}].attempts.${stack}.dns`, attempt.dns)
      put(`requests[${index}].attempts.${stack}.tcp`, attempt.tcp)
      put(`requests[${index}].attempts.${stack}.tls`, attempt.tls)
      put(`requests[${index}].attempts.${stack}.http`, attempt.http)
      if (attempt.quic) put(`requests[${index}].attempts.${stack}.quic`, attempt.quic)
    }
    for (const [name, audit] of Object.entries(request.audits)) {
      put(`requests[${index}].audits.${name}`, audit)
    }
  }

  return out
}
