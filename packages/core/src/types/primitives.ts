// Building blocks shared by every probe's ProbeResult.

export type ProbeStatus = "pass" | "warn" | "fail" | "skipped"

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F"

export interface Timing {
  startedAt_ms: number
  duration_ms: number
}

export interface Issue {
  severity: "info" | "warn" | "fail"
  code: string
  message: string
  advice?: string
  doc?: string
  cve?: string
  cwe?: string
  at?: string
}

export interface ProbeResult<T> {
  status: ProbeStatus
  data?: T
  issues: Issue[]
  timing: Timing
  skipped?: {
    reason: "upstream_failed" | "disabled_by_flag" | "not_applicable" | "rate_limited"
    details?: string
  }
  alertable_fields: string[]
}
