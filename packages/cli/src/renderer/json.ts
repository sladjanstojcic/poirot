import type { Trace } from "@poirot/core"

export function renderJson(trace: Trace): string {
  return JSON.stringify(trace, null, 2)
}
