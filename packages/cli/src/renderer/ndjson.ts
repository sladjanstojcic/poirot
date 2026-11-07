import type { Trace } from "@poirot/core"

export function renderNdjson(trace: Trace): string {
  return JSON.stringify(trace)
}
