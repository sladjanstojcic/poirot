import { afterEach, describe, expect, it } from "vitest"
import http from "node:http"
import { Bench } from "tinybench"
import { probe } from "../../src/index.js"

const BUDGET_MEAN_MS = 500
const BUDGET_P99_MS = 1050

let server: http.Server | null = null

afterEach(
  () =>
    new Promise<void>((resolve) => {
      if (server) {
        server.close(() => resolve())
      } else {
        resolve()
      }
    }),
)

describe("perf budget - probe() on localhost", () => {
  it(
    "mean and p99 stay below regression thresholds",
    { timeout: 60_000 },
    async () => {
      server = http
        .createServer((_, res) => {
          res
            .writeHead(200, {
              "content-type": "text/html",
              "strict-transport-security": "max-age=63072000; includeSubDomains",
              "content-security-policy": "default-src 'self'",
              "x-content-type-options": "nosniff",
            })
            .end("<!doctype html><html><body>hi</body></html>")
        })
        .listen(0, "127.0.0.1")
      await new Promise<void>((resolve) => server?.once("listening", () => resolve()))
      const port = (server.address() as any).port
      const url = `http://127.0.0.1:${port}/`

      const bench = new Bench({ time: 3000, warmupIterations: 2 })
      bench.add("probe localhost", async () => {
        await probe(url, { timeout: 5000 })
      })
      await bench.run()

      const task = bench.tasks[0]!
      const meanMs = task.result!.mean
      const p99Ms = task.result!.p99
      const n = task.result!.samples.length
      // eslint-disable-next-line no-console
      console.log(`[perf] probe localhost - mean=${meanMs.toFixed(1)}ms p99=${p99Ms.toFixed(1)}ms n=${n}`)

      expect(meanMs, `mean ${meanMs.toFixed(0)}ms exceeds ${BUDGET_MEAN_MS}ms budget`).toBeLessThan(BUDGET_MEAN_MS)
      expect(p99Ms, `p99 ${p99Ms.toFixed(0)}ms exceeds ${BUDGET_P99_MS}ms budget`).toBeLessThan(BUDGET_P99_MS)
    },
  )
})
