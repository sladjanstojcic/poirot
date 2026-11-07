import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    exclude: [
      ...(process.env.POIROT_LIVE === "1" ? [] : ["tests/live/**"]),
      ...(process.env.POIROT_PERF === "1" ? [] : ["tests/perf/**"]),
    ],
  },
})
