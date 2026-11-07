import { afterEach, beforeEach, describe, expect, it } from "vitest"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { readUrls } from "../../src/input/urls.js"

let tmp: string

beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), "poirot-"))
})

afterEach(() => fs.rm(tmp, { recursive: true, force: true }))

describe("readUrls", () => {
  it("merges positional + file, deduping", async () => {
    const f = path.join(tmp, "urls.txt")
    await fs.writeFile(f, "# comment\nexample.com\n\nex.test\n", "utf8")
    const r = await readUrls({ positional: ["example.com", "a.test"], file: f, stdin: null })
    expect(new Set(r.urls)).toEqual(new Set(["example.com", "a.test", "ex.test"]))
  })

  it("splits invalid tokens out", async () => {
    const r = await readUrls({ positional: ["example.com", "ht!tp:://??"] })
    expect(r).toEqual({ urls: ["example.com"], invalid: ["ht!tp:://??"] })
  })
})
