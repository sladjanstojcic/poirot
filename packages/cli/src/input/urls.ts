import fs from "node:fs/promises"
import { parseMaybeUrl } from "./normalize.js"

export interface ReadUrlsInput {
  positional: string[]
  file?: string
  stdin?: NodeJS.ReadableStream | null
}

export interface ReadUrlsResult {
  /** Valid tokens, deduped, in order positional → file → stdin. */
  urls: string[]
  /** Tokens that do not parse as a URL even after https:// auto-upgrade. */
  invalid: string[]
}

async function readStdin(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of stream) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks).toString("utf8")
}

function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
}

export async function readUrls(input: ReadUrlsInput): Promise<ReadUrlsResult> {
  const seen = new Set<string>()
  const urls: string[] = []
  const invalid: string[] = []
  const add = (token: string) => {
    if (!token || seen.has(token)) return
    seen.add(token)
    if (parseMaybeUrl(token)) urls.push(token)
    else invalid.push(token)
  }

  for (const token of input.positional) add(token.trim())
  if (input.file) splitLines(await fs.readFile(input.file, "utf8")).forEach(add)
  if (input.stdin) splitLines(await readStdin(input.stdin)).forEach(add)

  return { urls, invalid }
}
