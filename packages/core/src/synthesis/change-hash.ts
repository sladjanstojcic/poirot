import crypto from "node:crypto"

export function canonicalize(x: unknown): unknown {
  if (Array.isArray(x)) {
    return x
      .map(canonicalize)
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
  }
  if (x && typeof x === "object") {
    return Object.keys(x as object)
      .sort()
      .reduce((acc, key) => {
        ;(acc as Record<string, unknown>)[key] = canonicalize((x as Record<string, unknown>)[key])
        return acc
      }, {} as Record<string, unknown>)
  }
  return x
}

export function computeHash(fieldMap: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(canonicalize(fieldMap))).digest("hex")
}
