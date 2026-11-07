export function kv(pairs: Array<[string, string]>, labelWidth = 16): string[] {
  return pairs.map(([key, value]) => `  ${key.padEnd(labelWidth)}  ${value}`)
}
