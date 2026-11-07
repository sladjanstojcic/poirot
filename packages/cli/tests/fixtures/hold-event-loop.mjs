// Preload for cli-exit tests: keeps the event loop busy for 20 s, like a
// library's in-flight DNS request that cannot be cancelled.
setTimeout(() => {}, 20_000)
