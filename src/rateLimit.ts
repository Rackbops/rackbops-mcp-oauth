/** Fixed-window in-memory counter keyed by string. State is per-process and lost on restart, which
 *  is the right trade for a single-instance service: it bounds abuse, it is not an audit record. */
export interface RateLimiter {
  /** Charges one hit and reports whether it fits the budget. */
  hit(key: string): { allowed: true } | { allowed: false; retryAfterSeconds: number }
}

export function createRateLimiter(
  limit: number,
  windowMs: number,
  now: () => number = Date.now,
): RateLimiter {
  const windows = new Map<string, { start: number; count: number }>()
  return {
    hit(key) {
      const t = now()
      if (windows.size > 10_000) {
        for (const [k, w] of windows) if (t - w.start >= windowMs) windows.delete(k)
      }
      let w = windows.get(key)
      if (w === undefined || t - w.start >= windowMs) {
        w = { start: t, count: 0 }
        windows.set(key, w)
      }
      if (w.count >= limit) {
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil((w.start + windowMs - t) / 1000)),
        }
      }
      w.count += 1
      return { allowed: true }
    },
  }
}
