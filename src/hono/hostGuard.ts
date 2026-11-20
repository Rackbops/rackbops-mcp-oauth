import type { MiddlewareHandler } from "hono"
import { createHostCheck } from "../http/hostGuard.js"

/** The Host/Origin allowlist (`../http/hostGuard.ts`) as Hono middleware for every route: 400 on an
 *  unusable `Host`, 403 on a host or origin outside localhost and `publicHosts`, JSON `{error}` bodies. */
export function hostGuard(publicHosts: readonly string[]): MiddlewareHandler {
  const check = createHostCheck(publicHosts)
  return async (c, next) => {
    const refusal = check(c.req.raw.headers)
    if (refusal !== undefined) return c.json({ error: refusal.error }, refusal.status)
    await next()
  }
}
