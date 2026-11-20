import { NotLinked, NotMember, UsrRateLimited, UsrUnavailable } from "./errors.js"

// A server calls another service as the signed-in person with a usr delegation token (usr
// docs/design/tokens.md, "Delegation token"): it trades its own usr API key for a token that names the
// person (`sub`), the service (`aud`), and only the one operation it is about to call (`scope`
// `<audience>:<operation>`), for a few minutes. The key never leaves the process, and a token is no
// use to anything but that service, for anyone but that person, for anything but that operation.
// Moved from Rackbops/tracker-mcp `src/usr/delegation.ts`, with the audience passed in.
//
// usr mints one only when the person has an active service link to this key covering the operation,
// and holds a role in the audience's app; otherwise it answers 403, which is `NotLinked` here. Any
// role will do for usr, and the token carries none, so the service cannot check the specific role
// itself: with `memberCheck` set, this asks usr's role lookup before minting, so a person an admin took
// the role from is refused from their next token on, not only at the next OAuth refresh.

export interface DelegationOptions {
  /** The service the token is for (`aud`), also the scope prefix: `<audience>:<operation>`. */
  audience: string
  /** usr's origin, no trailing slash needed. */
  usrUrl: string
  /** This service's usr API key. Secret: never logged. */
  apiKey: string
  fetch?: typeof fetch
  /** Epoch milliseconds. */
  now?: () => number
  /** Requested lifetime in seconds; usr's own default is 300 and its cap 1800. */
  ttlSeconds?: number
  timeoutMs?: number
  /** Whether the person still holds the server's role (`./memberCheck.ts`): asked before every mint;
   *  a throw is usr being unreachable, except `UsrRateLimited`, which is passed on. */
  memberCheck?: (sub: string) => Promise<boolean>
}

/** A token for `operation` at the audience, acting for usr user `sub`; `forget` drops a cached one the
 *  service refused, so the next call asks usr again. */
export type TokenSource = ((sub: string, operation: string) => Promise<string>) & {
  forget?: (sub: string, operation: string) => void
}

/** Reused until a minute before it expires, so a burst of calls asks usr once. */
const REUSE_MARGIN_MS = 60_000
const MAX_CACHED = 500

export function createDelegation(options: DelegationOptions): TokenSource {
  const base = options.usrUrl.replace(/\/+$/, "")
  const doFetch = options.fetch ?? fetch
  const now = options.now ?? Date.now
  const cache = new Map<string, { token: string; expiresAt: number }>()
  const source: TokenSource = async (sub, operation) => {
    const key = `${sub}\n${operation}`
    const kept = cache.get(key)
    if (kept !== undefined && kept.expiresAt - REUSE_MARGIN_MS > now()) return kept.token
    cache.delete(key)
    if (options.memberCheck !== undefined) {
      let member: boolean
      try {
        member = await options.memberCheck(sub)
      } catch (err) {
        if (err instanceof UsrRateLimited) throw err
        throw new UsrUnavailable(`usr role lookup failed: ${(err as Error).name}`)
      }
      if (!member) throw new NotMember("the person no longer holds the required role")
    }
    let res: Response
    try {
      res = await doFetch(`${base}/api/token/exchange`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": options.apiKey },
        body: JSON.stringify({
          subject: sub,
          audience: options.audience,
          tools: [`${options.audience}:${operation}`],
          ...(options.ttlSeconds === undefined ? {} : { ttl: options.ttlSeconds }),
        }),
        signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
        // Never follow one: a redirect would carry the API key to wherever it points.
        redirect: "error",
      })
    } catch (err) {
      throw new UsrUnavailable(`usr token exchange failed: ${(err as Error).name}`)
    }
    if (res.status === 403) throw new NotLinked("usr refused the token exchange")
    if (res.status === 429) throw new UsrRateLimited("usr's token exchange limit was reached")
    if (!res.ok) throw new UsrUnavailable(`usr token exchange answered ${res.status}`)
    const body = (await res.json().catch(() => null)) as {
      access_token?: unknown
      expires_in?: unknown
    } | null
    if (
      body === null ||
      typeof body.access_token !== "string" ||
      body.access_token === "" ||
      typeof body.expires_in !== "number"
    ) {
      throw new UsrUnavailable("usr token exchange answered an unexpected body")
    }
    if (cache.size >= MAX_CACHED) cache.clear()
    cache.set(key, { token: body.access_token, expiresAt: now() + body.expires_in * 1000 })
    return body.access_token
  }
  source.forget = (sub, operation) => {
    cache.delete(`${sub}\n${operation}`)
  }
  return source
}
