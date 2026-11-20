import { UsrRateLimited } from "./errors.js"

// Whether a person still holds `<app>:<role>`, from usr's strongly consistent role lookup
// (`GET /api/roles/lookup?sub=&app=`, usr README "The hot path"). Moved from Meals for Two's
// `src/identity/memberCheck.ts` and tracker-mcp's `src/usr/memberCheck.ts`, taking tracker-mcp's
// stricter version (no redirects, 429 named). Pass it as `memberCheck` to `createTokenHandler` to
// re-check on every OAuth refresh, and to `createDelegation` to check before every token is minted.
// The caller needs a usr API key holding the `usr:service` role, sent as `x-api-key`.
//
// Fail closed: only an answer that says the person exists and holds the role returns true. A person
// who is gone or lost the role returns false (the token handler revokes the grant and answers
// `invalid_grant`). Anything else (network error, timeout, a redirect, a non-200, a body that isn't the
// contract) throws, which the token handler answers with 503: the grant is kept and the client
// retries, so a usr outage never lets a removed person through and never revokes a good grant. A 429
// throws `UsrRateLimited`, so a caller can tell "slow down" from "down".

export interface UsrMemberCheckOptions {
  /** usr's origin, e.g. `https://id.example.com`, no trailing slash needed. */
  usrUrl: string
  /** A usr API key with the `usr:service` role. Secret: never log it. */
  apiKey: string
  /** The usr app (`meals`). */
  app: string
  /** The role required, without the app prefix (`member`). */
  role: string
  fetch?: typeof fetch
  timeoutMs?: number
}

export function createUsrMemberCheck(
  options: UsrMemberCheckOptions,
): (memberSub: string) => Promise<boolean> {
  const base = options.usrUrl.replace(/\/+$/, "")
  const doFetch = options.fetch ?? fetch
  const required = `${options.app}:${options.role}`
  return async (memberSub) => {
    const query = new URLSearchParams({ sub: memberSub, app: options.app })
    const res = await doFetch(`${base}/api/roles/lookup?${query}`, {
      headers: { "x-api-key": options.apiKey },
      signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
      // Never follow one: a redirect would carry the API key to wherever it points.
      redirect: "error",
    })
    if (res.status === 429) throw new UsrRateLimited("usr's role lookup limit was reached")
    if (!res.ok) throw new Error(`usr role lookup answered ${res.status}`)
    const body = (await res.json()) as { exists?: unknown; roles?: unknown }
    if (typeof body.exists !== "boolean" || !Array.isArray(body.roles)) {
      throw new Error("usr role lookup answered an unexpected body")
    }
    return body.exists && body.roles.includes(required)
  }
}
