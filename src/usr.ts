import { createPublicKey, createVerify, type KeyObject } from "node:crypto"

// Offline verification of usr's `nz_id` SSO cookie, per usr `docs/sso-verifier.md`: ES256 against the
// JWKS (cached five minutes, refetched on an unknown kid at most every 30 seconds), `iss == "usr"`,
// `exp`, and delegation tokens refused (header typ `dlg+jwt`, or an `act` claim). Authorisation is
// the `<app>:` role prefix (`UsrVerifierOptions.app`), stripped from the roles it returns.

export interface Identity {
  /** usr's opaque user id: the only thing to key data on. */
  sub: string
  /** Display only. */
  name: string
  /** This app's roles, without the `<app>:` prefix. */
  roles: string[]
}

/** What /authorize needs from the sign-in system, so tests (and a later swap) don't touch usr. */
export interface IdentityPort {
  /** The verified identity behind the request's `nz_id` cookie, or `null` when missing or invalid. */
  fromRequest(request: Request): Promise<Identity | null>
  /** Where to send a browser with no valid cookie so usr can mint one and return it to `returnUrl`. */
  signInUrl(returnUrl: string): string
}

export interface UsrVerifierOptions {
  /** The usr app whose roles are returned: `meals` keeps `meals:member` as `member`. */
  app: string
  /** usr's origin, e.g. `https://id.rackbops.com`, no trailing slash. */
  usrUrl: string
  fetch?: typeof fetch
  now?: () => number
  cookieName?: string
}

interface CachedKey {
  kid: string
  key: KeyObject
}

function parseCookie(header: string | null, name: string): string | undefined {
  if (header === null) return undefined
  for (const part of header.split(";")) {
    const trimmed = part.trim()
    const eq = trimmed.indexOf("=")
    if (eq > 0 && trimmed.slice(0, eq) === name) return trimmed.slice(eq + 1)
  }
  return undefined
}

export function createUsrIdentity(options: UsrVerifierOptions): IdentityPort {
  const usrUrl = options.usrUrl.replace(/\/+$/, "")
  const doFetch = options.fetch ?? fetch
  const now = options.now ?? Date.now
  const cookieName = options.cookieName ?? "nz_id"
  let keys: CachedKey[] = []
  let keysAt = Number.NEGATIVE_INFINITY

  let inFlight: Promise<void> | undefined
  let lastAttempt = Number.NEGATIVE_INFINITY

  async function loadKeys(force: boolean): Promise<CachedKey[]> {
    const age = now() - keysAt
    // A failed fetch leaves keysAt stale, so rate-limit attempts too (30 s) and share one in flight.
    if ((age > 300_000 || (force && age > 30_000)) && now() - lastAttempt > 30_000) {
      lastAttempt = now()
      inFlight ??= refresh().finally(() => {
        inFlight = undefined
      })
    }
    await inFlight
    return keys
  }

  async function refresh(): Promise<void> {
    try {
      const res = await doFetch(`${usrUrl}/.well-known/jwks.json`, {
        signal: AbortSignal.timeout(5000),
      })
      if (res.ok) {
        const body = (await res.json()) as { keys: ({ kid: string } & Record<string, unknown>)[] }
        keys = body.keys.map((k) => ({
          kid: k.kid,
          key: createPublicKey({ key: k as never, format: "jwk" }),
        }))
        keysAt = now()
      }
    } catch {
      // Keep the previous keys; a failed refresh must not turn into a sign-in for nobody.
    }
  }

  async function verify(token: string): Promise<Identity | null> {
    const [h, p, s] = token.split(".")
    if (!h || !p || !s) return null
    try {
      const header = JSON.parse(Buffer.from(h, "base64url").toString()) as {
        alg?: string
        typ?: string
        kid?: string
      }
      if (header.alg !== "ES256" || header.typ === "dlg+jwt") return null
      const found =
        (await loadKeys(false)).find((k) => k.kid === header.kid) ??
        (await loadKeys(true)).find((k) => k.kid === header.kid)
      if (!found) return null
      const v = createVerify("SHA256")
      v.update(`${h}.${p}`)
      if (!v.verify({ key: found.key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"))) {
        return null
      }
      const claims = JSON.parse(Buffer.from(p, "base64url").toString()) as {
        iss?: string
        exp?: number
        act?: unknown
        sub?: string
        name?: string
        roles?: unknown
      }
      if (claims.iss !== "usr" || typeof claims.exp !== "number" || claims.exp * 1000 <= now()) {
        return null
      }
      if (claims.act !== undefined) return null
      if (typeof claims.sub !== "string" || claims.sub === "") return null
      const roles = (Array.isArray(claims.roles) ? claims.roles : [])
        .filter((r): r is string => typeof r === "string" && r.startsWith(`${options.app}:`))
        .map((r) => r.slice(options.app.length + 1))
      return { sub: claims.sub, name: typeof claims.name === "string" ? claims.name : "", roles }
    } catch {
      return null
    }
  }

  return {
    async fromRequest(request) {
      const token = parseCookie(request.headers.get("cookie"), cookieName)
      return token === undefined ? null : verify(token)
    },
    signInUrl(returnUrl) {
      return `${usrUrl}/api/auth/sso/refresh?return=${encodeURIComponent(returnUrl)}`
    },
  }
}
