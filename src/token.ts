import { randomBytes } from "node:crypto"
import type { OAuthConfig } from "./config.js"
import { normalizeResource } from "./discovery.js"
import { clientIdPattern } from "./registration.js"
import { type OAuthStore, sha256Hex } from "./store.js"

// POST /token (RFC 6749 3.2): authorization_code and refresh_token. Ported from Rackbops/discord-mcp
// `src/service/oauthToken.ts` without the Discord registration gate: atomic code exchange with
// resource binding and PKCE in the store, bounded refresh rotation with a grace-window sibling and
// reuse detection, concurrent refreshes of one token coalesced into one rotation.

const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/
const MAX_BODY_BYTES = 4096

function presentOnce(params: URLSearchParams, name: string): string | undefined {
  const all = params.getAll(name)
  return all.length === 1 ? all[0] : undefined
}

export type TokenRequestResult =
  | {
      ok: true
      grantType: "authorization_code"
      clientId: string
      resource: string
      code: string
      redirectUri: string
      codeVerifier: string
    }
  | {
      ok: true
      grantType: "refresh_token"
      clientId: string
      resource: string
      refreshToken: string
    }
  | {
      ok: false
      error: "invalid_request" | "unsupported_grant_type" | "invalid_client" | "invalid_target"
      description: string
    }

const invalidRequest = (description: string): TokenRequestResult => ({
  ok: false,
  error: "invalid_request",
  description,
})

export function parseTokenRequest(
  params: URLSearchParams,
  issuer: string,
  acceptOriginAsResource: boolean,
  idPrefix: string,
): TokenRequestResult {
  const CLIENT_ID_PATTERN = clientIdPattern(idPrefix)
  const CODE_PATTERN = new RegExp(`^${idPrefix}_ac_[A-Za-z0-9_-]{43}$`)
  const REFRESH_TOKEN_PATTERN = new RegExp(`^${idPrefix}_rt_[A-Za-z0-9_-]{43}$`)
  for (const key of new Set(params.keys())) {
    if (params.getAll(key).length > 1) return invalidRequest("a parameter must not be duplicated")
  }
  const grantType = presentOnce(params, "grant_type")
  if (grantType === undefined) return invalidRequest("grant_type is required")
  if (grantType !== "authorization_code" && grantType !== "refresh_token") {
    return {
      ok: false,
      error: "unsupported_grant_type",
      description: "grant_type must be authorization_code or refresh_token",
    }
  }
  const clientId = presentOnce(params, "client_id")
  if (clientId === undefined || !CLIENT_ID_PATTERN.test(clientId)) {
    return { ok: false, error: "invalid_client", description: "client_id is missing or malformed" }
  }
  if (params.get("client_secret") !== null) {
    return {
      ok: false,
      error: "invalid_client",
      description: "client_secret is not accepted -- no client of this service is ever issued one",
    }
  }
  const resource = normalizeResource(params.getAll("resource"), issuer, acceptOriginAsResource)
  if (!resource.ok) {
    return { ok: false, error: "invalid_target", description: `resource must be ${issuer}/mcp` }
  }
  if (grantType === "authorization_code") {
    const code = presentOnce(params, "code")
    if (code === undefined || !CODE_PATTERN.test(code))
      return invalidRequest("code is missing or malformed")
    const redirectUri = presentOnce(params, "redirect_uri")
    if (redirectUri === undefined) return invalidRequest("redirect_uri is required")
    const codeVerifier = presentOnce(params, "code_verifier")
    if (codeVerifier === undefined || !CODE_VERIFIER_PATTERN.test(codeVerifier)) {
      return invalidRequest("code_verifier is missing or malformed")
    }
    return {
      ok: true,
      grantType: "authorization_code",
      clientId,
      resource: resource.resource,
      code,
      redirectUri,
      codeVerifier,
    }
  }
  const refreshToken = presentOnce(params, "refresh_token")
  if (refreshToken === undefined || !REFRESH_TOKEN_PATTERN.test(refreshToken)) {
    return invalidRequest("refresh_token is missing or malformed")
  }
  return {
    ok: true,
    grantType: "refresh_token",
    clientId,
    resource: resource.resource,
    refreshToken,
  }
}

function mintToken(prefix: string): string {
  return `${prefix}${randomBytes(32).toString("base64url")}`
}

function tokenResponse(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      ...extra,
    },
  })
}

const tokenError = (error: string, description: string): Response =>
  tokenResponse(400, { error, error_description: description })

const unavailable = (retryAfterSeconds: number): Response =>
  tokenResponse(
    503,
    { error: "temporarily_unavailable" },
    { "Retry-After": String(retryAfterSeconds) },
  )

export interface TokenDeps {
  store: OAuthStore
  oauth: OAuthConfig
  clock?: () => number
  /** Optional: asked on every refresh whether the grant's member may still use the app (for
   *  example, still holds the usr role). `false` revokes the grant; a throw answers 503. Off by
   *  default, which keeps the behaviour that only the idle and absolute lifetimes end a grant. */
  memberCheck?: (memberSub: string) => Promise<boolean>
}

export function createTokenHandler(deps: TokenDeps): (request: Request) => Promise<Response> {
  const { store, oauth } = deps
  const clock = deps.clock ?? Date.now
  const coalescing = new Map<string, Promise<Response>>()

  function handleCodeExchange(
    req: Extract<TokenRequestResult, { grantType: "authorization_code" }>,
  ): Response {
    const now = clock()
    const grantId = `${oauth.app.idPrefix}_g_${randomBytes(16).toString("base64url")}`
    const accessToken = mintToken(`${oauth.app.idPrefix}_at_`)
    const refreshToken = mintToken(`${oauth.app.idPrefix}_rt_`)
    let outcome: ReturnType<OAuthStore["exchangeCode"]>
    try {
      outcome = store.exchangeCode(
        sha256Hex(req.code),
        {
          clientId: req.clientId,
          redirectUri: req.redirectUri,
          resource: req.resource,
          codeVerifier: req.codeVerifier,
        },
        {
          grantId,
          refreshTokenHash: sha256Hex(refreshToken),
          accessTokenHash: sha256Hex(accessToken),
          accessTokenExpiresAt: now + oauth.lifetimes.accessTokenSeconds * 1000,
        },
        now,
      )
    } catch (err) {
      console.error(
        `${oauth.app.logPrefix}: /token failed to exchange the authorization code:`,
        err,
      )
      return unavailable(5)
    }
    switch (outcome.kind) {
      case "resource_mismatch":
        return tokenError("invalid_target", `resource must be ${oauth.issuer}/mcp`)
      case "ok":
        return tokenResponse(200, {
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: oauth.lifetimes.accessTokenSeconds,
          refresh_token: refreshToken,
          scope: outcome.scopes,
        })
      default:
        return tokenError(
          "invalid_grant",
          "The authorization code is invalid, expired or already used.",
        )
    }
  }

  function performRotation(tokenHash: string, now: number, scope: string): Response {
    const childRefresh = mintToken(`${oauth.app.idPrefix}_rt_`)
    const childAccess = mintToken(`${oauth.app.idPrefix}_at_`)
    let outcome: ReturnType<OAuthStore["rotateRefreshToken"]>
    try {
      outcome = store.rotateRefreshToken(tokenHash, {
        now,
        graceMs: oauth.lifetimes.refreshGraceSeconds * 1000,
        maxChildren: 2,
        childRefreshTokenHash: sha256Hex(childRefresh),
        childAccessTokenHash: sha256Hex(childAccess),
        childAccessTokenExpiresAt: now + oauth.lifetimes.accessTokenSeconds * 1000,
      })
    } catch (err) {
      console.error(`${oauth.app.logPrefix}: /token failed to rotate the refresh token:`, err)
      return unavailable(5)
    }
    if (outcome.kind === "rotated" || outcome.kind === "sibling") {
      return tokenResponse(200, {
        access_token: childAccess,
        token_type: "Bearer",
        expires_in: oauth.lifetimes.accessTokenSeconds,
        refresh_token: childRefresh,
        scope,
      })
    }
    return tokenError("invalid_grant", "The refresh token is invalid, revoked or already used.")
  }

  async function handleRefresh(
    req: Extract<TokenRequestResult, { grantType: "refresh_token" }>,
  ): Promise<Response> {
    const now = clock()
    const tokenHash = sha256Hex(req.refreshToken)
    let grant: ReturnType<OAuthStore["getGrant"]>
    try {
      const row = store.getRefreshToken(tokenHash)
      grant = row !== undefined ? store.getGrant(row.grantId) : undefined
    } catch (err) {
      console.error(`${oauth.app.logPrefix}: /token failed to look up the refresh token:`, err)
      return unavailable(5)
    }
    if (grant === undefined)
      return tokenError("invalid_grant", "The refresh token is invalid or unknown.")
    if (grant.revokedAt !== null) return tokenError("invalid_grant", "This grant has been revoked.")
    if (grant.clientId !== req.clientId) {
      return tokenError("invalid_grant", "The refresh token does not belong to this client.")
    }
    if (grant.resource !== req.resource) {
      return tokenError("invalid_target", `resource must be ${oauth.issuer}/mcp`)
    }
    const idleMs = oauth.lifetimes.refreshIdleDays * 24 * 60 * 60 * 1000
    if (now - grant.lastUsedAt > idleMs) {
      try {
        store.revokeGrant(grant.grantId, now)
      } catch (err) {
        console.error(`${oauth.app.logPrefix}: /token failed to revoke an idle grant:`, err)
        return unavailable(5)
      }
      return tokenError("invalid_grant", "This grant has been idle too long and was revoked.")
    }
    // An absolute lifetime, so a member removed in usr (which nothing here re-checks) loses access
    // within grantMaxAgeDays at the latest, not only after going idle.
    if (now - grant.createdAt > oauth.grantMaxAgeDays * 24 * 60 * 60 * 1000) {
      try {
        store.revokeGrant(grant.grantId, now)
      } catch (err) {
        console.error(`${oauth.app.logPrefix}: /token failed to revoke an expired grant:`, err)
        return unavailable(5)
      }
      return tokenError("invalid_grant", "This grant has expired. Connect again.")
    }
    if (deps.memberCheck !== undefined) {
      let allowed: boolean
      try {
        allowed = await deps.memberCheck(grant.memberSub)
        if (!allowed) store.revokeGrant(grant.grantId, now)
      } catch (err) {
        console.error(`${oauth.app.logPrefix}: /token failed to re-check the member:`, err)
        return unavailable(5)
      }
      if (!allowed) return tokenError("invalid_grant", "This grant is no longer permitted.")
    }
    // Concurrent refreshes of one token from one client share one rotation.
    const key = `${tokenHash}|${req.clientId}|${req.resource}`
    const existing = coalescing.get(key)
    if (existing !== undefined) return (await existing).clone()
    const promise = Promise.resolve()
      .then(() => performRotation(tokenHash, now, grant.scopes))
      .finally(() => coalescing.delete(key))
    coalescing.set(key, promise)
    return (await promise).clone()
  }

  return async (request) => {
    try {
      if (request.method !== "POST") {
        return new Response(JSON.stringify({ error: "method not allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json", Allow: "POST" },
        })
      }
      const contentType = (request.headers.get("content-type") ?? "")
        .split(";", 1)[0]
        ?.trim()
        .toLowerCase()
      if (contentType !== "application/x-www-form-urlencoded") {
        return tokenError(
          "invalid_request",
          "Content-Type must be application/x-www-form-urlencoded",
        )
      }
      const bodyText = await request.text()
      if (Buffer.byteLength(bodyText, "utf8") > MAX_BODY_BYTES) {
        return tokenResponse(413, {
          error: "invalid_request",
          error_description: "request body too large",
        })
      }
      const parsed = parseTokenRequest(
        new URLSearchParams(bodyText),
        oauth.issuer,
        oauth.acceptOriginAsResource,
        oauth.app.idPrefix,
      )
      if (!parsed.ok) return tokenError(parsed.error, parsed.description)
      let client: ReturnType<OAuthStore["getClient"]>
      try {
        client = store.getClient(parsed.clientId)
      } catch (err) {
        console.error(`${oauth.app.logPrefix}: /token failed to look up the client:`, err)
        return unavailable(5)
      }
      if (client === undefined) return tokenError("invalid_client", "client_id is unknown.")
      return parsed.grantType === "authorization_code"
        ? handleCodeExchange(parsed)
        : await handleRefresh(parsed)
    } catch (err) {
      console.error(`${oauth.app.logPrefix}: /token failed unexpectedly:`, err)
      return unavailable(5)
    }
  }
}
