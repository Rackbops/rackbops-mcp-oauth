import { randomBytes, timingSafeEqual } from "node:crypto"
import type { OAuthApp, OAuthConfig } from "./config.js"
import { normalizeResource } from "./discovery.js"
import { pageHeaders, renderConsentPage, renderErrorPage } from "./page.js"
import {
  isLoopbackHttp,
  type RedirectPolicy,
  redirectMatchesRegistered,
  validateRedirectUri,
} from "./redirect.js"
import { clientIdPattern } from "./registration.js"
import { joinScopes, parseScopes, splitScopes } from "./scopes.js"
import { type OAuthStore, sha256Hex } from "./store.js"
import type { Identity, IdentityPort } from "./usr.js"

// GET/POST /authorize (RFC 6749 4.1). Parameter validation, the two error shapes (a page before a
// redirect_uri can be trusted, a redirect after), the request row and its __Host- binding cookie are
// ported from Rackbops/discord-mcp `src/service/oauthAuthorize.ts`. The difference is how the member
// is identified: discord-mcp spends a Discord pairing code; here /authorize reads usr's `nz_id`
// cookie (verified offline), requires the app's member role, and shows a consent page naming the member.

// An S256 challenge is the base64url of a 32-byte digest: exactly 43 unpadded characters.
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/
const MAX_STATE_BYTES = 1024
const KNOWN_PARAMS = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "resource",
  "scope",
])
const MAX_POST_BODY_BYTES = 4096
// __Host-: the browser refuses the cookie unless it is Secure, Path=/ and has no Domain attribute.
const cookiePrefix = (idPrefix: string): string => `__Host-${idPrefix}_ar_`
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{22}$/
/** Marker we add to the sign-in return URL so a cookie that still doesn't verify after usr's round
 *  trip ends in an error page instead of a redirect loop. */
const SSO_TRIED = "_sso"

export type ValidateAuthorizeResult =
  | {
      kind: "ok"
      clientId: string
      clientName: string | null
      redirectUri: string
      codeChallenge: string
      resource: string
      state: string | null
      scopes: string
    }
  | { kind: "page"; status: 400; message: string }
  | {
      kind: "redirect"
      redirectUri: string
      error: string
      description: string
      state: string | null
    }

function presentOnce(params: URLSearchParams, name: string): string | undefined {
  const all = params.getAll(name)
  return all.length === 1 ? all[0] : undefined
}

export function validateAuthorizeRequest(
  params: URLSearchParams,
  deps: {
    store: OAuthStore
    policy: RedirectPolicy
    issuer: string
    acceptOriginAsResource: boolean
    app: OAuthApp
  },
): ValidateAuthorizeResult {
  const clientIdValue = presentOnce(params, "client_id")
  const client =
    clientIdValue !== undefined && clientIdPattern(deps.app.idPrefix).test(clientIdValue)
      ? deps.store.getClient(clientIdValue)
      : undefined
  if (client === undefined || clientIdValue === undefined) {
    return {
      kind: "page",
      status: 400,
      message:
        "Unknown app (client_id). Go back to the app and connect again; it may need to register again.",
    }
  }
  const redirectUriValue = presentOnce(params, "redirect_uri")
  if (
    redirectUriValue === undefined ||
    !validateRedirectUri(redirectUriValue, deps.policy) ||
    !redirectMatchesRegistered(redirectUriValue, client.redirectUris)
  ) {
    return { kind: "page", status: 400, message: "The app's redirect address isn't registered." }
  }
  const stateForEcho = presentOnce(params, "state") ?? null
  const redirectError = (
    error: string,
    description: string,
    state: string | null = stateForEcho,
  ): ValidateAuthorizeResult => ({
    kind: "redirect",
    redirectUri: redirectUriValue,
    error,
    description,
    state,
  })
  if (presentOnce(params, "response_type") !== "code") {
    return redirectError("unsupported_response_type", "response_type must be code")
  }
  const challenge = presentOnce(params, "code_challenge")
  if (challenge === undefined || !CODE_CHALLENGE_PATTERN.test(challenge)) {
    return redirectError("invalid_request", "code_challenge is missing or malformed")
  }
  if (presentOnce(params, "code_challenge_method") !== "S256") {
    return redirectError(
      "invalid_request",
      "code_challenge_method must be S256 (plain is not accepted)",
    )
  }
  const stateAll = params.getAll("state")
  if (stateAll.length > 1)
    return redirectError("invalid_request", "state must not be duplicated", null)
  if (stateAll.length === 1 && Buffer.byteLength(stateAll[0] as string, "utf8") > MAX_STATE_BYTES) {
    return redirectError("invalid_request", "state exceeds 1024 bytes")
  }
  for (const key of new Set(params.keys())) {
    if (!KNOWN_PARAMS.has(key) && params.getAll(key).length > 1) {
      // A fixed string: the name is attacker-chosen and would be echoed into the redirect.
      return redirectError("invalid_request", "a parameter must not be duplicated")
    }
  }
  const resource = normalizeResource(
    params.getAll("resource"),
    deps.issuer,
    deps.acceptOriginAsResource,
  )
  if (!resource.ok) return redirectError("invalid_target", `resource must be ${deps.issuer}/mcp`)
  return {
    kind: "ok",
    clientId: clientIdValue,
    clientName: client.clientName,
    redirectUri: redirectUriValue,
    codeChallenge: challenge,
    resource: resource.resource,
    state: stateForEcho,
    scopes: joinScopes(parseScopes(presentOnce(params, "scope"), deps.app.scopes)),
  }
}

function constantTimeEqualHex(aHex: string, bHex: string): boolean {
  const a = Buffer.from(aHex, "hex")
  const b = Buffer.from(bHex, "hex")
  return a.length === b.length && timingSafeEqual(a, b)
}

function parseCookies(header: string | null): Map<string, string> {
  const map = new Map<string, string>()
  if (header === null) return map
  for (const part of header.split(";")) {
    const trimmed = part.trim()
    const eq = trimmed.indexOf("=")
    if (eq === -1) continue
    map.set(trimmed.slice(0, eq), trimmed.slice(eq + 1))
  }
  return map
}

function redirectResponse(
  target: string,
  params: Record<string, string>,
  setCookie?: string,
): Response {
  const url = new URL(target)
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value)
  const headers = new Headers({
    Location: url.href,
    "Cache-Control": "no-store",
    Pragma: "no-cache",
  })
  if (setCookie !== undefined) headers.set("Set-Cookie", setCookie)
  return new Response(null, { status: 302, headers })
}

export interface AuthorizeDeps {
  store: OAuthStore
  oauth: OAuthConfig
  identity: IdentityPort
  clock?: () => number
}

export type AuthorizeHandler = (request: Request, source: string) => Promise<Response>

export function createAuthorizeHandler(deps: AuthorizeDeps): AuthorizeHandler {
  const { store, oauth, identity } = deps
  const clock = deps.clock ?? Date.now
  const { app } = oauth
  const COOKIE_PREFIX = cookiePrefix(app.idPrefix)
  const errorPage = (status: number, message: string): Response =>
    new Response(renderErrorPage(app.name, message), { status, headers: pageHeaders(null) })

  /** The public URL of this request. `request.url` carries the internal origin behind the tunnel, so
   *  rebuild it from the issuer; usr only honours return URLs under its cookie domain. */
  function publicUrl(request: Request, extra?: [string, string]): string {
    const incoming = new URL(request.url)
    const url = new URL(`${oauth.issuer}${incoming.pathname}${incoming.search}`)
    if (extra !== undefined) url.searchParams.set(extra[0], extra[1])
    return url.href
  }

  function member(who: Identity | null): Identity | "denied" | null {
    if (who === null) return null
    return who.roles.includes(app.memberRole) ? who : "denied"
  }

  async function handleGet(request: Request, source: string): Promise<Response> {
    const params = new URL(request.url).searchParams
    const triedSso = params.get(SSO_TRIED) !== null
    params.delete(SSO_TRIED)
    let result: ValidateAuthorizeResult
    try {
      result = validateAuthorizeRequest(params, {
        store,
        policy: oauth.redirect,
        issuer: oauth.issuer,
        acceptOriginAsResource: oauth.acceptOriginAsResource,
        app,
      })
    } catch (err) {
      console.error(`${app.logPrefix}: /authorize failed to validate the request:`, err)
      return errorPage(503, "Try again in a moment.")
    }
    if (result.kind === "page") return errorPage(result.status, result.message)
    if (result.kind === "redirect") {
      return redirectResponse(result.redirectUri, {
        error: result.error,
        error_description: result.description,
        ...(result.state !== null ? { state: result.state } : {}),
        iss: oauth.issuer,
      })
    }

    const who = member(await identity.fromRequest(request))
    if (who === null) {
      if (triedSso) {
        return errorPage(401, app.signInFailedMessage)
      }
      return new Response(null, {
        status: 302,
        headers: {
          Location: identity.signInUrl(publicUrl(request, [SSO_TRIED, "1"])),
          "Cache-Control": "no-store",
        },
      })
    }
    if (who === "denied") {
      return errorPage(403, app.notMemberMessage)
    }

    const requestId = randomBytes(16).toString("base64url")
    const secret = randomBytes(32).toString("base64url")
    const now = clock()
    let stored: boolean
    try {
      stored = store.createRequest(
        {
          requestId,
          secretHash: sha256Hex(secret),
          clientId: result.clientId,
          redirectUri: result.redirectUri,
          codeChallenge: result.codeChallenge,
          resource: result.resource,
          state: result.state,
          memberSub: who.sub,
          source,
          expiresAt: now + oauth.lifetimes.requestSeconds * 1000,
          scopes: result.scopes,
        },
        oauth.liveRequestsPerSource,
      )
    } catch (err) {
      console.error(`${app.logPrefix}: /authorize failed to create a request row:`, err)
      return errorPage(503, "Try again in a moment.")
    }
    if (!stored) return errorPage(429, "Too many sign-in attempts. Try again in a few minutes.")

    const redirectUrl = new URL(result.redirectUri)
    const headers = new Headers(pageHeaders(redirectUrl.origin))
    headers.set(
      "Set-Cookie",
      `${COOKIE_PREFIX}${requestId}=${secret}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${oauth.lifetimes.requestSeconds}`,
    )
    return new Response(
      renderConsentPage({
        clientName: result.clientName,
        hostname: redirectUrl.hostname,
        isLoopback: isLoopbackHttp(redirectUrl),
        requestId,
        memberName: who.name,
        appName: app.name,
        summary: app.consentSummary,
        disclosures: app.scopes
          .filter((s) => splitScopes(result.scopes, app.scopes).includes(s.name))
          .map((s) => s.disclosureHtml),
        error: null,
      }),
      { status: 200, headers },
    )
  }

  async function handlePost(request: Request): Promise<Response> {
    const contentType = (request.headers.get("content-type") ?? "")
      .split(";", 1)[0]
      ?.trim()
      .toLowerCase()
    if (contentType !== "application/x-www-form-urlencoded") {
      return errorPage(415, "Go back to the app and connect again.")
    }
    const bodyText = await request.text()
    if (Buffer.byteLength(bodyText, "utf8") > MAX_POST_BODY_BYTES) {
      return errorPage(413, "That request was too large. Go back to the app and connect again.")
    }
    const body = new URLSearchParams(bodyText)
    const expired = "This sign-in link has expired. Go back to the app and connect again."

    const requestIdValue = body.get("request_id")
    let row: ReturnType<OAuthStore["getRequest"]>
    try {
      row =
        requestIdValue !== null && REQUEST_ID_PATTERN.test(requestIdValue)
          ? store.getRequest(requestIdValue)
          : undefined
    } catch (err) {
      console.error(`${app.logPrefix}: /authorize failed to look up the request:`, err)
      return errorPage(503, "Try again in a moment.")
    }
    if (row === undefined) return errorPage(400, expired)

    // The cookie's secret, hashed and compared in constant time: a missing cookie and a wrong secret
    // answer identically.
    const cookieValue = parseCookies(request.headers.get("cookie")).get(
      `${COOKIE_PREFIX}${row.requestId}`,
    )
    if (
      cookieValue === undefined ||
      !constantTimeEqualHex(sha256Hex(cookieValue), row.secretHash)
    ) {
      return errorPage(400, expired)
    }
    const clearCookie = `${COOKIE_PREFIX}${row.requestId}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`

    // The member who is signed in now must be the member the page was shown to.
    const who = member(await identity.fromRequest(request))
    if (who === null || who === "denied" || who.sub !== row.memberSub) {
      return errorPage(
        403,
        "You're no longer signed in as the same member. Connect again from the app.",
      )
    }
    if (store.getClient(row.clientId) === undefined) return errorPage(400, expired)

    const state: Record<string, string> = row.state !== null ? { state: row.state } : {}
    if (body.get("decision") !== "allow") {
      try {
        store.resolveRequest(row.requestId)
      } catch (err) {
        console.error(`${app.logPrefix}: /authorize failed to cancel a request:`, err)
      }
      return redirectResponse(
        row.redirectUri,
        {
          error: "access_denied",
          error_description: "The member declined",
          ...state,
          iss: oauth.issuer,
        },
        clearCookie,
      )
    }

    const code = `${app.idPrefix}_ac_${randomBytes(32).toString("base64url")}`
    const now = clock()
    try {
      store.resolveRequest(row.requestId, {
        codeHash: sha256Hex(code),
        clientId: row.clientId,
        redirectUri: row.redirectUri,
        codeChallenge: row.codeChallenge,
        resource: row.resource,
        memberSub: row.memberSub,
        createdAt: now,
        expiresAt: now + oauth.lifetimes.codeSeconds * 1000,
        scopes: row.scopes,
      })
    } catch (err) {
      console.error(`${app.logPrefix}: /authorize failed to store the issued code:`, err)
      return errorPage(503, "Try again in a moment.")
    }
    return redirectResponse(row.redirectUri, { code, ...state, iss: oauth.issuer }, clearCookie)
  }

  return async (request, source) => {
    if (request.method === "GET") return handleGet(request, source)
    if (request.method === "POST") return handlePost(request)
    return new Response(JSON.stringify({ error: "method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "GET, POST" },
    })
  }
}
