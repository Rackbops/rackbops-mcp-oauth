import { createHash, randomBytes } from "node:crypto"
import { DatabaseSync } from "node:sqlite"
import { createAuthorizeHandler } from "../src/authorize.js"
import { type OAuthApp, oauthConfig } from "../src/config.js"
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
  resourceMetadataUrl,
} from "../src/discovery.js"
import { createRateLimiter } from "../src/rateLimit.js"
import { createRegistrationHandler } from "../src/registration.js"
import { OAuthStore, sha256Hex } from "../src/store.js"
import { createTokenHandler, type TokenDeps } from "../src/token.js"
import type { Identity, IdentityPort } from "../src/usr.js"

export const ISSUER = "https://meals.example.test"
export const HOST = "meals.example.test"
export const CALLBACK = "https://claude.ai/api/mcp/auth_callback"

/** Meals for Two's profile, verbatim: the extraction must not change a byte of what it renders or issues. */
export const MEALS_APP: OAuthApp = {
  name: "Meals for Two",
  logPrefix: "meals-for-two",
  idPrefix: "mft",
  memberRole: "member",
  consentSummary: "read and manage your household's meals",
  notMemberMessage: "Your account isn't a member of this household's Meals for Two.",
  signInFailedMessage:
    "Signing in didn't complete. Open Meals for Two in this browser once, then connect again.",
  scopes: [
    {
      name: "meals.confirm",
      disclosureHtml:
        '<div class="extra"><h2>Extra permission: apply changes</h2><p>It also asks to <strong>apply changes</strong> to your recipes and plans, and to undo them, once you have said yes to them in the chat. Without this it can only read and propose.</p></div>',
    },
  ],
}

export interface Harness {
  store: OAuthStore
  setIdentity: (who: Identity | null) => void
  req: (path: string, init?: RequestInit) => Promise<Response>
  now: { t: number }
}

export const MEMBER: Identity = { sub: "user-1", name: "Anne", roles: ["member"] }

export function harness(
  options: { app?: OAuthApp; memberCheck?: TokenDeps["memberCheck"] } = {},
): Harness {
  const now = { t: Date.now() }
  let who: Identity | null = MEMBER
  const identity: IdentityPort = {
    fromRequest: async () => who,
    signInUrl: (returnUrl) =>
      `https://id.example.test/api/auth/sso/refresh?return=${encodeURIComponent(returnUrl)}`,
  }
  const store = new OAuthStore(new DatabaseSync(":memory:"), () => now.t)
  const oauth = oauthConfig(ISSUER, options.app ?? MEALS_APP)
  const clock = () => now.t
  const limiter = createRateLimiter(oauth.registration.perSourcePerHour, 3_600_000, clock)
  const register = createRegistrationHandler({ store, oauth, limiter, clock })
  const authorize = createAuthorizeHandler({ store, oauth, identity, clock })
  const token = createTokenHandler({
    store,
    oauth,
    clock,
    ...(options.memberCheck === undefined ? {} : { memberCheck: options.memberCheck }),
  })
  const scopes = oauth.app.scopes.map((s) => s.name)
  return {
    store,
    now,
    setIdentity: (w) => {
      who = w
    },
    req: async (path, init) => {
      const request = new Request(`http://${HOST}${path}`, init)
      const url = new URL(request.url)
      const json = (body: unknown) => Response.json(body)
      switch (url.pathname) {
        case "/register":
          return register(request, "test")
        case "/authorize":
          return authorize(request, "test")
        case "/token":
          return token(request)
        case "/.well-known/oauth-authorization-server":
          return json(authorizationServerMetadata(ISSUER, scopes))
        case "/.well-known/oauth-protected-resource/mcp":
          return json(protectedResourceMetadata(ISSUER, scopes))
        case "/mcp": {
          // What an app's bearer gate does with the store: a stand-in to prove revocation and expiry.
          const raw = /^Bearer (.+)$/.exec(request.headers.get("authorization") ?? "")?.[1]
          const row = raw === undefined ? undefined : store.getAccessToken(sha256Hex(raw))
          const grant = row === undefined ? undefined : store.getGrant(row.grantId)
          if (row === undefined || row.expiresAt <= now.t || grant?.revokedAt !== null) {
            return new Response(null, {
              status: 401,
              headers: {
                "www-authenticate": `Bearer resource_metadata="${resourceMetadataUrl(ISSUER)}"`,
              },
            })
          }
          return new Response(null, { status: 200 })
        }
        default:
          return new Response(null, { status: 404 })
      }
    },
  }
}

export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url")
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") }
}

export async function register(h: Harness, redirect = CALLBACK, name = "Claude"): Promise<string> {
  const res = await h.req("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [redirect], client_name: name }),
  })
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${await res.text()}`)
  return ((await res.json()) as { client_id: string }).client_id
}

/** Runs authorize GET + consent POST and returns the redirect Location. */
export async function authorize(
  h: Harness,
  clientId: string,
  challenge: string,
  extra: Record<string, string> = {},
  decision = "allow",
): Promise<Response> {
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: CALLBACK,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "st1",
    resource: `${ISSUER}/mcp`,
    ...extra,
  })
  const page = await h.req(`/authorize?${q}`)
  if (page.status !== 200) return page
  const html = await page.text()
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1] ?? ""
  const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? ""
  return h.req("/authorize", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({ request_id: requestId, decision }).toString(),
  })
}

export async function tokens(h: Harness, body: Record<string, string>): Promise<Response> {
  return h.req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  })
}

/** Full flow to a token pair. */
export async function connect(
  h: Harness,
  scope?: string,
): Promise<{
  clientId: string
  access: string
  refresh: string
  scope: string | undefined
}> {
  const clientId = await register(h)
  const { verifier, challenge } = pkce()
  const res = await authorize(h, clientId, challenge, scope === undefined ? {} : { scope })
  const code = new URL(res.headers.get("location") ?? "").searchParams.get("code") ?? ""
  const tok = await tokens(h, {
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: CALLBACK,
    code_verifier: verifier,
    resource: `${ISSUER}/mcp`,
  })
  const body = (await tok.json()) as {
    access_token: string
    refresh_token: string
    scope?: string
  }
  return { clientId, access: body.access_token, refresh: body.refresh_token, scope: body.scope }
}
