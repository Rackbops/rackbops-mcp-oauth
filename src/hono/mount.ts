import {
  createMcpHandler,
  type McpServerFactory,
  requireBearerAuth,
} from "@modelcontextprotocol/server"
import type { Context, Hono } from "hono"
import { bodyLimit } from "hono/body-limit"
import { createAuthorizeHandler } from "../authorize.js"
import type { OAuthConfig } from "../config.js"
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
  resourceMetadataUrl,
} from "../discovery.js"
import { createRateLimiter } from "../rateLimit.js"
import { createRegistrationHandler } from "../registration.js"
import { scopeNames } from "../scopes.js"
import { createBearerVerifier } from "../server/bearer.js"
import type { OAuthStore } from "../store.js"
import { createTokenHandler } from "../token.js"
import type { IdentityPort } from "../usr.js"

// The HTTP wiring Meals for Two's and tracker-mcp's `src/app.ts` each carried: the OAuth server's
// routes and discovery documents (`mountOAuth`) and the bearer-gated, per-person rate-limited `/mcp`
// (`mountMcp`). Mount the Host guard and the request trace first, as both servers do.

const SMALL_BODY_CAP = 16 * 1024

const tooLarge = (c: Context): Response => c.json({ error: "request body too large" }, 413)

export interface MountOAuthOptions {
  oauth: OAuthConfig
  store: OAuthStore
  identity: IdentityPort
  /** Asked on every OAuth refresh whether the grant's person still holds the role. */
  memberCheck?: (memberSub: string) => Promise<boolean>
  /** The rate-limit source of a request (`resolveClientSource` over the tunnel's client-IP header). */
  source: (c: Context) => string
  /** Epoch milliseconds. */
  clock?: () => number
}

/** `/register`, `/authorize` and `/token` (16 KiB body cap each) and the three discovery documents. */
// biome-ignore lint/suspicious/noExplicitAny: any app's Env and schema may mount these routes
export function mountOAuth(app: Hono<any, any, any>, options: MountOAuthOptions): void {
  const { oauth, store, source } = options
  const clock = options.clock ?? Date.now
  for (const path of ["/register", "/authorize", "/token"]) {
    app.use(path, bodyLimit({ maxSize: SMALL_BODY_CAP, onError: tooLarge }))
  }
  const scopes = scopeNames(oauth.app.scopes)
  const wellKnown = (build: () => unknown) => () =>
    new Response(JSON.stringify(build()), {
      headers: { "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
    })
  const resource = wellKnown(() => protectedResourceMetadata(oauth.issuer, scopes))
  app.get("/.well-known/oauth-protected-resource", resource)
  app.get("/.well-known/oauth-protected-resource/mcp", resource)
  app.get(
    "/.well-known/oauth-authorization-server",
    wellKnown(() => authorizationServerMetadata(oauth.issuer, scopes)),
  )

  const limiter = createRateLimiter(oauth.registration.perSourcePerHour, 60 * 60 * 1000, clock)
  const register = createRegistrationHandler({ store, oauth, limiter, clock })
  const authorize = createAuthorizeHandler({ store, oauth, identity: options.identity, clock })
  const token = createTokenHandler({
    store,
    oauth,
    clock,
    ...(options.memberCheck === undefined ? {} : { memberCheck: options.memberCheck }),
  })
  app.all("/register", (c) => register(c.req.raw, source(c)))
  app.all("/authorize", (c) => authorize(c.req.raw, source(c)))
  app.all("/token", (c) => token(c.req.raw))
}

export interface MountMcpOptions {
  oauth: OAuthConfig
  store: OAuthStore
  /** The MCP server for one request (`buildToolServerFactory`). */
  factory: McpServerFactory
  /** Largest `/mcp` request body, in bytes. */
  bodyCap: number
  /** Calls per person per minute; over it answers 429 with `Retry-After`. */
  perMinute: number
  /** Runs after every authenticated `/mcp` call (Meals for Two publishes its changes here). It must
   *  not throw: a throw replaces the call's answer with the app's error response. */
  after?: () => void
  /** Epoch milliseconds. */
  clock?: () => number
}

/** The bearer-gated `/mcp`. Returns the handler's `close`, for the app's own. */
// biome-ignore lint/suspicious/noExplicitAny: any app's Env and schema may mount this route
export function mountMcp(app: Hono<any, any, any>, options: MountMcpOptions): () => Promise<void> {
  const { oauth, store } = options
  const clock = options.clock ?? Date.now
  app.use("/mcp", bodyLimit({ maxSize: options.bodyCap, onError: tooLarge }))
  const gate = requireBearerAuth({
    resourceMetadataUrl: resourceMetadataUrl(oauth.issuer),
    verifier: createBearerVerifier({
      store,
      issuer: oauth.issuer,
      scopes: oauth.app.scopes,
      clock,
    }),
  })
  // The servers declare no list-changed capability, so they admit no subscriptions.
  const mcp = createMcpHandler(options.factory, { responseMode: "json", maxSubscriptions: 0 })
  const limiter = createRateLimiter(options.perMinute, 60 * 1000, clock)
  app.all("/mcp", async (c) => {
    const auth = await gate(c.req.raw)
    if (auth instanceof Response) return auth
    const hit = limiter.hit(`mcp:${auth.clientId}`)
    if (!hit.allowed) {
      return c.json({ error: "rate limited" }, 429, {
        "Retry-After": String(hit.retryAfterSeconds),
      })
    }
    const response = await mcp.fetch(c.req.raw, { authInfo: auth })
    options.after?.()
    // RFC 9110 15.5.6 requires Allow on a 405. SDK 2.4.0+ sends `Allow: POST` itself (2.3.1 sent
    // none); this only fills it in if a 405 ever comes back without one.
    if (response.status === 405 && !response.headers.has("allow")) {
      const headers = new Headers(response.headers)
      headers.set("Allow", "POST")
      return new Response(response.body, { status: 405, headers })
    }
    return response
  })
  return () => mcp.close()
}
