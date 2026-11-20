import { createHash, randomBytes } from "node:crypto"
import { DatabaseSync } from "node:sqlite"
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client"
import { OAuthStore } from "../store.js"
import type { Identity, IdentityPort } from "../usr.js"

// An in-process OAuth client for a server's own tests, moved from Meals for Two's and tracker-mcp's
// `src/test/harness.ts`: a fake usr identity, an in-memory store, PKCE, the register / authorize +
// consent / token steps, and an MCP SDK client on the resulting token, all against the app's `fetch`
// with no network. The servers keep their own `harness()`, which builds their app; these are the
// steps it then drives.

/** Sends a request to the app under test: `path` is resolved against the server's issuer. */
export type Requester = (path: string, init?: RequestInit) => Promise<Response>

/** A `Requester` over an app's `fetch`, setting `Host` to the issuer's host unless the test sets one. */
export function requester(
  fetch: (request: Request) => Response | Promise<Response>,
  issuer: string,
): Requester {
  const host = new URL(issuer).host
  return async (path, init) => {
    const headers = new Headers(init?.headers)
    if (!headers.has("host")) headers.set("host", host)
    return fetch(new Request(`http://${host}${path}`, { ...init, headers }))
  }
}

/** A usr identity the test switches: `set(null)` is a browser with no valid `nz_id` cookie. */
export function fakeIdentity(initial: Identity | null): IdentityPort & {
  set: (who: Identity | null) => void
} {
  let who = initial
  return {
    fromRequest: async () => who,
    signInUrl: (returnUrl) =>
      `https://id.example.test/api/auth/sso/refresh?return=${encodeURIComponent(returnUrl)}`,
    set: (next) => {
      who = next
    },
  }
}

/** An `OAuthStore` on a fresh `:memory:` database, on the test's clock. */
export function memoryStore(clock: () => number = Date.now): OAuthStore {
  return new OAuthStore(new DatabaseSync(":memory:"), clock)
}

export function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url")
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") }
}

/** Registers a public client (RFC 7591) and returns its `client_id`; throws unless 201. */
export async function register(req: Requester, redirect: string, name = "Claude"): Promise<string> {
  const res = await req("/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [redirect], client_name: name }),
  })
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${await res.text()}`)
  return ((await res.json()) as { client_id: string }).client_id
}

export interface AuthorizeInput {
  issuer: string
  clientId: string
  redirect: string
  challenge: string
  /** Extra query parameters (`scope`), or ones that replace the defaults. */
  extra?: Record<string, string>
  /** The consent button pressed. Default `allow`. */
  decision?: string
}

/** Runs `GET /authorize` and the consent POST; returns the POST's answer (its Location carries the
 *  code), or the GET's when it is not the consent page. */
export async function authorize(req: Requester, input: AuthorizeInput): Promise<Response> {
  const q = new URLSearchParams({
    client_id: input.clientId,
    redirect_uri: input.redirect,
    response_type: "code",
    code_challenge: input.challenge,
    code_challenge_method: "S256",
    state: "st1",
    resource: `${input.issuer}/mcp`,
    ...input.extra,
  })
  const page = await req(`/authorize?${q}`)
  if (page.status !== 200) return page
  const html = await page.text()
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1] ?? ""
  const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? ""
  return req("/authorize", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({
      request_id: requestId,
      decision: input.decision ?? "allow",
    }).toString(),
  })
}

/** `POST /token` with a form body. */
export function tokens(req: Requester, body: Record<string, string>): Promise<Response> {
  return req("/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body).toString(),
  })
}

export interface Connected {
  clientId: string
  access: string
  refresh: string
  scope: string | undefined
}

/** The whole flow, register to token pair, as the person the identity currently returns. */
export async function connect(
  req: Requester,
  options: { issuer: string; redirect: string; scope?: string; clientName?: string },
): Promise<Connected> {
  const clientId = await register(req, options.redirect, options.clientName)
  const { verifier, challenge } = pkce()
  const res = await authorize(req, {
    issuer: options.issuer,
    clientId,
    redirect: options.redirect,
    challenge,
    ...(options.scope === undefined ? {} : { extra: { scope: options.scope } }),
  })
  const code = new URL(res.headers.get("location") ?? "").searchParams.get("code") ?? ""
  const tok = await tokens(req, {
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: options.redirect,
    code_verifier: verifier,
    resource: `${options.issuer}/mcp`,
  })
  if (tok.status !== 200) throw new Error(`token failed: ${tok.status} ${await tok.text()}`)
  const body = (await tok.json()) as { access_token: string; refresh_token: string; scope?: string }
  return { clientId, access: body.access_token, refresh: body.refresh_token, scope: body.scope }
}

/** An MCP SDK client signed in with `access`, talking to the app's `fetch` in-process. Close it. */
export async function mcpClient(
  fetch: (request: Request) => Response | Promise<Response>,
  issuer: string,
  access: string,
  name = "test",
): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(`${issuer}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${access}`, host: new URL(issuer).host } },
    fetch: (url, init) => Promise.resolve(fetch(new Request(url, init))),
  })
  const client = new Client({ name, version: "0.0.0" })
  await client.connect(transport)
  return client
}
