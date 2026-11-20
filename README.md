# @rackbops/mcp-oauth

The OAuth 2.1 authorization server a remote MCP server needs, so each Rackbops MCP server does not
carry its own copy. Extracted from `Rackbops/meals-for-two` (`src/oauth`), which ported it from
`Rackbops/discord-mcp` and proved it live against ChatGPT and claude.ai.

What it is: RFC 7591 dynamic client registration (public clients, PKCE S256 only), `/authorize` that
identifies the member from [usr](https://github.com/Rackbops/usr)'s `nz_id` cookie, requires an app
role and shows a consent page, `/token` with code exchange and bounded refresh rotation with reuse
detection, RFC 8414/9728 discovery documents, and a SQLite store (`oauth_*` tables) that keeps only
hashes of everything that can authenticate.

What it is not: not a web framework (handlers are `(Request, source) => Promise<Response>`, mount
them on Hono or anything else) and not a user database (usr is the login). The root import has no
Host/Origin guard and no `/mcp` bearer gate; those, and the rest of what an MCP server shares, are in
the subpaths described under [The shared MCP server pieces](#the-shared-mcp-server-pieces).

## Use

```ts
import { DatabaseSync } from "node:sqlite"
import {
  OAuthStore,
  createAuthorizeHandler,
  createRateLimiter,
  createRegistrationHandler,
  createTokenHandler,
  createUsrIdentity,
  oauthConfig,
} from "@rackbops/mcp-oauth"

const oauth = oauthConfig("https://meals.rackbops.com", {
  name: "Meals for Two", // consent + error pages
  logPrefix: "meals-for-two", // console.error prefix
  idPrefix: "mft", // mft_c_ / mft_ac_ / mft_g_ / mft_at_ / mft_rt_ / __Host-mft_ar_
  memberRole: "member", // usr role `meals:member`
  consentSummary: "read and manage your household's meals",
  notMemberMessage: "...",
  signInFailedMessage: "...",
  scopes: [{ name: "meals.confirm", disclosureHtml: '<div class="extra">...</div>' }],
})
const store = new OAuthStore(db) // creates the oauth_* tables if absent
const identity = createUsrIdentity({ usrUrl: "https://id.rackbops.com", app: "meals" })
const limiter = createRateLimiter(oauth.registration.perSourcePerHour, 3_600_000)
const register = createRegistrationHandler({ store, oauth, limiter })
const authorize = createAuthorizeHandler({ store, oauth, identity })
const token = createTokenHandler({ store, oauth /*, memberCheck */ })
setInterval(
  () => store.prune(oauth.lifetimes.refreshIdleDays * 24 * 3600 * 1000),
  3_600_000,
).unref()
```

Call `store.prune` on a timer; nothing else sweeps expired rows.

The handlers bound what they parse (`/register` and `/token` refuse a body over 4 KB with 413); put a
real body limit at the host, since the body is still read first.

Then route `/register`, `/authorize`, `/token`, and serve `protectedResourceMetadata(issuer, scopes)` at
`/.well-known/oauth-protected-resource[/mcp]` and `authorizationServerMetadata(issuer, scopes)` at
`/.well-known/oauth-authorization-server`. Verify a bearer by `store.getAccessToken(sha256Hex(raw))`,
then check expiry, `store.getGrant(...).revokedAt` and `resource === ${issuer}/mcp`.

The `mountOAuth` and `mountMcp` helpers in `@rackbops/mcp-oauth/hono` (below) do all of this for a
Hono app.

## The shared MCP server pieces

Beside the OAuth server, the package carries the code every Rackbops MCP server had its own copy of
([#3](https://github.com/Rackbops/rackbops-mcp-oauth/issues/3)). The name is narrower than what it
holds, kept so existing installs and npm trusted publishing do not move. The root import stays free of
these: each is a subpath. `hono`, `@modelcontextprotocol/server` and `@modelcontextprotocol/client` are
optional peer dependencies, but a subpath loads what its row below names as soon as it is imported
(`/server` loads the SDK even for `buildRegistry` alone). `ajv` is a plain dependency, installed with
the root import too.

| Import                        | What it holds                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Needs                                  |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `@rackbops/mcp-oauth/server`  | `loadContractTools` + `buildRegistry` (the server's `contracts/tools.json` is the only place a schema lives; strict Ajv; a handler not in the contract is a boot error), `buildToolServerFactory` (hand-dispatched `tools/call`: every failure is a `{code, message}` tool result, `environment` added where the output schema has it, `mapError` for an upstream the server knows), `ToolError`, `withContent`, `createBearerVerifier` (for the SDK's `requireBearerAuth`), `createEnvironment` (prod/dev/local label from the issuer host) | `@modelcontextprotocol/server`         |
| `@rackbops/mcp-oauth/http`    | No Hono, so a `node:http` server can use it: `createHostCheck` (Host/Origin allowlist over `Headers`), `parsePublicHosts`, `resolveClientSource` (the tunnel's client-IP header, last value), `currentTrace`                                                                                                                                                                                                                                                                                                                                 | `@modelcontextprotocol/server`         |
| `@rackbops/mcp-oauth/hono`    | `hostGuard`, `requestTrace` (one line per request, never a token, query or argument; `redactPath` masks a path that carries a credential), `mountOAuth` (the three routes with 16 KiB caps and the discovery documents), `mountMcp` (bearer gate, per-person rate limit, `after` hook, 405 `Allow`)                                                                                                                                                                                                                                          | `hono`, `@modelcontextprotocol/server` |
| `@rackbops/mcp-oauth/usr`     | `createUsrMemberCheck({usrUrl, apiKey, app, role})` (usr's role lookup, fail closed, no redirects), `createDelegation({audience, ...})` (a short-lived usr delegation token per person and operation, cached until a minute before expiry), and their errors                                                                                                                                                                                                                                                                                 | --                                     |
| `@rackbops/mcp-oauth/testing` | `requester`, `fakeIdentity`, `memoryStore`, `pkce`, `register`, `authorize`, `tokens`, `connect`, `mcpClient`: the OAuth flow and an MCP client in-process, for a server's own tests                                                                                                                                                                                                                                                                                                                                                         | `@modelcontextprotocol/client`         |

A server built on them looks like this (tool handlers and instructions are the server's own):

```ts
import { hostGuard, mountMcp, mountOAuth, requestTrace } from "@rackbops/mcp-oauth/hono"
import { resolveClientSource } from "@rackbops/mcp-oauth/http"
import {
  buildRegistry,
  buildToolServerFactory,
  loadContractTools,
} from "@rackbops/mcp-oauth/server"

const contract = loadContractTools(new URL("../../contracts/tools.json", import.meta.url))
const registry = buildRegistry(contract, HANDLERS)
app.use("*", requestTrace(logger, { knownTools: new Set(contract.map((t) => t.name)) }))
app.use("*", hostGuard(publicHosts))
mountOAuth(app, {
  oauth,
  store,
  identity,
  memberCheck,
  source: (c) => resolveClientSource(c.req.raw.headers, "CF-Connecting-IP", peer(c)),
})
const close = mountMcp(app, {
  oauth,
  store,
  factory: buildToolServerFactory({
    name: "my-server",
    title,
    instructions,
    registry,
    context: (caller) => ({ ...deps, sub: caller.sub }),
    environment: envLabel,
  }),
  bodyCap: 1024 * 1024,
  perMinute: 60,
})
```

The trace and the dispatcher share one per-request record (`currentTrace`), so the tool count lands on
the `/mcp` line only when both come from this package.

## Shipped identifiers: do not change for a live app

`idPrefix` (token, client-id and cookie prefixes), the `oauth_*` table and column names (the package
creates them with `CREATE TABLE IF NOT EXISTS`, so an existing database is adopted as is), and the
page headers (`Referrer-Policy: same-origin` is load-bearing: with `no-referrer` a browser sends
`Origin: null` on the consent POST and an Origin guard correctly refuses it).

## Options

- `memberCheck(memberSub)` on `createTokenHandler`: opt-in re-check on every refresh (`false` revokes
  the grant, a throw answers 503). Off by default, so a member removed in usr loses access at the
  idle or `grantMaxAgeDays` limit, as before.
- `redirect`, `lifetimes`, `registration`, `grantMaxAgeDays`: overridable through `oauthConfig`'s third
  argument; defaults are the ones claude.ai and ChatGPT run against.

## Development

`just check` (biome, tsc, vitest, build). Release: a squash-merged PR to `main` is versioned from
conventional commits touching `src/` and published by `publish.yml` (OIDC trusted publishing).
