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
them on Hono or anything else), not the Host/Origin guard, not the `/mcp` bearer gate, and not a
user database (usr is the login).

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
```

Then route `/register`, `/authorize`, `/token`, and serve `protectedResourceMetadata(issuer, scopes)` at
`/.well-known/oauth-protected-resource[/mcp]` and `authorizationServerMetadata(issuer, scopes)` at
`/.well-known/oauth-authorization-server`. Verify a bearer by `store.getAccessToken(sha256Hex(raw))`,
then check expiry, `store.getGrant(...).revokedAt` and `resource === ${issuer}/mcp`.

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
