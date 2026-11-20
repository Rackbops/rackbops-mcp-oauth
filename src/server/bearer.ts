import { type AuthInfo, OAuthError, OAuthErrorCode } from "@modelcontextprotocol/server"
import type { ScopeDef } from "../config.js"
import { splitScopes } from "../scopes.js"
import { type OAuthStore, sha256Hex } from "../store.js"

// The `/mcp` bearer check, moved from Meals for Two's and tracker-mcp's `src/app.ts` (the same there):
// pass it as `verifier` to the SDK's `requireBearerAuth`. An access token is good only while it is
// unexpired, its grant unrevoked, and it was minted for this server's `/mcp`.

export interface BearerVerifierOptions {
  store: OAuthStore
  /** The OAuth issuer (the server's public origin); the token's resource must be `${issuer}/mcp`. */
  issuer: string
  /** The server's scopes (`OAuthApp.scopes`), to read a grant's back. */
  scopes: readonly ScopeDef[]
  /** Epoch milliseconds. */
  clock?: () => number
}

export function createBearerVerifier(options: BearerVerifierOptions): {
  verifyAccessToken(raw: string): Promise<AuthInfo>
} {
  const { store, issuer } = options
  const clock = options.clock ?? Date.now
  return {
    async verifyAccessToken(raw) {
      const row = store.getAccessToken(sha256Hex(raw))
      if (row === undefined)
        throw new OAuthError(OAuthErrorCode.InvalidToken, "Invalid or unknown token.")
      if (row.expiresAt <= clock())
        throw new OAuthError(OAuthErrorCode.InvalidToken, "Token has expired.")
      const grant = store.getGrant(row.grantId)
      if (grant === undefined || grant.revokedAt !== null) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "Token has been revoked.")
      }
      if (row.resource !== `${issuer}/mcp`) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "Token is not valid for this resource.")
      }
      // clientId carries the person (usr sub): the principal the tools act for.
      return {
        token: raw,
        clientId: row.memberSub,
        scopes: splitScopes(grant.scopes, options.scopes),
        // The client's registered name, for an audit trail; the person is `clientId` above.
        extra: { client: store.getClient(grant.clientId)?.clientName ?? grant.clientId },
        expiresAt: Math.floor(row.expiresAt / 1000),
      }
    },
  }
}
