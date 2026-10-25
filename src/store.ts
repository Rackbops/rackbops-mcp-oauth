import { createHash, timingSafeEqual } from "node:crypto"
import type { DatabaseSync } from "node:sqlite"

// SQLite store for the OAuth server's clients, pending requests, codes, grants and tokens. Shaped
// after Rackbops/discord-mcp `src/service/store.ts` (exchangeOAuthCode, rotateRefreshToken), with
// the Discord/bridge/registration columns replaced by a single `member_sub` (usr's opaque user id).
// There is no tenant column here: a grant maps to a tenant (household, workspace) through the
// member, not through this table.
//
// Every value that can authenticate (code, access token, refresh token, request secret) is stored
// as a SHA-256 hash only.

export interface OAuthClientRow {
  clientId: string
  clientName: string | null
  redirectUris: readonly string[]
  source: string
  createdAt: number
  lastUsedAt: number
  firstGrantAt: number | null
}

export interface OAuthRequestInsert {
  requestId: string
  secretHash: string
  clientId: string
  redirectUri: string
  codeChallenge: string
  resource: string
  state: string | null
  memberSub: string
  source: string
  expiresAt: number
  /** Space-delimited scopes the member is being asked to grant. */
  scopes?: string
}

export interface OAuthRequestRow extends OAuthRequestInsert {
  createdAt: number
  scopes: string
}

export interface OAuthCodeInsert {
  codeHash: string
  clientId: string
  redirectUri: string
  codeChallenge: string
  resource: string
  memberSub: string
  createdAt: number
  expiresAt: number
  scopes?: string
}

export interface OAuthGrantRow {
  grantId: string
  clientId: string
  memberSub: string
  resource: string
  createdAt: number
  lastUsedAt: number
  revokedAt: number | null
  /** Space-delimited scopes the member granted; empty for none. */
  scopes: string
}

export interface OAuthAccessTokenRow {
  tokenHash: string
  grantId: string
  memberSub: string
  resource: string
  expiresAt: number
}

export interface OAuthRefreshTokenRow {
  tokenHash: string
  grantId: string
  parentHash: string | null
  issuedAt: number
  rotatedAt: number | null
  retiredAt: number | null
}

export type RegisterResult = { kind: "ok" } | { kind: "unavailable"; retryAfterSeconds: number }

export type CodeExchangeOutcome =
  | { kind: "unknown" | "replay" | "expired" | "mismatch" | "resource_mismatch" }
  | { kind: "ok"; memberSub: string; resource: string; scopes: string }

export type RotateOutcome =
  | { kind: "unknown" | "revoked" | "reuse" }
  | { kind: "rotated" | "sibling" }

export interface RotateAttempt {
  now: number
  graceMs: number
  maxChildren: number
  childRefreshTokenHash: string
  childAccessTokenHash: string
  childAccessTokenExpiresAt: number
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}

function pkceMatches(verifier: string, challenge: string): boolean {
  const derived = createHash("sha256").update(verifier, "utf8").digest("base64url")
  const a = Buffer.from(derived, "utf8")
  const b = Buffer.from(challenge, "utf8")
  return a.length === b.length && timingSafeEqual(a, b)
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL, source TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL, first_grant_at INTEGER
);
CREATE TABLE IF NOT EXISTS oauth_requests (
  request_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, resource TEXT NOT NULL, state TEXT,
  member_sub TEXT NOT NULL, source TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, scopes TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL, resource TEXT NOT NULL, member_sub TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, grant_id TEXT,
  scopes TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS oauth_grants (
  grant_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, member_sub TEXT NOT NULL,
  resource TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
  revoked_at INTEGER, scopes TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  token_hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, parent_hash TEXT,
  issued_at INTEGER NOT NULL, rotated_at INTEGER, retired_at INTEGER
);
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
  token_hash TEXT PRIMARY KEY, grant_id TEXT NOT NULL, member_sub TEXT NOT NULL,
  resource TEXT NOT NULL, expires_at INTEGER NOT NULL
);
`

export class OAuthStore {
  constructor(
    private readonly db: DatabaseSync,
    private readonly clock: () => number = Date.now,
  ) {
    db.exec(SCHEMA)
    // Databases created before scopes existed: add the column; the empty default grants nothing.
    for (const table of ["oauth_requests", "oauth_codes", "oauth_grants"]) {
      const cols = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]
      if (!cols.some((c) => c.name === "scopes")) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN scopes TEXT NOT NULL DEFAULT ''`)
      }
    }
  }

  private transaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE")
    try {
      const result = fn()
      this.db.exec("COMMIT")
      return result
    } catch (err) {
      this.db.exec("ROLLBACK")
      throw err
    }
  }

  /** Stores a new public client. Clients that never completed a grant are capped per source and
   *  globally, so an anonymous registration loop cannot grow the table without bound. */
  registerClient(
    row: { clientId: string; clientName: string | null; redirectUris: string[]; source: string },
    caps: { perSourceGrantless: number; globalGrantless: number; protectMs: number },
  ): RegisterResult {
    return this.transaction(() => {
      const now = this.clock()
      const count = (sql: string, ...args: string[]): number =>
        (this.db.prepare(sql).get(...args) as { n: number }).n
      const global = count("SELECT COUNT(*) AS n FROM oauth_clients WHERE first_grant_at IS NULL")
      const perSource = count(
        "SELECT COUNT(*) AS n FROM oauth_clients WHERE first_grant_at IS NULL AND source = ?",
        row.source,
      )
      if (perSource >= caps.perSourceGrantless || global >= caps.globalGrantless) {
        // Make room by evicting the oldest grantless client past the protect window (from this
        // source when it is the source cap, anywhere when it is the global one); none old enough
        // means the caller really is registering faster than clients are being used.
        const evictable = perSource >= caps.perSourceGrantless
        const victim = this.db
          .prepare(
            `SELECT client_id FROM oauth_clients WHERE first_grant_at IS NULL AND created_at < ?${evictable ? " AND source = ?" : ""} ORDER BY created_at LIMIT 1`,
          )
          .get(
            ...([now - caps.protectMs, ...(evictable ? [row.source] : [])] as [
              number,
              ...string[],
            ]),
          ) as { client_id: string } | undefined
        if (victim === undefined) return { kind: "unavailable", retryAfterSeconds: 60 }
        this.db.prepare("DELETE FROM oauth_clients WHERE client_id = ?").run(victim.client_id)
      }
      this.db
        .prepare(
          "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, source, created_at, last_used_at, first_grant_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
        )
        .run(row.clientId, row.clientName, JSON.stringify(row.redirectUris), row.source, now, now)
      return { kind: "ok" }
    })
  }

  getClient(clientId: string): OAuthClientRow | undefined {
    const row = this.db.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").get(clientId) as
      | {
          client_id: string
          client_name: string | null
          redirect_uris: string
          source: string
          created_at: number
          last_used_at: number
          first_grant_at: number | null
        }
      | undefined
    if (!row) return undefined
    return {
      clientId: row.client_id,
      clientName: row.client_name,
      redirectUris: JSON.parse(row.redirect_uris) as string[],
      source: row.source,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      firstGrantAt: row.first_grant_at,
    }
  }

  /** Inserts a pending authorize request, refusing past `perSource` live requests from one source. */
  createRequest(row: OAuthRequestInsert, perSource: number): boolean {
    return this.transaction(() => {
      const now = this.clock()
      const live = (
        this.db
          .prepare("SELECT COUNT(*) AS n FROM oauth_requests WHERE source = ? AND expires_at > ?")
          .get(row.source, now) as { n: number }
      ).n
      if (live >= perSource) return false
      this.db
        .prepare(
          "INSERT INTO oauth_requests (request_id, secret_hash, client_id, redirect_uri, code_challenge, resource, state, member_sub, source, created_at, expires_at, scopes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .run(
          row.requestId,
          row.secretHash,
          row.clientId,
          row.redirectUri,
          row.codeChallenge,
          row.resource,
          row.state,
          row.memberSub,
          row.source,
          now,
          row.expiresAt,
          row.scopes ?? "",
        )
      return true
    })
  }

  /** `undefined` for no such request or an expired one. */
  getRequest(requestId: string): OAuthRequestRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM oauth_requests WHERE request_id = ? AND expires_at > ?")
      .get(requestId, this.clock()) as
      | {
          request_id: string
          secret_hash: string
          client_id: string
          redirect_uri: string
          code_challenge: string
          resource: string
          state: string | null
          member_sub: string
          source: string
          created_at: number
          expires_at: number
          scopes: string
        }
      | undefined
    if (!row) return undefined
    return {
      requestId: row.request_id,
      secretHash: row.secret_hash,
      clientId: row.client_id,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      resource: row.resource,
      state: row.state,
      memberSub: row.member_sub,
      source: row.source,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      scopes: row.scopes,
    }
  }

  /** Consumes the request row (single use) and, when `code` is given, stores the issued code. */
  resolveRequest(requestId: string, code?: OAuthCodeInsert): void {
    this.transaction(() => {
      const deleted = this.db
        .prepare("DELETE FROM oauth_requests WHERE request_id = ?")
        .run(requestId)
      if (Number(deleted.changes) !== 1) throw new Error("authorize request already consumed")
      if (code === undefined) return
      this.db
        .prepare(
          "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, resource, member_sub, created_at, expires_at, used_at, grant_id, scopes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
        )
        .run(
          code.codeHash,
          code.clientId,
          code.redirectUri,
          code.codeChallenge,
          code.resource,
          code.memberSub,
          code.createdAt,
          code.expiresAt,
          code.scopes ?? "",
        )
    })
  }

  /** The whole code-exchange decision in one BEGIN IMMEDIATE transaction, so two concurrent
   *  exchanges of one code can never both see it unused. A replay revokes the grant the code
   *  produced (RFC 6749 10.5); every refusal consumes the code. */
  exchangeCode(
    codeHash: string,
    request: { clientId: string; redirectUri: string; resource: string; codeVerifier: string },
    newGrant: {
      grantId: string
      refreshTokenHash: string
      accessTokenHash: string
      accessTokenExpiresAt: number
    },
    now: number,
  ): CodeExchangeOutcome {
    return this.transaction(() => {
      const row = this.db.prepare("SELECT * FROM oauth_codes WHERE code_hash = ?").get(codeHash) as
        | {
            client_id: string
            redirect_uri: string
            code_challenge: string
            resource: string
            member_sub: string
            expires_at: number
            used_at: number | null
            grant_id: string | null
            scopes: string
          }
        | undefined
      if (row === undefined) return { kind: "unknown" }
      if (row.used_at !== null) {
        if (row.grant_id !== null) this.revokeGrantCore(row.grant_id, now)
        return { kind: "replay" }
      }
      const consume = (): void => {
        this.db.prepare("UPDATE oauth_codes SET used_at = ? WHERE code_hash = ?").run(now, codeHash)
      }
      if (row.expires_at < now) {
        consume()
        return { kind: "expired" }
      }
      if (
        row.client_id !== request.clientId ||
        row.redirect_uri !== request.redirectUri ||
        !pkceMatches(request.codeVerifier, row.code_challenge)
      ) {
        consume()
        return { kind: "mismatch" }
      }
      if (row.resource !== request.resource) {
        consume()
        return { kind: "resource_mismatch" }
      }
      this.db
        .prepare("UPDATE oauth_codes SET used_at = ?, grant_id = ? WHERE code_hash = ?")
        .run(now, newGrant.grantId, codeHash)
      this.db
        .prepare(
          "INSERT INTO oauth_grants (grant_id, client_id, member_sub, resource, created_at, last_used_at, revoked_at, scopes) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
        )
        .run(newGrant.grantId, row.client_id, row.member_sub, row.resource, now, now, row.scopes)
      this.db
        .prepare(
          "INSERT INTO oauth_refresh_tokens (token_hash, grant_id, parent_hash, issued_at, rotated_at, retired_at) VALUES (?, ?, NULL, ?, NULL, NULL)",
        )
        .run(newGrant.refreshTokenHash, newGrant.grantId, now)
      this.insertAccessToken({
        tokenHash: newGrant.accessTokenHash,
        grantId: newGrant.grantId,
        memberSub: row.member_sub,
        resource: row.resource,
        expiresAt: newGrant.accessTokenExpiresAt,
      })
      this.db
        .prepare(
          "UPDATE oauth_clients SET last_used_at = ?, first_grant_at = COALESCE(first_grant_at, ?) WHERE client_id = ?",
        )
        .run(now, now, row.client_id)
      return { kind: "ok", memberSub: row.member_sub, resource: row.resource, scopes: row.scopes }
    })
  }

  insertAccessToken(row: OAuthAccessTokenRow): void {
    this.db
      .prepare(
        "INSERT INTO oauth_access_tokens (token_hash, grant_id, member_sub, resource, expires_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(row.tokenHash, row.grantId, row.memberSub, row.resource, row.expiresAt)
  }

  private revokeGrantCore(grantId: string, now: number): void {
    this.db
      .prepare("UPDATE oauth_grants SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL")
      .run(now, grantId)
    this.db.prepare("DELETE FROM oauth_access_tokens WHERE grant_id = ?").run(grantId)
  }

  revokeGrant(grantId: string, now: number): void {
    this.transaction(() => this.revokeGrantCore(grantId, now))
  }

  getGrant(grantId: string): OAuthGrantRow | undefined {
    const row = this.db.prepare("SELECT * FROM oauth_grants WHERE grant_id = ?").get(grantId) as
      | {
          grant_id: string
          client_id: string
          member_sub: string
          resource: string
          created_at: number
          last_used_at: number
          revoked_at: number | null
          scopes: string
        }
      | undefined
    if (!row) return undefined
    return {
      grantId: row.grant_id,
      clientId: row.client_id,
      memberSub: row.member_sub,
      resource: row.resource,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      revokedAt: row.revoked_at,
      scopes: row.scopes,
    }
  }

  getRefreshToken(tokenHash: string): OAuthRefreshTokenRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?")
      .get(tokenHash) as
      | {
          token_hash: string
          grant_id: string
          parent_hash: string | null
          issued_at: number
          rotated_at: number | null
          retired_at: number | null
        }
      | undefined
    if (!row) return undefined
    return {
      tokenHash: row.token_hash,
      grantId: row.grant_id,
      parentHash: row.parent_hash,
      issuedAt: row.issued_at,
      rotatedAt: row.rotated_at,
      retiredAt: row.retired_at,
    }
  }

  getAccessToken(tokenHash: string): OAuthAccessTokenRow | undefined {
    const row = this.db
      .prepare("SELECT * FROM oauth_access_tokens WHERE token_hash = ?")
      .get(tokenHash) as
      | {
          token_hash: string
          grant_id: string
          member_sub: string
          resource: string
          expires_at: number
        }
      | undefined
    if (!row) return undefined
    return {
      tokenHash: row.token_hash,
      grantId: row.grant_id,
      memberSub: row.member_sub,
      resource: row.resource,
      expiresAt: row.expires_at,
    }
  }

  /** Bounded refresh rotation with a grace-window sibling and reuse detection: a retired token, or
   *  an already-rotated one presented outside the grace window (or past `maxChildren`), is reuse and
   *  revokes the grant. */
  rotateRefreshToken(tokenHash: string, attempt: RotateAttempt): RotateOutcome {
    return this.transaction(() => {
      const row = this.getRefreshToken(tokenHash)
      if (row === undefined) return { kind: "unknown" }
      const grant = this.getGrant(row.grantId)
      if (grant === undefined || grant.revokedAt !== null) return { kind: "revoked" }
      if (row.retiredAt !== null) {
        this.revokeGrantCore(row.grantId, attempt.now)
        return { kind: "reuse" }
      }
      let outcome: "rotated" | "sibling"
      if (row.rotatedAt === null) {
        this.db
          .prepare(
            "UPDATE oauth_refresh_tokens SET rotated_at = ? WHERE token_hash = ? AND rotated_at IS NULL",
          )
          .run(attempt.now, tokenHash)
        if (row.parentHash !== null) {
          this.db
            .prepare(
              "UPDATE oauth_refresh_tokens SET retired_at = ? WHERE parent_hash = ? AND token_hash != ? AND retired_at IS NULL",
            )
            .run(attempt.now, row.parentHash, tokenHash)
        }
        outcome = "rotated"
      } else {
        const withinGrace = attempt.now - row.rotatedAt <= attempt.graceMs
        const children = this.db
          .prepare("SELECT rotated_at, retired_at FROM oauth_refresh_tokens WHERE parent_hash = ?")
          .all(tokenHash) as { rotated_at: number | null; retired_at: number | null }[]
        const allUnused = children.every((c) => c.rotated_at === null && c.retired_at === null)
        if (withinGrace && children.length < attempt.maxChildren && allUnused) {
          outcome = "sibling"
        } else {
          this.revokeGrantCore(row.grantId, attempt.now)
          return { kind: "reuse" }
        }
      }
      this.db
        .prepare(
          "INSERT INTO oauth_refresh_tokens (token_hash, grant_id, parent_hash, issued_at, rotated_at, retired_at) VALUES (?, ?, ?, ?, NULL, NULL)",
        )
        .run(attempt.childRefreshTokenHash, row.grantId, tokenHash, attempt.now)
      this.insertAccessToken({
        tokenHash: attempt.childAccessTokenHash,
        grantId: row.grantId,
        memberSub: grant.memberSub,
        resource: grant.resource,
        expiresAt: attempt.childAccessTokenExpiresAt,
      })
      this.db
        .prepare("UPDATE oauth_grants SET last_used_at = ? WHERE grant_id = ?")
        .run(attempt.now, row.grantId)
      this.db
        .prepare("UPDATE oauth_clients SET last_used_at = ? WHERE client_id = ?")
        .run(attempt.now, grant.clientId)
      return { kind: outcome }
    })
  }

  /** Bounds table growth: expired requests, codes and access tokens, and grants idle past `idleMs`. */
  prune(idleMs: number): void {
    const now = this.clock()
    this.transaction(() => {
      this.db.prepare("DELETE FROM oauth_requests WHERE expires_at < ?").run(now)
      // Clients that never completed a grant and are a day old.
      this.db
        .prepare("DELETE FROM oauth_clients WHERE first_grant_at IS NULL AND created_at < ?")
        .run(now - 24 * 60 * 60 * 1000)
      this.db.prepare("DELETE FROM oauth_codes WHERE expires_at < ?").run(now - 24 * 60 * 60 * 1000)
      this.db.prepare("DELETE FROM oauth_access_tokens WHERE expires_at < ?").run(now)
      const idle = this.db
        .prepare("SELECT grant_id FROM oauth_grants WHERE last_used_at < ?")
        .all(now - idleMs) as { grant_id: string }[]
      for (const { grant_id } of idle) {
        this.db.prepare("DELETE FROM oauth_refresh_tokens WHERE grant_id = ?").run(grant_id)
        this.db.prepare("DELETE FROM oauth_access_tokens WHERE grant_id = ?").run(grant_id)
        this.db.prepare("DELETE FROM oauth_grants WHERE grant_id = ?").run(grant_id)
      }
    })
  }
}
