import { randomBytes } from "node:crypto"
import type { OAuthConfig } from "./config.js"
import type { RateLimiter } from "./rateLimit.js"
import { type RedirectPolicy, validateRedirectUri } from "./redirect.js"
import type { OAuthStore } from "./store.js"

// RFC 7591 Dynamic Client Registration at POST /register. Ported from Rackbops/discord-mcp
// `src/service/clientRegistration.ts` (client-name control/format-character refusal, #792; redirect
// allowlist, #783). Public clients only: no secret is ever issued, and the response always says
// token_endpoint_auth_method "none".

/** The shape of a client id this app issues: `<idPrefix>_c_` plus 43 base64url characters. */
export const clientIdPattern = (idPrefix: string): RegExp =>
  new RegExp(`^${idPrefix}_c_[A-Za-z0-9_-]{43}$`)

export type ParseRegistrationResult =
  | { ok: true; redirectUris: string[]; clientName: string | null }
  | { ok: false; error: "invalid_redirect_uri" | "invalid_client_metadata"; description: string }

const MAX_REDIRECT_URIS = 5
const MAX_REDIRECT_URI_LENGTH = 2048
const MAX_CLIENT_NAME_LENGTH = 100
const SUPPORTED_GRANT_TYPES = new Set(["authorization_code", "refresh_token"])
const SUPPORTED_RESPONSE_TYPES = new Set(["code"])
// The name is shown on the consent page, so it is refused when it carries a code point that renders
// as nothing or breaks the line: control (Cc) and format (Cf: bidi overrides, zero-width, soft
// hyphen), surrogates, private-use, unassigned, line/paragraph separators, and the blank "filler"
// glyphs Unicode classes as letters or symbols. Also refused: more than four stacked combining marks
// and a name with no letter, number or emoji at all.
const UNRENDERABLE_CHAR_PATTERN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}ᅟᅠ⠀ㅤﾠ￼]/u
const COMBINING_MARK_RUN_PATTERN = /\p{M}{5,}/u
const VISIBLE_CHAR_PATTERN = /[\p{L}\p{N}\p{Extended_Pictographic}]/u

function invalidMetadata(description: string): ParseRegistrationResult {
  return { ok: false, error: "invalid_client_metadata", description }
}

function isStringArrayOf(value: unknown, allowed: ReadonlySet<string>): boolean {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === "string" && allowed.has(entry))
  )
}

export function parseRegistrationRequest(
  body: unknown,
  policy: RedirectPolicy,
): ParseRegistrationResult {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return invalidMetadata("body must be a JSON object")
  }
  const record = body as Record<string, unknown>
  const raw = record.redirect_uris
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_REDIRECT_URIS) {
    return invalidMetadata("redirect_uris must be an array of 1 to 5 strings")
  }
  const redirectUris: string[] = []
  for (const entry of raw) {
    const valid =
      typeof entry === "string" &&
      entry.length <= MAX_REDIRECT_URI_LENGTH &&
      validateRedirectUri(entry, policy)
    if (!valid) {
      return {
        ok: false,
        error: "invalid_redirect_uri",
        description: "redirect_uri is not allowed",
      }
    }
    if (!redirectUris.includes(entry as string)) redirectUris.push(entry as string)
  }

  let clientName: string | null = null
  if (record.client_name !== undefined) {
    if (typeof record.client_name !== "string")
      return invalidMetadata("client_name must be a string")
    const trimmed = record.client_name.trim()
    if (
      [...trimmed].length > MAX_CLIENT_NAME_LENGTH ||
      UNRENDERABLE_CHAR_PATTERN.test(trimmed) ||
      COMBINING_MARK_RUN_PATTERN.test(trimmed) ||
      (trimmed !== "" && !VISIBLE_CHAR_PATTERN.test(trimmed))
    ) {
      return invalidMetadata(
        "client_name must be at most 100 characters, with a letter, number or emoji, and no control, format, invisible or stacked combining characters",
      )
    }
    clientName = trimmed === "" ? null : trimmed
  }
  if (
    record.grant_types !== undefined &&
    !isStringArrayOf(record.grant_types, SUPPORTED_GRANT_TYPES)
  ) {
    return invalidMetadata('grant_types must be a subset of ["authorization_code","refresh_token"]')
  }
  if (
    record.response_types !== undefined &&
    !isStringArrayOf(record.response_types, SUPPORTED_RESPONSE_TYPES)
  ) {
    return invalidMetadata('response_types must be a subset of ["code"]')
  }
  return { ok: true, redirectUris, clientName }
}

function json(status: number, body: unknown, extra?: Record<string, string>): Response {
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

function unavailable(retryAfterSeconds: number): Response {
  return json(
    503,
    { error: "temporarily_unavailable" },
    { "Retry-After": String(retryAfterSeconds) },
  )
}

export interface RegistrationDeps {
  store: OAuthStore
  oauth: OAuthConfig
  limiter: RateLimiter
  clock?: () => number
}

export function createRegistrationHandler(
  deps: RegistrationDeps,
): (request: Request, source: string) => Promise<Response> {
  const { store, oauth, limiter } = deps
  const clock = deps.clock ?? Date.now
  return async (request, source) => {
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
    if (contentType !== "application/json") {
      return json(415, {
        error: "invalid_client_metadata",
        error_description: "Content-Type must be application/json",
      })
    }
    // Charged before the body is read: a malformed body is still an attempt.
    const hit = limiter.hit(`register:${source}`)
    if (!hit.allowed) return unavailable(hit.retryAfterSeconds)

    let parsedBody: unknown
    try {
      parsedBody = JSON.parse(await request.text())
    } catch {
      return json(400, {
        error: "invalid_client_metadata",
        error_description: "body must be valid JSON",
      })
    }
    const parsed = parseRegistrationRequest(parsedBody, oauth.redirect)
    if (!parsed.ok) return json(400, { error: parsed.error, error_description: parsed.description })

    const clientId = `${oauth.app.idPrefix}_c_${randomBytes(32).toString("base64url")}`
    try {
      const result = store.registerClient(
        { clientId, clientName: parsed.clientName, redirectUris: parsed.redirectUris, source },
        {
          perSourceGrantless: oauth.registration.perSourceGrantless,
          globalGrantless: oauth.registration.globalGrantless,
          protectMs: oauth.registration.evictionProtectMinutes * 60 * 1000,
        },
      )
      if (result.kind === "unavailable") return unavailable(result.retryAfterSeconds)
    } catch (err) {
      console.error(`${oauth.app.logPrefix}: /register failed to store a client:`, err)
      return unavailable(5)
    }
    return json(201, {
      client_id: clientId,
      client_id_issued_at: Math.floor(clock() / 1000),
      redirect_uris: parsed.redirectUris,
      ...(parsed.clientName !== null ? { client_name: parsed.clientName } : {}),
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    })
  }
}
