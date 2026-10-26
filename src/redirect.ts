// Redirect-URI policy for the OAuth server. Ported from Rackbops/discord-mcp
// `src/service/clientRegistration.ts` (validateRedirectUri) and `oauthAuthorize.ts`
// (redirectMatchesRegistered) at the commit this was read from, with the same rules; shared
// extraction is #5 (do not factor it out here).

export interface RedirectPolicy {
  allowedRedirectUris: readonly string[]
  allowedRedirectPrefixes: readonly string[]
}

/** Hosted-client callbacks, as proven in discord-mcp. ChatGPT's connector callback is either the
 *  fixed `connector_platform_oauth_redirect` URL or `connector/oauth/<id>` (one path segment). */
export const DEFAULT_REDIRECT_POLICY: RedirectPolicy = {
  allowedRedirectUris: [
    "https://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
  ],
  allowedRedirectPrefixes: ["https://chatgpt.com/connector/oauth/"],
}

const PREFIX_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/
// WHATWG URL.hostname keeps the brackets on an IPv6 literal; "::1" is accepted too in case a future
// Node drops them.
export const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set([
  "localhost",
  "127.0.0.1",
  "[::1]",
  "::1",
])

/** A redirect_uri is accepted only if it parses, carries no userinfo or fragment, and is either an
 *  exact allowlist entry, one path segment past an allowlisted prefix (no query), or plain http on a
 *  loopback hostname (RFC 8252 native clients such as Claude Code). */
export function validateRedirectUri(uri: string, policy: RedirectPolicy): boolean {
  let url: URL
  try {
    url = new URL(uri)
  } catch {
    return false
  }
  if (url.username !== "" || url.password !== "") return false
  // `new URL("http://localhost/cb#").hash` is "" although the href keeps the "#": an empty
  // fragment is still a fragment (RFC 6749 3.1.2), so look at the href itself.
  if (url.hash !== "" || url.href.includes("#")) return false

  for (const entry of policy.allowedRedirectUris) {
    try {
      if (url.href === new URL(entry).href) return true
    } catch {
      // A malformed policy entry can never match anything; skip it rather than 500.
    }
  }
  for (const prefix of policy.allowedRedirectPrefixes) {
    let prefixHref: string
    try {
      prefixHref = new URL(prefix).href
    } catch {
      continue
    }
    if (!url.href.startsWith(prefixHref)) continue
    const remainder = url.href.slice(prefixHref.length)
    if (PREFIX_SEGMENT_PATTERN.test(remainder) && url.search === "") return true
  }
  return url.protocol === "http:" && LOOPBACK_HOSTNAMES.has(url.hostname)
}

function isLoopbackHttp(url: URL): boolean {
  return url.protocol === "http:" && LOOPBACK_HOSTNAMES.has(url.hostname)
}

/** A registered loopback entry matches a requested loopback URI of the same scheme, hostname, path
 *  and query on ANY port (RFC 8252 7.3). Everything else needs exact `href` equality. Malformed
 *  input on either side never matches and never throws. */
export function redirectMatchesRegistered(
  requested: string,
  registered: readonly string[],
): boolean {
  let requestedUrl: URL
  try {
    requestedUrl = new URL(requested)
  } catch {
    return false
  }
  for (const entry of registered) {
    let registeredUrl: URL
    try {
      registeredUrl = new URL(entry)
    } catch {
      continue
    }
    if (isLoopbackHttp(registeredUrl)) {
      if (
        isLoopbackHttp(requestedUrl) &&
        requestedUrl.hostname === registeredUrl.hostname &&
        requestedUrl.pathname === registeredUrl.pathname &&
        requestedUrl.search === registeredUrl.search
      ) {
        return true
      }
      continue
    }
    if (requestedUrl.href === registeredUrl.href) return true
  }
  return false
}

export { isLoopbackHttp }
