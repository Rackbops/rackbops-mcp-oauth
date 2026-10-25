// RFC 9728 protected-resource and RFC 8414 authorization-server metadata. Ported from
// Rackbops/discord-mcp `src/service/discovery.ts`: DCR only, public clients only, S256 only, and
// and the optional scopes the app declares (see scopes.ts); any other requested scope is ignored.

export function protectedResourceMetadata(issuer: string, scopesSupported: readonly string[]) {
  return {
    resource: `${issuer}/mcp`,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: scopesSupported,
  }
}

export function authorizationServerMetadata(issuer: string, scopesSupported: readonly string[]) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    scopes_supported: scopesSupported,
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: false,
    authorization_response_iss_parameter_supported: true,
  }
}

/** What the 401 on /mcp advertises (RFC 9728 5.1): the path-aware document for the /mcp resource. */
export function resourceMetadataUrl(issuer: string): string {
  return `${issuer}/.well-known/oauth-protected-resource/mcp`
}

/** `resource` handling: zero values means the implicit default (`${issuer}/mcp`); exactly one is
 *  accepted if it normalizes to that, or to the bare issuer origin when `acceptOrigin`. Two or more,
 *  or anything else, is refused (the caller answers `invalid_target`). */
export function normalizeResource(
  values: readonly string[],
  issuer: string,
  acceptOrigin: boolean,
): { ok: true; resource: string } | { ok: false } {
  const canonical = `${issuer}/mcp`
  if (values.length === 0) return { ok: true, resource: canonical }
  if (values.length > 1) return { ok: false }
  let url: URL
  try {
    url = new URL(values[0] as string)
  } catch {
    return { ok: false }
  }
  const normalized = url.href.endsWith("/") ? url.href.slice(0, -1) : url.href
  if (normalized === canonical) return { ok: true, resource: canonical }
  if (acceptOrigin && normalized === issuer) return { ok: true, resource: canonical }
  return { ok: false }
}
