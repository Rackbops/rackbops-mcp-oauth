import {
  localhostAllowedHostnames,
  validateHostHeader,
  validateOriginHeader,
} from "@modelcontextprotocol/server"

// Host and Origin allowlist (DNS-rebinding and cross-origin guard) for every route, as plain functions
// over `Headers` so a `node:http` server can use it as well as Hono (`../hono/hostGuard.ts`). Moved
// from Rackbops/meals-for-two and Rackbops/tracker-mcp `src/hostGuard.ts` (byte-identical there), which
// ported it from Rackbops/discord-mcp `src/service/hostValidation.ts` and `hostHeader.ts`, on the SDK's
// own header parser. An absent Origin is fine (server-side MCP clients send none); a present one must
// resolve to localhost or a listed public host. Localhost stays allowed so the container's own health
// probe works. The scheme is not checked: the guard is about WHICH host is trusted.

// A plain `Host`: a bracketed IPv6 literal or a bare hostname/IPv4, with an optional port. Anything
// with userinfo, whitespace, `/`, `\`, `?` or `#` could throw inside a URL parser downstream.
const HOST_HEADER_PATTERN = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$/

export function isPlainHostHeader(value: string | undefined): boolean {
  if (value === undefined || !HOST_HEADER_PATTERN.test(value)) return false
  try {
    const u = new URL(`http://${value}`)
    return (
      u.username === "" &&
      u.password === "" &&
      u.pathname === "/" &&
      u.search === "" &&
      u.hash === ""
    )
  } catch {
    return false
  }
}

/** Public hostnames, bare (no scheme, port, path or wildcard), normalized the way the SDK compares
 *  them. A malformed entry throws at startup naming the entry: it could never match and would 403
 *  the real hostname with nothing in the log. */
export function parsePublicHosts(value: string | undefined): string[] {
  if (value === undefined) return []
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => {
      const bracketed = entry.startsWith("[") && entry.endsWith("]")
      if (
        /[\s/\\?#@*]/.test(entry) ||
        (!bracketed && entry.includes(":")) ||
        (entry.includes("[") && !bracketed)
      ) {
        throw new Error(
          `public host "${entry}" must be a bare hostname: no scheme, port, path, credentials or wildcard`,
        )
      }
      try {
        return new URL(`http://${entry}`).hostname
      } catch {
        throw new Error(`public host "${entry}" is not a valid hostname`)
      }
    })
}

/** The rate-limit source: with `headerName` set (the tunnel's client-IP header, `CF-Connecting-IP`)
 *  its LAST value, otherwise the socket peer. Last, not first: each hop appends to the right, so the
 *  leftmost value is whatever the client chose to send. Safe only when the service is reachable
 *  solely through the tunnel that sets the header. */
export function resolveClientSource(
  headers: Headers,
  headerName: string | undefined,
  socketPeer: string,
): string {
  if (headerName === undefined) return socketPeer
  const last = headers.get(headerName)?.split(",").at(-1)?.trim()
  return last !== undefined && last !== "" ? last : socketPeer
}

/** Why a request was refused: the status and the `error` text of the JSON body. */
export interface HostRefusal {
  status: 400 | 403
  error: "bad host header" | "host not allowed" | "origin not allowed"
}

/** A checker for one allowlist: `undefined` admits the request, a `HostRefusal` says how to refuse it. */
export function createHostCheck(
  publicHosts: readonly string[],
): (headers: Headers) => HostRefusal | undefined {
  const hostnames = [...localhostAllowedHostnames(), ...publicHosts]
  return (headers) => {
    const host = headers.get("host") ?? undefined
    if (!isPlainHostHeader(host)) return { status: 400, error: "bad host header" }
    if (!validateHostHeader(host, hostnames).ok) return { status: 403, error: "host not allowed" }
    if (!validateOriginHeader(headers.get("origin") ?? undefined, hostnames).ok) {
      return { status: 403, error: "origin not allowed" }
    }
    return undefined
  }
}
