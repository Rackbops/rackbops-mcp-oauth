import { randomBytes } from "node:crypto"
import type { MiddlewareHandler } from "hono"
import { type RequestTrace, runWithTrace } from "../http/trace.js"

// One structured line per request: time (the logger's), correlation id, HTTP method and path, status,
// duration, and for /mcp the JSON-RPC method, protocol version and (for tools/list) tool count.
// Never a token, a query string (authorization codes ride in it), a header value other than the two
// named below, an argument or a body. The lesson is Rackbops/discord-mcp#72: ChatGPT paired but no
// tools appeared, and with no per-request trace the cause was unknowable.

/** Where the line goes: `@rackbops/node-app-kit/log`'s `Logger` fits, as does anything with `info`. */
export interface TraceLogger {
  info(message: string, fields: Record<string, unknown>): void
}

export interface RequestTraceOptions {
  /** Every tool the contract promises; a `tools/call` naming anything else is logged without a tool. */
  knownTools: ReadonlySet<string>
  /** Paths answered without a line (`/healthz`), compared after `redactPath`. */
  skipPaths?: ReadonlySet<string>
  /** Masks a path that carries a credential before it is logged (Meals for Two's signed photo links). */
  redactPath?: (path: string) => string
  now?: () => number
}

const MAX_TRACED_BODY_BYTES = 64 * 1024

// A JSON-RPC method name is a short token like `tools/call`; anything else is logged as "other" so a
// hostile body cannot put arbitrary text into the log.
const RPC_METHOD = /^[a-z][a-z0-9_./-]{0,63}$/
const TOOL_NAME = /^[a-z][a-z0-9_]{0,63}$/
const CF_RAY = /^[A-Za-z0-9-]{1,40}$/

function describeRpc(
  body: unknown,
  knownTools: ReadonlySet<string>,
): Pick<RequestTrace, "rpcMethod" | "tool"> {
  if (Array.isArray(body)) return { rpcMethod: "batch" }
  if (typeof body !== "object" || body === null) return {}
  const record = body as { method?: unknown; params?: { name?: unknown } }
  if (typeof record.method !== "string") return {}
  const rpcMethod = RPC_METHOD.test(record.method) ? record.method : "other"
  const name = record.params?.name
  const tool =
    rpcMethod === "tools/call" &&
    typeof name === "string" &&
    knownTools.has(name) &&
    TOOL_NAME.test(name)
      ? name
      : undefined
  return tool === undefined ? { rpcMethod } : { rpcMethod, tool }
}

/** The request body as text, or `null` when it is longer than `max` bytes (the read stops there). */
async function readCapped(request: Request, max: number): Promise<string | null> {
  if (request.body === null) return ""
  const reader = request.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > max) {
      void reader.cancel() // not awaited: on a tee branch it settles only when the other branch does
      return null
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString("utf8")
}

export function requestTrace(logger: TraceLogger, options: RequestTraceOptions): MiddlewareHandler {
  const now = options.now ?? Date.now
  const redact = options.redactPath ?? ((path: string) => path)
  return async (c, next) => {
    const path = redact(new URL(c.req.url).pathname)
    if (options.skipPaths?.has(path)) return next()
    const trace: RequestTrace = { correlationId: randomBytes(6).toString("hex") }
    const started = now()
    if (path === "/mcp" && c.req.method === "POST") {
      // Runs before the Host guard, the body cap and auth, so it reads at most 64 KiB of a clone
      // and gives up past that; the body itself is never held beyond this.
      try {
        const text = await readCapped(c.req.raw.clone(), MAX_TRACED_BODY_BYTES)
        if (text === null) trace.rpcMethod = "unread"
        else Object.assign(trace, describeRpc(JSON.parse(text), options.knownTools))
      } catch {
        trace.rpcMethod = "unparseable"
      }
    }
    let status = 500
    try {
      await runWithTrace(trace, next)
      status = c.res.status
      c.res.headers.set("X-Request-Id", trace.correlationId)
    } finally {
      const ray = c.req.header("cf-ray")
      logger.info("request", {
        id: trace.correlationId,
        method: c.req.method,
        path,
        status,
        ms: now() - started,
        ...(ray !== undefined && CF_RAY.test(ray) ? { cfRay: ray } : {}),
        ...(path === "/mcp"
          ? {
              protocolVersion: c.req.header("mcp-protocol-version") ?? null,
              rpc: trace.rpcMethod ?? null,
              ...(trace.tool !== undefined ? { tool: trace.tool } : {}),
              ...(trace.toolCount !== undefined ? { tools: trace.toolCount } : {}),
            }
          : {}),
      })
    }
  }
}
