import type { McpServerFactory, ServerContext } from "@modelcontextprotocol/server"
import { Server } from "@modelcontextprotocol/server"
import { currentTrace } from "../http/trace.js"
import { type Registry, ToolError, ToolResult } from "./registry.js"

// The MCP surface, hand-dispatched over the low-level Server rather than McpServer.registerTool, as
// Rackbops/discord-mcp `src/service/tools.ts` first did and Meals for Two and tracker-mcp copied:
// registerTool turns an unexpected throw into a protocol-level error with no body a caller can act on.
// Owning tools/call means a bad input or a bug in a handler is always a tool result whose body is
// `{code, message}` JSON.

/** Who is calling, from the bearer verifier's `AuthInfo` (`./bearer.ts`). */
export interface Caller {
  /** usr's opaque user id of the signed-in person (the grant's `member_sub`). */
  sub: string
  scopes: readonly string[]
  /** The OAuth client's registered name, for an audit trail; "unknown" when it has none. */
  client: string
}

export interface ToolServerOptions<Ctx> {
  /** The MCP server name, also the prefix of every console line (`meals-for-two`). */
  name: string
  /** The name people see (`Meals for Two (dev)`). */
  title: string
  /** The server's instructions, which ChatGPT and claude.ai show the model on connect. */
  instructions: string
  registry: Registry<Ctx>
  /** What a handler receives for one call. */
  context: (caller: Caller) => Ctx
  /** Added as `environment` to every answer whose output schema declares that field. */
  environment?: string
  /** Turns a thrown error the server knows (an upstream it could not reach) into a contract error;
   *  `undefined` leaves it to the generic INTERNAL answer. */
  mapError?: (err: unknown) => { code: string; message: string } | undefined
  /** Longest error message sent; longer ones are cut. Default 2000. */
  maxErrorMessage?: number
}

function errorResult(code: string, message: string, max: number, result?: unknown) {
  const body = { code, message: message.slice(0, max), ...(result === undefined ? {} : { result }) }
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: JSON.stringify(body) }],
  }
}

export function buildToolServerFactory<Ctx>(options: ToolServerOptions<Ctx>): McpServerFactory {
  const { registry, name } = options
  const max = options.maxErrorMessage ?? 2000
  const environment = options.environment
  const labelled: ReadonlySet<string> = new Set(
    registry.catalog
      .filter((t) => {
        const props = (t.outputSchema as { properties?: Record<string, unknown> }).properties
        return props !== undefined && "environment" in props
      })
      .map((t) => t.name),
  )
  const label = (tool: string, value: unknown): unknown =>
    environment !== undefined && typeof value === "object" && value !== null && labelled.has(tool)
      ? { ...value, environment }
      : value

  return (mctx) => {
    // The person is the OAuth grant's usr sub (`clientId` from the bearer verifier); a request that got
    // here was authenticated, so a missing authInfo is a wiring bug, never an anonymous caller.
    const sub = mctx.authInfo?.clientId
    const scopes = mctx.authInfo?.scopes ?? []
    const clientName = mctx.authInfo?.extra?.client
    const client = typeof clientName === "string" && clientName !== "" ? clientName : "unknown"
    const server = new Server(
      { name, title: options.title, version: "0.0.0" },
      { capabilities: { tools: {} }, instructions: options.instructions },
    )

    server.setRequestHandler("tools/list", () => {
      const trace = currentTrace()
      if (trace !== undefined) trace.toolCount = registry.catalog.length
      return { tools: registry.catalog } as never
    })

    server.setRequestHandler("tools/call", async (request, _ctx: ServerContext) => {
      const { name: tool, arguments: args } = request.params
      const handler = registry.handlers.get(tool)
      const inputValidate = registry.inputValidators.get(tool)
      const outputValidate = registry.outputValidators.get(tool)
      if (!handler || !inputValidate || !outputValidate) {
        return errorResult("INVALID_INPUT", `Unknown tool: ${tool}`, max)
      }
      if (sub === undefined) {
        console.error(`${name}: ${tool} called without an authenticated caller`)
        return errorResult("FORBIDDEN", "Not signed in.", max)
      }
      const candidate = args ?? {}
      if (!inputValidate(candidate)) {
        const first = inputValidate.errors?.[0]
        return errorResult(
          "INVALID_INPUT",
          `${first?.instancePath || "(root)"} ${first?.message ?? "is invalid"}`.trim(),
          max,
        )
      }
      try {
        let output = await handler(
          candidate as Record<string, unknown>,
          options.context({ sub, scopes, client }),
        )
        // A handler may return content blocks (a picture) beside its structured answer.
        const extra = output instanceof ToolResult ? output.content : []
        if (output instanceof ToolResult) output = output.output
        // Every answer says which deployment it came from (an optional contract field), checked below.
        output = label(tool, output)
        if (!outputValidate(output)) {
          console.error(`${name}: ${tool} produced output failing its own outputSchema`)
          return errorResult("INTERNAL", "Internal error.", max)
        }
        // The contract's response rule: the text block is the same sentence as structuredContent.summary.
        const structured = output as Record<string, unknown>
        return {
          content: [{ type: "text" as const, text: String(structured.summary) }, ...extra],
          structuredContent: structured,
        }
      } catch (err) {
        if (err instanceof ToolError) {
          // A stored answer carried on the error is labelled like a fresh one.
          return errorResult(err.code, err.message, max, label(tool, err.result))
        }
        const mapped = options.mapError?.(err)
        if (mapped !== undefined) return errorResult(mapped.code, mapped.message, max)
        // Never return err.message: it may carry a path, a URL or a raw driver error.
        console.error(`${name}: ${tool} threw an unexpected error:`, err)
        return errorResult("INTERNAL", "Internal error.", max)
      }
    })
    return server
  }
}
