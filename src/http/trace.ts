import { AsyncLocalStorage } from "node:async_hooks"

// The per-request trace record, shared by the Hono request-trace middleware (`../hono/trace.ts`), which
// writes the line, and the tool dispatcher (`../server/dispatch.ts`), which adds the tool count to it.
// Framework-free so a `node:http` server can keep one too.

export interface RequestTrace {
  correlationId: string
  rpcMethod?: string
  tool?: string
  toolCount?: number
}

const storage = new AsyncLocalStorage<RequestTrace>()

/** The trace of the request being served, so a handler can add facts (the tool count) to its line. */
export function currentTrace(): RequestTrace | undefined {
  return storage.getStore()
}

/** Runs `fn` with `trace` as the current trace. */
export function runWithTrace<T>(trace: RequestTrace, fn: () => T): T {
  return storage.run(trace, fn)
}
