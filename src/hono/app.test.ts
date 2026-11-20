import type { DatabaseSync } from "node:sqlite"
import { Hono } from "hono"
import { afterEach, describe, expect, it } from "vitest"
import { type OAuthApp, oauthConfig } from "../config.js"
import { buildToolServerFactory, type Caller } from "../server/dispatch.js"
import { buildRegistry, loadContractTools, ToolError, withContent } from "../server/registry.js"
import { type OAuthStore, sha256Hex } from "../store.js"
import {
  connect,
  fakeIdentity,
  mcpClient,
  memoryStore,
  type Requester,
  requester,
} from "../testing/index.js"
import { hostGuard } from "./hostGuard.js"
import { mountMcp, mountOAuth } from "./mount.js"
import { requestTrace } from "./trace.js"

// The whole shared surface wired the way Meals for Two and tracker-mcp wire it: Host guard, request
// trace, the OAuth routes, and the bearer-gated /mcp serving a two-tool contract, driven by the
// package's own test client and a real MCP SDK client, in-process.

const ISSUER = "https://app.example.test"
const HOST = "app.example.test"
const CALLBACK = "https://chatgpt.com/connector_platform_oauth_redirect"

const APP: OAuthApp = {
  name: "Test App",
  logPrefix: "test-app",
  idPrefix: "tst",
  memberRole: "member",
  consentSummary: "read your things",
  notMemberMessage: "Not a member.",
  signInFailedMessage: "Sign in first.",
  scopes: [{ name: "app.write", disclosureHtml: "<p>write</p>" }],
}

class Upstream extends Error {}

interface Ctx {
  caller: Caller
}

const contract = loadContractTools(new URL("../../test/fixtures/tools.json", import.meta.url))
const registry = buildRegistry<Ctx>(contract, {
  echo: async (args, ctx) => ({
    summary: `You said ${String(args.text)}.`,
    who: ctx.caller.sub,
    client: ctx.caller.client,
  }),
  fail: async (args) => {
    switch (args.how) {
      case "tool":
        throw new ToolError("NOT_FOUND", "No such thing.")
      case "duplicate":
        throw new ToolError("DUPLICATE", "Already done.", { summary: "Done before." })
      case "upstream":
        throw new Upstream("http://10.0.0.5/secret-path refused")
      case "bad_output":
        return { summary: "x", extra: true }
      case "picture":
        return withContent({ summary: "A picture." }, [
          { type: "image", data: "AAAA", mimeType: "image/png" },
        ])
      default:
        throw new Error("/srv/app/db.sqlite is locked")
    }
  },
})

function build(options: { perMinute?: number; after?: () => void } = {}) {
  const now = { t: Date.now() }
  const logs: Record<string, unknown>[] = []
  const identity = fakeIdentity({ sub: "usr-anne", name: "Anne", roles: ["member"] })
  const store: OAuthStore = memoryStore(() => now.t)
  const oauth = oauthConfig(ISSUER, APP)
  const app = new Hono()
  app.use(
    "*",
    requestTrace(
      { info: (_message, fields) => logs.push(fields) },
      {
        knownTools: new Set(contract.map((t) => t.name)),
        skipPaths: new Set(["/healthz"]),
        redactPath: (path) => (path.startsWith("/signed/") ? "/signed/*" : path),
      },
    ),
  )
  app.use("*", hostGuard([HOST]))
  app.get("/healthz", (c) => c.json({ ok: true }))
  app.get("/signed/:token", (c) => c.json({ ok: true }))
  mountOAuth(app, { oauth, store, identity, source: () => "203.0.113.9", clock: () => now.t })
  const close = mountMcp(app, {
    oauth,
    store,
    factory: buildToolServerFactory<Ctx>({
      name: "test-app",
      title: "Test App (dev)",
      instructions: "Test instructions.",
      registry,
      context: (caller) => ({ caller }),
      environment: "dev",
      mapError: (err) =>
        err instanceof Upstream ? { code: "UNAVAILABLE", message: "Try again." } : undefined,
      maxErrorMessage: 40,
    }),
    bodyCap: 64 * 1024,
    perMinute: options.perMinute ?? 60,
    clock: () => now.t,
    ...(options.after === undefined ? {} : { after: options.after }),
  })
  const req: Requester = requester((r) => app.fetch(r), ISSUER)
  return { app, req, store, logs, now, identity, close }
}

type Built = ReturnType<typeof build>
let open: Built | undefined
afterEach(async () => {
  await open?.close()
  open = undefined
})

const client = (b: Built, access: string) =>
  mcpClient((r) => b.app.fetch(r), ISSUER, access, "ChatGPT")

const errorBody = (result: { content?: unknown }) =>
  JSON.parse((result.content as { text: string }[])[0]?.text ?? "{}") as Record<string, unknown>

const rpc = (b: Built, access: string, body: unknown) =>
  b.req("/mcp", {
    method: "POST",
    headers: {
      authorization: `Bearer ${access}`,
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify(body),
  })

describe("the OAuth routes", () => {
  it("serves the discovery documents with the app's scopes", async () => {
    open = build()
    const resource = await open.req("/.well-known/oauth-protected-resource/mcp")
    expect(resource.headers.get("cache-control")).toBe("public, max-age=300")
    expect(await resource.json()).toMatchObject({
      resource: `${ISSUER}/mcp`,
      scopes_supported: ["app.write"],
    })
    expect(await (await open.req("/.well-known/oauth-protected-resource")).json()).toMatchObject({
      resource: `${ISSUER}/mcp`,
    })
    expect(await (await open.req("/.well-known/oauth-authorization-server")).json()).toMatchObject({
      issuer: ISSUER,
      registration_endpoint: `${ISSUER}/register`,
    })
  })

  it("caps the body of /register at 16 KiB", async () => {
    open = build()
    const res = await open.req("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: [CALLBACK], client_name: "x".repeat(17 * 1024) }),
    })
    expect(res.status).toBe(413)
  })

  it("runs register, consent and token to a working access token", async () => {
    open = build()
    const tokens = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    expect(tokens.access.startsWith("tst_at_")).toBe(true)
    expect(open.store.getAccessToken(sha256Hex(tokens.access))?.memberSub).toBe("usr-anne")
  })
})

describe("the /mcp gate", () => {
  it("answers 401 with the resource metadata URL to a call with no token", async () => {
    open = build()
    const res = await rpc(open, "nope", { jsonrpc: "2.0", id: 1, method: "tools/list" })
    expect(res.status).toBe(401)
    expect(res.headers.get("www-authenticate")).toContain(
      `${ISSUER}/.well-known/oauth-protected-resource/mcp`,
    )
  })

  it("refuses an expired token, a revoked grant and a token for another resource", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const row = open.store.getAccessToken(sha256Hex(access))
    if (row === undefined) throw new Error("no token row")
    const list = { jsonrpc: "2.0", id: 1, method: "tools/list" }

    const db = (open.store as unknown as { db: DatabaseSync }).db
    db.prepare("UPDATE oauth_access_tokens SET resource = ? WHERE token_hash = ?").run(
      "https://other.example.test/mcp",
      sha256Hex(access),
    )
    expect((await rpc(open, access, list)).status).toBe(401)
    db.prepare("UPDATE oauth_access_tokens SET resource = ? WHERE token_hash = ?").run(
      `${ISSUER}/mcp`,
      sha256Hex(access),
    )

    db.prepare("UPDATE oauth_grants SET revoked_at = 1 WHERE grant_id = ?").run(row.grantId)
    expect((await rpc(open, access, list)).status).toBe(401)
    db.prepare("UPDATE oauth_grants SET revoked_at = NULL WHERE grant_id = ?").run(row.grantId)

    open.now.t = row.expiresAt
    expect((await rpc(open, access, list)).status).toBe(401)
  })

  it("rate-limits per person with Retry-After, and runs `after` on each authenticated call", async () => {
    let after = 0
    open = build({
      perMinute: 2,
      after: () => {
        after++
      },
    })
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const list = { jsonrpc: "2.0", id: 1, method: "tools/list" }
    expect((await rpc(open, access, list)).status).toBe(200)
    expect((await rpc(open, access, list)).status).toBe(200)
    const third = await rpc(open, access, list)
    expect(third.status).toBe(429)
    expect(Number(third.headers.get("retry-after"))).toBeGreaterThan(0)
    expect(after).toBe(2)
  })

  it("answers a GET with 405 and an Allow header", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const res = await open.req("/mcp", {
      headers: { authorization: `Bearer ${access}`, accept: "text/event-stream" },
    })
    expect(res.status).toBe(405)
    expect(res.headers.get("allow")).toContain("POST")
  })
})

describe("the tool dispatch", () => {
  it("lists only the tools with a handler, and calls one as the signed-in person", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const c = await client(open, access)
    expect((await c.listTools()).tools.map((t) => t.name)).toEqual(["echo", "fail"])
    const result = await c.callTool({ name: "echo", arguments: { text: "hi" } })
    expect(result.structuredContent).toEqual({
      summary: "You said hi.",
      who: "usr-anne",
      client: "Claude",
      environment: "dev",
    })
    expect(result.content).toEqual([{ type: "text", text: "You said hi." }])
    await c.close()
  })

  it("turns every failure into a {code, message} tool result, never a protocol error", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const c = await client(open, access)
    const call = (how: string) => c.callTool({ name: "fail", arguments: { how } })

    expect(errorBody(await c.callTool({ name: "echo", arguments: { text: 5 } }))).toMatchObject({
      code: "INVALID_INPUT",
      message: "/text must be string",
    })
    expect(errorBody(await c.callTool({ name: "unhandled", arguments: {} }))).toEqual({
      code: "INVALID_INPUT",
      message: "Unknown tool: unhandled",
    })
    expect(errorBody(await call("tool"))).toEqual({ code: "NOT_FOUND", message: "No such thing." })
    expect(errorBody(await call("duplicate"))).toEqual({
      code: "DUPLICATE",
      message: "Already done.",
      result: { summary: "Done before.", environment: "dev" },
    })
    expect(errorBody(await call("upstream"))).toEqual({
      code: "UNAVAILABLE",
      message: "Try again.",
    })
    const bug = await call("bug")
    expect(bug.isError).toBe(true)
    expect(errorBody(bug)).toEqual({ code: "INTERNAL", message: "Internal error." })
    expect(JSON.stringify(bug)).not.toContain("sqlite")
    expect(errorBody(await call("bad_output"))).toEqual({
      code: "INTERNAL",
      message: "Internal error.",
    })
    await c.close()
  })

  it("cuts a long error message at maxErrorMessage", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const c = await client(open, access)
    const message = errorBody(
      await c.callTool({ name: "echo", arguments: { text: "x".repeat(30) } }),
    ).message as string
    expect(message.length).toBe(40)
    await c.close()
  })

  it("sends a handler's picture after the summary text", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    const c = await client(open, access)
    const result = await c.callTool({ name: "fail", arguments: { how: "picture" } })
    expect(result.content).toEqual([
      { type: "text", text: "A picture." },
      { type: "image", data: "AAAA", mimeType: "image/png" },
    ])
    expect(result.structuredContent).toEqual({ summary: "A picture.", environment: "dev" })
    await c.close()
  })
})

describe("the request trace", () => {
  it("logs one line per /mcp call with the method and tool, never a token or argument", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    open.logs.length = 0
    const res = await rpc(open, access, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "echo", arguments: { text: "secret-arg" } },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get("x-request-id")).toMatch(/^[0-9a-f]{12}$/)
    expect(open.logs).toHaveLength(1)
    expect(open.logs[0]).toMatchObject({
      method: "POST",
      path: "/mcp",
      status: 200,
      rpc: "tools/call",
      tool: "echo",
    })
    const line = JSON.stringify(open.logs)
    expect(line).not.toContain(access)
    expect(line).not.toContain("secret-arg")
  })

  it("counts the tools on tools/list, skips /healthz and masks a redacted path", async () => {
    open = build()
    const { access } = await connect(open.req, { issuer: ISSUER, redirect: CALLBACK })
    open.logs.length = 0
    await rpc(open, access, { jsonrpc: "2.0", id: 1, method: "tools/list" })
    await open.req("/healthz")
    await open.req("/signed/credential-in-path")
    expect(open.logs.map((l) => [l.path, l.tools])).toEqual([
      ["/mcp", 2],
      ["/signed/*", undefined],
    ])
    expect(JSON.stringify(open.logs)).not.toContain("credential-in-path")
  })

  it("logs the Host guard's refusals too", async () => {
    open = build()
    const res = await open.req("/healthz", { headers: { host: "evil.example.test" } })
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: "host not allowed" })
    const foreign = await open.req("/register", {
      method: "POST",
      headers: { origin: "https://evil.example.test", "content-type": "application/json" },
      body: "{}",
    })
    expect(foreign.status).toBe(403)
    expect(open.logs.map((l) => l.status)).toEqual([403])
  })
})
