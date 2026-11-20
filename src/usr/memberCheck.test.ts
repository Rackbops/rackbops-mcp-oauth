import { describe, expect, it } from "vitest"
import { UsrRateLimited } from "./errors.js"
import { createUsrMemberCheck } from "./memberCheck.js"

const answer = (status: number, body: unknown): typeof fetch =>
  (async () => new Response(JSON.stringify(body), { status })) as typeof fetch

const check = (f: typeof fetch) =>
  createUsrMemberCheck({
    usrUrl: "https://id.example.test/",
    apiKey: "k",
    app: "meals",
    role: "member",
    fetch: f,
  })

describe("usr member check", () => {
  it("asks usr for this person's app roles with the service key, never following a redirect", async () => {
    let seen: { url: string; key: string | null; redirect?: RequestRedirect } | undefined
    const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen = {
        url: String(input),
        key: new Headers(init?.headers).get("x-api-key"),
        ...(init?.redirect === undefined ? {} : { redirect: init.redirect }),
      }
      return Response.json({ exists: true, roles: ["meals:member"] })
    }) as typeof fetch
    expect(await check(f)("user 1")).toBe(true)
    expect(seen).toEqual({
      url: "https://id.example.test/api/roles/lookup?sub=user+1&app=meals",
      key: "k",
      redirect: "error",
    })
  })

  it("is false for a person who lost the role or no longer exists", async () => {
    expect(await check(answer(200, { exists: true, roles: ["meals:guest"] }))("u")).toBe(false)
    expect(await check(answer(200, { exists: true, roles: [] }))("u")).toBe(false)
    expect(await check(answer(200, { exists: false, sub: null, roles: [] }))("u")).toBe(false)
  })

  it("does not take another app's role of the same name", async () => {
    expect(await check(answer(200, { exists: true, roles: ["nazu:member"] }))("u")).toBe(false)
  })

  it("throws, rather than answering false, when usr cannot answer", async () => {
    await expect(check(answer(401, { error: "unauthorized" }))("u")).rejects.toThrow("401")
    await expect(check(answer(500, {}))("u")).rejects.toThrow("500")
    await expect(check(answer(200, { roles: "meals:member" }))("u")).rejects.toThrow("unexpected")
    const down = (async () => {
      throw new Error("ECONNREFUSED")
    }) as typeof fetch
    await expect(check(down)("u")).rejects.toThrow("ECONNREFUSED")
  })

  it("names usr's rate limit apart from an outage", async () => {
    await expect(check(answer(429, {}))("u")).rejects.toBeInstanceOf(UsrRateLimited)
  })
})
