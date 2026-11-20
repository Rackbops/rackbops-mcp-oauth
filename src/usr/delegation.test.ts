import { describe, expect, it } from "vitest"
import { createDelegation } from "./delegation.js"
import { NotLinked, NotMember, UsrRateLimited, UsrUnavailable } from "./errors.js"

type Call = { url: string; key: string | null; body: unknown; redirect?: RequestRedirect }

function usr(answer: () => Response | Promise<Response>) {
  const calls: Call[] = []
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      key: new Headers(init?.headers).get("x-api-key"),
      body: JSON.parse(String(init?.body)),
      ...(init?.redirect === undefined ? {} : { redirect: init.redirect }),
    })
    return answer()
  }) as typeof fetch
  return { calls, f }
}

const minted = (token = "dlg-1", expiresIn = 300) =>
  Response.json({ access_token: token, token_type: "Bearer", expires_in: expiresIn })

describe("usr delegation tokens", () => {
  it("asks usr for one operation at the audience as the person, with the service key", async () => {
    const u = usr(() => minted())
    const token = createDelegation({
      audience: "tracker",
      usrUrl: "https://id.example.test/",
      apiKey: "k",
      fetch: u.f,
    })
    expect(await token("usr-1", "list_tasks")).toBe("dlg-1")
    expect(u.calls).toEqual([
      {
        url: "https://id.example.test/api/token/exchange",
        key: "k",
        body: { subject: "usr-1", audience: "tracker", tools: ["tracker:list_tasks"] },
        redirect: "error",
      },
    ])
  })

  it("reuses a token until a minute before it expires, per person and operation", async () => {
    const now = { t: 1_000_000 }
    let n = 0
    const u = usr(() => minted(`dlg-${++n}`, 300))
    const token = createDelegation({
      audience: "tracker",
      usrUrl: "https://u",
      apiKey: "k",
      fetch: u.f,
      now: () => now.t,
    })
    expect(await token("a", "list_tasks")).toBe("dlg-1")
    expect(await token("a", "list_tasks")).toBe("dlg-1")
    expect(await token("a", "get_task")).toBe("dlg-2")
    expect(await token("b", "list_tasks")).toBe("dlg-3")
    now.t += 239_000
    expect(await token("a", "list_tasks")).toBe("dlg-1")
    now.t += 2_000
    expect(await token("a", "list_tasks")).toBe("dlg-4")
  })

  it("is NotLinked on 403 and UsrUnavailable on anything else that is not a token", async () => {
    const at = (r: () => Response | Promise<Response>) =>
      createDelegation({
        audience: "tracker",
        usrUrl: "https://u",
        apiKey: "k",
        fetch: usr(r).f,
      })("a", "list_tasks")
    await expect(at(() => Response.json({ error: "no link" }, { status: 403 }))).rejects.toThrow(
      NotLinked,
    )
    await expect(at(() => Response.json({}, { status: 429 }))).rejects.toThrow(UsrRateLimited)
    await expect(at(() => Response.json({}, { status: 500 }))).rejects.toThrow(UsrUnavailable)
    await expect(at(() => Response.json({ access_token: 5 }))).rejects.toThrow(UsrUnavailable)
    await expect(at(() => new Response("not json"))).rejects.toThrow(UsrUnavailable)
    await expect(
      at(() => {
        throw new TypeError("fetch failed")
      }),
    ).rejects.toThrow(UsrUnavailable)
  })

  it("forgets a token the service refused", async () => {
    let n = 0
    const u = usr(() => minted(`dlg-${++n}`))
    const token = createDelegation({
      audience: "tracker",
      usrUrl: "https://u",
      apiKey: "k",
      fetch: u.f,
    })
    expect(await token("a", "list_tasks")).toBe("dlg-1")
    token.forget?.("a", "list_tasks")
    expect(await token("a", "list_tasks")).toBe("dlg-2")
  })

  it("never caches a refusal", async () => {
    let refuse = true
    const u = usr(() => (refuse ? Response.json({}, { status: 403 }) : minted()))
    const token = createDelegation({
      audience: "tracker",
      usrUrl: "https://u",
      apiKey: "k",
      fetch: u.f,
    })
    await expect(token("a", "list_tasks")).rejects.toThrow(NotLinked)
    refuse = false
    expect(await token("a", "list_tasks")).toBe("dlg-1")
  })
})

describe("the member role, re-checked before each token", () => {
  it("refuses a person without the role, treats a failed lookup as usr down, and skips it for a cached token", async () => {
    const u = usr(() => minted())
    let member: boolean | Error = true
    const checked: string[] = []
    const token = createDelegation({
      audience: "tracker",
      usrUrl: "https://u",
      apiKey: "k",
      fetch: u.f,
      memberCheck: async (sub) => {
        checked.push(sub)
        if (member instanceof Error) throw member
        return member
      },
    })
    expect(await token("a", "list_tasks")).toBe("dlg-1")
    expect(await token("a", "list_tasks")).toBe("dlg-1")
    expect(checked).toEqual(["a"])
    member = false
    await expect(token("a", "get_task")).rejects.toBeInstanceOf(NotMember)
    member = new Error("timeout")
    await expect(token("a", "get_task")).rejects.toBeInstanceOf(UsrUnavailable)
    // Neither refusal reached the token exchange.
    expect(u.calls).toHaveLength(1)
  })
})

it("passes usr's role-lookup limit on as a rate limit, not an outage", async () => {
  const u = usr(() => minted())
  const token = createDelegation({
    audience: "tracker",
    usrUrl: "https://u",
    apiKey: "k",
    fetch: u.f,
    memberCheck: async () => {
      throw new UsrRateLimited("slow")
    },
  })
  await expect(token("a", "list_tasks")).rejects.toBeInstanceOf(UsrRateLimited)
})
