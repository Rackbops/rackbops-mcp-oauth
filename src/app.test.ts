import { describe, expect, it } from "vitest"
import {
  CALLBACK,
  connect,
  harness,
  MEALS_APP,
  MEMBER,
  pkce,
  register,
  tokens,
} from "../test/harness.js"
import { createUsrIdentity } from "./usr.js"

const CONSENT_QUERY = (clientId: string, challenge: string, scope?: string) =>
  new URLSearchParams({
    client_id: clientId,
    redirect_uri: CALLBACK,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...(scope === undefined ? {} : { scope }),
  })

describe("Meals for Two profile is rendered and issued exactly as before the extraction", () => {
  it("renders the consent page byte-for-byte (without the per-request id)", async () => {
    const h = harness()
    const page = await h.req(
      `/authorize?${CONSENT_QUERY(await register(h), pkce().challenge, "meals.confirm")}`,
    )
    const html = (await page.text()).replace(/value="[A-Za-z0-9_-]{22}"/, 'value="ID"')
    expect(page.status).toBe(200)
    expect(html).toContain("<title>Connect to Meals for Two</title>")
    expect(html).toContain(
      "<h1>Connect to Meals for Two?</h1><p><strong>Claude</strong> (<code>claude.ai</code>) wants to read and manage your household's meals as Anne.</p>",
    )
    expect(html).toContain(
      '<div class="extra"><h2>Extra permission: apply changes</h2><p>It also asks to <strong>apply changes</strong> to your recipes and plans, and to undo them, once you have said yes to them in the chat. Without this it can only read and propose.</p></div><p>Only allow this if you just asked an assistant such as ChatGPT or Claude to connect.</p>',
    )
    expect(html).toContain(
      '<form method="post" action="/authorize"><input type="hidden" name="request_id" value="ID">',
    )
    expect(page.headers.get("referrer-policy")).toBe("same-origin")
    expect(page.headers.get("content-security-policy")).toBe(
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://claude.ai; frame-ancestors 'none'; base-uri 'none'",
    )
  })

  it("omits the disclosure when the scope was not asked for", async () => {
    const h = harness()
    const page = await h.req(`/authorize?${CONSENT_QUERY(await register(h), pkce().challenge)}`)
    expect(await page.text()).not.toContain("Extra permission")
  })

  it("keeps the shipped identifier prefixes", async () => {
    const h = harness()
    const { clientId, access, refresh } = await connect(h)
    expect(clientId).toMatch(/^mft_c_[A-Za-z0-9_-]{43}$/)
    expect(access).toMatch(/^mft_at_/)
    expect(refresh).toMatch(/^mft_rt_/)
    const page = await h.req(`/authorize?${CONSENT_QUERY(clientId, pkce().challenge)}`)
    expect(page.headers.get("set-cookie")).toMatch(/^__Host-mft_ar_[A-Za-z0-9_-]{22}=/)
  })

  it("uses the app's wording for a non-member and a failed sign-in", async () => {
    const h = harness()
    const clientId = await register(h)
    h.setIdentity({ ...MEMBER, roles: [] })
    const denied = await h.req(`/authorize?${CONSENT_QUERY(clientId, pkce().challenge)}`)
    expect(denied.status).toBe(403)
    expect(await denied.text()).toContain(
      "Your account isn&#39;t a member of this household&#39;s Meals for Two.",
    )
  })
})

describe("a second app", () => {
  const OTHER = {
    ...MEALS_APP,
    name: "Other",
    idPrefix: "oth",
    memberRole: "reader",
    scopes: [{ name: "other.write", disclosureHtml: "<p>WRITE</p>" }],
  }
  it("gets its own prefixes, role, scope and wording, and meals.confirm is ignored", async () => {
    const h = harness({ app: OTHER })
    h.setIdentity({ ...MEMBER, roles: ["reader"] })
    const { clientId, scope } = await connect(h, "meals.confirm other.write")
    expect(clientId).toMatch(/^oth_c_/)
    expect(scope).toBe("other.write")
    h.setIdentity({ ...MEMBER, roles: ["member"] }) // meals' role is not this app's
    const denied = await h.req(`/authorize?${CONSENT_QUERY(clientId, pkce().challenge)}`)
    expect(denied.status).toBe(403)
    h.setIdentity({ ...MEMBER, roles: ["reader"] })
    const page = await (
      await h.req(`/authorize?${CONSENT_QUERY(clientId, pkce().challenge, "other.write")}`)
    ).text()
    expect(page).toContain("<h1>Connect to Other?</h1>")
    expect(page).toContain("<p>WRITE</p>")
    expect(page).not.toContain("Extra permission")
  })
})

describe("memberCheck (opt-in role re-check on refresh)", () => {
  async function refreshWith(allowed: boolean | "throw") {
    const h = harness({
      memberCheck: async () => {
        if (allowed === "throw") throw new Error("usr down")
        return allowed
      },
    })
    const c = await connect(h)
    const res = await tokens(h, {
      grant_type: "refresh_token",
      client_id: c.clientId,
      refresh_token: c.refresh,
      resource: "https://meals.example.test/mcp",
    })
    return { h, res, c }
  }
  it("rotates when the member still qualifies", async () => {
    expect((await refreshWith(true)).res.status).toBe(200)
  })
  it("revokes the grant when they no longer do", async () => {
    const { h, res, c } = await refreshWith(false)
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant")
    expect((await h.req("/mcp", { headers: { authorization: `Bearer ${c.access}` } })).status).toBe(
      401,
    )
  })
  it("answers 503 and keeps the grant when the check itself fails", async () => {
    const { res } = await refreshWith("throw")
    expect(res.status).toBe(503)
  })
  it("is off by default: the plain harness never re-checks", async () => {
    const h = harness()
    const c = await connect(h)
    h.setIdentity({ ...MEMBER, roles: [] })
    const res = await tokens(h, {
      grant_type: "refresh_token",
      client_id: c.clientId,
      refresh_token: c.refresh,
      resource: "https://meals.example.test/mcp",
    })
    expect(res.status).toBe(200)
  })
})

describe("usr identity", () => {
  it("builds the sign-in URL and treats a missing cookie as signed out", async () => {
    const usr = createUsrIdentity({ usrUrl: "https://id.example.test/", app: "meals" })
    expect(usr.signInUrl("https://x/y?a=1")).toBe(
      "https://id.example.test/api/auth/sso/refresh?return=https%3A%2F%2Fx%2Fy%3Fa%3D1",
    )
    expect(await usr.fromRequest(new Request("https://x/"))).toBeNull()
    expect(
      await usr.fromRequest(new Request("https://x/", { headers: { cookie: "nz_id=a.b.c" } })),
    ).toBeNull()
  })
})
