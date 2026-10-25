import { describe, expect, it } from "vitest"
import {
  authorize,
  CALLBACK,
  connect,
  harness,
  ISSUER,
  MEMBER,
  pkce,
  register,
  tokens,
} from "../test/harness.js"
import {
  DEFAULT_REDIRECT_POLICY,
  redirectMatchesRegistered,
  validateRedirectUri,
} from "./redirect.js"
import { parseRegistrationRequest } from "./registration.js"

describe("redirect policy", () => {
  const ok = (u: string) => validateRedirectUri(u, DEFAULT_REDIRECT_POLICY)
  it("accepts the hosted-client callbacks and loopback", () => {
    expect(ok("https://claude.ai/api/mcp/auth_callback")).toBe(true)
    expect(ok("https://chatgpt.com/connector_platform_oauth_redirect")).toBe(true)
    expect(ok("https://chatgpt.com/connector/oauth/abc_123-X")).toBe(true)
    expect(ok("http://127.0.0.1:5555/cb?x=1")).toBe(true)
  })
  it("refuses lookalikes, extra segments, queries, fragments, userinfo and non-loopback http", () => {
    expect(ok("https://claude.ai/api/mcp/auth_callback/")).toBe(false)
    expect(ok("https://chatgpt.com/connector/oauth/a/b")).toBe(false)
    expect(ok("https://chatgpt.com/connector/oauth/a?x=1")).toBe(false)
    expect(ok("https://chatgpt.com/connector/oauth/")).toBe(false)
    expect(ok("https://claude.ai/api/mcp/auth_callback#")).toBe(false)
    expect(ok("https://u:p@claude.ai/api/mcp/auth_callback")).toBe(false)
    expect(ok("https://evil.example/cb")).toBe(false)
    expect(ok("http://claude.ai/api/mcp/auth_callback")).toBe(false)
    expect(ok("http://localhost.evil.com/cb")).toBe(false)
  })
  it("matches a registered loopback on any port, others exactly", () => {
    expect(redirectMatchesRegistered("http://127.0.0.1:9/cb", ["http://127.0.0.1:1/cb"])).toBe(true)
    expect(redirectMatchesRegistered("http://127.0.0.1:9/other", ["http://127.0.0.1:1/cb"])).toBe(
      false,
    )
    expect(redirectMatchesRegistered(CALLBACK, [CALLBACK])).toBe(true)
    expect(
      redirectMatchesRegistered("https://claude.ai:444/api/mcp/auth_callback", [CALLBACK]),
    ).toBe(false)
  })
})

describe("client registration", () => {
  const parse = (b: unknown) => parseRegistrationRequest(b, DEFAULT_REDIRECT_POLICY)
  it("refuses control, format and blank client names", () => {
    for (const name of ["a‮b", "a\u0007b", "​", "ㅤㅤ", "a".repeat(101)]) {
      expect(parse({ redirect_uris: [CALLBACK], client_name: name }).ok).toBe(false)
    }
    expect(parse({ redirect_uris: [CALLBACK], client_name: "ChatGPT" }).ok).toBe(true)
  })
  it("refuses a bad redirect and unsupported grant types", () => {
    expect(parse({ redirect_uris: ["https://evil.example/cb"] })).toMatchObject({
      error: "invalid_redirect_uri",
    })
    expect(parse({ redirect_uris: [CALLBACK], grant_types: ["password"] }).ok).toBe(false)
  })
  it("rate limits /register per source", async () => {
    const h = harness()
    let last = 0
    for (let i = 0; i < 61; i++)
      last = (
        await h.req("/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        })
      ).status
    expect(last).toBe(503)
  })
  it("never issues a secret and always says auth method none", async () => {
    const h = harness()
    const res = await h.req("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [CALLBACK],
        token_endpoint_auth_method: "client_secret_basic",
      }),
    })
    const body = (await res.json()) as Record<string, unknown>
    expect(body.token_endpoint_auth_method).toBe("none")
    expect(body.client_secret).toBeUndefined()
  })
})

describe("authorize + token", () => {
  it("runs the whole flow and the access token works exactly once per code", async () => {
    const h = harness()
    const { clientId } = await connect(h)
    expect(clientId).toMatch(/^mft_c_/)
  })

  it("redirects to usr sign-in with no cookie, and errors instead of looping", async () => {
    const h = harness()
    const clientId = await register(h)
    const { challenge } = pkce()
    h.setIdentity(null)
    const q = new URLSearchParams({
      client_id: clientId,
      redirect_uri: CALLBACK,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
    })
    const res = await h.req(`/authorize?${q}`)
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get("location") ?? "")
    expect(loc.origin).toBe("https://id.example.test")
    const back = new URL(loc.searchParams.get("return") ?? "")
    expect(back.origin).toBe(ISSUER)
    expect(back.searchParams.get("_sso")).toBe("1")
    const again = await h.req(`${back.pathname}${back.search}`)
    expect(again.status).toBe(401)
  })

  it("refuses a signed-in user without meals:member", async () => {
    const h = harness()
    const clientId = await register(h)
    h.setIdentity({ ...MEMBER, roles: [] })
    const res = await authorize(h, clientId, pkce().challenge)
    expect(res.status).toBe(403)
  })

  it("refuses a POST when the signed-in member changed, or the binding cookie is wrong", async () => {
    const h = harness()
    const clientId = await register(h)
    const { challenge } = pkce()
    const q = new URLSearchParams({
      client_id: clientId,
      redirect_uri: CALLBACK,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
    })
    const page = await h.req(`/authorize?${q}`)
    const html = await page.text()
    const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1] ?? ""
    const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? ""
    const post = (c: string) =>
      h.req("/authorize", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", cookie: c },
        body: `request_id=${requestId}&decision=allow`,
      })
    expect((await post("")).status).toBe(400)
    h.setIdentity({ ...MEMBER, sub: "someone-else" })
    expect((await post(cookie)).status).toBe(403)
    h.setIdentity(MEMBER)
    expect((await post(cookie)).status).toBe(302)
    expect((await post(cookie)).status).toBe(400) // request is single use
  })

  it("answers access_denied on Cancel", async () => {
    const h = harness()
    const res = await authorize(h, await register(h), pkce().challenge, {}, "deny")
    expect(new URL(res.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    )
  })

  it("sends unregistered redirects to a page, other errors to the redirect", async () => {
    const h = harness()
    const clientId = await register(h)
    const bad = await h.req(`/authorize?client_id=${clientId}&redirect_uri=https://evil.example/cb`)
    expect(bad.status).toBe(400)
    const plain = await authorize(h, clientId, pkce().challenge, { code_challenge_method: "plain" })
    expect(new URL(plain.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "invalid_request",
    )
    const wrongResource = await authorize(h, clientId, pkce().challenge, {
      resource: "https://other.example/mcp",
    })
    expect(new URL(wrongResource.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "invalid_target",
    )
  })

  async function codeFor(h: ReturnType<typeof harness>) {
    const clientId = await register(h)
    const { verifier, challenge } = pkce()
    const res = await authorize(h, clientId, challenge)
    const code = new URL(res.headers.get("location") ?? "").searchParams.get("code") ?? ""
    return { clientId, verifier, code }
  }
  const exchange = (
    h: ReturnType<typeof harness>,
    c: { clientId: string; verifier: string; code: string },
    over: Record<string, string> = {},
  ) =>
    tokens(h, {
      grant_type: "authorization_code",
      client_id: c.clientId,
      code: c.code,
      redirect_uri: CALLBACK,
      code_verifier: c.verifier,
      resource: `${ISSUER}/mcp`,
      ...over,
    })

  it("rejects a wrong PKCE verifier and consumes the code", async () => {
    const h = harness()
    const c = await codeFor(h)
    const bad = await exchange(h, c, { code_verifier: pkce().verifier })
    expect(((await bad.json()) as { error: string }).error).toBe("invalid_grant")
    expect((await exchange(h, c)).status).toBe(400)
  })

  it("binds the code to its resource", async () => {
    const h = harness()
    const c = await codeFor(h)
    const res = await exchange(h, c, { resource: "https://other.example/mcp" })
    expect(((await res.json()) as { error: string }).error).toBe("invalid_target")
  })

  it("revokes the grant when a code is replayed", async () => {
    const h = harness()
    const c = await codeFor(h)
    const first = (await (await exchange(h, c)).json()) as { access_token: string }
    expect((await exchange(h, c)).status).toBe(400)
    const mcp = await h.req("/mcp", {
      method: "POST",
      headers: {
        authorization: `Bearer ${first.access_token}`,
        "content-type": "application/json",
      },
      body: "{}",
    })
    expect(mcp.status).toBe(401)
  })

  it("expires codes", async () => {
    const h = harness()
    const c = await codeFor(h)
    h.now.t += 61_000
    expect((await exchange(h, c)).status).toBe(400)
  })

  it("rotates refresh tokens, allows a grace sibling, and revokes on reuse", async () => {
    const h = harness()
    const { clientId, refresh } = await connect(h)
    const refreshWith = (t: string) =>
      tokens(h, {
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: t,
        resource: `${ISSUER}/mcp`,
      })
    const a = await refreshWith(refresh)
    expect(a.status).toBe(200)
    const sibling = await refreshWith(refresh) // inside the grace window
    expect(sibling.status).toBe(200)
    h.now.t += 120_000
    expect((await refreshWith(refresh)).status).toBe(400) // reuse outside grace
    const child = ((await a.json()) as { refresh_token: string }).refresh_token
    expect((await refreshWith(child)).status).toBe(400) // grant revoked
  })

  it("refuses a refresh token from another client", async () => {
    const h = harness()
    const { refresh } = await connect(h)
    const other = await register(h)
    const res = await tokens(h, {
      grant_type: "refresh_token",
      client_id: other,
      refresh_token: refresh,
      resource: `${ISSUER}/mcp`,
    })
    expect(res.status).toBe(400)
  })

  it("refuses client_secret", async () => {
    const h = harness()
    const res = await tokens(h, {
      grant_type: "refresh_token",
      client_id: await register(h),
      client_secret: "x",
    })
    expect(((await res.json()) as { error: string }).error).toBe("invalid_client")
  })
})

describe("discovery", () => {
  it("serves both metadata documents without auth", async () => {
    const h = harness()
    const as = (await (await h.req("/.well-known/oauth-authorization-server")).json()) as Record<
      string,
      unknown
    >
    expect(as.code_challenge_methods_supported).toEqual(["S256"])
    expect(as.registration_endpoint).toBe(`${ISSUER}/register`)
    const pr = (await (await h.req("/.well-known/oauth-protected-resource/mcp")).json()) as Record<
      string,
      unknown
    >
    expect(pr.resource).toBe(`${ISSUER}/mcp`)
  })
  it("advertises the resource metadata on the 401", async () => {
    const h = harness()
    const res = await h.req("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    })
    expect(res.status).toBe(401)
    expect(res.headers.get("www-authenticate")).toContain(
      `${ISSUER}/.well-known/oauth-protected-resource/mcp`,
    )
  })
})

describe("abuse bounds", () => {
  const registerRaw = (h: ReturnType<typeof harness>) =>
    h.req("/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://localhost/cb"] }),
    })

  it("evicts old grantless clients instead of locking /register out", async () => {
    const h = harness()
    for (let i = 0; i < 30; i++) expect((await registerRaw(h)).status).toBe(201)
    expect((await registerRaw(h)).status).toBe(503) // all still inside the protect window
    h.now.t += 16 * 60 * 1000
    expect((await registerRaw(h)).status).toBe(201)
  })

  it("prunes day-old grantless clients but keeps ones that completed a grant", async () => {
    const h = harness()
    const { clientId } = await connect(h)
    const stale = ((await (await registerRaw(h)).json()) as { client_id: string }).client_id
    h.now.t += 25 * 60 * 60 * 1000
    h.store.prune(30 * 24 * 60 * 60 * 1000)
    expect(h.store.getClient(stale)).toBeUndefined()
    expect(h.store.getClient(clientId)).toBeDefined()
  })

  it("stops refreshing a grant past its absolute lifetime", async () => {
    const h = harness()
    const { clientId, refresh } = await connect(h)
    let token = refresh
    for (let day = 0; day < 9; day++) {
      h.now.t += 10 * 24 * 60 * 60 * 1000 // 90 days in 10-day steps, never idle
      const res = await tokens(h, {
        grant_type: "refresh_token",
        client_id: clientId,
        refresh_token: token,
        resource: `${ISSUER}/mcp`,
      })
      if (day < 8) token = ((await res.json()) as { refresh_token: string }).refresh_token
      else expect(res.status).toBe(200)
    }
    h.now.t += 24 * 60 * 60 * 1000
    const res = await tokens(h, {
      grant_type: "refresh_token",
      client_id: clientId,
      refresh_token: token,
      resource: `${ISSUER}/mcp`,
    })
    expect(((await res.json()) as { error: string }).error).toBe("invalid_grant")
  })
})

describe("consent form POST in a browser", () => {
  async function consent(h: ReturnType<typeof harness>) {
    const clientId = await register(h)
    const q = new URLSearchParams({
      client_id: clientId,
      redirect_uri: CALLBACK,
      response_type: "code",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256",
    })
    const page = await h.req(`/authorize?${q}`)
    const html = await page.text()
    return {
      page,
      requestId: /name="request_id" value="([^"]+)"/.exec(html)?.[1] ?? "",
      cookie: (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "",
    }
  }

  it("serves the page with a referrer policy under which the browser sends its real Origin", async () => {
    const { page } = await consent(harness())
    // A browser sends `Origin: null` on a form POST from a no-referrer page; same-origin sends the origin.
    expect(page.headers.get("referrer-policy")).toBe("same-origin")
  })

  it("still accepts the POST when the usr cookie was re-issued (same subject, new session)", async () => {
    const h = harness()
    const { requestId, cookie } = await consent(h)
    h.setIdentity({ ...MEMBER }) // a fresh identity object for the same sub, as after a cookie refresh
    const res = await h.req("/authorize", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie, origin: ISSUER },
      body: `request_id=${requestId}&decision=allow`,
    })
    expect(res.status).toBe(302)
  })
})
