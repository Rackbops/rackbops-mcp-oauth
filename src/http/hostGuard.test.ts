import { describe, expect, it } from "vitest"
import { createHostCheck, parsePublicHosts, resolveClientSource } from "./hostGuard.js"

describe("resolveClientSource", () => {
  it("uses the socket peer when no header is configured", () => {
    const headers = new Headers({ "x-forwarded-for": "9.9.9.9" })
    expect(resolveClientSource(headers, undefined, "10.0.0.1")).toBe("10.0.0.1")
  })

  it("takes the LAST value of the header, not the one the client chose", () => {
    const headers = new Headers({ "x-forwarded-for": "6.6.6.6, 7.7.7.7 , 203.0.113.9" })
    expect(resolveClientSource(headers, "x-forwarded-for", "10.0.0.1")).toBe("203.0.113.9")
  })

  it("falls back to the peer when the header is missing or blank", () => {
    expect(resolveClientSource(new Headers(), "x-forwarded-for", "10.0.0.1")).toBe("10.0.0.1")
    const blank = new Headers({ "x-forwarded-for": "1.2.3.4, " })
    expect(resolveClientSource(blank, "x-forwarded-for", "10.0.0.1")).toBe("10.0.0.1")
  })
})

describe("parsePublicHosts", () => {
  it("normalizes bare hostnames and ignores blanks", () => {
    expect(parsePublicHosts(" Meals.Example.com, ,b.example.com ")).toEqual([
      "meals.example.com",
      "b.example.com",
    ])
    expect(parsePublicHosts(undefined)).toEqual([])
    expect(parsePublicHosts("[::1]")).toEqual(["[::1]"])
  })

  it("throws on a scheme, a port, a path or a wildcard", () => {
    for (const bad of ["https://x", "x:443", "x/y", "*.x.com", "u@x", "a b", "x?y", "x#y", "[x"])
      expect(() => parsePublicHosts(bad), bad).toThrow(/bare hostname/)
  })
})

describe("createHostCheck", () => {
  const check = createHostCheck(["app.example.test"])
  const h = (init: Record<string, string>) => new Headers(init)

  it("admits a listed host and localhost, with or without an Origin", () => {
    expect(check(h({ host: "app.example.test" }))).toBeUndefined()
    expect(check(h({ host: "localhost:8080" }))).toBeUndefined()
    expect(
      check(h({ host: "app.example.test", origin: "https://app.example.test" })),
    ).toBeUndefined()
  })

  it("answers 400 for a missing or unusable Host", () => {
    expect(check(h({}))).toEqual({ status: 400, error: "bad host header" })
    expect(check(h({ host: "user@app.example.test" }))).toEqual({
      status: 400,
      error: "bad host header",
    })
  })

  it("answers 403 for an unlisted host or a foreign Origin", () => {
    expect(check(h({ host: "evil.example.test" }))).toEqual({
      status: 403,
      error: "host not allowed",
    })
    expect(check(h({ host: "app.example.test", origin: "https://evil.example.test" }))).toEqual({
      status: 403,
      error: "origin not allowed",
    })
  })
})
