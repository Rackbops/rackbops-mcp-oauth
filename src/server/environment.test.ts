import { describe, expect, it } from "vitest"
import { createEnvironment } from "./environment.js"

const env = createEnvironment({
  envVar: "APP_ENV_LABEL",
  knownHosts: { "app.example.com": "prod", "app-dev.example.com": "dev" },
  name: "The App",
})

describe("resolveEnvLabel", () => {
  it("derives the label from the issuer host, exactly", () => {
    expect(env.resolveEnvLabel(undefined, "https://app-dev.example.com")).toBe("dev")
    expect(env.resolveEnvLabel(undefined, "https://APP.example.com")).toBe("prod")
    expect(env.resolveEnvLabel(undefined, "https://app.example.com.evil.test")).toBe("local")
    expect(env.resolveEnvLabel("", "http://localhost:8790")).toBe("local")
    expect(env.resolveEnvLabel(undefined, "not a url")).toBe("local")
  })

  it("never takes an inherited property name for a known host", () => {
    expect(env.resolveEnvLabel(undefined, "http://constructor")).toBe("local")
  })

  it("prefers an explicit label, lowercased", () => {
    expect(env.resolveEnvLabel(" Staging ", "https://app.example.com")).toBe("staging")
  })

  it("refuses a label that is not a short slug, naming the env var", () => {
    expect(() => env.resolveEnvLabel("dev env", "https://app.example.com")).toThrow(/APP_ENV_LABEL/)
    expect(() => env.resolveEnvLabel("x".repeat(17), "https://app.example.com")).toThrow(
      /APP_ENV_LABEL/,
    )
  })
})

describe("display name", () => {
  it("leaves prod unlabelled and marks everything else", () => {
    expect(env.isProd("prod")).toBe(true)
    expect(env.isProd("dev")).toBe(false)
    expect(env.displayName("prod")).toBe("The App")
    expect(env.displayName("dev")).toBe("The App (dev)")
  })
})
