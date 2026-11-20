import { describe, expect, it } from "vitest"
import { buildRegistry, loadContractTools } from "./registry.js"

const contract = loadContractTools(new URL("../../test/fixtures/tools.json", import.meta.url))
const noop = async (): Promise<unknown> => ({})

describe("buildRegistry", () => {
  it("serves only the contract entries that have a handler, in contract order", () => {
    const registry = buildRegistry(contract, { fail: noop, echo: noop })
    expect(registry.catalog.map((t) => t.name)).toEqual(["echo", "fail"])
    expect([...registry.handlers.keys()]).toEqual(["echo", "fail"])
  })

  it("refuses a handler for a tool the contract does not list", () => {
    expect(() => buildRegistry(contract, { not_a_tool: noop })).toThrow(/not_a_tool/)
  })

  it("serves nothing when no handler is registered", () => {
    expect(buildRegistry(contract, {}).catalog).toEqual([])
  })

  it("compiles every schema with strict Ajv, so an unknown keyword is a boot error", () => {
    const all = Object.fromEntries(contract.map((t) => [t.name, noop]))
    expect(buildRegistry(contract, all).catalog).toHaveLength(contract.length)
    const [first] = contract
    if (first === undefined) throw new Error("fixture has no tools")
    const broken = [{ ...first, inputSchema: { type: "object", notAKeyword: true } }]
    expect(() => buildRegistry(broken, { echo: noop })).toThrow(/notAKeyword/)
  })
})
