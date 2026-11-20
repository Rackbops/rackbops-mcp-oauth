import { readFileSync } from "node:fs"
import type { ValidateFunction } from "ajv"
import { Ajv2020 } from "ajv/dist/2020.js"

// The tool registry, moved from Rackbops/meals-for-two and Rackbops/tracker-mcp `src/mcp/registry.ts`:
// the server's `contracts/tools.json` is the source of every tool's name, description, schemas and
// annotations, and the server's handlers supply the behaviour. The served catalog is the contract's
// entries that have a handler, so a tool appears in tools/list the moment its handler lands and never
// before. A handler whose name is not in the contract is a boot error; there is no second place a
// schema can be written. What a handler receives (`Ctx`) is the server's own.

export interface ToolAnnotations {
  readOnlyHint: boolean
  destructiveHint: boolean
  idempotentHint?: boolean
  openWorldHint: boolean
}

export interface ToolCatalogEntry {
  name: string
  title: string
  description: string
  inputSchema: Record<string, unknown>
  outputSchema: Record<string, unknown>
  annotations: ToolAnnotations
}

/** An MCP image content block: standard base64 (with padding) of the picture's bytes. */
export interface ImageBlock {
  type: "image"
  data: string
  mimeType: string
}

/** A handler's answer that carries content blocks beside its structured output (a picture). */
export class ToolResult {
  constructor(
    readonly output: unknown,
    readonly content: readonly ImageBlock[],
  ) {}
}

export const withContent = (output: unknown, content: readonly ImageBlock[]): ToolResult =>
  new ToolResult(output, content)

export type ToolHandler<Ctx> = (args: Record<string, unknown>, ctx: Ctx) => Promise<unknown>

/** A failure a caller can act on: surfaced as `{code, message}` JSON. `code` is a contract error code. */
export class ToolError extends Error {
  constructor(
    readonly code: string,
    message: string,
    /** Carried in the error body as `result` (Meals for Two's DUPLICATE returns the stored answer). */
    readonly result?: unknown,
  ) {
    super(message)
  }
}

interface ContractFile {
  tools: ToolCatalogEntry[]
}

/** The `tools` of a contract file. Pass the server's own path or URL, resolved from the caller's
 *  module (`new URL("../../contracts/tools.json", import.meta.url)`): this package cannot know where
 *  a server keeps its contract. */
export function loadContractTools(file: string | URL): readonly ToolCatalogEntry[] {
  return (JSON.parse(readFileSync(file, "utf8")) as ContractFile).tools
}

export interface Registry<Ctx> {
  /** Contract entries that have a handler, in contract order. */
  catalog: readonly ToolCatalogEntry[]
  handlers: ReadonlyMap<string, ToolHandler<Ctx>>
  inputValidators: ReadonlyMap<string, ValidateFunction>
  outputValidators: ReadonlyMap<string, ValidateFunction>
}

export function buildRegistry<Ctx>(
  contractTools: readonly ToolCatalogEntry[],
  handlers: Readonly<Record<string, ToolHandler<Ctx>>>,
): Registry<Ctx> {
  const known = new Set(contractTools.map((t) => t.name))
  for (const name of Object.keys(handlers)) {
    if (!known.has(name))
      throw new Error(`handler for ${name}, which is not in contracts/tools.json`)
  }
  const catalog = contractTools.filter((t) => Object.hasOwn(handlers, t.name))
  const ajv = new Ajv2020({ strict: true, allowUnionTypes: true, allErrors: true })
  return {
    catalog,
    handlers: new Map(
      catalog.map((t): [string, ToolHandler<Ctx>] => [
        t.name,
        handlers[t.name] as ToolHandler<Ctx>,
      ]),
    ),
    inputValidators: new Map(
      catalog.map((t): [string, ValidateFunction] => [t.name, ajv.compile(t.inputSchema)]),
    ),
    outputValidators: new Map(
      catalog.map((t): [string, ValidateFunction] => [t.name, ajv.compile(t.outputSchema)]),
    ),
  }
}
