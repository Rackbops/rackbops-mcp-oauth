// Scope handling. An app declares its optional scopes in `OAuthApp.scopes`; a client that asks for
// none, or for an unknown one, gets a grant with no extra scopes.

import type { ScopeDef } from "./config.js"

/** The supported scope names, in declaration order. */
export const scopeNames = (scopes: readonly ScopeDef[]): string[] => scopes.map((s) => s.name)

/** The supported scopes named in a space-delimited `scope` parameter; anything else is ignored. */
export function parseScopes(requested: string | undefined, scopes: readonly ScopeDef[]): string[] {
  if (requested === undefined) return []
  const asked = new Set(requested.split(/[ \t]+/).filter((s) => s !== ""))
  return scopeNames(scopes).filter((s) => asked.has(s))
}

/** Scopes as stored: space-delimited, in a fixed order. */
export const joinScopes = (scopes: readonly string[]): string => scopes.join(" ")
export const splitScopes = (stored: string, scopes: readonly ScopeDef[]): string[] =>
  parseScopes(stored, scopes)
