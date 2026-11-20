// Which deployment a server is: `prod`, `dev`, or `local` (anything else a person names). Shown to
// people and agents so a test server's answer is never taken for real data. Display only: nothing
// security-relevant (issuer, hosts, grants, tokens) reads it. Moved from Meals for Two's and
// tracker-mcp's `src/environment.ts`, whose label logic differed only in the names passed in here
// (their server instructions stay in each server).

export const PROD_LABEL = "prod"

const LABEL = /^[a-z0-9][a-z0-9-]{0,15}$/

export interface EnvironmentOptions {
  /** The override's env-var name, quoted in the startup error (`MEALS_ENV_LABEL`). */
  envVar: string
  /** Public host -> label, matched exactly so a look-alike host is never prod. */
  knownHosts: Readonly<Record<string, string>>
  /** The plain name people see in prod (`Meals for Two`). */
  name: string
}

export interface Environment {
  /** The configured label when set (lowercased, 1-16 of a-z 0-9 -), else the issuer host's label from
   *  `knownHosts`, else `local`. Throws on an unusable label so a typo fails at startup instead of
   *  mislabelling prod as something else. */
  resolveEnvLabel(configured: string | undefined, issuer: string): string
  isProd(label: string): boolean
  /** Plain in prod, `<name> (<label>)` elsewhere. */
  displayName(label: string): string
}

export function createEnvironment(options: EnvironmentOptions): Environment {
  const isProd = (label: string): boolean => label === PROD_LABEL
  return {
    resolveEnvLabel(configured, issuer) {
      const explicit = configured?.trim().toLowerCase()
      if (explicit !== undefined && explicit !== "") {
        if (!LABEL.test(explicit)) {
          throw new Error(
            `${options.envVar} must be 1-16 characters of a-z, 0-9 and -, got "${explicit}".`,
          )
        }
        return explicit
      }
      let host = ""
      try {
        host = new URL(issuer).hostname.toLowerCase()
      } catch {
        // an unparsable issuer is reported where it is used; the label just falls back
      }
      return Object.hasOwn(options.knownHosts, host)
        ? (options.knownHosts[host] as string)
        : "local"
    },
    isProd,
    displayName: (label) => (isProd(label) ? options.name : `${options.name} (${label})`),
  }
}
