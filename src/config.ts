import { DEFAULT_REDIRECT_POLICY, type RedirectPolicy } from "./redirect.js"

/** An optional scope an app offers on the consent page. */
export interface ScopeDef {
  /** The scope string clients request, e.g. `app.confirm`. */
  name: string
  /** Trusted HTML shown on the consent page when a client asks for this scope. Written by the
   *  app, never derived from client input. */
  disclosureHtml: string
}

/** Everything that makes this server one app's rather than another's. */
export interface OAuthApp {
  /** Display name on the consent and error pages: `My App`. */
  name: string
  /** Prefix of the console.error lines: `my-app`. */
  logPrefix: string
  /** Prefix of every issued identifier: `mft` gives `mft_c_`, `mft_ac_`, `mft_g_`, `mft_at_`,
   *  `mft_rt_` and the `__Host-mft_ar_` cookie. Shipped identifiers: never change it for a live app. */
  idPrefix: string
  /** The usr role (without the `<app>:` prefix) an account needs to authorize. */
  memberRole: string
  /** Consent-page phrase after "wants to": `read and manage your household's meals`. */
  consentSummary: string
  /** 403 page text for a signed-in account without `memberRole`. */
  notMemberMessage: string
  /** 401 page text when usr's round trip still leaves no valid cookie. */
  signInFailedMessage: string
  scopes: readonly ScopeDef[]
}

export interface OAuthConfig {
  app: OAuthApp
  /** Public origin of this service, no trailing slash: `https://app.example.com`. */
  issuer: string
  redirect: RedirectPolicy
  /** Also accept the bare issuer origin as the RFC 8707 `resource` (some clients send it). */
  acceptOriginAsResource: boolean
  lifetimes: {
    accessTokenSeconds: number
    refreshIdleDays: number
    codeSeconds: number
    requestSeconds: number
    refreshGraceSeconds: number
  }
  registration: {
    perSourcePerHour: number
    perSourceGrantless: number
    globalGrantless: number
    evictionProtectMinutes: number
  }
  liveRequestsPerSource: number
  /** A grant stops refreshing this long after it was issued, however active it is. */
  grantMaxAgeDays: number
}

/** Defaults are discord-mcp's (`src/service/config.ts`), which real claude.ai clients run against. */
export function oauthConfig(
  issuer: string,
  app: OAuthApp,
  overrides: Partial<OAuthConfig> = {},
): OAuthConfig {
  return {
    app,
    issuer: issuer.replace(/\/+$/, ""),
    redirect: DEFAULT_REDIRECT_POLICY,
    acceptOriginAsResource: true,
    lifetimes: {
      accessTokenSeconds: 900,
      refreshIdleDays: 30,
      codeSeconds: 60,
      requestSeconds: 600,
      refreshGraceSeconds: 60,
    },
    registration: {
      perSourcePerHour: 60,
      perSourceGrantless: 30,
      globalGrantless: 1000,
      evictionProtectMinutes: 15,
    },
    liveRequestsPerSource: 20,
    grantMaxAgeDays: 90,
    ...overrides,
  }
}
