export type { AuthorizeDeps, AuthorizeHandler } from "./authorize.js"
export { createAuthorizeHandler, validateAuthorizeRequest } from "./authorize.js"
export { type OAuthApp, type OAuthConfig, oauthConfig, type ScopeDef } from "./config.js"
export {
  authorizationServerMetadata,
  normalizeResource,
  protectedResourceMetadata,
  resourceMetadataUrl,
} from "./discovery.js"
export { createRateLimiter, type RateLimiter } from "./rateLimit.js"
export {
  DEFAULT_REDIRECT_POLICY,
  isLoopbackHttp,
  LOOPBACK_HOSTNAMES,
  type RedirectPolicy,
  redirectMatchesRegistered,
  validateRedirectUri,
} from "./redirect.js"
export {
  createRegistrationHandler,
  type ParseRegistrationResult,
  parseRegistrationRequest,
} from "./registration.js"
export { joinScopes, parseScopes, scopeNames, splitScopes } from "./scopes.js"
export { OAuthStore, sha256Hex } from "./store.js"
export { createTokenHandler, type TokenDeps } from "./token.js"
export {
  createUsrIdentity,
  type Identity,
  type IdentityPort,
  type UsrVerifierOptions,
} from "./usr.js"
