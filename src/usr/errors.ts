/** The person has no usr service link to this server covering the operation, or no role in the app. */
export class NotLinked extends Error {}

/** usr could not be asked (network, timeout, a redirect, 5xx, an answer that is not the contract). */
export class UsrUnavailable extends Error {}

/** usr's per-key limit was reached (429). */
export class UsrRateLimited extends Error {}

/** usr's role lookup says the person no longer holds the role the server requires. */
export class NotMember extends Error {}
