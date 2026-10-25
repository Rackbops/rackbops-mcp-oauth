// The two server-rendered pages of the authorize flow. Plain HTML with an inline style and no
// script. Every dynamic value is escaped; the client name is attacker-chosen (DCR) and is shown
// only after registration.ts has refused control/format/invisible characters in it.

const ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ESCAPES[c] as string)
}

const STYLE = `body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1b1b1b;background:#fff}
@media(prefers-color-scheme:dark){body{color:#eee;background:#161616}}
h1{font-size:1.3rem}button{font:inherit;padding:.6rem 1.2rem;margin-right:.6rem;border-radius:.4rem;border:1px solid #888;cursor:pointer}
button.allow{background:#1d6b3a;color:#fff;border-color:#1d6b3a}.err{color:#b00020}code{word-break:break-all}
.extra{border:2px solid #b36b00;border-radius:.4rem;padding:.2rem 1rem;margin:1rem 0}.extra h2{font-size:1rem;margin:.6rem 0 0}`

/** `form-action` has to name the client's origin: browsers enforce it on the redirect that follows a
 *  form POST, so a bare 'self' would block the hand-off back to claude.ai or chatgpt.com. */
export function pageHeaders(redirectOrigin: string | null): Record<string, string> {
  const formAction = redirectOrigin === null ? "'self'" : `'self' ${redirectOrigin}`
  return {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    "X-Frame-Options": "DENY",
    // same-origin, not no-referrer: with no-referrer a browser sends `Origin: null` on the consent form POST,
    // which the Host/Origin guard (correctly) refuses, so Allow would 403. Cross-origin gets no referrer.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
  }
}

function shell(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body>${body}</body></html>`
}

export function renderErrorPage(appName: string, message: string): string {
  return shell(appName, `<h1>Can't connect</h1><p class="err">${escapeHtml(message)}</p>`)
}

export interface ConsentPageInput {
  clientName: string | null
  hostname: string
  isLoopback: boolean
  requestId: string
  memberName: string
  appName: string
  /** Consent-page phrase after "wants to": `read and manage your household's meals`. */
  summary: string
  /** Trusted HTML for each optional scope the client asked for (`ScopeDef.disclosureHtml`). */
  disclosures: readonly string[]
  error: string | null
}

export function renderConsentPage(input: ConsentPageInput): string {
  const who = input.clientName === null ? "An app that gave no name" : escapeHtml(input.clientName)
  const where = input.isLoopback
    ? "a program running on your own computer"
    : `<code>${escapeHtml(input.hostname)}</code>`
  const name = input.memberName === "" ? "you" : escapeHtml(input.memberName)
  const confirm = input.disclosures.join("")
  const error = input.error === null ? "" : `<p class="err">${escapeHtml(input.error)}</p>`
  return shell(
    `Connect to ${input.appName}`,
    `<h1>Connect to ${escapeHtml(input.appName)}?</h1>${error}<p><strong>${who}</strong> (${where}) wants to ${input.summary} as ${name}.</p>${confirm}<p>Only allow this if you just asked an assistant such as ChatGPT or Claude to connect.</p><form method="post" action="/authorize"><input type="hidden" name="request_id" value="${escapeHtml(input.requestId)}"><button class="allow" name="decision" value="allow" type="submit">Allow</button><button name="decision" value="deny" type="submit">Cancel</button></form>`,
  )
}
