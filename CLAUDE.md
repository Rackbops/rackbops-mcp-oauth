# rackbops-mcp-oauth -- Claude Instructions

`@rackbops/mcp-oauth`: the shared OAuth 2.1 server for Rackbops MCP servers, extracted from
`Rackbops/meals-for-two` `src/oauth` (issue meals-for-two#5). Behaviour-preserving: meals-for-two's
live grants and the claude.ai/ChatGPT connectors must keep working. My personal `~/.claude/CLAUDE.md`
governs how I work; this covers only this repo.

- **Shipped identifiers are frozen**: token/client/cookie prefixes (`OAuthApp.idPrefix`), the `oauth_*`
  tables and columns, the consent-page wording and `Referrer-Policy: same-origin`. `src/app.test.ts`
  pins Meals for Two's rendering byte-for-byte; a change there needs a reason in the PR.
- **App-specific text and names are options (`OAuthApp`), never branches on which app is calling.**
- **Public repo, public npm**: no hostnames, secrets or household data.
- `just check` mirrors CI. Public repo, so all workflows run on GitHub-hosted runners (private repos use the
  self-hosted pool).
- Release flow and publish auth are the same as `rackbops-node-app-kit` (OIDC; `NPM_TOKEN` is the
  break-glass for the first publish; `RELEASE_TOKEN` unset makes release.yml inert).
