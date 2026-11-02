# Fork changes

Updated: 2026-11-02.

This document records work on the `ukkii/openobserve` fork, on branch
`codex/privacy-community-auth`. It covers the five local privacy/community WIP
commits and subsequent working-tree changes. Work in this session has not been
pushed to the original OpenObserve repository.

The conversion is incomplete. Known automatic vendor reporting paths have been
removed, but this is not a completed repository-wide egress audit or a claim that
all Enterprise code has been deleted. MCP is implemented, locally tested, and
deployed to the local Docker preview; independent review remains pending.

## Privacy and automatic network activity

- Removed the known default vendor telemetry implementation and remote usage
  reporting transport.
- Removed Reo.dev, product analytics calls, browser RUM initialization for the
  application's own UI, and editor-suggestion telemetry.
- Removed automatic webinar fetching and default external map tile requests.
- Removed automatic GeoIP database downloads. Existing local MaxMind City/ASN
  files can still be loaded; missing or invalid optional files do not prevent
  startup.
- Removed automatic remote model-pricing synchronization and its refresh action.
  Database-backed/user-defined pricing logic remains, although its community UI
  route needs follow-up as noted below.
- Adjusted tracing/export configuration so remote exporters require explicit
  configuration rather than an implicit default destination.
- Retained local self-reporting and explicitly configured administrator
  destinations. This does not disable integrations that an administrator or user
  deliberately connects.

Main areas: `src/common/src/meta`, `src/core/src/self_reporting`,
`src/jobs/src/job`, `src/config/src/config.rs`, `src/telemetry.rs`, and frontend
services and initialization code under `web/src`.

## Google sign-in

- Added community Google OIDC sign-in for existing, pre-created users. Google
  sign-in does not automatically create an account or grant a role.
- Added Authorization Code flow with PKCE, state, nonce, and JWKS validation.
- Added shared single-use pending state, bounded opaque sessions, replay
  protection, and rate limiting for public authentication endpoints.
- Added a dedicated frontend callback and server-side session cleanup when
  post-login initialization fails.

Implementation: `src/api/management/src/request/google_auth.rs`, session storage,
and `web/src/views/GoogleCallback.vue`. OAuth credentials must be configured by
the operator; Google sign-in is not configured in the local preview.

## Community roles and read-only access

- Preserved built-in Admin, Editor, Viewer, and User role values instead of
  silently converting them to Admin.
- Added backend Viewer enforcement, including an explicit allowlist for
  read/query POST operations and denial of credential-retrieval endpoints.
- Added an inventory of 231 documented non-GET OpenAPI operations in
  `src/core/src/viewer_mutation_routes.txt`.
- Made the login-only User role fail closed and hardened role changes against
  privileged/custom-role assignment and Editor-driven escalation.
- Added initial Viewer-aware controls in Dashboards and Alerts. Full UI coverage
  and classification of undocumented routes remain unfinished.

Main areas: `src/core/src/auth.rs`, `src/core/src/authz.rs`,
`src/core/src/users.rs`, common/config role types, and affected frontend controls.

## Enterprise UI and activation cleanup

- Removed a substantial set of premium startup, shutdown, migration, CLI, and
  shared route-registration paths from the community build.
- Removed the header's Enterprise upgrade CTA and its dedicated styling.
- Hid locked Enterprise entries in the main navigation, nested navigation, and
  shared section rails, including Settings and IAM surfaces.
- Hid unavailable in-page controls such as Service Graph, log Patterns,
  Scheduled Search, correlation tabs, Enterprise Alert Insights tabs, and Agent
  mode. The header AI action is hidden when unavailable.

Hiding entries does not remove their underlying implementation. Enterprise/cloud
compatibility flags, private dependency stubs, premium APIs/jobs, and residual
locked/upgrade components still exist. Backend authorization remains necessary
for direct requests.

## Local NotoSans font

- Set the shared sans stack to
  `NotoSans, Lucida Grande, Lucida Sans Unicode, sans-serif`.
- Added local normal and italic variable Noto Sans TrueType files and
  `@font-face` declarations using the `NotoSans` alias, with weights 100–900.
- Added the Noto Sans OFL license and included it in frontend build output.
- Removed the previous Geist Sans asset. Geist Mono remains for monospace
  content.

The browser loads NotoSans from this application's assets; no runtime font CDN
is needed. Sources are under `web/src/styles/fonts`, with declarations in
`web/src/lib/styles/tokens/base.css` and license packaging in `web/vite.config.ts`.

## HT branding

A separate branding change replaces the primary default OpenObserve SVG
wordmark with `HT`, retaining the original colored icon. It covers the light
and dark logo variants and matching logo alternative text. The deployed SVG
hashes match the source and frontend build output. Existing browser sessions may
need a hard reload because the stable logo URLs previously used a one-hour cache
lifetime.

## MCP credentials

The original token generator attempted to create a service account, which the
community role policy rejects. The replacement provides:

- A dedicated credential per user and organization, available to active users
  with supported roles and actual organization membership, including Viewer.
- Read-only telemetry scope bounded by the owner's live permissions and
  organization, with an explicit route allowlist that excludes credentials,
  management settings, destinations, pipelines, and future unreviewed APIs.
- A 24-hour lifetime, self-service revocation, and replacement of the previous
  credential when regenerated.
- Cryptographic secrets with only their digest persisted in existing session
  storage, plus checks for expiry, revocation, role changes, and removed
  membership.
- Bearer authentication carried through MCP's internal API calls so tool
  execution cannot bypass the token's read-only scope.
- Self-service issuance and revocation through the community credential
  endpoints, without enabling community ServiceAccount access.
- Expired UI credentials are removed on remount, while displayed, and before
  another generation attempt, restoring the token generation action.

Implementation is in `src/core/src/mcp_credentials.rs`, API/auth handlers, and
`web/src/composables/useMcpCredential.ts`. The coder verified debug `cargo build`,
the exact workspace/all-target clippy command, frontend `verify` and build,
38 MCP UI tests, and targeted Rust lifecycle/authentication tests.

An isolated local HTTP server verified Viewer and Admin self-issuance,
`initialize`, `tools/list`, `StreamList`, `StreamSchema`, and `SearchSQL` returning
a seeded row. It also verified rejection of direct writes, the `UserSave` MCP
tool, cross-organization requests, and credential issuance using an MCP bearer.
Rotation, revocation, expiry, membership removal, per-user revocation isolation,
and hashed-only persistence were checked.

The updated backend is deployed in the local Docker preview. HTTP MCP smoke
tests queried the existing demo logs and confirmed 100 rows each in `demo_api`,
`demo_web`, and `demo_worker`. An independently supplied user token completed
initialization, listed seven top-level tools, and returned 100 `demo_web` rows
through `SearchSQL`, without being rotated or revoked by that validation.

One earlier HTTP 401 was traced to a smoke test replacing and revoking the same
user/organization credential slot. It was test interference with the active
credential, rather than a credential-validation failure. Tests that rotate or
revoke credentials must use an isolated user/organization slot.

These results are implementation and runtime checks, not independent review
approval. External review remains pending because the execution environment's
consent/automatic approval checks have not permitted that review run.

## Local Docker preview and demo data

These are local development artifacts, separate from committed source changes:

- Preview URL: `http://127.0.0.1:5080/web/`, bound to loopback.
- Container: `ukkii-openobserve-preview`.
- Image: `ukkii-openobserve:community-mcp-debug`.
- Persistent volume: `ukkii-openobserve-preview-data`.
- The backend uses a debug build. Temporary Dockerfiles outside this repository
  package the binary and frontend assets; they are not a checked-in deployment
  recipe.
- The preview contains 300 synthetic logs: 100 each in `demo_web`, `demo_api`,
  and `demo_worker`.
- `demo_traces` contains 160 spans forming 40 linked four-service traces.
- There are 180 metric samples: 60 each in `demo_http_requests_total`,
  `demo_request_duration_ms`, and `demo_queue_depth`.

The demo worker verified counts with SQL queries. Data was timestamped near its
generation time, so adjust the time range when inspecting it later. Example log
filters include `level = 'ERROR'` and `duration_ms > 500`. No existing non-demo
streams were modified by the generator.

## Publication status

The requested public Docker Hub target is `ykki/openobserve`, for `linux/amd64`
only. That image is currently building under emulation and has not been pushed.
The requested Git push and pull request target only the `ukkii/openobserve`
fork; they are pending at the time of this update.

## Verification and remaining work

The five-round privacy/community implementation passed debug `cargo build`,
`cargo fmt --all`, the required workspace/all-target clippy command, focused
Google-auth/security tests, frontend formatting, frontend `verify`, and a
production frontend build. The latest UI cleanup passed 535 targeted tests with
one skipped test, full frontend `verify`, formatting, and an offline frontend
build using cached datasource content. The local preview passed its health
check and served the updated frontend and font assets. These results do not
represent a full workspace test run or completed browser viewport inspection.

The earlier independent review ended after five rounds with five open findings:

1. Full community-only conversion remains partial: physical Enterprise/cloud
   feature/dependency removal, premium backend/UI deletion, full Viewer UI
   coverage, undocumented-route classification, and the final egress audit.
2. The retained database-backed model-pricing UI route was removed and needs
   restoration or an explicit product decision.
3. Some remaining guards/locked affordances target deleted Enterprise routes.
   Subsequent navigation hiding addresses visible cases but has not closed this
   finding through a new independent review.
4. Empty Enterprise/cloud compatibility switches and dead optional dependencies
   still need cleanup.
5. A `master_key` indirection in `src/main.rs` remains even though it is always
   `None` in the converted startup path.

The final automatic-egress audit, 375/768/1280 viewport inspection, and private
Enterprise manifest/build verification remain outstanding. The private paired
repository was unavailable. MCP is deployed locally; its independent review
remains pending.

Local privacy/community WIP commits, in implementation order:
`516f22ce9`, `39ac182c6`, `2e3c4041f`, `596901347`, and `95f38b5e3`.
Later font, UI, and MCP edits are currently working-tree changes.
