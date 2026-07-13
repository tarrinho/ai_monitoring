# Changelog

All notable changes to AI-Monitoring are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **OpenSSF Scorecard** — `.github/workflows/scorecard.yml` (pinned action SHAs)
  runs the OpenSSF Scorecard analysis weekly + on push to `main`, publishes results
  to the public crawler (`api.securityscorecards.dev`), and uploads SARIF to
  code-scanning. New README badge links to the Scorecard viewer. Added to the
  publish ALLOW-list.
- **Supply-chain: verify-on-deploy + signed release assets.** README now documents
  the `cosign verify` (keyless, identity-scoped to `release.yml`) an operator should
  run before deploying, plus the SLSA-provenance/SBOM attestations. `release.yml`
  additionally `cosign sign-blob`s a small image-provenance manifest and attaches
  `*.txt` + `*.txt.sig` + `*.txt.pem` to each GitHub Release — the OCI image
  signature isn't visible to OpenSSF Scorecard's Signed-Releases check, but release
  assets are.
- **Fuzzing via ClusterFuzzLite** — `fuzz/fuzz_parsers.py` (Atheris harness over the
  untrusted-input parsers: nvidia-smi CSV, the `/spend/logs` byte parser, timestamp
  and numeric coercion), `.clusterfuzzlite/` build config, and
  `.github/workflows/cflite-pr.yml` (runs on PRs, SHA-pinned, minimal permissions,
  uploads crashes as SARIF). Satisfies Scorecard's Fuzzing check.
- **Solo-maintainer un-blockers** — `.github/CODEOWNERS` (informational; owns the
  tree without requiring approval) and `.github/workflows/dependabot-auto-merge.yml`
  (auto-approves + enables auto-merge on Dependabot PRs via the built-in `gh` CLI —
  no third-party action to pin — so dependency bumps land automatically once CI
  passes, with no second reviewer needed). Merge still gates on required checks.
- **CI coverage expanded** (matching a mature reference pipeline) — three new `ci.yml`
  jobs: **`deps-audit`** (`pip-audit` on shipped deps + `pip-licenses` fail-on
  strong-copyleft, keeping the tree Apache-2.0-compatible), **`dependency-review`**
  (PR-only `actions/dependency-review-action`, blocks vulnerable / GPL-family deps
  before merge), and **`lighthouse`** (boots the dashboard and runs Lighthouse
  perf/a11y/best-practices via headless Chromium over 5 pages — doubles as a render
  smoke; scores are advisory `warn`, so only a failed boot/render reds the job).

### Changed
- **Node 20 → 24 action bump.** `scorecard.yml`'s three Node-20 actions were the only
  ones left triggering GitHub's Node-20 deprecation warning; pinned to node24 SHAs:
  `actions/checkout` v4.2.2 → v7.0.0 (reusing the repo's existing pin),
  `actions/upload-artifact` v4.6.0 → v7.0.1, `github/codeql-action/upload-sarif`
  v3.28.9 → codeql-bundle-v2.26.0. Verified every remaining action across all
  workflows is node24 / composite / docker — no Node-20 warnings remain.
- **Supply-chain hardening for OpenSSF Scorecard.** `release.yml` now uses a minimal
  top-level `permissions: contents: read` and escalates writes only in the release
  job (Token-Permissions 0 → 10). The Dockerfile base image is pinned by multi-arch
  manifest digest (Pinned-Dependencies; Dependabot's docker ecosystem bumps it).

### Fixed
- **Flaky in-image test gate (CI `build-scan` red on amd64).** Two nav tests
  (`test_unconfigured_backend_links_stripped_serverside`,
  `test_token_auth_hides_alerts_link`) raced the background sampler, which rebinds
  the module-global `_latest` on its own cadence — a prior test's lingering sampler
  could leave a stale `"unconfigured"` collector note that stripped a sidebar link
  the test expected to see. Surfaced only in CI because the in-image pytest gate
  runs native on amd64 (emulated arches skip it). Fix: `_client()` now cancels the
  background sampler tasks right after startup, so tests fully control `_latest`;
  the reconfigure assertion also pins `_latest` explicitly. Test-only change.
- **Trivy fs red on `.clusterfuzzlite/Dockerfile` (`AVD-DS-0002`, HIGH).** The
  ClusterFuzzLite/OSS-Fuzz build image runs as root by contract; added `AVD-DS-0002`
  to `.trivyignore` as a documented accepted-risk (the shipped runtime image still
  runs non-root). CI `trivy-fs` job back to green.
- **CodeQL default-setup conflict** — the advanced `.github/workflows/codeql.yml`
  was rejected by code-scanning because CodeQL **default setup** is enabled
  (*"analyses from advanced configurations cannot be processed when the default
  setup is enabled"*). Resolved by **disabling** the advanced workflow (reduced to
  a `workflow_dispatch`-only no-op stub — it no longer runs on push/PR, so it
  uploads no conflicting SARIF) and keeping default setup, which already scans
  Python + Actions. Kept as a stub rather than deleted because the publish/sync
  pipeline does not propagate file deletions. README CodeQL badge stays on the
  default-setup path.

## [1.5.7] — 2026-07-11

### Added
- **`SECURITY.md`** — vulnerability-disclosure policy (private reporting via GitHub
  advisories + email, supported-version window, coordinated-disclosure + safe-harbor
  terms, scope, image-signature verification, and an operator hardening checklist).
  Linked from the README Security section and added to the publish ALLOW-list.
- **Sidebar icons + grouping** — every nav item now carries an icon, and related
  pages are indented as sub-items: **Spend & Quota / Ollama / llama.cpp** under
  **LiteLLM**, and **Alerts / Users** under **Settings**.
- **New QA test suites** (all in the in-image gate): `test_property_parsers.py`
  (Hypothesis property/fuzz), `test_time_frozen.py` (freezegun deterministic dates),
  `test_error_matrix.py` (upstream failure-mode matrix), `test_contract_litellm.py`
  (recorded LiteLLM response-shape contract + no-real-data guard), `test_snapshot_api.py`
  (golden/snapshot of API row shapes).
- **README badges** — CodeQL (code-scanning status) and a Security-Policy badge.

### Changed
- **Settings page: "Reset layout" moved into the header, before the title.**

### Fixed
- **`_norm_date` no longer raises `OverflowError`** on out-of-range epoch input from
  upstream (surfaced by the new property tests) — malformed values degrade to empty.
- **armv7 image build** — dev dependencies (and the pytest run) are now installed
  only when `RUN_TESTS=1`, so emulated cross-arch builds no longer fail on a dev dep
  that lacks a musl/armv7 wheel and would need a Rust toolchain. The native arch
  still gates the full suite.
- The "hide Alerts link for token/PAT auth" removal is now attribute/icon-tolerant
  (regex, not an exact-string match), so it keeps working with the new nav markup.

## [1.5.6] — 2026-07-10

### Changed
- **The shared URL/master token is now withheld from Alerts and the admin surfaces
  (Settings, Users).** The dashboard token rides in the `?token=` URL and is meant
  for read-only dashboard sharing, so it no longer counts as admin: the **Alerts**
  and **Settings** links are absent from its sidebar, and `/alerts`, `/settings`,
  `/api/alerts*` and `/api/admin/*` return **403** for it (previously the token was
  full admin and could reach all of them). These surfaces now require an interactive
  login, or a scoped **admin PAT** for automation — mint one under Account → Tokens.
  A new env-keyed `_is_master_token_auth()` gate drives both the nav flags and the
  backend block; user sessions and PATs are unaffected. Also gates Spend & Quota on
  LiteLLM being configured (link hidden + `/spend` 404s when it isn't).
- **Settings page: all explanatory text moved into click-the-title info popups.**
  The inline descriptions that crowded the compact board are gone; each title is
  now a button that opens an organized, labelled modal (click or focus +
  Enter/Space; closed by "Got it", overlay click, or Escape). Three titles are
  now buttons: the **Teams** card (Purpose/Layout/Set team/Change user/Refresh/
  Caching/Budgets), the **Model costs** card (Purpose/Auto-detect/Override/Cost
  basis), and the page **Settings** header itself (Purpose/Persistence/Scope/Edit
  a setting/Arrange cards — merging the old intro paragraph and its `ⓘ` hover
  tooltip). All render through one DOM-built `cardInfoModal(title, rows)` helper
  (no `innerHTML`).
- **Settings: removed the section quick-nav bar.** The sticky row of jump chips
  (Alerts / Sampling / Retention / GPU / LiteLLM / Teams / Models) was redundant
  with the draggable free-form board and is gone; the "Reset layout" button
  stays.
- **CI now runs the full test suite.** The `tests` job ran only
  `test_static_qa.py` + `test_dynamic_qa.py`, silently skipping five files
  (`property_parsers`, `snapshot_api`, `error_matrix`, `time_frozen`,
  `contract_litellm`). It now runs the whole `tests/` dir (matching the in-image
  build gate and rules.md §2), so a new suite can never go unrun. The badges job
  is `continue-on-error` + warns instead of failing the run when the token is
  read-only.
- **Architecture diagram rebuilt for accuracy** (`docs/img/architecture.svg`).
  Now shows the decoupled per-backend loops → `_backend_latest` cache (the
  anti-freeze design), all eight dashboards, SSE `/api/stream`, and the real
  storage tables — the old one showed a single `asyncio.gather()` loop and six
  dashboards. rules.md §15 gains an architecture-diagram-parity rule.
- **CI supply-chain hardening.** Every GitHub Action pinned to a full 40-char
  commit SHA (was major-tag `@vN` / branch `@main`). The `trufflesecurity/trufflehog@main`
  branch pin — the highest-risk mutable ref — is now `@27b0417c…` (v3.95.9).
  `.github/workflows/{ci,release}.yml` cover 9 action pins in total. Dependabot's
  `github-actions` ecosystem opens PRs against SHA pins so update visibility is
  preserved. Aligns with GitHub's security-hardening guide for workflows.
- **Release pipeline provenance.** `docker/build-push-action` now emits
  `provenance: mode=max` (SLSA-level attestation) and `sbom: true`
  (CycloneDX SBOM) alongside the multi-arch image push. Consumers can
  `cosign verify-attestation …` without extra CI.

### Added
- **Cosign keyless signing of the release image.** Sigstore/Fulcio OIDC
  identity — no long-lived key material. The release workflow signs by the
  immutable digest (not the mutable tag). Release notes now embed the
  `cosign verify --certificate-identity-regexp … --certificate-oidc-issuer …`
  command a consumer runs to check the signature. New `cosign` badge in
  README next to `dependabot`. Required `id-token: write` permission added
  at workflow level.
- **"Require CI green on this SHA" release gate.** New first step in
  `release.yml` looks up the CI workflow's most-recent conclusion for the
  tag's HEAD SHA and aborts unless it is `success` — a tag pushed straight
  to `main`, or a `workflow_dispatch` on a stale tag, no longer ships a
  build that CI never signed off on. Override via the new `skip_ci_check`
  boolean `workflow_dispatch` input for re-tag scenarios where CI was
  cancelled/expired but the operator has verified locally.

### Fixed
- **Spend "Cost by key" was missing keys — three separate caps.** (1) `merge_key_budgets`
  used `/key/list` **or** the spend snapshot, never both, so a key with real spend in
  `/global/spend/keys` but absent from `/key/list` was silently dropped from `/api/budgets`
  (the chart's source) — it now **unions** the two. (2) The chart sliced to a hardcoded top
  12 (`.slice(0,12)`) — removed; it shows **every key with spend** and grows taller to fit.
  (3) The `/spend`-lite snapshot capped keys at 10 — raised to 100. Regression tests added
  for all three: `merge_key_budgets` unions live+snapshot, `budget_rows` returns every key,
  `_lite_spend` keeps all keys, and the served page carries no top-12 slice.
- **No user emails on the Teams board — `/user/list` was 422-rejected.** The `_paginate`
  helper requested `page_size=500`, which LiteLLM's `/user/list` rejects with **HTTP 422**
  (it caps the page size). Every `/user/list` call failed, so the `user_id → user_email`
  map was empty and the board fell back to "Unnamed user" / the key name — even though the
  email is on the LiteLLM user object. Now `_paginate` uses `page_size=100` (accepted by
  both `/user/list` and `/key/list`); verified live that all keys then resolve to their
  owner's email. (The email lives on the *user* object, not the key row — key-row
  `user_email`/`created_by` are null/UUID on this deployment.)

### Changed
- **Settings → Teams: reassigning a key's user is restricted to existing users.** The
  key→user popup is now a **dropdown of the users LiteLLM actually reported** (no free-text),
  and the server rejects any user it hasn't seen (`unknown user — pick an existing user`).
  So a key can be moved between real users but never assigned to a made-up one. (This is a
  local grouping override — LiteLLM's real `user_id` is unchanged.)
- **Settings → Teams: ranked by usage, click for details, taller card.** Users are now
  ordered by **total spend (usage)**, top first, and the list is tall enough to show the
  top ~10 before scrolling. Clicking a user's name opens a **structured details panel** —
  **User ID · Username · Email · Team · Keys** (each key with its team, budget, spend and
  override state) — replacing the hover tooltip.

### Added
- **`GET /api/admin/keys-diag`** — admin diagnostic that reports the raw `/key/list` and
  `/user/list` field names and *which* fields hold an email-like value (values redacted),
  to locate the field carrying the user email when it doesn't surface on the Teams board.
- **Docs: Spend & Quota and Settings pages** — added a `/settings` row to the Dashboards
  table, expanded the `/spend` row, and added both screenshots to the README gallery
  (captured from a running instance with data remapped to placeholders).

### Fixed
- **`collectors/litellm.py::spend_report_debug` mypy dict-item errors** — the
  `attempts` list and its intermediate `row` were inferred as
  `list[dict[str, str]]` from the first-branch append, so later mixed-type
  entries (list/int/bool/list-of-dict) failed mypy. Explicit
  `list[dict[str, object]]` / `dict[str, object]` annotations resolve.
- **`tests/test_static_qa.py::test_ci_actions_pinned_to_current_majors`
  now accepts SHA-pinned actions.** Previously required literal `@vN` tag
  strings in workflow files; broke as soon as the workflows switched to the
  hardened `action@<sha> # vN` form. Test rewrites: pass when either the bare
  tag OR the SHA-pin-plus-tag-comment form is present. Same fix removes the
  in-image test-gate failure in `docker build --build-arg RUN_TESTS=1`
  (both jobs run the same pytest).

### Awk / release-notes housekeeping
- `release.yml` CHANGELOG-section extraction switched from a regex-based awk
  match (`$0 ~ "^## \\[" ver "\\]"`) to a literal-string match — semver tags
  are safe today, but a future non-semver tag containing a regex metachar
  would break the older form.
- `docs/img/banner.svg` a11y upgrade: `<title>` + `<desc>` elements + `aria-labelledby`
  (was `aria-label` only). Screen readers now get both a short label and
  the fuller description including sample KPI values.

## [1.5.5] — 2026-07-10

### Changed
- **Spend page timeline is now "Usage over time" (requests + tokens), not "Spend over
  time".** Daily dollar cost comes from LiteLLM's `/global/spend/report`, which is
  **Enterprise-licensed only** — a free/OSS proxy answers `400 "You must be a LiteLLM
  Enterprise user…"`, and `/global/activity` (the free daily endpoint) carries no spend
  field. So there is no daily-$ series to draw on the free tier. The timeline now plots
  what the free tier does provide — daily tokens (bars) and requests (line) — with a
  note that per-day cost needs Enterprise and that cumulative per-key spend is below.
  Year tiles show token/request totals. Cost data (per-key/team cumulative spend, from
  `/global/spend/keys`) is unchanged and still shown.

### Added
- **Settings → Model costs card.** A per-model board showing each model's cost
  classification — **real** (external paid API, a market price LiteLLM tracks) vs
  **estimated** (self-hosted / reference rate) — with the auto-detected default, whether
  LiteLLM prices it, and an admin-editable override (Save/Reset). The override wins on the
  Spend & Quota real-vs-estimated split for both the cost-by-model breakdown and the
  cost-over-time estimate. Backed by a new `model_cost_kind` table + `/api/admin/model-kinds`
  (GET board / POST set|reset), admin-only via the `/api/admin/*` gate, CSRF-guarded and
  audited (`model_kind.set` / `model_kind.reset`). `classify_model()` and `per_model_range()`
  now accept an override map; the board stays populated from `/v1/models` even when the
  master key can't reach the spend endpoints. The override flows straight into the
  **cost-over-time** estimate (`cost_rates` reads each row's override-adjusted `cost_kind`),
  so reclassifying a model shifts its tokens×price between the real and estimated series.

### Added
- **Current-year cost card (top-right of "Cost over time").** A compact card shows this
  year's estimated cost broken into **real (external)**, **estimated (self-hosted)**, and
  **total**, from the same per-year rollup that backs the chart (tokens × per-model price).
  Falls back to the most recent year if the current one has no data.

### Changed
- **Spend cost-over-time legend.** The *Estimated (self-hosted)* series is now **grey**
  (was amber) to read as "not real cash". Hovering *Real (external)* / *Estimated
  (self-hosted)* in the note line lists the models in each bucket (`/api/spend/series` now
  returns `cost_models: {real:[…], reference:[…]}`, biggest-usage first).

### Fixed
- **Settings → Teams board is now one LINE per user: email · team · budget · keys.** The
  email, the team dropdown, the per-user budget, the actions and all of that user's keys
  (horizontally scrolling) sit on a single row — matching the proposed layout. Each user
  shows their **email as the primary identifier** (raw `user_id` only in the tooltip;
  falls back to the key name when LiteLLM reports no email), a **team dropdown** to pick one
  of the identified teams or **add a new one**, a **per-user budget** input, and **all of
  that user's keys on a single horizontally-scrolling line** of chips (overridden key
  highlighted). Save/⟳/↺ apply to every key the user owns (a user has one team + budget).
  **User email now reads straight off the key row** — LiteLLM carries it in the key's
  `User`/`Created By` columns (`user_email` / `created_by`), which populate even when
  `/user/list` returns no email; the board prefers an email-shaped value (`_pick_email`)
  from `user_email` → metadata → `/user/list` → `created_by`, so real emails show as the
  per-user identity instead of "Unnamed user".
- **Settings → Teams board is more compact.** The "by user · team · keys" list is capped
  to ~10 rows and scrolls beyond that (so a long key list no longer stretches the page),
  each entry stays on one line, and a user's raw `user_id` (UUID) is now shown **only in
  the hover tooltip** — the inline label shows the human name (or "Unnamed user"), never a
  truncated UUID.
- **Settings → Teams: per-key ⟳ now lets LiteLLM win.** The **⟳** button re-detects a
  key's team from LiteLLM and **overwrites any saved override** with the freshly detected
  team (the endpoint drops the override so the detected value shows; the board reloads).
  This matches the operator expectation that clicking refresh overwrites the
  previously-defined name. To *set* a manual team, type it and click **✓** (save); to
  revert a key to what LiteLLM reports, click **⟳**. The per-key budget override is left
  untouched by ⟳.
- **Teams rendered as raw UUIDs ("strange numbers").** When `/team/list` couldn't resolve
  a key's `team_id` to a human alias (a transient failure, or a team with no alias),
  `key_budgets()` fell back to the raw `team_id` UUID as the team NAME — and the new
  `team_detect` persistence then saved that UUID, so the board stayed stuck on UUIDs even
  across restarts. Now: the collector never surfaces a `team_id` as a name (unresolved →
  blank, so the sticky cache keeps the last real alias); the team directory keeps a
  last-good `by_id`/`by_user` alias map and reuses it when `/team/list` blips; `_merge_team`
  rejects any UUID-looking value; and poisoned UUIDs are scrubbed from `team_detect` on load
  so they re-resolve to real aliases. Added `litellm._is_team_id()` (UUID detector).
- **Spend & Quota "top spenders" intermittently vanished.** When a *later* `/key/list`
  page timed out mid-walk, `key_budgets()` served only the pages fetched so far (e.g. the
  first 10 of 16 keys) AND overwrote its last-good cache with that partial set — so the
  by-key board flickered from 16 keys/12 spenders down to 10/7 and back on the next poll.
  Now a partial walk (a page failing mid-walk, or fewer keys than the server's reported
  `total_count`) is detected and the fuller last-good cache is reused instead of shrinking
  the board or poisoning the cache.
- **Cost-over-time smeared an external model's cost across days it never ran.** The daily
  estimate was `(that day's TOTAL tokens) × (a window-blended real $/token)`, so a single
  external model (e.g. `azure_ai/gpt-5-mini`, used only 3 days) showed "real (external)"
  cost on *every* day with traffic — because the blended rate was applied to each day's
  total token count (dominated by self-hosted usage). Now, when LiteLLM's
  `/global/activity/model` returns a per-model `daily_data` breakdown, the series computes
  each day's cost from THAT day's actual model mix (`per_model_daily_cost` →
  `apply_daily_cost`), so an external model's cost lands only on the days it ran. Falls
  back to the blended estimate when no daily breakdown is available; the response carries
  `cost_basis: "per-day" | "blended"` so the basis is visible. Applies to the chart, the
  per-year rollup, and the current-year cost card alike.
- **Teams not 100% assigned — `/key/list` pagination stopped after page 1.** LiteLLM
  caps `/key/list` at ~10 keys per page and (on some versions) returns no `total_pages`,
  ignoring our `size=100`. The walker's stop test was `len(page) < 100`, which is true for
  every capped 10-key page — so it broke after the first page and every key past #10 fell
  back to the team-less `/global/spend/keys` snapshot (`team=""`, `user=""`). Now it walks
  by the server's *actual* page size (prefers `total_pages`/`total_count`, else pages until
  a short page). `/user/list` in the team directory is likewise paginated via a new
  `_paginate` helper that de-dupes and stops if an endpoint ignores `page=`. A **Refresh**
  on the Settings Teams board re-detects and heals keys the cache had stuck at "no team".
- **Clear log on a rejected LiteLLM master key.** When the proxy answers `401/403` on
  the admin/spend endpoints (`/spend`, `/key/list`, `/global/activity`) the collector now
  emits a single, plain-language line — `[litellm] AUTH FAILED: LiteLLM rejected the
  master key … LITELLM_MASTER_KEY is invalid, expired, or not an admin/master key` — the
  first time auth flips bad (and an `AUTH OK` line when it recovers), instead of a wall of
  bare `HTTP 401` debug lines that only show under `LITELLM_DEBUG`. `collectors/litellm.sample()`
  also surfaces `auth_error: true` + a human `error` string so the dashboard/status can say
  *why* spend and teams are empty. This is the case where a key still lists `/v1/models`
  but is refused the admin endpoints — it authenticates as a proxy key yet is not a valid
  master key.
- **Spend date parsing.** LiteLLM's `/global/activity` daily rows use the display date
  `Jul 02` (month-abbrev, no year); `collectors/litellm._norm_date` now normalizes it
  (plus ISO, `YYYY/MM/DD`, epoch) to canonical `YYYY-MM-DD` so daily rows are no longer
  dropped. Spend-report calls cap `end_date` to today and fall back across variants for
  the (Enterprise) case where the endpoint is available.

### Changed
- **`/api/spend/series?diag=1`** returns a per-variant attempt matrix for the spend
  report (status, top-level keys, row count, has-spend, sample), and also probes
  `/global/activity/model`, `/global/spend/tags`, `/global/spend/report` (no dates),
  and `/global/spend/keys` — so it reports whether ANY daily-spend source is alive on
  a given LiteLLM.

### Packaging
- Added `web/spend.html` and `web/settings.html` to the `deploy/publish-github.sh`
  ALLOW-list — they were omitted, so the published tree lacked them and CI failed
  (`/spend` 500 + `FileNotFoundError` in the static page tests).
## [1.5.4] — 2026-07-10

### Fixed
- **Key teams now resolve via the user.** A LiteLLM key's team is read key →
  `team_id` → **user**: if the key carries no team but has a `user_id`, its team is
  taken from that user's team membership, and a bare `team_id` UUID is mapped to its
  human alias — matching what the LiteLLM UI shows (e.g. `AppSec`). Backed by
  `/team/list` + `/user/list` (master-key). The Settings → Teams board now shows
  **key → user → team**, and the Spend & Quota by-team rollup groups on the resolved
  team. (`LITELLM_DEBUG=1` logs `teams=/users_mapped=` for diagnosis.)

### Fixed
- **Spend chart empty even after the 500 fix** — the date parser only understood
  `YYYY-MM-DD`, so any other format from LiteLLM (ISO datetime, `YYYY/MM/DD`, or a
  numeric epoch) dropped every row → `available:true` but zero points. `_date_epoch`
  now parses ISO datetimes and epoch seconds/millis too.
- **Token-in-URL navigation.** When a page is opened with `?token=`, internal links
  (sidebar + in-page) now carry the token forward so navigation stays authenticated;
  with a session cookie (no token) links stay clean.

### Added
- **`/api/spend/series?diag=1`** — a viewer-safe diagnostic that returns the raw
  daily rows the collector received (count, a 3-row sample, and any dates it couldn't
  parse), so an empty Spend chart can be diagnosed from the browser without the
  LiteLLM master key or container logs.

## [1.5.3] — 2026-07-10

### Added
- **Settings page (`/settings`, admin-only) — runtime-tunable config.** A curated,
  **non-secret** subset of `.env` (alert thresholds; sample interval; raw/audit
  retention; GPU file-age; LiteLLM SLO, spend window, heavy-poll interval, spend
  mode, circuit-breaker) is now editable from the UI, **applied live (no restart)**
  and **persisted** across restarts, overriding the env defaults. Backed by a
  `settings` table + `config.tunable()` overlay; validated (type + bounds +
  choices), CSRF-protected, audited (`settings.update`/`settings.reset`), with a
  per-key **Reset to default**. Secrets, ports, backend URLs and security switches
  (`ALLOW_OPEN`, `COOKIE_ALLOW_INSECURE`, `AUTH_TRUSTED_PROXY`) are deliberately
  **not** exposed. `GET/POST /api/admin/settings`.
- **Team management (Settings → Teams).** Assign each LiteLLM key to a team for the
  Spend & Quota by-team rollup. **LiteLLM team *budgets* are a LiteLLM Enterprise
  feature**, so team grouping is managed here: the board shows each key's
  LiteLLM-**detected** team and an admin **override** that wins over it (Reset falls
  back). `key_teams` table + `GET/POST /api/admin/teams` (admin, CSRF, audited);
  applied in `merge_key_budgets` so the by-team rollup honours it.
- **Admin-only sidebar link.** `/api/nav` now returns `admin`; the **Settings** link
  shows only for an admin session.

### Fixed
- **Spend endpoint returned 500 on real LiteLLM data.** The daily parser assumed
  `YYYY-MM-DD` dates and numeric spend; a different date format (`/` or ISO
  datetime) or a string/None value from `/global/spend/report` raised and 500'd the
  page. Dates are now parsed tolerantly (`-`/`/`/`T` separators), values coerced,
  unparseable rows dropped, and the handler wrapped so it degrades to an empty
  chart with a clear message instead of a 500.

## [1.5.2] — 2026-07-10

### Fixed
- **Spend-over-time chart was empty against real LiteLLM.** `spend_activity` read the
  daily rows from `data`, but LiteLLM nests them under **`daily_data`** (and
  `/global/activity` carries no spend). The parser is now shape-tolerant
  (`daily_data`/`data`/`results`, aliased field names) and falls back to
  `/global/spend/report` for daily spend. The empty-state message now names the real
  cause (LiteLLM connectivity) instead of talking about the real/reference split.
- **Model classification mislabelled self-hosted models as external.** A blank/absent
  model name was counted as **real** external spend; bare open-weight names (e.g.
  `gemma4`) had no provider prefix and defaulted to external. Now a blank model is
  **`unknown`** (never real/reference), and open-weight FAMILIES
  (`MONITOR_INTERNAL_MODEL_FAMILIES`: gemma/qwen/mistral/deepseek/…) classify as
  self-hosted reference.

### Added
- **Usage mix (real vs reference by tokens/requests) — works in lite mode.**
  `/api/litellm/models` returns a `usage` split (real/reference/unknown by tokens +
  requests) and the Per-model card shows a mix bar + headline
  (e.g. *“98% of tokens self-hosted (reference) · 2% external (real)”*) plus a
  self-hosted / external / unattributed chip per row. This tells the real/reference
  story even when per-model **cost** is unavailable (lite mode).

## [1.5.1] — 2026-07-10

### Added
- **Budgets are read from LiteLLM itself.** `key_budgets()` queries
  `GET /key/list?return_full_object=true` (master-key) for each key's real
  `max_budget`, `spend`, and team, so the Spend & Quota page fills in with **zero
  configuration**. `MONITOR_KEY_BUDGETS` still works and now acts as an explicit
  **override**; a LiteLLM without `/key/list` falls back to it. `/api/budgets`
  reports which source it used via `budget_source` (`litellm` / `env` / `none`).

### Fixed
- **Keys with no budget were silently hidden.** `budget_rows` skipped any key whose
  budget was 0, so uncapped spend simply disappeared from the page. Such keys are
  now **always listed** — spend, reference cost and burn/day are shown, with
  `budget`/`pct`/`days_to_cap` = `null` and status `none`, ranked after the budgeted
  keys. The gap is surfaced rather than hidden: a **callout** names how many keys
  are unbudgeted and how much real spend is uncapped, the summary reads *“N of M
  keys budgeted”*, team cards show `N unbudgeted`, and each row carries a **“No
  budget”** pill. So the bar still renders, an unbudgeted key is drawn against an
  **implied baseline = the month's top spender** (`implied_budget`/`implied_pct`),
  shown muted + hatched with a `ref*` label and a footnote. The baseline is purely
  visual: `budget`/`pct`/`days_to_cap` stay `null`, it consumes no quota and never
  triggers a cap alert.
- **Misleading empty state.** It told operators to “set per-key max_budget in
  LiteLLM”, which was never implemented. It now names what actually works
  (`LITELLM_BASE_URL` + `LITELLM_MASTER_KEY`; budgets optional) — and, with the
  `/key/list` read above, the original promise is now true.

## [1.5.0] — 2026-07-10

### Added
- **New “Spend & Quota” page (`/spend`) — the LLM-cost landing.** A dedicated,
  first-in-the-sidebar page that leads with the money story: a real-cash summary
  strip, a **spend-over-time** chart (30-day daily / 12-month monthly toggle) with
  **year-to-date per-year totals**, a **by-team** budget rollup, and a **per-key
  budget** table ranked closest-to-cap first. Backed by `GET /api/budgets` (per-key
  `spent`/`budget`/burn/days-to-cap/projected/status) and `GET /api/spend/series`
  (`bucket_spend` → day/month buckets + per-year rollup). Optional per-key budgets
  via `MONITOR_KEY_BUDGETS`; real `max_budget` from LiteLLM `/key/info` is the
  production source.
- **Real (external) vs reference (internal) cost split.** Self-hosted models
  (Ollama / llama.cpp / vLLM / open-weights) carry only an imputed **reference**
  cost — no real cash — while external hosted APIs are **real spend**.
  `classify_model()` detects this from the model's provider prefix / name
  (configurable via `MONITOR_INTERNAL_PROVIDERS`). Budgets cap **real** cash only;
  reference cost is shown alongside but never consumes budget. The split runs
  through the whole page (summary, teams, per-key, the stacked spend chart, and the
  per-year tiles) and reconciles exactly (reference = total − real).

### Fixed
- **Per-year total covered only the window, not the year.** On the 30-day view the
  “2026 total” summed just the 30-day slice; per-year totals now always cover the
  full year (`window_and_years`), while chart points still follow the selected
  window.
- **Per-key budget table spilled out of its card** on narrow widths; it now scrolls
  inside its own `overflow-x:auto` container with non-wrapping headers.

## [1.4.3] — 2026-07-09

### Hardening
- **Last-admin guard is now atomic (defense-in-depth).** The "you can't remove the
  last admin" rail in `POST /api/admin/users/action` previously read the admin
  count and then mutated in separate steps. It is not exploitable on the current
  single-threaded event loop (the count read and the write are synchronous with no
  `await` between them, so concurrent requests are serialized) — but the invariant
  is now enforced *inside* the write via `db.user_{update,disable,delete}_guarded`
  (`… WHERE … AND (SELECT COUNT(*) FROM users WHERE role='admin') > 1`), so it holds
  regardless of the concurrency model (e.g. if a mutation is ever moved to
  `asyncio.to_thread` or run under multiple workers). No behavioural change; adds
  `test_last_admin_guard_is_live_counted_not_stale` +
  `test_last_admin_guard_survives_concurrent_demote`.

### Fixed
- **Ollama dashboard was missing the 12-month window.** It only offered
  15m/1h/24h/30d (no `12mo` button, and `12mo` absent from its `WSECS` map so pan
  would break) — the one page the "12mo on all graphs" pass skipped. Added the
  button + `WSECS` entry; its charts already support the year window server-side.

### Tests
- **Window-card QA guards.** `test_all_windowed_pages_have_full_window_set`
  enforces the full 15m/1h/24h/30d/12mo button set + `12mo` in `WSECS` on every
  windowed page. `test_every_windowed_loader_is_in_the_reload_path` asserts every
  JS loader that fetches a `?window=` endpoint is called from `rangedReload` — so a
  card can never silently ignore the selector again (the Per-model regression
  class; verified to flag a synthetic break).

## [1.4.2] — 2026-07-09

### Fixed
- **Per-model table now follows the time window.** It was a fixed collector
  snapshot (lite mode = today-only via `/global/activity/model?start_date=today`;
  full mode = last `LITELLM_SPEND_WINDOW_MIN` = 15 min) and ignored the
  15m/1h/24h/30d/12mo selector, so switching to 24h never showed yesterday. New
  `GET /api/litellm/models?window=…` queries LiteLLM's pre-aggregated per-model
  endpoint for the selected date range (day-granular: 24h opens yesterday, 30d/12mo
  open prior months) — the cheap aggregate, **not** the heavy `/spend/logs`. The
  table reloads on window change / pan / Live and shows requests + tokens over the
  window plus the live serving-process CPU/RAM. Header shows the active window.
  Per-model latency/cost still require `spend_mode=full` (KPI tiles).

## [1.4.1] — 2026-07-09

### Security
- **Alert config requires authentication — always.** The Alerts page and
  `/api/alerts*` now return **403** when the dashboard is opened without auth
  (`MONITOR_ALLOW_OPEN` / no token + no users), so webhook URLs and thresholds are
  never exposed unauthenticated. The sidebar **Alerts** link is shown only to a
  real login session (hidden for token/PAT access and open mode — no dead link
  that just 403s). Token/PAT access to alerts is unchanged (master token = admin,
  PAT = its role).

### Fixed
- **Reverse-proxy sub-path login.** `_apply_prefix` now also rewrites the login
  form `action="/login"` and the account page's `location.href="/"` redirect, so
  behind `X-Forwarded-Prefix` (e.g. `/ai_monitoring`) the login POST and
  post-password-change nav stay inside the sub-path instead of hitting the proxy
  root.
- **12-month axis showed a bogus “day”.** The `12mo` label used a 2-digit year
  (`Jul 25`) that read as *July 25th*; the axis is now span-aware (`axisT`) and
  renders `Jul '25` for a year span, `Jul 8` for a multi-day span, `HH:MM` for a
  short span — chosen from the data span, not the window name.
- **Uptime card no longer shows an empty tile.** When a window has no backend
  history the whole card is hidden (self-healing when data returns).
- **CI lint annotation (vulture exit 3).** The GPU SSRF-guard override
  (`_NoRedirect.redirect_request`) had unused `*args/**kwargs`; renamed to
  `*_args/**_kwargs`. Runtime behavior unchanged; now regression-tested.

### Added
- **12-month (`12mo`) time window on every graph** (host, GPU, llama.cpp,
  LiteLLM), backed by the 1-hour rollup tier (365-day retention).
- **Token / PAT access hides the Alerts link** (see Security).

## [1.4.0] — 2026-07-08

### Added
- **Overview leads with an “LLM usage & cost” summary.** A new hero strip at the
  top of the Overview — above the host/GPU/container panels — surfaces the numbers
  the tool is really about: **spend (window)**, **cost rate ($/h)**, **tokens**
  (today's total, or in+out throughput), **requests** (+ per-second rate), and
  **active API keys**. It binds to the existing LiteLLM snapshot, degrades tile by
  tile across lite/full spend modes (each falls back to `—`), links to the full
  LiteLLM dashboard, and hides entirely when no LiteLLM backend is configured
  (pure-infra deployments look unchanged). Rendered through the sanitized `setHtml`
  sink — no new `innerHTML`. This repositions the dashboard as LLM-usage
  observability first, system monitoring second.

### Docs
- **README repositioned.** Tagline now leads with *LLM usage, cost, and
  infrastructure observability*; added a **“What it is / isn’t”** note clarifying
  it tracks self-hosted LLM spend/tokens/keys (via LiteLLM) — not third-party SaaS
  subscription billing — and that per-key **budgets** are on the roadmap.

### Fixed
- **Time-axis labels repeated the same month on long windows.** The chart label
  formatter chose its granularity from the *window name* (`12mo`/`30d`), so a 12mo
  view holding only a few days of history drew the identical `Jul '26` on every
  tick (and `30d` similarly). Replaced with `axisT(pts)`, which picks granularity
  from the **actual span of the plotted data**: > 180 d → month + year
  (`Jul '26`), > 2 d → month + day (`Jul 3`), else time-of-day. So five days of
  history on a 12mo axis now reads `Jul 3 … Jul 8`, while a full year still
  collapses to distinct months. Applied to every windowed dashboard (Overview,
  GPU, Ollama, llama.cpp, LiteLLM); single-timestamp uses (event rows) keep the
  plain time formatter.
- **`scripts/demo_seed.py` 500 on every page.** Its theme-shim wrapper still used
  the old `_serve_page` signature and didn't forward the `user`/`role` kwargs the
  app now passes, so the seeded demo server returned 500. The wrapper now forwards
  `**kw`.

## [1.3.3] — 2026-07-08

### Added
- **12-month (`12mo`) time window on every graph.** All windowed dashboards
  (host, GPU, llama.cpp, LiteLLM) gain a **12mo** button alongside 15m/1h/24h/30d.
  It reads the 1-hour rollup tier (365-day retention) and is downsampled to ~300
  buckets (~29 h each), so a year of history renders without touching raw rows.
  Server accepts `window=12mo` on every series endpoint via `db.WINDOWS`.

### Fixed
- **30d/12mo x-axis showed no dates.** The chart label formatter emitted
  time-of-day only (`HH:MM`), so long windows were an unreadable run of repeating
  times. `fmtT` is now window-aware: **30d** labels show a calendar date
  (`Jul 8`), **12mo** show month + year (`Jul '26`); shorter windows keep `HH:MM`.

### Changed
- **Dependency + toolchain bumps (Dependabot).** Test toolchain moved to
  `pytest>=9.1.1,<10` and `pytest-asyncio>=1.4.0` (full suite green on the new
  majors); runtime base image bumped to `python:3.14-alpine`; CI actions bumped —
  `actions/checkout@v7`, `aquasecurity/trivy-action@v0.36.0`,
  `docker/setup-qemu-action@v4`, `docker/setup-buildx-action@v4`,
  `docker/login-action@v4`, `docker/build-push-action@v7`.

### Fixed
- **CI Trivy filesystem scan.** Added a documented `.trivyignore` accepting
  `AVD-KSV-0010` (node DaemonSet `hostPID: true`) — it is required by design for
  the host-process (top-N CPU/RAM) collector, not a defect. The image scan was
  already clean; this unblocks the filesystem-scan job that had been red on every
  push.

## [1.3.2] — 2026-07-06

### Added
- **LiteLLM “Top 10 API keys — requests in window” timeline.** A new line chart next
  to *Top 10 API keys over time* that plots the **cumulative requests during the
  window** — a running total from the window start, so the line climbs from ~0 to each
  key's window total and a key with no new activity (1000 → 1000) stays a **flat 0
  line**. Top-10 ranked by total net requests over the window; follows the
  window/pan/**Live** controls. Backed by `GET /api/keydelta` + `db.key_delta_series`
  (tiered raw/1m/1h like the over-time chart; sums per-bucket increases, reset-safe — a
  mid-window daily counter reset contributes that bucket's own value instead of a
  negative step).
- **“Live” button on the time window.** Every windowed dashboard (Overview, LiteLLM,
  GPU, Ollama, llama.cpp) gains a **Live** button next to the ◀ ▶ pan arrows that snaps
  the view straight back to the current time (`TIMEEND=null`) instead of paging forward
  one window at a time. It is disabled (greyed) while already live and highlights in the
  accent colour once you've panned into history.
- **Per-user API tokens (personal access tokens).** Every user can mint their own
  bearer tokens from *Account* → *API tokens* for scripts / the API
  (`Authorization: Bearer aimon_pat_…`). A **viewer** can only create **viewer**
  (read-only) tokens; an **admin** chooses the token's permission (viewer *or* admin).
  A token carries its own role, so a viewer's token can never reach an admin endpoint
  (enforced server-side — the role field is ignored for non-admins). The raw secret is
  shown **once** at creation; only its SHA-256 is stored. Tokens are listed with
  label / role / prefix / last-used, revocable instantly, capped at 20 per user, and
  stop working the moment the owner is disabled or deleted (cascade). Backed by
  `GET/POST /api/account/tokens` and `POST /api/account/tokens/revoke` (session-only,
  CSRF-protected); create/revoke are audited (`token.create`, `token.revoke`).
- **Per-account login lockout.** In addition to the existing per-IP throttle, an
  account is now locked after **10 failed password attempts** (within
  `MONITOR_AUTH_WINDOW_S`) for **5 minutes** — every further login for that username,
  *including with the correct password*, is refused (`/login?e=locked`) until it
  expires. This protects a targeted account even when the attacker rotates source IPs
  (the per-IP lock alone wouldn't). A successful login clears the counter; the lock is
  logged (`[auth] account LOCKED user=…`). Tunable via `MONITOR_AUTH_USER_MAX_FAILS`
  (10) and `MONITOR_AUTH_USER_LOCKOUT_S` (300). Counting an unknown username the same
  as a real one keeps the lock from leaking which accounts exist.
- **Forced first-login password change.** A user created by an admin (or whose
  password an admin **resets**) is flagged `must_change_pw` and, on their next login,
  is sent to `/account` and **confined** there — every page redirects back to it and
  every API call returns `403` until they set their own password. Clearing it is
  automatic on a successful self-service change (`POST /api/account/password`), which
  also lifts the gate on the live session. The admin *User management* table shows a
  **“reset pending”** badge for anyone who hasn't reset yet. The env-seeded bootstrap
  admin is exempt (the operator chose that password deliberately). New DB column
  `users.must_change_pw` (idempotent `ADD COLUMN`, default `0`); `/api/me` exposes the
  flag so the account page can render the lock banner. Because the column defaults to
  `0`, users that existed **before** this feature are not retroactively flagged — use
  **Force reset** (below) to require them to reset.
- **Admin “Force reset” action.** A per-row button in *User management* flags a user
  `must_change_pw` and ends their active sessions immediately, forcing them to choose a
  new password on next login **without** the admin setting one (their current password
  keeps working only to reach `/account`). This is how you apply the reset rule to
  pre-existing accounts. Backed by the `force_reset` action on
  `POST /api/admin/users/action` (admin-only, CSRF-protected, audited as
  `user.force_reset`); the button hides once a user is already pending.
- **Server-side error logging.** Every error is now recorded to the server's stderr
  (`docker logs`), never the normal `200` traffic: failed/locked-out logins
  (`[auth] login FAILED user=… ip=…`), denied writes (`[deny] METHOD /path -> 4xx ip=…`
  for `400/403/409/413/415/429`), and unhandled exceptions (`[error] … -> 500` with a
  full traceback). Implemented as an outermost `_log_mw` middleware plus an explicit
  log on the login-fail redirect. No new configuration.
- **Edit a user's profile.** Admins can now change an existing user's **email and
  role** inline from *User management* → the per-row **Edit** button turns the email
  and role cells into an input + a viewer/admin dropdown (Save / Cancel). Backed by
  the `update` action on `POST /api/admin/users/action` (admin-only, CSRF-protected):
  it validates the email + role, refuses to demote the **last** admin, and is audited
  as `user.update`. A role change takes effect on the target's next request (roles are
  revalidated per request). The editor is built with DOM APIs (no `innerHTML`).

### Fixed
- **“CPU usage by app (stacked)” phantom bands.** An app that had no sample in a time
  bucket (process absent / not in the top-N then) was left out of that point, so the
  frontend saw `null` and — with `spanGaps` on — drew a straight diagonal across the
  gap, producing huge phantom stacked bands. `db.proc_series` now densifies every
  bucket (absent app → **0**), and the chart maps missing → `0` with `spanGaps:false`,
  so an absent process draws a flat 0.
- **GPU stuck at 0% (file mode).** The host-side `gpu-metrics.service` writer moved
  into a standalone script (`deploy/gpu-metrics-writer.sh`): an *inline* systemd
  `ExecStart` mangles a literal `%` (a unit specifier), which silently corrupted the
  embedded `awk` (`printf "%d"`) and crashed the writer, **freezing the CSV** on the
  last value — a dashboard stuck at 0% even under load. The writer now also (1) reads
  **`nvidia-smi dmon`-averaged** utilization instead of the instantaneous
  `utilization.gpu` point, which bursty LLM load aliases to ~0; (2) wraps every
  `nvidia-smi` call in `timeout` so a D-state hang under GPU load can't freeze the
  loop; and (3) sets an explicit `PATH` + a `sleep` floor. Docs lower the recommended
  `GPU_FILE_MAX_AGE` to `30` so a dead writer surfaces as *unavailable* fast instead
  of showing a frozen reading for minutes.

## [1.3.1] — 2026-07-06

### Security
Hardening from a secure code review of the 1.3.0 additions (no Critical/High):
- **M1 — `/metrics` can't be broken by a non-finite value.** `metrics_prom` now skips
  `inf`/`nan` gauges — those render as invalid Prometheus floats (it wants +Inf/NaN)
  and a single bad line makes Prometheus reject the WHOLE scrape, silently dropping
  every metric for the instance. (Guard: `test_metrics_skips_non_finite_values`.)
- **M2 — Kubernetes pods hardened to the restricted Pod Security Standard.** The
  Deployment/DaemonSet + Helm chart now set `allowPrivilegeEscalation: false`,
  `readOnlyRootFilesystem: true` (with writable `/data` + `/tmp` volumes),
  `capabilities.drop: [ALL]`, and `seccompProfile: RuntimeDefault`; plus an optional
  `NetworkPolicy` (Helm `networkPolicy.enabled`, and a commented template in the raw
  manifests) to restrict who can reach the dashboard/metrics.
- **L1 — `/metrics` now honours the brute-force lockout.** A presented-but-wrong
  token on `/metrics` counts as a strike (was exempt because the path self-gates
  outside the auth middleware); a locked-out IP gets 429. (Guard:
  `test_metrics_endpoint_enforces_lockout`.)
- **L2 — demo stack insecure toggles clearly flagged.** `deploy/prometheus-example`
  now carries prominent "LOCAL DEMO ONLY — do not deploy as-is" warnings on the
  `MONITOR_COOKIE_ALLOW_INSECURE`, Grafana `admin/admin`, and placeholder-secret lines.

## [1.3.0] — 2026-07-06

### Added
- **Prometheus / OpenMetrics export.** `GET /metrics` exposes the latest snapshot as
  `aimon_*` gauges (host CPU/mem/disk/load, per-GPU util/power/temp/VRAM, per-backend
  `aimon_backend_up`, LiteLLM req/token/cost/latency, llama.cpp tokens-per-second /
  KV-cache / slots, Ollama, per-container `aimon_container_up`, top-N process CPU,
  user/session/alert counts). An existing **Prometheus / Grafana / Datadog /
  AlertManager** stack can scrape it, and a central Prometheus can aggregate a whole
  **fleet** of instances. Gated like the API (session / dashboard token / a dedicated
  scrape-only `MONITOR_METRICS_TOKEN`); toggle with `MONITOR_METRICS_ENABLED`.
- **Kubernetes / multi-node deployment.** A **Helm chart** (`deploy/helm/ai-monitoring`)
  and plain manifests (`deploy/k8s/`) run AI-Monitoring centrally (Deployment) or
  **one pod per node** (DaemonSet, `hostPID` + hostPath GPU CSV), with a
  **ServiceMonitor** for Prometheus Operator and a ready-made **Grafana dashboard**
  (`deploy/grafana/ai-monitoring-dashboard.json`) that aggregates the fleet by
  `instance` — the standard per-node-agent + central-Prometheus fleet pattern.

## [1.2.3] — 2026-07-05

### Security
- **Internal-identifier leak scrubbed + gate hardened.** A validation pass over the
  public repo found two low-severity internal-identifier disclosures (no secrets):
  a private SSH-remote alias named in a test docstring, and the corporate author
  email (employer domain + employee id) baked into commit metadata by the publisher
  falling back to the machine's `git config user.email`. Fixed: the docstring no
  longer names the alias; the publisher now commits with a **fixed public identity**
  (never the machine's git config — overridable via `GIT_NAME`/`GIT_EMAIL`); the
  pre-publish gate's marker list now also blocks the alias + employee id; and the
  leak-regression test scans `tests/` too (fixture literals stay in the unpublished
  `tests/_internal_markers.py`). Note: HEAD is clean going forward — existing history
  still carries the old author email until a history rewrite (see `validation/1.2.3.md`).

## [1.2.2] — 2026-07-05

### Added
- **Per-user alert webhooks.** Each user configures **their own** webhook at
  `/account` (Slack / Discord / generic JSON POST) with an enable toggle and a
  *Send test* button. When an alert fires, the notifier fans out to every enabled
  webhook (of non-disabled users) **plus** the operator-set global
  `ALERT_WEBHOOK_URL` (backward compatible); recipients are resolved + validated
  once per tick. Backed by `GET/POST /api/account/webhook` and
  `POST /api/account/webhook/test` (session-only, CSRF-protected); set/test are
  audited (`webhook.set`, `webhook.test`).

### Security
Per-user webhooks are user-supplied, so they are **SSRF-guarded**: a URL is refused
(on save **and** re-checked before each send — DNS-rebinding aware) when it resolves
to a private / loopback / link-local / reserved / metadata address; only `http(s)`
schemes are allowed and redirects are not followed. Opt-in hardening:
`MONITOR_WEBHOOK_HTTPS_ONLY=1`, host allowlist `MONITOR_WEBHOOK_ALLOW_HOSTS`, and
`MONITOR_WEBHOOK_ALLOW_PRIVATE=1` to relax the block on a trusted LAN. The
operator-set global `ALERT_WEBHOOK_URL` is trusted and unchecked.

Plus hardening from a full secure code review (no Critical/High found; these close
the Medium/Low findings). No functional change — all existing auth/cookie/stream/login
flows are unchanged and regression-tested (`test_sec_*`).
- **Opaque legacy-token cookie.** The `aimon_session` cookie now holds a random
  server-side session id instead of the master token itself, so cookie theft or a
  mis-logged `Set-Cookie` can no longer leak the raw shared secret.
- **Collector response size cap.** `fetch_json` caps a backend body at
  `MONITOR_HTTP_MAX_BYTES` (16 MiB) *before* deserialising, so a compromised/MITM'd
  backend can't stream a huge body and OOM the monitor. Outbound calls also stop
  following redirects (`allow_redirects=False`; urllib `_NoRedirect` for the GPU
  HTTP feed) — an SSRF-to-metadata guard.
- **Open-redirect fixed.** `_safe_path`/`_login_dest` now reject a backslash, so
  `?next=/\evil.com` (which browsers normalise to `//evil.com`) can't bounce a user
  off-site.
- **Alerts test is admin-only + CSRF.** `POST /api/alerts/test` now requires the
  admin role and a CSRF token (was reachable by any logged-in viewer); the *test*
  button is hidden for non-admins.
- **Login timing equalised.** An unknown username now runs a decoy scrypt verify,
  removing the response-time side-channel that revealed which usernames exist.
- **Weak shared token refused at boot.** `validate()` now rejects a
  `MONITOR_DASHBOARD_TOKEN` shorter than 16 chars (was only a skippable warning).
- **Bounded auth/session state.** Server-side sessions are hard-capped
  (`MONITOR_SESSION_MAX`, default 2000, oldest-expiring evicted) and the per-IP
  brute-force maps are pruned, so neither can grow without bound.
- **SSH argument-injection hardening.** The GPU-over-SSH command refuses a host or
  key path beginning with `-` and inserts `--` before the host, so a config value
  like `-oProxyCommand=…` can't be parsed by `ssh` as an option.
- **Webhook SSRF: DNS-rebinding closed + CGNAT blocked.** Per-user webhooks now send
  over a dedicated session whose resolver re-checks the IP aiohttp actually connects
  to (`ttl_dns_cache=0`), so a low-TTL rebind after validation can't reach an internal
  host; the checked IP is the connected IP. `_ip_blocked` also rejects RFC 6598 CGNAT
  (`100.64.0.0/10`) and collapses IPv4-mapped IPv6. The `WEBHOOK_ALLOW_PRIVATE` opt-in
  is still honoured for trusted-LAN targets.
- **Webhook fan-out can't wedge the sampling loop (§6).** Per-user webhook resolution
  + delivery is now capped (`MONITOR_WEBHOOK_MAX_RECIPIENTS`, default 50), run
  concurrently, and time-boxed (`HTTP_TIMEOUT` per validate); the notifier tick is
  wrapped in a 15 s `wait_for`. A user pointing their webhook at a slow/blackholed
  host can no longer stall monitoring for everyone. The webhook POST is also released
  via `async with` (was leaking connections).
- **Auth lockout no longer self-locks the operator.** An expired opaque session
  cookie on an auto-polling dashboard is no longer counted as a brute-force strike —
  only a presented (guessable) bearer/query token is. A 256-bit session cookie can't
  be brute-forced, and counting an expired one locked the operator's own IP out.

## [1.2.1] — 2026-07-05

### Added
- **Self-service password change.** Every logged-in user (admin or viewer) now has
  an *Account* link in the sidebar → `/account`, where they can change their own
  password. Changing it **requires the current password** (proves it's really them)
  plus a policy-valid, different new one. On success the user's other sessions are
  signed out (the current one stays); the change is audited as `account.password`
  (and a wrong current password as `account.password.fail`). Backed by
  `GET /api/me` (session identity + CSRF) and `POST /api/account/password`
  (CSRF-protected, session-only — a bearer token is not a person).

## [1.2.0] — 2026-07-05

### Added
- **Audit trail.** The platform now records access + admin actions to a SQLite
  `audit_log` table, and admins review them in the *Activity log* section of
  `/admin/users` (filter by logins / user changes). Logged events: `login.ok`,
  `login.fail`, `login.lockout`, `logout`, and `user.create` / `user.disable` /
  `user.enable` / `user.delete` / `user.reset` — each with actor, target, client
  IP, and timestamp. Read via `GET /api/admin/audit` (admin-only). Rows are pruned
  by age (`MONITOR_AUDIT_RETENTION_DAYS`, default 90) alongside the metrics prune.

## [1.1.0] — 2026-07-05

### Added
- **Multi-user access (username + password login).** External users no longer
  share one token. Each account has a username, an **email**, a scrypt-hashed
  password (`hashlib.scrypt` — no new image dependency), and a role:
  - **admin** — full dashboard access **plus** a *Users* menu to create, disable,
    reset-password, and delete users (view-only or admin).
  - **viewer** — read-only dashboard access.
  Accounts live in SQLite (`users` table); admins manage them from `/admin/users`
  (UI) or `/api/admin/users` (JSON). The first admin is seeded from
  `MONITOR_ADMIN_USER` / `MONITOR_ADMIN_PASSWORD` / `MONITOR_ADMIN_EMAIL` on an
  empty users table (idempotent).
- **Login/session flow.** `/login` + `/logout`; server-side sessions
  (`aimon_user` cookie: HttpOnly, SameSite=Strict, Secure by default per F3),
  revalidated against the DB every request so disabling/deleting a user takes
  effect immediately. Login is IP rate-limited (reuses the F4 lockout). Session
  TTL via `MONITOR_SESSION_TTL_S` (default 7 days).
- Admins get a **Users** link + a **Logout** link injected into the sidebar;
  viewers see only Logout.

### Security
- Admin write endpoints are **CSRF-protected** (per-session token via
  `X-CSRF-Token`); bearer-token automation is exempt (not a browser-auto cookie).
- The last remaining admin cannot be disabled or deleted (lock-out guard).
- The legacy single `MONITOR_DASHBOARD_TOKEN` keeps working alongside user login
  (counts as admin for automation/bootstrap). F2 now treats *either* a token *or*
  at least one user account as configured auth.

## [1.0.7] — 2026-07-04

### Security
Internal secure code review hardening (no remotely-exploitable bug found; these
raise the floor and shrink blast radius):
- **F1 — Docker socket no longer host-root-by-default.** A `:ro` socket mount does
  not make the Docker API read-only. `docker-compose.yml` now runs a read-only
  `docker-socket-proxy` (allows only `GET /containers`) and the monitor reaches it
  over TCP via `MONITOR_DOCKER_API_URL`; the raw socket is not mounted into the
  monitor. Legacy direct-socket mode still works when the URL is unset.
- **F2 — no-token no longer boots silently open.** Running without
  `MONITOR_DASHBOARD_TOKEN` now fails config validation unless `MONITOR_ALLOW_OPEN=1`
  is set explicitly, so a forgotten token can't silently expose metrics.
- **F3 — session cookie is `Secure` by default.** The cookie carries the bearer
  token; it is now marked `Secure` unless `MONITOR_COOKIE_ALLOW_INSECURE=1`
  (local plain-HTTP testing only).
- **F4 — lockout no longer evadable via `X-Forwarded-For`.** With
  `AUTH_TRUSTED_PROXY=1` the client IP is now taken from the rightmost XFF entry
  (appended by the trusted proxy), so a client can't spoof a leftmost value to
  dodge the lockout or frame a victim IP.
- **F5 — CSP `script-src` uses a per-response nonce instead of `'unsafe-inline'`.**
  Inline `<script>` tags are stamped with a fresh nonce; an injected script without
  it won't execute. `style-src` keeps `'unsafe-inline'` for benign inline styles.

## [1.0.6] — 2026-07-04

### Added
- **gitleaks in the CI secret-scan** — a second, independent secret scanner now
  runs alongside TruffleHog in the `secret-scan` job, driven by a `.gitleaks.toml`
  (built-in rule set + an allowlist for the synthetic values in `tests/` and
  `.env.example`, which are the only non-real "secrets" committed). Fails the job
  on any leak in the working tree or commit history.

### Fixed
- **ruff E702 in `collectors/host.py`** — the `cpu_cores` parse used a
  `…; break` one-liner; split so `ruff check .` stays clean (source is strict;
  E70x are only relaxed under `tests/`).

### Docs
- **`ARCHITECTURE.md` brought in line with the code** — documents the `containers`
  collector, the **decoupled backend loops** (`_backend_loop` + `asyncio.wait_for`
  → `_backend_latest`) that keep a wedged `nvidia-smi`/proxy from stalling the tick,
  the `/api/stream` SSE channel + `/api/events` model timeline, the per-IP auth
  brute-force lockout, and that the per-deployment LiteLLM `/health` probe was
  removed (+ `spend_mode=lite` aggregates). Version bump cuts a clean release.

## [1.0.5] — 2026-07-04

### Tests
- **+7 QA tests** for the 1.0.5 changes: sidebar order (Overview→GPU→LiteLLM),
  full-width "metrics over time" (regression), default 24h window on the LLM pages,
  GPU name rendered in the header via `textContent` (security — no new HTML sink),
  the window start→end date range wiring, the Apache-2.0 LICENSE + README + publish
  allow-list, and the consolidated `ci.yml` (five control jobs + a badges job, old
  split workflows removed, per-control README endpoint badges).

### Changed
- **CI consolidated into one workflow with per-control badges** — the five split
  workflows were merged back into a single `ci.yml` (secret-scan / lint / tests /
  trivy-fs / build-scan run as jobs), so the Actions page shows **one aggregated
  run per push**. A final `badges` job writes each control's status as a shields
  "endpoint" JSON to an orphan `badges` branch, so the README keeps **individual
  per-control badges** (plus one overall CI badge). No third-party services.
- **Publish auto-tags the release** — after a successful `publish-github.sh` push,
  it pushes an annotated `v<version>` tag (unless it already exists, or
  `SKIP_TAG=yes`), which triggers the release workflow. Commit subjects are
  version+timestamp stamped so each push is distinct.
- **Full-width "metrics over time"** — the charts card on the GPU and LiteLLM
  dashboards now spans every grid column (`grid-column: 1 / -1`) instead of two,
  so on wide screens it uses the whole width instead of ~50%.
- **Default time window is now 24h** on the LiteLLM, Ollama, and llama.cpp
  dashboards (was 1h) — their charts open on a full day by default; the 15m / 1h /
  30d buttons and history pan are unchanged.

## [1.0.4] — 2026-07-04

### Added
- **Release workflow** (`.github/workflows/release.yml`) — pushing a `vX.Y.Z` tag
  now publishes a **GitHub Release** (notes pulled from this CHANGELOG) and pushes
  the **multi-arch container image** (amd64 / arm64 / armv7) to GitHub Packages
  (`ghcr.io/tarrinho/ai_monitoring`), using the built-in `GITHUB_TOKEN` — no extra
  secrets. Each publish commit is now titled with the version + a UTC timestamp so
  successive pushes have distinct descriptions.
- **Per-control CI badges** — the single `ci.yml` workflow was split into five
  independent workflows (`secret-scan`, `lint`, `tests`, `trivy-fs`, `build-scan`),
  each surfacing its own GitHub Actions status badge in the README so a failure is
  attributable to a specific control at a glance.
- **LiteLLM "Load vs resource impact" chart** — a dual-axis correlation chart on
  the LiteLLM dashboard plotting request rate (req/s) against the per-execution
  cost signals of a GPU-served LLM: GPU util %, KV-cache %, the llama.cpp process
  **CPU %** and **RAM %** (RSS / host memory). (Exact per-request CPU/RAM isn't
  measurable with interval sampling and is mostly noise for a GPU-bound model —
  this shows the honest correlation. Host RAM is static; KV-cache is the real
  per-request memory.)
- **Dedicated CPU + RAM over-time charts** on the LiteLLM dashboard — one line per
  LLM serving process (`llama-server`, `ollama`): CPU % over time, and RSS (RAM)
  over time. Fed from the procs collector (`/api/procseries`) — no new sampling.
- **Per-model resource columns** — the LiteLLM per-model table gained **svc CPU**
  and **svc RAM** columns: each model's serving-process CPU % and RSS, mapped via
  its served-by backend (llama.cpp → `llama-server`, ollama → `ollama`) from the
  existing procs collector — no new sampling, no observer-effect.

### Tests
- **Expanded QA coverage (+13)** across categories: **security** (CSP
  script/object-src lock-down, HttpOnly+SameSite=Strict session cookie, GPU HTTP-
  agent SSRF scheme guard), **functional** (`/api/export` CSV+JSON shapes, robust
  `/api/series` bounds), **unit** (`config.validate` clean, redacted-summary key
  hiding, `_parse_spend_bytes` junk tolerance), **regression** (LiteLLM down-on-5xx
  liveliness; Overview GPU-badge `live`, Uptime-under-GPU, RAM-banner threshold),
  and **performance** (`_metrics_row` 500× pure builds < 2 s). Suite: 176 passing.

### Fixed
- **CI (GitHub Actions)** — pinned `aquasecurity/trivy-action` to an existing
  release (`@0.35.0`; `@0.24.0` no longer resolves) in both the filesystem and
  image scans, and added a `ruff.toml` so `ruff check .` passes: test fixtures may
  use compact semicolon one-liners / grouped imports (E701/E702/E401/E402 relaxed
  in `tests/**` only — app code stays strict). Cleared the Node.js-20 deprecation
  warnings: `actions/checkout@v4`→`v5`, `actions/setup-python@v5`→`v6` (both now
  node24), and `cache: "false"` on the Trivy steps to skip trivy-action's internal
  node20 `actions/cache`. Overview: Uptime card stacked under the GPU card; the GPU
  card badge shows `live` instead of the `file nvidia` mode.

### Docs
- **Apache-2.0 license** — added a `LICENSE` file (Apache License 2.0, © 2026
  Pedro Tarrinho) plus a README "License" section and license badge, matching the
  other projects. README badges: added `release` + `ghcr.io`; the image-size badge
  was dropped rather than depend on a small third-party badge service for GHCR.
- **README GPU-setup section** — consolidated step-by-step for the three GPU
  feed modes (local file via `deploy/gpu-metrics.service`, remote SSH, remote
  HTTP agent) plus the unified-memory GB10 caveat (VRAM reads N/A by design).
- **`rules.md`: documentation is English-only** — a global convention (enforced at
  §15) that everything committed to the repo is written in English.
- **`rules.md`: never run the monitored backends on the monitor host** — a global
  constraint that LiteLLM / Ollama / llama.cpp must not be installed or run
  alongside AI-Monitoring (they would compete for GPU/CPU/RAM with the server it
  watches); the monitor only reaches REMOTE backends over the network.

## [1.0.3] — 2026-07-04

### Added
- **Auth brute-force protection** — per-IP failed-token rate limiting: after
  `MONITOR_AUTH_MAX_FAILS` (10) bad tokens within `MONITOR_AUTH_WINDOW_S` (300s),
  that IP is locked out (**HTTP 429** + `Retry-After`) for `MONITOR_AUTH_LOCKOUT_S`
  (900s) — a correct token is refused while locked. `MONITOR_AUTH_TRUSTED_PROXY`
  gates whether the client IP is read from `X-Forwarded-For` (off by default so the
  header can't be spoofed to dodge the lockout). Weak tokens (<16 chars) are
  flagged at boot. Essential now that the dashboard can be exposed via a tunnel.
- **Live push over SSE** — new `GET /api/stream` (`text/event-stream`) pushes the
  latest snapshot every `SAMPLE_INTERVAL` over one connection. The Overview uses it
  in place of the 5 s snapshot poll and is self-healing — on any stream error it
  falls back to polling and the browser auto-reconnects. Windowed series still poll.
- **Model load/unload timeline** — the sampling loop now records `kind='model'`
  events when Ollama models load/unload or llama.cpp swaps its loaded model. New
  `GET /api/events?kind=model` and a **Model activity** card on the Ollama page.
  The `events` table gained a `kind` column (idempotent migration); uptime only
  counts `kind='state'`, so the model timeline never distorts uptime %.
- **GitHub Actions CI** (`.github/workflows/ci.yml`) running the rules.md controls
  on every push/PR: TruffleHog secret scan, lint+type (ruff/bandit/semgrep/mypy/
  vulture), pytest (static+dynamic), a Trivy **filesystem** scan (deps/config/
  secrets) and a **build-gate + Trivy image** scan (HIGH/CRITICAL → fail). The
  workflow and `.trufflehog-exclude` are now in the publish allow-list so they
  actually reach GitHub.

## [1.0.2] — 2026-07-03

### Changed
- **LiteLLM dashboard, lite mode** — hide the metrics that only exist under
  `spend_mode=full` (p50/p95/p99, SLO, wait, req/s, error %, cost/h, TTFT, cache)
  instead of a wall of "—"; the per-model table drops the same columns. Header
  badge now reads `live · lite`, a **Tokens today** tile is always shown, and the
  note explains latency **+ rates + cost + cache** are aggregate-mode-only.
- **Overview** — the Host card now carries a CPU/Mem sparkline (fills the card so
  it matches its row height); top cards size to their content (`align-items:start`)
  instead of stretching; a single-GPU host shows a compact GPU caption instead of
  the redundant per-GPU table.

### Added
- **Host RAM-pressure banner** on the Overview when memory ≥ 90% (with a
  stop-containers / reduce-context hint).

### Fixed
- LiteLLM per-model rows with an empty model name now render as `(unnamed)`
  instead of a blank cell.
- **LiteLLM down-detection** — a `/health/liveliness` **timeout or 5xx** is now
  reported as the backend being **down** instead of up. Previously only a raw
  connection error counted as down, so a saturated/timing-out proxy read as
  healthy and the heavy `/spend` call still fired at it — the exact hammering the
  circuit-breaker/decoupled-loop design exists to prevent.
- **Container collector** — per-container inspects now run **concurrently**, so
  the aggregate sample time stays ≈ one timeout regardless of container count and
  can no longer overrun the backend loop's `wait_for` bound (which previously
  cancelled the sample every tick on a busy host → permanently stale panel).
  `_last_seen` is also pruned (>1 week, auto-discover mode) to bound memory.

## [1.0.0] — 2026-07-03

First public release. AI-Monitoring is a **read-only**, dependency-light aiohttp
monitor for a local LLM stack: it samples host, GPU, Ollama, llama.cpp, LiteLLM
and containers, stores tiered time-series in SQLite, evaluates alerts + per-key
anomalies, and serves token-gated dashboards — without ever mutating or
overloading the systems it watches.

### Added — Collectors
- **host** — CPU %, memory %, disk %, load average, core count (pure `/proc`).
- **procs** — top-5 apps by CPU and by RAM, with per-app time-series.
- **gpu** — util, VRAM used/total/%, power, temperature, throttle, per-GPU table,
  tokens/watt. Sources: local `nvidia-smi`/`rocm-smi`, a file written by a host
  agent, a remote GPU box over SSH, or an HTTP metrics agent. Handles
  unified-memory GPUs (e.g. GB10) that report no separate VRAM.
- **ollama** — running/installed models, model RAM/VRAM, %-resident-on-GPU,
  params/quant/family, keep-alive unload countdown, version.
- **llamacpp** — `/health` status (incl. `loading`), model path, context size,
  slot count/active/busy %, KV-cache %, tokens/s (reads both top-level and
  nested `.timings` slot shapes).
- **litellm** — requests, tokens/day, backlog (in-flight), per-model breakdown,
  top-10 keys, spend; latency (wait/p50/p95/p99/TTFT/SLO), req/s, prompt &
  completion tok/s, error %, cost/h, cache-hit in full mode.
- **containers** — Docker liveness + uptime / down-duration per container.

### Added — Dashboards (six, token-gated)
- **Overview `/`** — host CPU/mem/disk/load, top-5 apps by CPU & RAM with per-app
  evolution, uptime, and every metric as time-series grouped into collapsible
  **Host / GPU / LLM** sections.
- **LiteLLM `/litellm`** — wait avg + p50/p95/p99 + SLO, req/s, prompt/completion
  tok/s, error %, cost/h, backlog, TTFT, cache-hit; per-model table; top-10 keys
  (bar + colored over-time); failed-request viewer; key anomalies;
  concurrency-vs-latency.
- **GPU `/gpu`** — util, power, temp, throttle, per-GPU table, tokens/watt
  (VRAM tiles shown only on discrete GPUs).
- **Ollama `/ollama`** — running/installed models, RAM/VRAM, %-on-GPU, per-model
  params/quant/unload-countdown, over-time charts.
- **llama.cpp `/llamacpp`** — tokens/s, active/total slots, busy %, KV-cache %,
  context size, status, loaded-model card, over-time charts.
- **Alerts `/alerts`** — configured channel, thresholds, active breaches, "Send
  test alert", fired-alert history.
- Common controls on every windowed page: **15m / 1h / 24h / 30d** windows,
  **◀ ▶ history pan**, **🌙/☀️ day-night** (persisted), **collapsible sidebar**,
  **⬇ CSV export**, and a pulsing red dot on the sidebar Alerts item while an
  alert is firing.
- **Empty-chart auto-hide** — a metric with no data in the window hides its tile
  (self-healing: reappears when data returns); collapsed groups re-count visible
  tiles.
- **Containers card** — show/hide-exited toggle (exited hidden by default),
  persisted; down-duration for stopped containers.

### Added — API (JSON, token-gated; `/healthz` open)
- `GET /api/data?history=N` — latest snapshot + recent samples.
- `GET /api/series?window=&end=` — downsampled metric series (history pan via `end`).
- `GET /api/keyseries` — top-10 API keys over time.
- `GET /api/procseries?kind=cpu|ram` — top-5 apps over time.
- `GET /api/uptime?window=` — per-backend uptime % + transition events.
- `GET /api/anomalies` — active + recent per-key anomalies.
- `GET /api/alerts` · `POST /api/alerts/test` — channels/thresholds/active/history · fire test.
- `GET /api/nav` — which backends are configured (drives nav visibility).
- `GET /api/export?window=&format=csv|json` — export a window.
- `GET /healthz` — liveness (container probe).

### Added — Storage & processing
- SQLite store: flat numeric metric columns + per-key / per-app series, events,
  alerts, uptime.
- **Tiered retention** — raw 24h + 1-minute and 1-hour rollups, configurable to
  years; hourly rollup + prune.
- **Alerting** — threshold evaluation with a debounced webhook notifier
  (recovery + history); channel test.
- **Anomaly detection** — per-key spike and budget-abuse detection.

### Added — Load-safety (observer-effect guards)
- LiteLLM `/spend/logs` JSON parsed **off the event loop**, throttled, byte-capped,
  timeout-bounded; **lite spend mode** using `/global/activity` aggregates
  (~200 ms, ~0 CPU) vs the whole-day raw pull.
- **Circuit breaker** for a failing/slow proxy (stop-and-recover).
- Per-deployment `/health` probing off by default.
- **GPU sampling decoupled** into its own loop; every backend loop and the main
  tick are `asyncio.wait_for`-bounded so a wedged `nvidia-smi` (D-state) can never
  freeze the sampler.

### Added — Deployment & ops
- Single Alpine **Dockerfile** with an in-image test gate (`RUN_TESTS=1` runs the
  suite; no pass → no image / `/qa-passed` marker).
- **Multi-arch** build (`deploy/build-multiarch.sh`): amd64 / arm64 / arm/v7 +
  Trivy scan each.
- `docker-compose.yml` (+ override), server compose, systemd unit
  (`deploy/ai-monitoring.container.service`), host GPU-metrics service, and a
  persistent tunnel helper (`deploy/tunnel.sh` — ngrok / cloudflared).
- Reverse-proxy sub-path support; ship-a-tarball flow (no registry needed).
- `deploy/publish-github.sh` — publish source to GitHub via an allow-list +
  secret-scan gate (no secrets / artefacts / internal references).

### Added — Security
- Optional dashboard token — constant-time compare, HttpOnly cookie flow.
- Security headers: `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`,
  nosniff, referrer-policy; self-hosted assets (no CDN).
- XSS: single DOMPurify-sanitised `innerHTML` sink per page + `escapeHtml`;
  `setInterval` leak prevention (`_timers` + `beforeunload`).
- SSRF: GPU-agent fetch restricted to `http(s)`, bypasses proxy env.
- Secrets env-only, git-ignored, never logged or stored; boot banner on weak/missing.

### Added — Quality pipeline
- Full QA suite: `tests/test_static_qa.py` (HTML/JS + source invariants),
  `tests/test_dynamic_qa.py` (collectors, endpoints, series, alerts),
  `tests/test_testenv.py` (live Ollama + LiteLLM + Postgres integration).
- **`rules.md`** — 0–18 build/test/security/release pipeline (version, static +
  dynamic tests, observer-effect, secret-leak, Bandit/Semgrep/ruff/mypy/vulture,
  Trivy, dashboard-security, black-box dynamic check, multi-arch gate, status
  report). Validation records under `validation/<version>.md`.

[1.0.4]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.4
[1.0.3]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.3
[1.0.2]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.2
[1.0.0]: https://github.com/tarrinho/ai_monitoring/releases/tag/v1.0.0
