# Admin UI — Apple-HIG-Inspired Redesign (Implementation Plan)

Full contract inventory and bug list: `docs/admin-ui-audit.md`. Read it first.

## Hard contract — do not break

Preserve all of the following or `go test ./internal/admin/...` fails:

- 16 `define` names (see audit).
- HTMX URLs / targets / swaps (see audit). Row IDs `#tenant-{id}`, `#user-{id}`,
  `#cert-{id}` must survive `outerHTML` swaps so repeat swaps keep working.
- Swap containers `#tenant-list`, `#user-list`, `#cert-list`, `#form-area`,
  `#download-link`.
- Test strings: `data-confirm-name="tenant X"`, `data-confirm-name="API key for X"`,
  `This key is shown once`, `I have saved this key`, `Copy to clipboard`,
  `No tenants configured`, `No certificates issued`, `OTLP Proxy`,
  `Return to dashboard`, `confirm-overlay`/`confirm-yes`/`confirm-no`,
  `/static/app.css`, `/static/htmx.min.js`.
- `class="key-reveal-row"` must NOT appear on the index page (only in
  create/regenerate responses). Keep the `{{if .Tenant.APIKey}}` guard.
- Local assets `app.css`, `htmx.min.js`, `chart.umd.min.js` (no CDN).
- Existing tests are part of the contract — never edit, delete, weaken, skip, or
  replace them to make the redesign pass; fix the implementation instead.
- The ONLY HTMX-contract exception: `/login`, `/setup`, `/logout` become plain
  form submissions. Everything else keeps its URL/target/swap.
- Template funcs: `maskKey`, `megaBytes`, `percent`, `certRowData`, `formatTime`,
  `expired`, `expiringSoon`, `daysUntil`, `fingerprintFormat`, `fingerprintShort`, `dict`.

## Phase 0 — fix confirmed bugs first

- [ ] Fix `renderError` data-shape mismatch so error pages show code/title/detail
      (`handlers.go` `renderError` or `error_page` template — see audit Bug #1).
- [ ] Replace the `emerald-*` inline download-banner HTML in
      `handlers_certs.go` with semantic-token markup (see audit Bug #2).
- [ ] Convert `/login`, `/setup`, `/logout` forms from HTMX to plain form
      submissions (full page navigation) — see audit Bug #3. This is the only
      sanctioned HTMX-contract exception.
- [ ] Build a nav-less auth shell for `login`/`setup` (see audit Bug #4). The
      shell must still reference local `/static/app.css` and
      `/static/htmx.min.js` (tests assert both on `/login`).

## Phase 1 — design tokens + global shell

- [ ] Rewrite `app.css` as a design system (tokens → reset → typography →
      layout → nav → grouped-list → buttons → forms → segmented → dialogs →
      badges → progress → empty-state → key-reveal → charts → toast → utilities
      → responsive → a11y/motion → print).
- [ ] Define semantic light tokens in `:root` and dark tokens under
      `@media (prefers-color-scheme: dark)`. UI/component CSS must contain no
      hardcoded color literals outside token definitions. The only permitted
      non-token color literals are HTML metadata values that cannot consume CSS
      custom properties (e.g. dual `theme-color` meta tags).
- [ ] Set `<meta name="color-scheme" content="light dark">` and dual
      `theme-color` metas with `media` attributes.
- [ ] Native system font stack; monospace stack for keys/fingerprints/serials.
- [ ] Remove the Tailwind-style utility pile only after templates no longer
      reference it (grep templates + `handlers_certs.go` first).
- [ ] `prefers-reduced-motion` respected globally.

## Phase 2 — application chrome + navigation

- [ ] Redesign the top navigation (translucent backdrop, brand, section links,
      cert-warning badge, logout). Keep brand text `OTLP Proxy`.
- [ ] Keep `data-nav` active-state script working; add a real mobile nav
      (collapsed menu or bottom sheet) with no lost controls.
- [ ] Keep the cert-expiry badge (`ExpiringCerts`) discoverable on every
      authenticated page; not required on login/setup.

## Phase 3 — authentication (login/setup)

- [ ] Minimal, centered, purposeful auth layout; clear label/helper/error
      hierarchy; comfortable touch targets; strong focus states.
- [ ] Setup password field keeps `minlength=12` + helper copy.

## Phase 4 — tenants (index) + tenant form

- [ ] Restyle tenant list as Apple-style inset grouped rows (identity, status,
      limits, trailing actions), with a single clear primary "New tenant".
- [ ] Secondary/destructive controls visually de-emphasized (ghost/text).
- [ ] Keep `#tenant-list` and per-row `#tenant-{id}`; keep `beforeend`/`outerHTML`
      swaps functional.
- [ ] Tenant create/edit form restyled as grouped settings (sheet or inline
      panel). Keep `#form-area` swap target and `{{.Target}}`/`{{.Swap}}`.
- [ ] Preserve correct tenant `ExpiringCount` after Update and RegenerateKey row
      swaps (audit Bug #5). Minimal handler-side lookup allowed; do not silently
      replace a real count with zero.
- [ ] Responsive: stacked rows at 320/390px, no horizontal scroll for long names.

## Phase 5 — API-key one-time reveal

- [ ] Restyle reveal banner; unmistakable "shown once / save it / copyable /
      intentional dismiss". Keep all test copy and the `.Tenant.APIKey` guard.
- [ ] Do NOT interpolate the plaintext key into JS source. Store it in a safely
      HTML-escaped `data-key` attribute and invoke the existing `copyKey(key)`
      hook with the DOM value (`copyKey(this.dataset.key)` or equivalent
      event-listener logic). Preserve the `copyKey(key)` name and signature.
- [ ] Ensure dismiss removes only the reveal row, never the tenant row.

## Phase 6 — usage / analytics

- [ ] Polished analytics view: stat cards, quota progress, charts, time-range
      segmented control. Keep IDs `stat-requests/volume/signals`,
      `requestsChart/volumesChart/signalsChart`, `loadData(range, btn)`.
- [ ] Keep Chart.js + `/usage/data?range=`; destroy/reuse chart instances on
      re-render; track current range and preserve it across re-renders.
- [ ] Chart colors read CSS variables; re-read + re-render on
      `matchMedia('(prefers-color-scheme: dark)')` change (audit Bug #9).
- [ ] Readable charts in both appearances; responsive stacking at mobile widths.

## Phase 7 — users

- [ ] Grouped user-management presentation; lightweight intentional create;
      deletion keeps the accessible confirm flow. Keep `#user-list`, `#user-{id}`.

## Phase 8 — certificates

- [ ] Clear state (valid / expiring / expired / revoked) with non-color-only
      indicators. Fingerprint/serial legible but not overwhelming.
- [ ] Issue (CSR + keygen), renew, revoke, download with correct hierarchy;
      destructive actions never look primary.
- [ ] Keep `#cert-list`, `#cert-{id}`, `#download-link` and all swap targets.
- [ ] When `CAEnabled == false`: render the `CA integration is disabled` notice
      and render NO certificate-issuance controls at all (genuinely absent, not
      relabeled to pass the substring test).

## Phase 9 — accessible confirm dialog

- [ ] Rebuild `confirm_overlay` with native `<dialog>` + `showModal()` where
      practical (browser-managed modal focus containment + Escape), or an
      equivalent accessible modal implementation.
- [ ] Destructive confirmation uses `role="alertdialog"` + `aria-modal="true"`
      + `aria-labelledby` + `aria-describedby`.
- [ ] Preserve `htmx:confirm` + `evt.detail.issueRequest()` flow; IDs
      `confirm-overlay`/`confirm-yes`/`confirm-no`/`confirm-message`.
- [ ] Repeated opens must not double-fire requests; do not accumulate handlers
      or stale request state.
- [ ] Implement explicit focus restoration that safely handles a trigger
      removed/replaced by HTMX.

## Phase 10 — polish, dead code, verification

- [ ] Do NOT remove `CancelForm` or `/tenants/cancel`. If confirmed unused,
      document it as a dead-code follow-up item only (audit Bug #10).
- [ ] Grep rendered/frontend code for external dependencies (no CDN/fonts/JS).
- [ ] Verify no unstyled legacy fragments remain (grep for old utility classes
      vs new CSS).
- [ ] Run `go build ./...` and `go test ./internal/admin/...`; fix every failure
      by fixing the implementation — never by editing, deleting, weakening,
      skipping, or replacing tests.
- [ ] Manual reasoning pass: repeat HTMX swaps, dialog opened repeatedly, mobile
      nav, dark/light toggle, chart re-render, focus behavior, long-content wrap.
