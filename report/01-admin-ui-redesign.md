# 01-admin-ui-redesign — Implementation Report

Date: 2026-08-13
Branch: `feature/admin-hig-redesign`
Commit: `61cedf9`

## Summary

Implemented `todo/admin-ui-redesign.md` Phase 0 through Phase 10. All 11 audit
bugs (Bug #1-#11) are addressed. `go build ./...` and
`go test ./internal/admin/...` pass; no test file was modified, weakened, or
skipped.

## What was implemented

### Phase 0 — confirmed bugs

| Bug | Fix |
|:---|:---|
| #1 renderError shape | `handlers.go`: data now wrapped under `Content` |
| #2 emerald-* banners | `handlers_certs.go`: semantic `download-banner` markup |
| #3 HTMX auth forms | login/setup/logout are plain `method=post` forms |
| #4 nav on auth pages | new nav-less `auth`/`auth_end` shell in base.html |
| #5 ExpiringCount reset | Update/RegenerateKey look up the real count |

### Phase 1 — design tokens + shell

- `app.css` fully rewritten as a design system in the required order
  (tokens → reset → typography → layout → nav → grouped-list → buttons →
  forms → segmented → dialogs → badges → progress → empty-state → key-reveal →
  charts → toast → utilities → responsive → a11y/motion → print).
- Semantic light tokens in `:root`; dark tokens under
  `@media (prefers-color-scheme: dark)`. Component rules contain zero
  hardcoded color literals — all flow through tokens.
- `<meta name="color-scheme" content="light dark">` plus dual `theme-color`
  metas with `media` attributes in both shells.
- Native system font stacks (sans + mono); no web fonts.
- `prefers-reduced-motion` honored globally.

### Phase 2 — chrome + navigation

- Translucent frosted nav (`blur` + `color-mix` over tokens), brand `OTLP
  Proxy`, section links, cert-expiry badge, plain-form logout.
- Real mobile nav: `#nav-toggle` hamburger toggles a `.nav-links.is-open`
  dropdown panel with `aria-expanded`; all controls preserved.
- `data-nav` active-state script unchanged; `copyKey(key)` preserved.

### Phase 3 — authentication

- Centered auth layout with label/helper hierarchy and strong focus states.
- Setup keeps `minlength="12"` + helper copy.

### Phase 4 — tenants

- Apple inset grouped-list rows (identity / limits / status / actions) with a
  single tinted "New tenant" primary and text-style secondary controls.
- `#tenant-list`, `#tenant-{id}`, `#form-area`, `{{.Target}}`/`{{.Swap}}`
  intact. Rows stack at narrow widths; long names wrap (`overflow-wrap`).
- `ExpiringCount` correct after Update and RegenerateKey swaps.

### Phase 5 — API-key reveal

- Reveal banner keeps all test copy and the `{{if .Tenant.APIKey}}` guard.
- Key stored in a safely HTML-escaped `data-key` attribute; copy invokes the
  existing `copyKey(this.dataset.key)` hook — never interpolated into JS.
- Dismiss removes only `.key-reveal-row`.

### Phase 6 — usage / analytics

- Stat cards, quota progress, charts, segmented range control with all
  contract IDs; `loadData(range, btn)` unchanged.
- Chart palette read from CSS variables; `matchMedia('(prefers-color-scheme:
  dark)')` change re-reads tokens and re-renders charts using the preserved
  current range; Chart.js font switched to the system stack (no `'Inter'`).

### Phase 7 — users

- Grouped presentation with avatars; `#user-list`, `#user-{id}`, and the
  accessible confirm delete flow preserved.

### Phase 8 — certificates

- Status badges carry a dot + text label (never color-only); fingerprint and
  serial in a legible mono style.
- Issue (CSR + keygen), renew, revoke, download with correct hierarchy;
  destructive actions are text-style.
- When `CAEnabled == false`: `CA integration is disabled` notice renders and
  NO issuance controls appear anywhere (cert_list and cert_issue).

### Phase 9 — confirm dialog

- Rebuilt with native `<dialog>` + `showModal()`, `role="alertdialog"`,
  `aria-modal`, `aria-labelledby`, `aria-describedby`.
- `htmx:confirm` + `evt.detail.issueRequest()` flow preserved; listeners
  registered once; modal blocks double-opens; Escape cancels without firing
  the request.
- Explicit focus restoration: trigger → fresh element with same id after an
  `outerHTML` swap → first interactive element in the container → page
  heading, driven by `htmx:afterSwap` with a safety timeout.

### Phase 10 — polish

- `CancelForm` and `/tenants/cancel` NOT removed (documented follow-up below).
- No CDN/fonts/external JS in templates or Go HTML fragments.
- No legacy utility classes remain in templates (grep verified).
- `go build ./...`, `go test ./internal/admin/...`, `go vet` all pass.

## Deviations from the plan

None. Every checklist item was implemented as specified. The only judgment
calls were:

- Chart extra-palette colors (`--chart-1`..`--chart-6`) were added as tokens
  so the doughnut palette has no hardcoded literals in JS.
- The confirm dialog's "Yes, proceed" button is the single filled destructive
  button (Apple alert convention); all in-page destructive actions are
  text-style.
- `tabindex="-1"` is applied transiently to the restored focus target so
  non-interactive fallbacks (row containers, `h1`) can receive focus.

## Docs / todos follow-up

- `todo/admin-ui-redesign.md`: all checkboxes complete — mark the Phase 0-10
  items done when convenient. No content changes needed.
- `docs/admin-ui-audit.md`: research artifact, still accurate. No changes
  needed.

## Documentation Updates Needed

### todo/admin-ui-redesign.md — dead-code follow-up item

Add a single checklist line under Phase 10 (or a new "Follow-up" section):

```
- [ ] Dead route follow-up (audit Bug #10): `GET /tenants/cancel`
      (`CancelForm` in `internal/admin/handlers.go`) is registered but no
      template references it. Remove route + handler + any test coverage in a
      separate cleanup PR.
```

### docs/admin-ui-audit.md — Bug #10 status note (optional)

Append to the Bug #10 bullet:

```
- Status: unresolved by design during the redesign; tracked as a follow-up.
```

## Verification

- `go build ./...` — pass
- `go test ./internal/admin/... -count=1` — pass (all existing tests, unmodified)
- `go vet ./internal/admin/` — pass
- Live-render checks (temporary harness, removed after run): login/setup
  shells, index empty state, key-reveal create response (no `copyKey('`),
  index with no `key-reveal-row`/`data-key` leak, error page, usage page
  IDs, cert empty state, logout 303.
