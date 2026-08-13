# Admin UI — Frontend Contract Audit

Purpose: a complete inventory of the existing admin-dashboard frontend contract,
so a full Apple-HIG-inspired redesign can be executed without breaking backend
behavior, HTMX swaps, or the Go test suite.

This is a research document, not a plan. The implementation checklist lives in
`todo/admin-ui-redesign.md`.

## Source inventory

| Path | Role |
|:---|:---|
| `internal/admin/server.go` | Routes, template load, auth, template helper funcs |
| `internal/admin/handlers.go` | Tenants/users/usage handlers + render wrappers |
| `internal/admin/handlers_certs.go` | Certificates handlers + 2 inline HTML fragments |
| `internal/admin/templates/*.html` | 12 files, 16 `define` blocks |
| `internal/admin/static/app.css` | Single dark-only stylesheet (Tailwind-style utilities) |
| `internal/admin/static/htmx.min.js` | Local HTMX runtime |
| `internal/admin/static/chart.umd.min.js` | Local Chart.js runtime |

Templates are embedded via `//go:embed templates/*.html` and parsed with
`template.ParseFS` + a `FuncMap`. Static files are embedded via `//go:embed
static/*` and served at `GET /static/...`.

## Template define inventory

| define | File | Kind |
|:---|:---|:---|
| `base` | base.html | Shell open (head + nav) |
| `base_end` | base.html | Shell close (scripts + overlay) |
| `confirm_overlay` | base.html | Destructive-confirm overlay |
| `error_page` | base.html | Full page (error) |
| `index` | index.html | Full page (tenants) |
| `login` | login.html | Full page |
| `setup` | setup.html | Full page |
| `tenant_form` | tenant_form.html | HTMX fragment |
| `tenant_row` | tenant_row.html | HTMX fragment (+ one-time key reveal) |
| `quota_fragment` | quota_fragment.html | HTMX fragment |
| `users` | users.html | Full page |
| `user_list` | users.html | HTMX fragment |
| `cert_list` | cert_list.html | Full page |
| `cert_row` | cert_row.html | HTMX fragment |
| `cert_issue` | cert_issue.html | Full page |
| `tenant_usage` | tenant_usage.html | Full page (Chart.js) |

`base.html` contains 4 defines (`base`, `base_end`, `confirm_overlay`,
`error_page`); `users.html` contains 2 (`users`, `user_list`).

## Page wrapping convention

- Full pages are rendered via `renderPage`, which wraps data as
  `{"Content": <data>, "ExpiringCerts": n}` and renders into a full-page define.
- Fragments are rendered via `render` with the raw struct/map (no `Content`
  wrapper).
- `login`/`setup` are rendered directly with `{"Content": nil, "ExpiringCerts": 0}`.

## Data contracts (fields accessed by each template)

- `index` → `IndexData{Tenants []Tenant, ExpiringCerts map[int64]int}`
  - accesses `.Content.Tenants`, `.Content.ExpiringCerts` (via `$expiring`).
- `tenant_form` → `FormData{Action, Target, Swap, Tenant}`
  - accesses `.Action`, `.Target`, `.Swap`, `.Tenant.ID/Name/Description/Active/RateLimitRPS/BurstBytes/DailyByteQuota`.
- `tenant_row` → `map[string]any{"Tenant": Tenant, "ExpiringCount": int}`
  - accesses `.Tenant.*` and `.ExpiringCount`.
- `users` → `UsersPage{Users []User}`; `user_list` accesses `.Users`, `.ID/.Username/.CreatedAt`.
- `cert_list`/`cert_issue` → `CertListData{Tenant, Certificates, ExpiryWarnDays, CAEnabled}`.
- `cert_row` → `CertRowData{Certificate, TenantID, ExpiryWarnDays, CAEnabled}`.
- `tenant_usage` → `UsagePage{Tenant}`; JS reads `{{.Content.Tenant.ID}}`.
- `quota_fragment` → `struct{Used, Quota int64}`.
- `error_page` → expects `.Content.StatusCode/.Title/.Detail` + `.ExpiringCerts`.

Store types (fields): `Tenant{ID, Name, APIKey, KeyPrefix, Active, Description,
RateLimitRPS *int64, BurstBytes *int64, DailyByteQuota *int64, CreatedAt,
UpdatedAt}`; `User{ID, Username, CreatedAt}`; `Certificate{ID, TenantID,
SerialNumber, FingerprintSHA256, SubjectCN, NotBefore, NotAfter, RevokedAt
sql.NullTime, CreatedAt, LastSeenAt sql.NullTime}`.

## Go template helper functions

| Func | Behavior |
|:---|:---|
| `maskKey` | first 4 + `...` + last 4 (or all `*` if short) |
| `megaBytes` | bytes / 1048576 |
| `percent` | used/quota % clamped 0..100 |
| `certRowData` | builds `CertRowData` for `cert_row` |
| `formatTime` | `2006-01-02` UTC |
| `expired` / `expiringSoon` / `daysUntil` | cert expiry predicates |
| `fingerprintFormat` | hex grouped in 4-char blocks |
| `fingerprintShort` | first 8 chars + ellipsis |
| `dict` | key/value map builder for nested template calls |

## HTMX contract

All request attributes (must keep URLs, targets, swaps semantically intact):

- `hx-get="/tenants/new"` → `#form-area` `innerHTML` (NewForm)
- `hx-get="/tenants/{id}/edit"` → `#form-area` `innerHTML` (EditForm)
- `hx-put/post` tenant form → `{{.Target}}` `{{.Swap}}` (`#tenant-list` beforeend / `#tenant-{id}` outerHTML)
- `hx-delete="/tenants/{id}"` → `#tenant-{id}` outerHTML + `hx-confirm`
- `hx-post="/tenants/{id}/regenerate"` → `#tenant-{id}` outerHTML + `hx-confirm`
- `hx-get="/tenants/{id}/quota"` → innerHTML, `hx-trigger="load"`
- `hx-post="/users"` → `#user-list` innerHTML
- `hx-delete="/users/{id}"` → `#user-{id}` outerHTML + `hx-confirm`
- `hx-post="/tenants/{id}/certificates"` → `#cert-list` beforeend
- `hx-post="/tenants/{id}/certificates/keygen"` → `#download-link` innerHTML
- `hx-post="/tenants/{id}/certificates/{cid}/renew"` → `#cert-{cid}` outerHTML + `hx-confirm`
- `hx-post="/tenants/{id}/certificates/{cid}/revoke"` → `#cert-{cid}` outerHTML + `hx-confirm`
- `hx-post="/login"` `hx-target="this"` outerHTML (see Bug #3)
- `hx-post="/setup"` `hx-target="this"` outerHTML (see Bug #3)
- `hx-post="/logout"` `hx-target="body"` (see Bug #3)

## DOM IDs and JS hooks

Swap targets / JS hooks that must remain reachable after any redesign:
`#tenant-list`, `#form-area`, `#user-list`, `#cert-list`, `#download-link`,
`#htmx-progress`, `#confirm-overlay`, `#confirm-yes`, `#confirm-no`,
`#confirm-message`, `#stat-requests`, `#stat-volume`, `#stat-signals`,
`#requestsChart`, `#volumesChart`, `#signalsChart`, plus per-row `#tenant-{id}`,
`#user-{id}`, `#cert-{id}`, `#key-reveal-{id}`.

Global JS functions referenced by inline handlers:
`copyKey(key)` (key reveal), `loadData(range, btn)` (usage range switch).
The nav-active highlight and HTMX progress-bar listeners live in `base_end`.

## Test-asserted strings and IDs

The Go tests assert these exact substrings. The redesign MUST keep them:

- `data-confirm-name="tenant <name>"` and `data-confirm-name="API key for <name>"`
- `This key is shown once`, `I have saved this key`, `Copy to clipboard`
- `key-reveal` (present in create response), and `class="key-reveal-row"` ABSENT from index
- `No tenants configured`, `No certificates issued`
- `OTLP Proxy` (must appear in nav/title), `Return to dashboard`
- `confirm-overlay`, `confirm-yes`, `confirm-no`
- `/static/app.css`, `/static/htmx.min.js` (and all 3 static files served 200)

## Static assets (must remain, locally served)

`app.css`, `htmx.min.js`, `chart.umd.min.js` under `/static/`. No CDN allowed.

## Bugs discovered during audit

1. **`renderError` data-shape mismatch** — `error_page` reads
   `.Content.StatusCode/.Title/.Detail`, but `renderError` passes them at the
   top level (no `Content` wrapper). Result: error pages render empty
   code/title/detail. Fix in `handlers.go` (wrap under `Content`) or in the
   template (read top-level keys). Tests pass today only because they don't
   assert those values.

2. **Undefined `emerald-*` classes** — the two inline download-banner fragments
   in `handlers_certs.go` (`CertificateIssueWithKeygen` ~L162, `CertificateRenew`
   ~L260) use `emerald-500/30`, `emerald-950/30`, `emerald-300`, `emerald-400/70`,
   `emerald-600`, `emerald-500` — none defined in `app.css`, and the `/30`
   Tailwind opacity syntax is unsupported. The "Certificate Issued/Renewed"
   banners render without their intended colors. Restyle with semantic tokens.

3. **Auth/logout forms via HTMX with 303 redirects** — `hx-post="/login"`,
   `/setup`, `/logout` receive 303 redirects to full HTML pages. HTMX follows the
   redirect and swaps a complete document into `this`/`body`, corrupting the DOM.
   These become ordinary form submissions (full page navigation). This is the
   ONLY sanctioned deviation from the HTMX contract.

4. **Admin nav shown on login/setup** — `login`/`setup` include `{{template
   "base" .}}`, which renders the full nav (Tenants/Users/Logout) to
   unauthenticated users. Auth pages should use a nav-less shell that still
   references local `/static/app.css` and `/static/htmx.min.js` (tests assert
   both on `/login`).

5. **`ExpiringCount` resets to 0 on row swaps** — `Update`/`RegenerateKey`
   render `tenant_row` with `ExpiringCount: 0`, so editing or regenerating a key
   makes the "expiring certs" column read `—` even when certs are expiring.
   Required fix: preserve the real count (minimal handler-side lookup allowed).

6. **Dark-only, no light appearance** — `color-scheme: dark`, `theme-color`
   dark, all tokens dark, no `prefers-color-scheme` support.

7. **No mobile navigation** — `nav-links` just wraps; narrow viewports get
   overflow, no collapsed menu/sheet.

8. **Confirm overlay accessibility gaps** — no `role=dialog`/`aria-modal`/label,
   no focus trap, no Escape handling, no focus restore. Rebuild with native
   `<dialog>` (or equivalent), using `role="alertdialog"` + `aria-modal="true"`
   + `aria-labelledby` + `aria-describedby` for destructive confirmations.

9. **Chart palette read once** — `COL` is captured from `getComputedStyle` once
   at load; an OS scheme change does not update chart colors. Chart.js also
   hardcodes `'Inter'` in its font family.

10. **Dead route** — `GET /tenants/cancel` (`CancelForm`) is registered but no
    template references it. Do NOT remove it during this redesign; document as a
    dead-code follow-up only.

11. **Inline `copyKey('{{.Tenant.APIKey}}')`** — key interpolated directly into
    an inline JS handler. Replace with a safely HTML-escaped `data-key`
    attribute read by the existing `copyKey(key)` hook
    (`copyKey(this.dataset.key)` or equivalent); keep the `copyKey(key)` name
    and signature.

## One-time key reveal invariant (must preserve)

- `CreateTenant` and `RegenerateKey` return a `Tenant` whose `APIKey` holds the
  full plaintext; `tenant_row` reveals it only when `.Tenant.APIKey` is non-empty.
- `ListTenants`/`LookupTenantByID` always return `APIKey == ""` (the `tenants`
  table stores `''`; real keys live in `api_keys` with only `key_prefix`
  exposed). So ordinary index loads never render the reveal banner.
- Preserve: the `{{if .Tenant.APIKey}}` guard, the `key-reveal-row`/`key-reveal`
  class names, and the "shown once" / dismiss / copy copy-text.

## Locked implementation decisions

- HTMX URLs/targets/swaps are preserved EXCEPT `/login`, `/setup`, `/logout`,
  which become ordinary form submissions.
- Cert-expiry badge (`ExpiringCerts`) stays discoverable on every authenticated
  page; not required on login/setup.
- `CancelForm` and `/tenants/cancel` are NOT removed; document as dead-code
  follow-up only.
- `confirm_overlay` rebuilt with native `<dialog>` + `showModal()` where
  practical (browser-managed focus containment + Escape), or an equivalent
  accessible modal; destructive confirmations use `role="alertdialog"` +
  `aria-modal="true"` + `aria-labelledby` + `aria-describedby`. Repeated opens
  must not double-fire requests; no handler/state accumulation; focus
  restoration must tolerate a trigger removed/replaced by HTMX.
- Existing tests are part of the contract: never edit, delete, weaken, skip, or
  replace them to make the redesign pass.
- `ExpiringCount` must stay correct after Update/RegenerateKey row swaps
  (minimal handler-side lookup allowed).
- The plaintext API key is never interpolated into JS source; it lives in a
  safely HTML-escaped `data-key` attribute and is passed to the existing
  `copyKey(key)` hook via `copyKey(this.dataset.key)` (or equivalent
  event-listener logic). Preserve the `copyKey(key)` name and signature.
- The nav-less login/setup shell still references local `/static/app.css` and
  `/static/htmx.min.js`.
- Semantic light tokens in `:root`, dark tokens under
  `@media (prefers-color-scheme: dark)`. UI/component CSS contains no hardcoded
  color literals outside token definitions. The only permitted non-token color
  literals are HTML metadata values that cannot consume CSS custom properties
  (e.g. dual `theme-color` meta tags).
- When `CAEnabled == false`: render the `CA integration is disabled` notice and
  render NO certificate-issuance controls at all (never relabel to pass tests).
