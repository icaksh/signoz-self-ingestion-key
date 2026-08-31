# OTLP Proxy Admin — Design System (Apple HIG informed)

Design authority: **apple-hig** skill (HIGAgentSkills, OS 27 distilled reference).
Loading protocol followed: Tier-1 (all 16) → Tier-2 platform files → Tier-3 keyword
matches → related expansion. Web accessibility governed by the **accessibility** skill
(WCAG 2.2). Web quality gate later uses `best-practices` + `web-quality-audit`.

> Translation note: this is a **web** admin console for a backend proxy. We translate
> native HIG intent (macOS desktop → iPadOS tablet → iOS phone) to semantic
> server-rendered HTML + small vanilla ES modules. We do **not** fake native window
> chrome (no traffic lights, no menu bar, no tab bar chrome).

## 1. Exact apple-hig topics loaded

Tier-1 (all): `accessibility`, `branding`, `color`, `dark-mode`,
`design-principles`, `icons`, `images`, `inclusion`, `layout`, `materials`, `motion`,
`privacy`, `right-to-left`, `sf-symbols`, `typography`, `writing`.

Tier-2 (platforms): `designing-for-macos`, `designing-for-ipados`, `designing-for-ios`.

Tier-3 (keyword-matched to this product): `buttons`, `alerts`, `action-sheets`,
`entering-data`, `lists-and-tables`, `segmented-controls`, `text-fields`, `toggles`,
`progress-indicators`, `loading`, `charts`, `charting-data`, `managing-accounts`,
`settings`, `focus-and-selection`, `modality`, `menus`, `toolbars`, `sidebars`,
`feedback`, `privacy`, `inclusion` (also tier-1).

Accessibility: `web-quality-skills/accessibility` (WCAG 2.2 POUR, contrast, focus,
target size, reduced motion, forms/errors).

## 2. HIG principles applied

| Principle | Application |
|:---|:---|
| Purpose | The admin's job is managing tenants/keys/usage/certs; every screen focuses that. |
| Agency | Reversible destructive actions confirm first; "Cancel" always available. |
| Responsibility | Secrets revealed once, hashed at rest; collection limited to what the proxy needs. |
| Familiarity | Native form controls, standard buttons/links, one persistent top nav. |
| Flexibility | Responsive desktop/tablet/phone; light+dark; keyboard + pointer + touch. |
| Simplicity | Tenants/users/certs as grouped lists; usage as three stats + three charts. |
| Craft | System font stack, consistent 8-pt spacing, deliberate tokens, reduced-motion. |
| Delight | Restrained: smooth chart transitions, clear empty states — no decoration. |

## 3. Desktop / macOS interpretation

- Primary reference. Density moderate (macOS body 13pt default) but the admin is a
  sparse CRUD console, so we use 14–17pt body for comfortable reading.
- Persistent left sidebar (macOS application-style) is the primary application
  navigation: brand header, **Tenants**/**Users** destinations, a quiet footer
  (expiring-certificate indicator + Log out). Navigation belongs in the sidebar;
  the main pane carries only contextual page toolbars (title + primary action).
  Matches HIG: sidebars provide broad navigation; toolbars act on content.
- Content max-width ~1200 px centered; grouped inset "lists and tables" for rows.
- Destructive actions are inline text buttons with red semantic color; confirmation
  via a modal `<dialog>` (alert-style) — not a bottom action sheet (pointer context).
- Keyboard-first: visible focus rings, logical tab order, Enter submits forms,
  Escape dismisses dialogs.

## 4. Tablet / iPadOS interpretation

- Same sidebar shell; between ~768–1023 px the sidebar becomes an off-canvas
  drawer toggled from a contextual mobile bar (split-view-inspired navigation),
  with a scrim and Escape/backdrop dismissal.
- Pointing devices supported; hover states kept for pointer, touch targets enlarged.
- Segmented control for 24h/7d/30d range selector (exactly the "closely related
  choices affecting a view" use case).

## 5. Phone / iOS interpretation

- Phone widths (320–430 px): the sidebar becomes a full-height navigation drawer
  revealed by a menu button in a slim contextual bar; all destinations + logout
  remain reachable. Single column; tables become stacked rows.
- Touch targets ≥ 44×44 px; forms single-column; segmented control full-width;
  primary actions full-width where appropriate.
- Large title-like page headings; content edge-to-edge with system-margin insets.

## 6. Information architecture

- **Tenants** (home): grouped list of tenants with name/description, key prefix,
  rate-limit chips, expiring-cert badge, active status, actions (Usage, Certs, Edit,
  Revoke Key, Delete). "New tenant" primary action opens a form.
- **Tenant → Usage**: stats (total requests, data ingested, signal types), quota bar,
  requests/volume/signal charts with 24h/7d/30d segmented control.
- **Tenant → Certificates**: list of certs with validity state, fingerprint/serial,
  expiry/last-seen, actions (Renew, Revoke, Download) + Issue form (CSR / keygen).
- **Users**: grouped list + add-user form, delete action.
- **Auth**: setup (first run) and login pages, nav-less centered layout.

## 7. Navigation

- **Persistent left sidebar** (desktop, ≥1024 px) is the primary application
  navigation. It holds the brand ("OTLP Proxy" + "Admin"), the global
  destinations **Tenants** and **Users**, and a quiet footer with an
  expiring-certificate indicator and **Log out** (plain POST form).
- **Usage** and **Certificates** are tenant-contextual destinations, reached from a
  tenant's actions and breadcrumbs inside the main pane — not global sidebar items
  (no broken global routes).
- Selected destination indicated with `aria-current="page"`, a tinted pill
  background, a leading accent bar, and semibold text (more than color alone).
- Breadcrumb "eyebrow" links (All tenants / Certificates) for nested pages.
- The sidebar is `position: sticky` so it stays put while the main pane scrolls.

## 8. Responsive layout

- Breakpoints: desktop persistent sidebar (≥1024 px), adaptive off-canvas sidebar
  (768–1023 px), phone drawer (≤767 px, incl. 320/390/430 px).
- CSS grid for stat cards and chart cards (2-up → 1-up); grouped tables → stacked
  rows; forms 2/3-column → 1-column.
- Use `clamp()`/relative units; honor `prefers-reduced-motion` and OS font scaling
  (web `rem` scales with browser font size — the web analog of Dynamic Type).

## 9. Typography

- System font stack (SF Pro on Apple platforms, Segoe UI on Windows, system-ui
  elsewhere); monospace stack (`ui-monospace, "SF Mono", Menlo, Consolas`) for keys,
  fingerprints, serials. No web fonts, no remote fonts.
- macOS text-style hierarchy (cited values) translated to `rem`:
  - Title 1 ≈ 22pt/28px → page title
  - Title 2 ≈ 17pt → section heading
  - Headline ≈ 13pt bold → card/row titles
  - Body ≈ 13–16pt → body
  - Footnote/Caption ≈ 11–12pt → secondary/placeholder
- Weight guidance: prefer Regular/Medium/Semibold; avoid Ultralight/Thin/Light
  (HIG typography). Adjust `letter-spacing` negative for large titles per SF tracking
  table; positive for sub-12px captions.
- Line-height: body 1.4–1.5; headings 1.2. Long technical identifiers
  (`overflow-wrap: anywhere`) never overflow.

## 10. Semantic colors / light / dark

Use CSS custom-property tokens in `:root` (light) and under
`@media (prefers-color-scheme: dark)`; component CSS contains no hardcoded color
literals. `<meta name="color-scheme" content="light dark">` + dual `theme-color` metas.

Semantic token roles (names only — values chosen for ≥4.5:1 normal / 3:1 large text,
and ≥3:1 UI-component contrast):

- Backgrounds: `--bg` (window), `--bg-grouped`, `--bg-surface`, `--bg-elevated`,
  `--bg-input`, hover/active/scrim.
- Foreground: `--fg-primary`, `--fg-secondary`, `--fg-tertiary` (text hierarchy).
- Accent/tint (primary action, links, focus): one indigo-family tint + hover + soft
  tint backgrounds + gradient for the brand mark.
- Semantic status: `--success` (active/valid/within quota), `--warning`
  (expiring/approaching quota), `--danger` (revoked/expired/over quota) — each with
  `-bg`/`-border` variants. **Status is always paired with a text label/icon**,
  never color alone (color + accessibility skills).
- Separators, chart palette (6 series), shadows, focus ring.

Dark mode follows HIG: dimmer backgrounds + brighter foregrounds (not inversion);
elevated surfaces brighter than base; accent brightened for contrast.

## 11. Spacing / material / elevation

- 8-pt base grid: 4/8/12/16/24/32/48 px spacing scale; consistent insets (grouped-list
  rows ~16 px horizontal).
- Radii: `--radius-sm` 8 px, `--radius` 10 px, `--radius-lg` 12 px, `--radius-xl` 16 px,
  `--radius-full` for pills/badges.
- Material: the sidebar uses a quiet solid grouped surface (`--sidebar-bg`) that
  visually defers to the opaque content layer; no heavy glassmorphism. Honor
  `prefers-reduced-transparency`.
- Elevation: 3 shadow levels (sm/md/lg) + a scrim for dialogs; increased in dark mode.

## 12. Forms / data entry

- Every field has a programmatically associated `<label>`; placeholders show format,
  never replace labels. Errors shown next to the field with `aria-invalid` +
  `aria-describedby`, framed positively (writing skill: "Use only letters" > "Don't use
  numbers").
- Sensitive fields (passwords, CSRs, keys) use appropriate input types / `monospace`
  textareas; secure text for passwords.
- Required data gates submit (client `required` + server validation); min 12-char
  password rule preserved with inline help.
- Number fields for RPS/bytes/MB quota; daily quota entered in MB, stored in bytes
  (server converts — preserve contract).
- Tab order logical; `autocomplete` attributes on username/password.

## 13. Lists / tables

- iOS grouped-list idiom: section header + inset group; rows contain identity /
  metadata / status / actions. Alternating-row background (macOS bordered-style)
  for wide tables where helpful; rows stack on narrow screens.
- Succinct item text; long values truncated with ellipsis; full value on `title`
  or a copy action.
- Status conveyed by badge text + color (Active/Inactive, Valid/Expiring/Expired/
  Revoked).

## 14. Actions / menus

- One tinted (accent) primary button per view; secondary actions as text buttons or
  bordered buttons; destructive actions use danger semantic color.
- Buttons start with a verb ("Create", "Revoke Key", "Issue Certificate").
- Button hierarchy by style, not size; consistent min height; target size ≥ 44×44 px
  on touch, ≥ 24×24 px pointer (WCAG 2.5.8 / HIG mobility tables).

## 15. Destructive confirmation

- Destructive actions (delete tenant, delete user, revoke key, revoke cert) trigger a
  native `<dialog>` (alert-style, `role="alertdialog"`, `aria-modal`, labelled)
  before the form submits. No action fires until "Yes, …" is confirmed.
- Dialog: title + descriptive text naming the object, "Cancel" (default focus) and a
  destructive "Delete/Revoke" action. Escape/cancel dismisses without action; focus
  restored to trigger.
- Per HIG alerts: 1–2 word verb titles, never "OK" for consequential actions, Cancel
  always present, destructive action clearly labelled.

## 16. Secret / API-key reveal

- Full API key shown **once** after create/regenerate in a distinct reveal banner with
  a warning ("This key is shown once"), a monospace code block, **Copy** (Clipboard
  API, with a toast confirmation) and **"I have saved this key"** dismiss.
- Afterwards only the 12-char prefix is shown; the full key is not re-displayed and is
  never in the DOM again (guard so the reveal never renders on list pages).
- Copy is the web-safe analog; no remote clipboard dependencies.

## 17. Usage charts

- **Requests over time** (bar), **Data volume over time** (line/area),
  **Signal type breakdown** (doughnut). Common chart types (charting-data skill).
- Small vanilla SVG/canvas chart module (no Chart.js). Colors read from CSS tokens so
  light/dark stay correct; re-render on `prefers-color-scheme` change.
- **Accessible**: each chart is accompanied by a text summary + a hidden/detail
  HTML table of the underlying values (charts skill: "describe what data represents",
  "don't require interaction to reveal critical info"). Axis labels with full units.
- Doughnut has a legend; never rely on color alone (use labels).
- Range via segmented control (24h/7d/30d); `fetch()` loads the JSON data endpoint.

## 18. Empty / loading / error states

- Empty states give a next step + action ("No tenants configured — Create your first
  tenant"; "No certificates issued — Issue Certificate").
- Loading: show something immediately (skeleton/placeholder text) — never a blank
  screen; determinate quota bar where possible.
- Errors: full-page error view (status code + title + actionable "Return to
  dashboard"), not raw `http.Error`; form errors inline.

## 19. Accessibility / keyboard / focus

- Semantic HTML: `nav`, `main`, headings order, `label`s, native `<button>`/`<a>`,
  `fieldset`/`legend`, `<table>` or lists, `dialog`.
- Visible keyboard focus via `:focus-visible` (≥3:1 ring); no `outline: none`.
- Skip link to main content; `aria-current` on active nav; `aria-label`s on icon-only
  controls; `aria-live` for toast/dynamic updates.
- No keyboard traps (native `<dialog>` handles focus); focus restored on close.
- Target size ≥ 24×24 px (AA), ≥ 44×44 px touch; scrolling focus not obscured by the
  fixed nav (`scroll-margin-top`).
- `lang="en"` on `<html>`; `prefers-reduced-motion` disables animations;
  `prefers-reduced-transparency` removes blur.

## 20. Motion / reduced motion

- Motion is purposeful (chart transitions, dialog fade/scale, toast) and brief
  (120–200 ms). No auto-playing animation; no parallax.
- `@media (prefers-reduced-motion: reduce)` collapses transitions/animations to near
  zero and disables chart animation (motion + accessibility skills).

## 21. Writing / content

- Verb-based button/link labels; descriptive link text (never "click here");
  sentence-style UI copy; no "we" in errors ("Unable to load" not "We're having
  trouble"); specific, blame-free error messages; no interjections ("oops").
- Gender-neutral, jargon-light language; consistent capitalization.

## 22. Intentional web departures from native HIG

- No native window chrome / menu bar / tab bar chrome — the browser supplies those.
- No SF Symbols (Apple-licensed) — use inline SVG glyphs with `aria-hidden` +
  accessible labels, or text.
- Typography uses CSS `rem` (browser font-size scaling) instead of Dynamic Type.
- Segmented control and dialogs are ARIA-native web widgets, not UIKit components.
- The sidebar is a solid, grouped surface rather than a Liquid Glass blur — the
  web has no first-class material API, and a quiet sidebar defers to content.
- Confirmations are single `<dialog>` alerts (pointer context), not iOS action sheets.
