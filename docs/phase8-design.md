# Phase 8 — Design Plan

## Palette — 6 named hex values

| Name | Hex | Role |
|:---|:---|:---|
| `--bg-shell` | `#0c0d14` | Page background (deep navy-black, not gray) |
| `--bg-surface` | `#141620` | Cards, tables, form containers |
| `--bg-input` | `#1a1d2b` | Form fields, code blocks |
| `--fg-primary` | `#e1e4ed` | Body text (meets 4.5:1 on `--bg-shell`) |
| `--fg-secondary` | `#8b90a0` | Labels, secondary text, placeholders |
| `--accent` | `#5470f0` | Primary actions, active nav, focus rings (cool indigo-blue, ~4.6:1 on `--bg-shell`) |

**Why these**: The current Tailwind gray-950/indigo-600 is a generic "dark mode starter." A security console should feel deliberate. The navy-black base (`#0c0d14`) is slightly blue-shifted from neutral gray, which reduces eye strain on dark interfaces without looking like an entertainment dashboard. The accent is a cool indigo-blue — distinct from red/green semantic colors, so status badges (active/revoked/expiring) carry unambiguous meaning.

**Semantic colors** (these carry state meaning and are never used decoratively):

| State | Light | Dark bg | Meaning |
|:---|:---|:---|:---|
| Success / active | `#34d399` (emerald-400) | `#1a3a2e` | Active tenant, valid cert, within quota |
| Warning / expiring | `#fbbf24` (amber-400) | `#3d3414` | Expiring soon, approaching quota |
| Danger / revoked | `#f87171` (red-400) | `#3d1a1a` | Revoked, expired, over quota |
| Info / neutral | `#8b90a0` | `#1a1d2b` | Disabled, unknown, last-seen |

**Color vision safety**: Every state is always accompanied by a text label (badge text, "Expired"/"Active"/"Revoked") and never encoded in color alone. The dashboard progress bar and cert status badges are the only color-encoded elements; both have explicit text percentages/labels.

## Type choices

| Role | Stack | Rationale |
|:---|:---|:---|
| Display (headings) | `system-ui, -apple-system, 'Segoe UI', sans-serif` | Native OS UI font — no font download, crisp at small sizes |
| Body | same | System stack works for both macOS and Linux admins |
| Monospace (keys, fingerprints, serials) | `'JetBrains Mono', 'Cascadia Code', 'Fira Code', 'Source Code Pro', 'SF Mono', 'Menlo', 'Consolas', monospace` | All have clear 0/O and 1/l/I distinction. JetBrains Mono is the preferred; the rest are fallbacks that also meet the functional requirement. No font download — the first installed one wins. |

**Fingerprint formatting**: 64-char SHA-256 hex displayed as `aaaa bbbb cccc dddd` (4×4 grouped by 4 chars, space every 4) so operators can compare by eye. Short fingerprints (< 32 chars) shown with one midpoint space.

## Layout concept

> Single-column nav at top → main content area with cards. No sidebar. One scroll direction (vertical). The nav is persistent but occupies minimal vertical space.

Nav: `[OTLP Proxy | Admin] ---- [Tenants] [Certificates*] [Users] -- [Logout]`
(*Certificates nav item: includes a count badge when any cert expires within 7 days.)

Desktop: max-width 1200px centered. Mobile: nav collapses to home+logout, content stacks single-column.

## Design plan revision notes

**Before review**: Initial palette was gray-900/indigo-500 — essentially the Tailwind default with slightly adjusted hex values. Felt like a theme swap, not a choice.

**After review**:
- Replaced gray-950 with navy-black (`#0c0d14`) — the slight blue undertone is deliberate: neutral gray on a security console feels sterile; a cool dark reads as "calm and controlled."
- Picked `#5470f0` over indigo-500/600 as the accent. It's cooler (less purple) and has better contrast against the navy-black background than Tailwind's default indigo-600.
- Added explicit semantic color definitions. The original just used emerald/amber/red Tailwind utilities ad-hoc.
- Narrowed the mono stack to fonts with proven glyph distinction, dropping generic `monospace` from the first slot.
