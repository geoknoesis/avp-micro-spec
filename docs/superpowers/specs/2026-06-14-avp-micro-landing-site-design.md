# AVP-Micro landing site — design

**Date:** 2026-06-14
**Author:** Stephane Fellah / Geoknoesis LLC (with Claude Code)
**Status:** Approved for implementation

## Goal

Replace the out-of-date root [`index.html`](../../../index.html) (a ReSpec overview that still
says "four documents") with a polished, accurate single-page **introduction site** for the
AVP-Micro specification suite. The page must explain the problem, the challenges, an overview of
all **six** specifications with links, usage examples, a comparison with other standards, and the
features the suite supports.

The six per-bundle ReSpec specifications under `spec/<bundle>/` are **unchanged**; the landing page
links out to them. Nothing in `spec/` or the harness is touched.

## Visual direction (decided in brainstorming)

- **Style:** product-landing (Stripe/Linear vibe) — bold gradient hero, big type, feature cards,
  clear CTAs. Approachable for a first-time visitor while still linking into the formal specs.
- **Palette:** Royal Blue `#1d4ed8` → Teal `#14b8a6` gradient; dark sections `#0f172a`;
  light surface `#eff6ff`; neutral text on white.
- **Layout:** single long scrolling page, sticky top nav with anchor links, mobile-first responsive.

## Tech approach (no build step)

Plain static files with zero runtime dependencies, deployed as-is by the existing
`.github/workflows/pages.yml` (`path: '.'` + `.nojekyll`):

- `index.html` — semantic markup (landmarks, headings, `<section>` per block)
- `assets/avp.css` — all styling; CSS custom properties for the palette
- `assets/avp.js` — vanilla JS only for: mobile-nav toggle, tabbed code examples, smooth-scroll +
  scroll-spy active nav
- `assets/` — favicon (inline-SVG mark reused), an OpenGraph/social preview image, the logo SVG
- Accessibility: semantic HTML, color-contrast AA, keyboard-navigable nav and tabs, `prefers-reduced-motion`
- SEO/social: `<title>`, meta description, canonical, OpenGraph + Twitter card tags

CSS and JS are split out (not inlined) for maintainability.

## Page structure — 9 sections

1. **Hero** — headline ("The trust layer for AI-agent payments"), subhead (delegated, verifiable
   spending authority above any settlement rail), CTAs: *Read the specs* (→ §specs) and *GitHub*.
   "Unofficial draft" honesty note.
2. **The problem** — the three questions every deployment must answer (who is paying / under what
   authority / did value move and what was delivered) + a compact "why cards/OAuth/API keys fall
   short" note. Source: `docs/problem-challenges-and-sota.md` §1.
3. **The insight** — "separate trust from settlement", rendered as a two-layer CSS/SVG diagram
   (trust & authorization layer above; pluggable settlement rails below). Source: §1.4.
4. **The six specifications** — responsive card grid; each card = name, one-line role, dependency,
   namespace (monospace), and a link to its ReSpec doc:
   - Authority (DSA) → `spec/authority/` — `https://w3id.org/spending-authority/v1#`
   - Payments → `spec/payments/` — `https://w3id.org/avp-micro/v1#`
   - Settlement → `spec/settlement/` — `https://w3id.org/avp-micro/settlement/v1#`
   - Disputes → `spec/disputes/` — `https://w3id.org/avp-micro/disputes/v1#`
   - Interop (SD-JWT-VC) → `spec/interop-sd-jwt-vc/` — `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`
   - Transport → `spec/transport/` — `https://w3id.org/avp-micro/transport/v1#`
5. **How it works** — the forward flow `Quote → Authorize → Execute → Receipt` as a horizontal
   diagram, plus a **tabbed code panel** showing trimmed-but-real signed objects from the repo's own
   `test-vectors/`: `SpendingAuthorizationCredential`, `PaymentAuthorization`, `SettlementProof`,
   and a `PaymentChallenge` (HTTP 402). Closes with the one-line `python spec/verify.py → PASS`.
6. **Challenges → how AVP-Micro addresses them** — condensed from the four challenge tables
   (economic, technical, trust/interop, operational). Source: §2.
7. **Features it supports** — feature grid: per-tx & daily caps, payee allowlists, service
   categories, time windows, streaming/session budgets & signed accruals, request/replay binding
   (`requestHash`/`quoteDigest`, nonces, expiry), single-use consumption, revocation
   (BitstringStatusList), refunds/reversals/disputes, on-chain settlement + escrow, SD-JWT-VC
   selective-disclosure interop, HTTP 402 transport, mandatory-to-implement `ecdsa-jcs-2022` cryptosuite.
8. **How it compares** — the SOTA positioning table (AVP-Micro vs AP2, Skyfire KYA, ACP, UCP,
   Mastercard Agent Pay, Visa TAP, x402/L402/MPP) plus the "what SOTA covers vs what's still
   missing" framing. Source: §3.6–3.7. Honest note: AP2 is an **interop target**, not just a rival;
   settlement rails are **bridge targets**, not competitors.
9. **Conformance + footer** — signed vectors / shared harness / protocol simulator, with
   `verify · validate · sim → PASS` badges (static); footer with Geoknoesis, CC-BY, GitHub link,
   and the namespace list.

## Content principles

- **Real, not invented.** Code examples are genuine (trimmed) signed objects from the repo's test
  vectors. The comparison table is the vetted analysis already in the SOTA doc.
- **Accurate to six bundles.** Fixes the current page's "four documents" error; includes Settlement
  and Transport.
- **Honest framing** preserved: settlement is out of scope by design; interop is a bridge, not a
  third pillar; this is an unofficial draft not reviewed by a W3C Working Group.

## Out of scope (YAGNI)

No framework, no SSG/build, no analytics, no dark-mode toggle, no live/dynamic data, no changes to
the spec bundles or the Python harness, no new CI.

## Acceptance

- Root `index.html` renders the 9 sections, looks like the approved product-landing direction in the
  Royal Blue → Teal palette, and is responsive on mobile widths.
- All six spec cards link to the correct `spec/<bundle>/` directory; GitHub and namespace links resolve.
- Embedded examples are faithful to the real test vectors.
- No broken internal links; page works offline with `.nojekyll` (no external runtime deps).
