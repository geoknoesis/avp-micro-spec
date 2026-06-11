# Spec Readability Overhaul Design

**Date:** 2026-06-04  
**Status:** Approved — pending implementation plan  
**Author:** Stephane Fellah (with Claude)  
**Scope:** `spec/authority/index.html` (pilot) then `spec/payments/index.html`

---

## 1. Goal

Make both peer W3C specifications immediately readable to a newcomer — someone who understands DIDs and VCs but has not yet read AVP-Micro — without changing a single normative requirement. Every MUST/SHOULD/MUST NOT is preserved verbatim; only presentation, framing, and informative context are added.

---

## 2. Hard constraints

- **Zero normative change.** No RFC 2119 keyword may be added, removed, or reworded. No member requirement, ordering rule, or algorithm step may change.
- **Unchanged machine artifacts.** `context/v1.jsonld`, schemas, SHACL shapes, ontologies, test-vectors, and harness scripts are untouched. `verify.py` + `validate.py` must both report PASS after the overhaul.
- **ReSpec-idiomatic.** Use standard ReSpec/W3C markup and features; minimal inline `<style>` limited to what figures and tables genuinely need. No new external dependencies.
- **Accessible.** Every figure carries `role="img"`, a `<title>`, and a `<desc>` element. Every table has `<thead>` with `<th scope="col">` headers.
- **Both specs share the same conventions.** Identical template, diagram style, CSS block, and aside/note usage — so DSA and Payments are visually consistent. DSA is the style pilot; Payments is applied identically once the pilot is approved.

---

## 3. Shared style system

### 3.1 Normative/informative section tagging

All new framing, overview, walkthrough, and diagram sections are `class="informative"`. Existing normative sections keep their current class (or absence of it). ReSpec automatically renders "This section is non-normative." on informative sections.

### 3.2 Rationale asides

Short `<aside class="note">` boxes attached immediately after the rule they explain. Non-normative. Used only for rules where the *why* is non-obvious to a careful reader — roughly one per significant security/correctness decision. Examples:

- After `@protected` / no-`@vocab`: why unknown terms being dropped is a security property, not a convenience.
- After `quoteDigest`: why a hash of the quote (not just its IRI) is what the payer's signature covers.
- After payer↔quote `payee` binding: what the `allowedPayees` bypass scenario it prevents looks like.
- After `did-state-binding`: why "use the DID document at `proof.created`" matters specifically for `did:web`.

### 3.3 Inline SVG figures

`<figure>` + `<figcaption>` with hand-authored inline `<svg>`. ReSpec auto-numbers the figures. SVG conventions:

- `role="img"` on the `<svg>` element.
- `<title id="fig-N-title">…</title>` and `<desc id="fig-N-desc">…</desc>` inside each SVG; `aria-labelledby="fig-N-title fig-N-desc"` on the `<svg>`.
- 640 px wide, `viewBox` relative units, no fixed pixel heights on shapes.
- Minimal palette: two grays (`#f5f5f5` fill, `#333` stroke/text), one accent (`#005a9c` — W3C blue) for emphasized flows.
- Font: `sans-serif` (inherited from the page).

### 3.4 Annotated examples

Each `<pre class="example json">` gains a descriptive `title=""` attribute (ReSpec renders it as a caption) and, where a single member deserves explanation, a `<figcaption>` or a sentence after the `<pre>` block calls it out. No comments are inserted inside JSON example blocks — ReSpec validates them and non-standard JSON would break that check.

---

## 4. Newcomer on-ramp (both specs, informative, after Introduction)

A new `<section class="informative" id="overview">` inserted immediately after `<section id="introduction">`. Contents:

### 4.1 "How it works" subsection (`id="overview-how"`)

Three to five plain-language paragraphs explaining the spec's purpose and core mechanism without RFC 2119 language. Ends with a reference to the architecture/roles figure below.

### 4.2 Roles and objects at a glance (`id="overview-glance"`)

**Roles table** — who participates, their role, and which objects they produce/consume.

| Role | Produces | Verifies/consumes |
|------|----------|-------------------|
| Principal / issuer | SpendingAuthorizationCredential | — |
| Payer agent | PaymentAuthorization, SessionBudgetAuthorization | PaymentQuote, PaymentReceipt |
| … | | |

**Object catalog table** — every object/credential defined in the spec, one row each:

| Object | Purpose (one line) | Signer | Section |
|--------|--------------------|--------|---------|
| SpendingAuthorizationCredential | Delegates bounded spending authority from a principal to a payer agent | Principal | §X |
| … | | | |

Both tables are informative and link to the relevant normative sections.

### 4.3 Architecture / roles diagram (`id="fig-arch"`)

**DSA only:** a single SVG showing Principal → (issues) SpendingAuthorizationCredential → Payer Agent; Trust Anchor → (issues) MerchantCredential → is evaluated by → Relying Party (wallet); Relying Party holds a TrustedIssuer / IssuerScope configuration. Arrows labelled.

**Payments additions** (in the Payments spec's overview): the same roles plus Payee Service and Wallet Service, with the message flow at a high level.

### 4.4 Worked walkthrough subsection (`id="overview-walkthrough"`)

**DSA:** a short prose narrative — "A company (the principal) creates a SpendingAuthorizationCredential for its purchasing agent, constraining it to spend at most $0.05 per call with approved vendors. The wallet holding that credential checks it against a TrustedIssuer entry before acting on it." — followed by the delegation/trust diagram.

**Payments:** a one-off end-to-end narrative ("The agent discovers a PaymentOffer, requests a quote, checks it satisfies its credential's limits, authorises payment…") followed by the one-off sequence diagram. Then a parallel streaming narrative followed by the streaming sequence diagram.

---

## 5. Object-definition template

This is the highest-impact structural change. Applied to every object/credential definition section.

### Current pattern

Each object section has a prose lead ("type MUST include X. It MUST be signed by Y.") followed by a bulleted list of members.

### New pattern

Every object section uses this four-part structure:

```
<p class="object-summary">
  One sentence: what this object IS and what job it does.
</p>

<p>
  <strong>type</strong> MUST include <code>X</code>.
  [One sentence on who signs it and the fundamental signing requirement, verbatim from existing prose.]
</p>

<table class="simple">
  <caption>…</caption>
  <thead>
    <tr><th>Member</th><th>Req.</th><th>Type</th><th>Description</th></tr>
  </thead>
  <tbody>
    [one row per member — REQUIRED/OPTIONAL/RECOMMENDED in the Req. column]
  </tbody>
</table>

[Any normative paragraphs that don't fit the table — algorithm steps, special cases — stay as paragraphs AFTER the table.]
```

The `Req.` column values are the RFC 2119 keyword from the existing prose, wrapped in `<em class="rfc2119">`. The `Description` column is the existing prose description for that member, verbatim or lightly tightened for parallel structure (no substantive change).

**What changes:** presentation only — from bullets to table rows.  
**What stays identical:** every REQUIRED/OPTIONAL/RECOMMENDED keyword; every constraint clause; every cross-reference.

---

## 6. Per-spec diagram inventory

### 6.1 Delegated Spending Authority (pilot)

| Figure ID | Type | Content |
|-----------|------|---------|
| `fig-arch` | Architecture/roles | Principal, Payer Agent, Relying Party, Trust Anchor; credential issuance and verification arrows |
| `fig-trust` | Trust / delegation | Principal → SpendingAuthorizationCredential → Payer Agent; TrustedIssuer/IssuerScope at the wallet; IssuerScope constraint boxes |

### 6.2 AVP-Micro Payments

| Figure ID | Type | Content |
|-----------|------|---------|
| `fig-arch` | Architecture/roles | All roles from DSA plus Payee Service, Wallet Service, Settlement Rail; which messages flow between them |
| `fig-seq-oneoff` | Sequence | Offer → Quote → Authorization → Execution → Receipt; 5 lifelines (Agent, Payee, Wallet, Settlement Rail, Auditor) |
| `fig-seq-streaming` | Sequence | Session → Budget Auth → Accruals × N → Close → Receipt; same lifeline set |

---

## 7. Inline CSS block

A single `<style>` block inserted in the `<head>` (before the ReSpec script) of each document. Contains only:

```css
/* Object-definition summary line */
p.object-summary {
  font-style: italic;
  color: #333;
  margin-bottom: 0.5em;
}

/* Figure / SVG */
figure { margin: 1.5em 0; text-align: center; }
figure svg { max-width: 100%; height: auto; }
figcaption { font-size: 0.9em; color: #555; margin-top: 0.4em; }
```

Everything else uses ReSpec's default stylesheet.

---

## 8. Execution sequence

### Phase 1 — DSA pilot
1. Add shared `<style>` block.
2. Insert newcomer on-ramp (`overview` section with how-it-works, glance tables, arch + trust diagrams, walkthrough).
3. Convert all credential/object definitions to the member-table template.
4. Add rationale asides (≈ 4 in DSA).
5. Annotate existing examples with `title` attributes.
6. Structural check: balanced tags; harness still green.
7. Commit: `feat(spec): readability overhaul — DSA pilot`.

**Checkpoint:** human reviews the rendered DSA spec before Payments begins.

### Phase 2 — Payments
1. Copy the `<style>` block (identical).
2. Insert the Payments on-ramp (how-it-works, larger glance tables, arch + two sequence diagrams, two walkthrough narratives).
3. Convert all message/credential definitions to the member-table template (≈ 12 objects).
4. Add rationale asides (≈ 6 in Payments).
5. Annotate existing examples.
6. Structural check + harness green.
7. Commit: `feat(spec): readability overhaul — Payments`.

---

## 9. Non-goals (explicitly out of scope)

- Custom ReSpec theme or overriding W3C stylesheet globally.
- Interactive elements (collapsible sections, tabs, search).
- Hosted/CDN deployment or GitHub Pages setup.
- Changing the normative content, object model, namespace, or examples in any substantive way.
- Updating the test vectors, context files, schemas, shapes, or harness.
