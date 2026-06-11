# Generalized `pricingModel` vocabulary for AVP-Micro Payments

**Date:** 2026-06-11
**Status:** Design — approved, pending implementation plan
**Bundle:** `spec/payments/` (namespace `https://w3id.org/avp-micro/v1#`)
**Motivating question:** How can we represent offers and quotes for AWS-style services?

## 1. Problem

A `PaymentOffer` advertises a `pricingModel`, and a `UsageSession` carries one as the
active terms governing accruals. Today `pricingModel` is mapped in the JSON-LD context
as `@type: @json` — an **opaque literal blob**. Consequences:

- Its internal terms (`type`, `amount`, `unit`) **do not expand to IRIs**, so they are
  invisible to RDF, SHACL, and the ontology.
- The ontology leaves `avp:pricingModel` abstract with only a prose comment
  ("the RECOMMENDED model is `{type:PerUnit, amount, unit}`"). There are no classes for
  `PerCall` / `PerUnit`.
- The SHACL `PaymentOfferShape` / `UsageSessionShape` only assert `pricingModel`
  *exists* (`sh:minCount 1`); they cannot see inside it.

So the only two pricing shapes in the wild — `{type:PerCall, amount, currency}` (offer
`00`) and `{type:PerUnit, amount, unit}` (session `05`) — have **zero machine-checkable
semantics**, and nothing expresses AWS-style pricing: multi-dimensional charges, tiered
rates, commitments, or free tiers.

## 2. Goal

Replace the opaque shape with a **composable rate-component vocabulary** that:

1. Expresses per-unit metered, multi-dimensional, tiered/graduated, and
   commitment/free-tier pricing.
2. Is **general**, not AWS-specific — AWS is the stress-test, not a dependency.
3. Stays **back-compatible**: existing `PerCall` / `PerUnit` vectors remain valid as the
   single-component degenerate case.
4. Reuses the spec's existing interoperability mechanisms (JSON-LD context, OWL
   ontology, SHACL, normative prose, signed test vectors).
5. Does **not** touch the running app (spec-only, per `CLAUDE.md`) or the DSA bundle.

## 3. The vocabulary (composable rate components)

A `pricingModel` is either a single inlined component (back-compat) or a
`CompositePricing` wrapping a `components[]` list. The total charge is the sum of all
components, all denominated in one model-level `currency`.

### 3.1 Component classes

| Class | Members | Meaning |
|---|---|---|
| `PerCall` | `{ type, amount }` | Flat charge per invocation. |
| `PerUnit` | `{ type, dimension, unit, amount }` | Linear rate per unit of one dimension. |
| `TieredRate` | `{ type, dimension, unit, tierMode, tiers[] }` | Rate varies with cumulative volume. |
| `CommitmentRate` | `{ type, dimension?, unit?, upfront, recurring:{amount,period}, includedQuantity? }` | Reserved-instance style: upfront fee + reduced recurring rate. |
| `Allowance` | `{ type, dimension, unit, freeQuantity }` | Free tier: first N units at zero cost. |
| `CompositePricing` | `{ type, currency, components[] }` | Sum of nested components. |

- **`tiers`** is an ordered list of `{ upTo?, amount }`. Every tier except the last has an
  `upTo` breakpoint (cumulative quantity ceiling, as a decimal string); the last tier
  omits `upTo` and is open-ended.
- **`tierMode`** is `"graduated"` (marginal/progressive — each band priced at its own
  rate, like income tax) or `"volume"` (the entire usage priced at the single tier the
  total lands in).
- **`Allowance`** is applied to its dimension's quantity **before** any other component on
  the same dimension evaluates. (A free tier can alternatively be encoded as a leading
  `tiers` entry with `amount:"0"`; `Allowance` is the explicit, clearer form.)

### 3.2 Back-compatibility

`{ type:"PerCall", amount, currency }` and `{ type:"PerUnit", amount, unit, currency }`
are valid pricing models on their own — they are single components with the `currency`
carried at the component level. `CompositePricing` is the canonical general form; a
single-dimension service need not wrap one component in a composite.

## 4. Interoperability stack

Interoperability is a five-layer ladder; each rung reuses a mechanism the spec already
uses elsewhere, now pointed at the pricing internals.

| Layer | What it guarantees | Mechanism | File(s) |
|---|---|---|---|
| 0 De-opaque | Pricing terms become RDF-visible | Drop `@type:@json`; make `pricingModel` a real JSON-LD node | `context/v1.jsonld` |
| 1 Identity | Same name → same global IRI | Map every class/property term to an `avp:` IRI | `context/v1.jsonld` |
| 2 Definition | Shared human/machine meaning | OWL classes + properties, `rdfs:label`, `skos:definition`, domains/ranges | `vocab/avp.ttl` |
| 3 Controlled vocabularies | Agreed values for divergence-prone terms | `dimension`→SKOS scheme; `unit`→QUDT + AVP composites; `currency`→ISO 4217 | new `vocab/dimensions.ttl`, `vocab/units.ttl` |
| 4 Structural conformance | "Is this a well-formed rate card?" | JSON Schema `$defs/pricingModel` (per-type `oneOf`) + class-targeted SHACL | `schemas/avp-micro.schema.json`, `shapes/avp-shapes.ttl` |
| 5 Operational semantics | Two implementations compute the same total | Normative evaluation algorithm + conformance vectors | `index.html`, `test-vectors/` |

### 4.1 Layer 3 — the controlled vocabularies (the heart of interop)

`type` is fully handled by Layers 1–2. The terms where independent parties actually
diverge are `dimension`, `unit`, and `currency`.

**`dimension` — SKOS concept scheme.** An AVP scheme of standard metering dimensions
(`requests`, `invocations`, `computeTime`, `computeMemoryTime`, `dataTransferIn`,
`dataTransferOut`, `storageDuration`, `tokens`, …), mirroring the existing
`cat:`/`categories` IRI convention. A `dimension` IRI is **the same value used as
`meterType`** in the accrual flow — pricing dimensions and metering dimensions share one
namespace.

**`unit` — QUDT IRIs + AVP composite registry.** Atomic units reference QUDT IRIs
(`unit:GigaBYTE` vs `unit:GibiBYTE`, `unit:HR`), which removes the decimal-vs-binary
"GB" ambiguity (a ~7% disputed-charge gap, since AWS bills both ways). Composite billing
units (`GB-second`, `GB-month`) that are not atomic in QUDT live in an `avp-unit:`
registry, each **defined** via `qudt:hasQuantityKind` + a base unit + a time factor, so
even custom units inherit standard semantics.

**`currency` — ISO 4217.** Constrained to `^[A-Z]{3}$`, with an extension slot (a token
contract IRI/DID) for non-fiat. Today it is an unconstrained literal; the tightening is
applied in the payments schema/shapes only (currency is `dsa:currency`; the DSA bundle is
not edited).

**`amount`** is already a typed decimal string. Its interop rule is *contextual*: an
amount is only meaningful as the tuple `(amount, currency, per-unit, per-dimension)`, so
shapes and prose bind these together — an amount never floats free.

### 4.2 Governance — hybrid (closed core + extension slot)

`dimension`, `unit`, and `currency` use a SHACL `sh:or( closed-core-list ,
namespaced-extension-IRI )`:

- The **core set** is `sh:in`-enforced → guaranteed interop on the common case.
- A **namespaced extension IRI** (`avp-x:`-prefixed, or an `x-` member) is structurally
  accepted but carries no semantic guarantee → escape hatch for the long tail.

This works within the `@protected` context because the extension slot is itself a
declared term, so unknown provider terms do not break JSON-LD expansion.

## 5. Connection to the metered flow (no new message fields)

A component's `dimension` IRI is a valid `meterType`. A multi-dimensional `UsageSession`
references a `CompositePricing`; each `UsageAccrual` tags itself with `meterType` =
dimension IRI, `meterUnit` = unit IRI, `meterReading`, and `amountAccrued` computed from
that dimension's component via the Layer-5 algorithm.

`UsageAccrual` **already** has optional `meterType` / `meterUnit`, so nothing new is
added. The session-level singular `meterType` / `meterUnit` simply become optional hints
when the pricing model is composite. `PaymentReceipt.totalMeterReading` remains the
rolled-up total; per-dimension totals stay expressible via per-accrual tagging (a
per-dimension map is deferred — YAGNI).

## 6. Quote behavior — two paths, unchanged schemas

- **Firm path (bounded request):** the payee evaluates the offer's `pricingModel` against
  the known usage vector and returns a deterministic `PaymentQuote.amount`. The
  `PaymentQuote` schema is untouched.
- **Metered path (unbounded/streaming):** the existing
  `UsageSession` → `UsageAccrual` → `SessionBudgetAuthorization` flow, where the
  `pricingModel` governs accrual math.

The deferred `usageAssumptions` quote-verifiability add-on (Section 9) would let a payer
re-derive `amount = evaluate(rateCard, usage)`; it is intentionally out of scope for this
iteration.

## 7. Normative evaluation algorithm (Layer 5)

`evaluate(pricingModel, usageVector) → amount`:

- **`CompositePricing`** → Σ `evaluate(component, usageVector[component.dimension])`.
- **`PerCall`** → `amount` (per invocation).
- **`PerUnit`** → `amount × quantity`.
- **`TieredRate` / `graduated`** → Σ over tiers of `(quantity falling in that band) ×
  tier.amount`.
- **`TieredRate` / `volume`** → `quantity × (amount of the tier the total quantity lands
  in)`.
- **`Allowance`** → subtract `freeQuantity` from the dimension's quantity (floor at 0)
  before that dimension's other components evaluate.
- **`CommitmentRate`** → `upfront` (once) + `recurring.amount × periods`;
  `includedQuantity` offsets metered usage on the dimension before metered components
  evaluate.

Rules:

- All components MUST share the model-level `currency`; a mismatch makes the model
  invalid.
- The final total is `quantize(0.00000001, ROUND_HALF_UP)` — matching the app's money
  rule (`Numeric(18,8)`).

The algorithm is pinned by **conformance vectors**: signed fixtures pairing
`(pricingModel, usageVector)` with an `expectedAmount`, regenerated by `generate.py` and
re-derived/checked by `verify.py`, so any implementation can self-test to byte-equality.

## 8. Worked AWS examples (become test vectors)

- **Lambda-like:** `CompositePricing` of `PerUnit(requests / request)` +
  `PerUnit(computeMemoryTime / GB-second)`, each with an `Allowance` free tier.
- **S3-like:** `TieredRate(storageDuration / GB-month, graduated)` with descending
  per-GB rates across volume tiers.

Each yields a `PaymentOffer` vector plus a conformance vector pinning a usage vector to an
exact computed amount.

## 9. Out of scope (YAGNI / deferred)

- Elastic quotes (estimate + cap on `PaymentQuote`).
- The `usageAssumptions` quote-verifiability add-on.
- Deep commitment variants (multi-year, partial/all-upfront, blended discounts) — the
  `CommitmentRate` shape is defined; examples stay minimal.
- Currency conversion / multi-currency models — one currency per model.
- Per-region pricing matrices — modeled as separate offers per region, not a vocabulary
  feature.
- Any wiring into the running app.

## 10. Files touched

| File | Change |
|---|---|
| `spec/payments/context/v1.jsonld` | De-opaque `pricingModel`; map component classes + properties; add `avp-dim:`/`avp-unit:`/`qudt:` prefixes. |
| `spec/payments/vocab/avp.ttl` | OWL classes + properties for components; replace the abstract `pricingModel` comment. |
| `spec/payments/vocab/dimensions.ttl` | **New** — SKOS concept scheme of standard metering dimensions. |
| `spec/payments/vocab/units.ttl` | **New** — AVP composite-unit registry referencing QUDT quantity kinds. |
| `spec/payments/schemas/avp-micro.schema.json` | `$defs/pricingModel` + `$defs/rateComponent` (per-type `oneOf`, tier shape); reference from `PaymentOffer` + `UsageSession`. |
| `spec/payments/shapes/avp-shapes.ttl` | Class-targeted component shapes; `dimension`/`unit`/`currency` `sh:or(core, extension)`; tier well-formedness. |
| `spec/payments/index.html` | New normative section: vocabulary + evaluation algorithm + AWS examples + governance notes. |
| `spec/payments/README.md` | List new artifacts and vectors. |
| `spec/payments/test-vectors/` | New rich-pricing offer vector(s) + conformance vectors. |
| `spec/generate.py`, `spec/verify.py`, `spec/validate.py` | Generate/verify new vectors; run pricing-evaluation conformance checks. |

`spec/avp_crypto.py` and the entire `spec/authority/` (DSA) bundle are untouched.

## 11. Done = green

`python spec/verify.py` and `python spec/validate.py` both report PASS, including the new
conformance-vector checks.
