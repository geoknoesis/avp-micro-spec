# Design: Split AVP-Micro into two peer specifications

**Date:** 2026-06-04
**Status:** Approved (brainstorming) — pending implementation plan
**Author:** Stephane Fellah (with Claude)

## 1. Motivation

The current single specification (`spec/index.html`) has grown to cover two
separable concerns:

1. **Standing, transaction-independent authority** — who a principal is, the
   credential by which it delegates spending authority to an agent, how trust in
   issuers is established, and the cryptographic/identity primitives that secure
   all of this.
2. **Per-transaction payments** — negotiating, authorizing, executing, and
   receipting a specific payment (and streaming sessions).

External review observed that the `SpendingAuthorizationCredential` /
delegated-authority layer is the unique, reusable contribution and deserves to
stand on its own ("delegated machine financial authority"), independent of the
micropayment flow. Splitting now — before any `w3id.org` registration or CG
adoption — is the cheapest time to do it.

## 2. Decisions (resolved during brainstorming)

| # | Decision | Choice |
|---|----------|--------|
| Topology | How the specs relate | **Two peer specs; Payments normatively depends on Authority.** |
| Namespace | IRI strategy | **Independent namespaces.** Authority owns its own; Payments keeps `avp-micro`. |
| Naming | Authority spec identity | **"Delegated Spending Authority" (DSA)**, `https://w3id.org/spending-authority/v1#`, prefix `dsa:`, shortName `spending-authority`. |
| Layout | Repo structure | **`spec/authority/` + `spec/payments/`** with a shared top-level harness. |

Payments stays **"AVP-Micro Payments"**, `https://w3id.org/avp-micro/v1#`,
prefix `avp:`, shortName `avp-micro`.

## 3. Cut principle

> **DSA owns everything that exists independent of a specific payment
> transaction. Payments owns everything about negotiating and settling one
> transaction.**

### 3.1 Section mapping (from current `spec/index.html`)

**→ Delegated Spending Authority (DSA)**
- Front matter: DSA-specific abstract, SOTD, introduction.
- Conformance; terminology subset: Principal, payer agent, Securing mechanism, **content digest** (primitive), **monetary amount format** (primitive), `currency`.
- Namespace & JSON-LD context (DSA context); `agent-service-categories` SKOS vocabulary.
- DID documents & service endpoints (`did-requirements`).
- Securing mechanisms (`securing`) incl. verification-method binding (`key-binding`) and DID-state-at-`proof.created` (`did-state-binding`).
- The generic **content-digest form** definition (the `<alg>:<base64url>` datatype).
- Credential types: `SpendingAuthorizationCredential`, `PaymentCapabilityCredential`, `MerchantCredential`.
- Category matching semantics + service-category vocabulary.
- `dailyLimit` claim semantics and the day-boundary definition (the *enforcement/aggregation step* stays in Payments wallet processing).
- Trust establishment + trust vocabulary (`TrustAnchor`/`TrustedIssuer`/`IssuerScope`).
- Security/Privacy/i18n/Accessibility considerations — DSA subset (credential theft/replay, issuer trust, term injection, currency/asset formatting).
- DSA conformance classes; DSA Security & Privacy self-review appendix; acknowledgements.

**→ AVP-Micro Payments (depends on DSA)**
- Front matter: Payments abstract/SOTD/introduction (states the DSA dependency).
- Conformance; terminology subset: Payee service, Wallet service, Settlement rail, Payment quote, Economic terms (Securing mechanism, content digest, amount format **referenced from DSA**).
- Namespace & JSON-LD context (`avp-micro` context; references DSA).
- Request binding: `serviceRequestHash`, `quoteDigest`, default request canonicalization (built on the DSA content-digest form).
- Securing: references DSA; defines **execution-signer binding** (`execution-binding`).
- Messages: `PaymentOffer`, `PaymentQuote`, `PaymentAuthorization` (embeds a VP carrying a DSA `SpendingAuthorizationCredential`), `PaymentExecution`, `PaymentReceipt`.
- Streaming: `UsageSession`, `UsageAccrual`, `SessionBudgetAuthorization`, `UsageSessionExtension` + lifecycle/settlement/integrity.
- Workflows; wallet verification (one-off, session-budget, streaming accrual, **daily-limit aggregation enforcement**); replay protection (`integrity`).
- Error model; disputes; extensions; audit.
- Security/Privacy considerations — Payments subset (term/settlement-target tampering, request substitution, replay, over-spend, streaming-charge inflation).
- Examples; Payments conformance classes; Payments Security & Privacy self-review appendix; acknowledgements.

### 3.2 Boundary call-outs
- **`currency`** is the one genuinely shared *term*; it is defined **once in the DSA context** and reused by Payments (resolved via the 4-entry `@context`, see §4).
- **MerchantCredential** and **category-matching semantics** land in **DSA** (standing attestation + classification), while the Payments wallet algorithm *invokes* the matching and also handles the discovery-only `PaymentOffer` self-asserted-category case.
- **`dailyLimit`**: claim definition + day boundary in DSA; cross-transaction aggregation/serialization requirement in the Payments wallet algorithm.

## 4. Namespace & context mechanics (explicit arrays, no `@import`)

- **DSA objects** (e.g. `SpendingAuthorizationCredential`) declare:
  `["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/data-integrity/v2", "https://w3id.org/spending-authority/v1"]`
- **Payments objects** declare a **4-entry** array:
  `["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/data-integrity/v2", "https://w3id.org/spending-authority/v1", "https://w3id.org/avp-micro/v1"]`
  so the shared `currency` term and the embedded SAC resolve from the DSA
  context.
- The `avp-micro` context defines **only** payment terms and **MUST NOT**
  redefine any `dsa:` term. Both contexts remain `@protected` with no `@vocab`;
  identical/disjoint definitions compose without conflict.
- Explicit arrays were chosen over JSON-LD 1.1 `@import` for signature
  determinism and to avoid a fetch-time dependency between contexts.
- **`@context` array order is signature-significant** (JCS preserves array
  order); both specs restate the mandatory order.

## 5. Repo layout

```
spec/
├─ authority/
│  ├─ index.html                         # DSA ReSpec document
│  ├─ context/v1.jsonld                   # dsa: context (+ shared currency, primitives)
│  ├─ schemas/dsa.schema.json
│  ├─ shapes/dsa-shapes.ttl
│  ├─ vocab/dsa.ttl                        # RDFS/OWL ontology (authority classes)
│  ├─ vocab/agent-service-categories.ttl  # SKOS service categories
│  ├─ test-vectors/                        # SAC, merchant cred, capability cred, trusted-issuers, dids
│  └─ README.md
├─ payments/
│  ├─ index.html                          # AVP-Micro Payments ReSpec document
│  ├─ context/v1.jsonld                    # avp: context (payment terms only)
│  ├─ schemas/avp-micro.schema.json
│  ├─ shapes/avp-shapes.ttl
│  ├─ vocab/avp.ttl                         # RDFS/OWL ontology (payment classes)
│  ├─ test-vectors/                         # quote→authz→exec→receipt + streaming chain
│  └─ README.md
├─ avp_crypto.py        # shared eddsa-jcs-2022 + did:key primitives
├─ generate.py          # shared generator → writes BOTH test-vector dirs
├─ verify.py            # shared reference verifier over the linked chain
├─ validate.py          # Turtle / JSON-LD / JSON Schema / SHACL over BOTH bundles
└─ README.md            # top-level: the two specs and how they relate
```

## 6. Test vectors & harness

- `authority/test-vectors/`: `spending-authorization-credential.json` (issuer-signed),
  `merchant-credential.json`, `payment-capability-credential.json`,
  `trusted-issuers.json` (a trust-config example; not a signed wire message),
  `dids.json`.
- `payments/test-vectors/`: `01-payment-quote` → `02-payment-authorization`
  (embeds the DSA SAC) → `03-payment-execution` → `04-payment-receipt`, plus the
  streaming chain (session, budget-auth, accrual, session execution, session
  receipt, session extension, re-auth budget). **Note the renumber:** the current
  bundle's `02-spending-authorization-credential` moves to
  `authority/test-vectors/` (as a named, not numbered, fixture), so the payment
  one-off chain is renumbered `01`–`04` and the streaming vectors follow.
- **One shared `generate.py`** produces both bundles because the payment
  authorization cryptographically embeds the authority SAC; they must be
  generated together. **One `verify.py`** re-checks the full linked chain. **One
  `validate.py`** runs Turtle parse (both ontologies + SKOS + both SHACL files),
  JSON-LD expansion, JSON Schema, and SHACL across **both** dirs and MUST report
  all PASS.
- Verification gate: the existing green-bar (all `verify.py` + `validate.py`
  checks PASS) is preserved after the split — proof that no behavior changed.

## 7. Document cross-references & conformance classes

- Payments cites DSA via a `localBiblio` `[[DSA]]` entry (href to the DSA
  document) and links DSA section URLs; each document keeps its own ReSpec
  config, SOTD, IPR/CLA, and Security & Privacy self-review.
- **DSA conformance classes:** credential issuer / principal; credential
  verifier; trust evaluator.
- **Payments conformance classes:** payer agent; wallet; payee; verifier
  (unchanged). The Payments verifier additionally relies on DSA verification
  (proofs, key-binding, DID-state-at-proof-time).

## 8. Migration approach

This is a **restructure, not a rewrite**. Ordered steps:

1. Create `spec/authority/` and `spec/payments/` skeletons.
2. Move authority sections + DSA context/schema/SHACL/ontology/SKOS into
   `authority/`; repoint moved terms to the `dsa:` namespace.
3. Move payment sections + context/schema/SHACL/ontology into `payments/`; add
   the `[[DSA]]` bibliography and cross-links; switch payment objects to the
   4-entry `@context`.
4. Split the shared harness so `generate.py` writes both vector dirs and
   `validate.py`/`verify.py` cover both.
5. Regenerate all vectors; run `verify.py` + `validate.py`; confirm all PASS.
6. Update top-level and per-spec READMEs; record both `w3id.org` registrations
   as prerequisites.

**No normative requirement changes.** Section text is relocated and IRIs
repointed; the harness green-bar proves behavior is preserved.

## 9. Risks & mitigations

- **Shared `currency` term across namespaces** → defined once in DSA; Payments
  objects include the DSA context (4-entry array). Mitigation verified by the
  JSON-LD expansion check.
- **Two `w3id.org` registrations** instead of one → both still unregistered, so
  no added migration cost; documented as prerequisites.
- **More files to keep in sync** → single shared harness validates both bundles
  on every run.
- **Cross-document anchors** (Payments → DSA) can rot → tracked via the `[[DSA]]`
  bibliography and a link-check during the ReSpec build.

## 10. Out of scope (this change)

- Defining `Refund`/`Reversal` or `DelegatedAuthorizationCredential` objects
  (remain noted extensions).
- Any change to normative requirements, wire formats, or the securing mechanism.
- `w3id.org` registration and independent cross-implementation crypto validation
  (external prerequisites, unchanged).
