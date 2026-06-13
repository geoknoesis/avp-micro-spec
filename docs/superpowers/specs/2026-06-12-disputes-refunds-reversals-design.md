# Design: Refunds, Reversals, Chargebacks & Dispute Lifecycles extension

**Date:** 2026-06-12
**Status:** Approved design — ready for implementation planning
**Bundle:** `spec/disputes/` (new fourth peer bundle)
**Namespace:** `https://w3id.org/avp-micro/disputes/v1#` (prefix `disp:`)

## 1. Summary

A fourth peer bundle (alongside `authority/`, `payments/`, `interop-sd-jwt-vc/`) that
adds the **reverse value-flow** to AVP-Micro: returning value to a payer, whether
voluntarily (a refund) or adversarially (a disputed charge that is upheld — a
"chargeback"), together with a full **dispute lifecycle**.

The central modelling insight: **"refund", "reversal", and "chargeback" are not three
parallel objects.** They are the same reverse value-movement reached by different
triggers:

- **Refund** — voluntary; the payee decides to return value.
- **Chargeback** — adversarial; a *dispute* is upheld and forces value back.
- **Reversal** — the wallet-signed settlement *fact* that actually moves value back
  (the artifact both of the above produce).

So the model is **two trigger paths** (a voluntary `Refund` intent; an adversarial
`Dispute → DisputeEvidence* → DisputeResolution` lifecycle) that **converge on one
wallet-signed `Reversal` settlement fact**, with an optional payer acknowledgement.

### Decisions that shaped this design

1. **Deliverable:** full buildable design — brainstorm → spec → plan → build, ending
   with `verify.py` and `validate.py` reporting PASS.
2. **Resolution model:** **bilateral + optional arbiter.** Default flow is
   payer↔payee; an optional arbiter DID can sign a binding resolution on escalation.
   The arbiter is a *role*, not a requirement.
3. **External anchor:** **native model + informative mapping notes.** Clean,
   settlement-agnostic reason codes as an extensible SKOS vocabulary, with
   non-normative mappings to card-network chargebacks / ISO 20022 reversals. No
   binding to any external framework — consistent with the spec's domain-neutral
   stance.
4. **Reverse-flow depth:** **intent + settlement fact.** A signed return-intent
   record (`Refund`, or a `DisputeResolution`) plus a wallet-signed settlement fact
   (`Reversal`, mirroring `PaymentExecution`), with an optional payer-signed
   acknowledgement. Symmetric with the forward flow, without exploding object count.

### Non-goals (YAGNI)

- No new cryptosuite — reuse `ecdsa-jcs-2022` via `avp_crypto.sign_ecdsa_jcs_2022`.
- No new spending-authority semantics — reverse-flow value movement does **not**
  consume a `SpendingAuthorizationCredential` (see §3, note).
- No mutable/stateful objects — the lifecycle is append-only signed records; "state"
  is *derived* from the record set, never stored in a field.
- No changes to the payments or authority bundles — disputes only *reference* them.
- Not card-network-specific (no representment SLAs, no arbitration fee tiers, no
  mandatory reason-code enumerations beyond the extensible native scheme).

## 2. Bundle layout, namespace & dependencies

```
spec/disputes/
  context/v1.jsonld          # JSON-LD 1.1, @version 1.1, @protected true
  schemas/disputes.schema.json
  shapes/disputes-shapes.ttl
  vocab/disputes.ttl         # RDFS/OWL classes + properties
  vocab/reasons.ttl          # SKOS reason-code scheme
  test-vectors/*.json        # signed examples
  README.md                  # artifact table + vector index
  index.html                 # W3C ReSpec normative prose
```

- **Namespace:** `https://w3id.org/avp-micro/disputes/v1#` (prefix `disp:`) — a
  sub-path of `avp-micro`, mirroring how the interop bundle nests under
  `avp-micro/interop/...`.
- **Context URL → file:** `https://w3id.org/avp-micro/disputes/v1` →
  `spec/disputes/context/v1.jsonld`, served offline by the local document loader in
  `validate.py` (same pattern as the other bundles).
- **Context array (5-entry):**
  `["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/data-integrity/v2",
  "https://w3id.org/spending-authority/v1", "https://w3id.org/avp-micro/v1",
  "https://w3id.org/avp-micro/disputes/v1"]`.
  The payments context is included so dispute objects **reuse** existing terms
  (`amount`, `currency`, `payer`, `payee`, `settlementRef`, `status`) instead of
  redefining them; the disputes context adds only the new dispute terms.
- **Dependencies:**
  - **Payments** — dispute objects reference `PaymentReceipt`, `PaymentExecution`,
    and `PaymentAuthorization` by IRI **plus** a JCS digest.
  - **DSA** — identity via `did:key` (P-256 Multikey), the mandatory `ecdsa-jcs-2022`
    cryptosuite.
- **Securing:** every dispute object is a `DataIntegrityProof` / `ecdsa-jcs-2022`
  envelope (`type: DataIntegrityProof`, `cryptosuite: ecdsa-jcs-2022`,
  `proofPurpose: assertionMethod`), signed with the existing crypto core. No new
  crypto primitives.

**Binding principle:** a dispute object binds to the payment object it concerns the
same way the forward flow binds — an IRI reference **plus** a `*Digest` JCS hash — so
the object is cryptographically pinned to the exact receipt/execution/authorization it
concerns and cannot be re-pointed at a different transaction.

## 3. Object model

Six objects. Every object reuses the payments `amount` / `currency` / `payer` /
`payee` / `settlementRef` / `status` terms, and binds to what it concerns with IRI +
JCS digest.

| Object | `type` / id prefix | Signer | Binds to (IRI + digest) | Purpose |
|---|---|---|---|---|
| **Refund** | `Refund` / `urn:avp:refund:` | payee | `receipt` (+ optional `execution`) | Voluntary return intent |
| **Dispute** | `Dispute` / `urn:avp:dispute:` | payer | `receipt` / `execution` / `authorization` (≥1) | Opens an adversarial case |
| **DisputeEvidence** | `DisputeEvidence` / `urn:avp:dispute-evidence:` | payer **or** payee | `dispute` | Evidence / representment (append-only) |
| **DisputeResolution** | `DisputeResolution` / `urn:avp:dispute-resolution:` | payer, payee, **or** arbiter | `dispute` (+ optional `supersedes`) | Decision: upheld / rejected / partial / withdrawn |
| **Reversal** | `Reversal` / `urn:avp:reversal:` | wallet | `refund` **xor** `resolution` (+ optional original `execution`) | Settlement fact: value actually moved back |
| **ReversalAcknowledgement** | `ReversalAcknowledgement` / `urn:avp:reversal-ack:` | payer | `reversal` | Optional: payer confirms funds received |

### 3.1 Field detail

**Refund** (`disp:Refund`)
- `receipt` (IRI) + `receiptDigest` — required: the receipt being refunded.
- `execution` (IRI) + `executionDigest` — optional: the original forward settlement.
- `payer`, `payee` (DIDs).
- `amount`, `currency` — the refunded amount (partial = `amount` < original; multiple
  partials allowed, governed by accounting rules in §5).
- `reason` (IRI into the SKOS reason scheme).
- `note` — optional human text.
- `timestamp`; optional `expires`.
- `proof`.

**Dispute** (`disp:Dispute`)
- At least one of `receipt` / `execution` / `authorization`, each with its `*Digest`.
- `payer`, `payee` (DIDs).
- `disputedAmount`, `currency` — amount in dispute (≤ original).
- `reason` (IRI into the SKOS reason scheme).
- `claim` — optional human text describing the dispute.
- `arbiter` — optional DID proposed/agreed for escalation.
- `timestamp`; optional `respondBy` (payee response deadline).
- `proof`.

**DisputeEvidence** (`disp:DisputeEvidence`)
- `dispute` (IRI) + `disputeDigest`.
- `submittedBy` (DID).
- `role` — `payer` | `payee` (which side submitted; MUST be consistent with
  `submittedBy`).
- `sequence` — integer, unique and ordered per dispute.
- `evidenceType` — optional string/SKOS (e.g. delivery proof, usage log,
  communication).
- `contentDigest` + `uri` — optional: the evidence artifact itself is off-spec /
  out-of-band; the object carries only its hash (and optional locator).
- `statement` — optional human text.
- `timestamp`.
- `proof`.

This is the **representment / rebuttal** mechanism: the payee submits evidence to
contest a dispute; the payer may submit rebuttal evidence.

**DisputeResolution** (`disp:DisputeResolution`)
- `dispute` (IRI) + `disputeDigest`.
- `resolvedBy` (DID).
- `resolverRole` — `payer` | `payee` | `arbiter`.
- `outcome` — `upheld` (payer wins, value returned) | `rejected` (payee wins, no
  return) | `partial` (partial return) | `withdrawn` (payer abandons the claim).
- `resolvedAmount`, `currency` — value to be returned (0 for `rejected` /
  `withdrawn`).
- `note` — optional rationale.
- `supersedes` (IRI) + `supersedesDigest` — optional: an arbiter resolution
  superseding a prior payee resolution (the only escalation mechanism).
- `timestamp`.
- `proof`.

**Reversal** (`disp:Reversal`)
- `cause` — `refund` | `dispute` (discriminator).
- Exactly one of: `refund` (IRI) + `refundDigest` (when `cause=refund`) **xor**
  `resolution` (IRI) + `resolutionDigest` (when `cause=dispute`) — a `oneOf`,
  mirroring `PaymentExecution`'s `authorization` / `sessionBudgetAuthorization`
  `oneOf`.
- `execution` (IRI) + `executionDigest` — optional: the original forward
  `PaymentExecution` being reversed (links money-out to money-back).
- `payer`, `payee` (DIDs).
- `amount`, `currency` — value actually returned.
- `status` — `completed` | `partial` | `failed` | `pending`.
- `settlementRef` — optional rail identifier for the reverse movement.
- `timestamp`.
- `proof`.

**ReversalAcknowledgement** (`disp:ReversalAcknowledgement`)
- `reversal` (IRI) + `reversalDigest`.
- `payer`, `payee` (DIDs).
- `amount`, `currency`.
- `receivedAt` — timestamp the payer observed the funds.
- `proof`.

### 3.2 Spending authority (note)

Reverse-flow value movement does **not** consume a `SpendingAuthorizationCredential`.
None of these six objects subclass `dsa:AuthorizationInstance` — they are
payee / payer / wallet / arbiter-signed records, not payer spend-authorizations. A
chargeback returning value to the payer obviously requires no payer spend-permission;
a voluntary refund is the payee's own decision. This keeps the bundle settlement- and
authority-agnostic.

## 4. Dispute lifecycle (state machine)

**Crucial framing:** state is *derived from the set of signed records*, not stored in
a mutable field. Each transition **is** the creation of a new signed object. This
keeps everything append-only and independently signed — no object is ever mutated,
which is what makes the bilateral + arbiter model work cryptographically (three
different parties can each sign their own records).

### 4.1 Voluntary path (no dispute)

```
Refund (payee)  →  Reversal cause=refund (wallet)  →  [ReversalAcknowledgement (payer)]
```

### 4.2 Adversarial path

Derived states in CAPS; the signed object that effects each transition in parens.

```
            Dispute (payer)
                 │
              ┌──┴───────────────┐
              ▼                   ▼
           OPENED ───────────► WITHDRAWN   (DisputeResolution, role=payer, outcome=withdrawn) ─┐
              │  DisputeEvidence* (payer/payee, append-only, "representment")                   │ terminal
              ▼                                                                                 │
          UNDER-REVIEW                                                                          │
              │  DisputeResolution (role=payee)                                                 │
              ▼                                                                                 │
           RESOLVED ── outcome=rejected ───────────────────────► CLOSED ─────────────────────────┘
              │
              ├─ outcome=upheld|partial ─► SETTLED: Reversal cause=dispute (wallet) → [Ack] → CLOSED
              │
              └─ payer escalates (out-of-band to the agreed arbiter)
                     │  DisputeResolution (role=arbiter, supersedes=payee resolution)  ← BINDING
                     ▼
                 ARBITRATED ── rejected → CLOSED
                            └─ upheld|partial → SETTLED → CLOSED
```

- `resolverRole` is `payer | payee | arbiter`. `withdrawn` requires `role=payer` and
  may occur from either `OPENED` or `UNDER-REVIEW` (the diagram shows it from `OPENED`
  for brevity); an `arbiter` resolution MUST carry `supersedes` + `supersedesDigest`
  pointing at the payee resolution it overrides (escalation is the only way an arbiter
  enters the lifecycle).
- A `Reversal` may exist only when a terminal resolution has `outcome ∈ {upheld,
  partial}` (dispute path) or a `Refund` exists (voluntary path). §5 makes this a
  normative, machine-checkable rule.
- Escalation itself is an out-of-band agreement to use the `arbiter`; the on-spec
  artifact is the arbiter's superseding `DisputeResolution`.

## 5. Normative rules (machine-checkable)

Every rule below becomes a check in `verify.py` (semantic) or `validate.py`
(structural), so a PASS run actually means the dispute semantics hold.

### 5.1 Integrity / binding (`verify.py`)

- **B1** — every `proof` verifies under `ecdsa-jcs-2022`.
- **B2** — signer binding (proof `verificationMethod` DID matches the expected role):
  - `Refund` → payee
  - `Dispute` → payer
  - `DisputeEvidence` → `submittedBy` (which MUST be the payer or payee of the
    referenced dispute, matching `role`)
  - `DisputeResolution` → `resolvedBy`, where `role=payee` ⇒ payee DID, `role=payer`
    ⇒ payer DID, `role=arbiter` ⇒ the dispute's `arbiter` DID
  - `Reversal` → wallet (the same wallet that signed the original `execution`, when
    `execution` is present)
  - `ReversalAcknowledgement` → payer
- **B3** — digest binding: every `*Digest` equals `jcs_digest()` of the referenced
  object (`receiptDigest == jcs_digest(receipt)`, etc.).
- **B4** — party consistency: `payer` / `payee` on a dispute object match the
  `payer` / `payee` of the referenced payment object(s).
- **B5** — currency consistency across the whole refund / dispute chain.

### 5.2 Accounting (partial & multiple refunds) (`verify.py`)

- **A1** — `amount` (and `resolvedAmount`) MUST be > 0 and ≤ the referenced original
  `amount`.
- **A2** — no over-refund: the sum of all *settled* returned value — i.e. every
  `Reversal` with `status ∈ {completed, partial}`, whether `cause=refund` or
  `cause=dispute` — against one original execution MUST NOT exceed the original
  `amount`.
- **A3** — a Reversal's `amount` equals the triggering `Refund.amount`
  (`cause=refund`) or the resolution's `resolvedAmount` (`cause=dispute`); `≤` when
  `status=partial`.
- **A4** — `disputedAmount` ≤ original `amount`; `resolvedAmount` ≤ `disputedAmount`.

### 5.3 State validity (`verify.py`)

- **S1** — a Reversal with `cause=dispute` MUST reference a `DisputeResolution` whose
  `outcome ∈ {upheld, partial}`.
- **S2** — an arbiter `DisputeResolution` MUST carry `supersedes` → a prior payee
  resolution for the same dispute, and its arbiter DID MUST equal the dispute's
  `arbiter`.
- **S3** — `outcome=withdrawn` ⇒ `resolverRole=payer` and `resolvedAmount=0`.
- **S4** — `outcome=rejected` ⇒ `resolvedAmount=0` and no Reversal references it.
- **S5** — `DisputeEvidence.sequence` is unique and ordered per dispute; `role`
  matches `submittedBy`.

### 5.4 Structural (`validate.py`)

The four existing layers, extended to the disputes bundle:

1. **Turtle parse** — `vocab/disputes.ttl`, `vocab/reasons.ttl`,
   `shapes/disputes-shapes.ttl`.
2. **JSON-LD expansion** — each vector, with the disputes context added to the local
   document loader `_LOCAL`.
3. **JSON Schema** — Draft 2020-12 against `schemas/disputes.schema.json` `$defs/<Type>`.
4. **SHACL** — `shapes/disputes-shapes.ttl`, parsed fresh per instance inside the loop
   (existing convention, because `pyshacl` with `advanced=True` mutates the graph
   between runs).

## 6. Reason-code vocabulary

A native, extensible SKOS scheme `disp:DisputeReasonScheme` in `vocab/reasons.ttl`.
Each concept has `skos:prefLabel` and `skos:definition`; informative mappings to
external frameworks are carried as non-normative `skos:note` / `rdfs:seeAlso`.
Implementers MAY mint additional concepts in their own scheme.

| Concept | Use | Informative mapping (non-normative) |
|---|---|---|
| `not-delivered` | service / output never provided | card "services not rendered"; ISO 20022 return |
| `not-as-described` | output did not match agreed terms | card "not as described / defective" |
| `unauthorized` | payer / principal did not authorize | card fraud / unauthorized family |
| `incorrect-amount` | charged ≠ quote / usage | card "incorrect amount" |
| `duplicate` | duplicate charge | card "duplicate processing" |
| `canceled` | canceled before delivery | card "canceled recurring / services" |
| `quality` | subjective quality complaint | — |
| `goodwill` | voluntary, no fault (Refund only) | — |
| `other` | requires a `note` | — |

## 7. Test vectors

~13 signed vectors, naming convention `NN-<type>-<variant>.json`, reusing the existing
payments receipt (`04`) and execution (`03`) as the originals being refunded /
disputed:

```
20-refund-full              Refund (full) against receipt 04
21-reversal-refund          Reversal cause=refund for vector 20
22-reversal-ack             ReversalAcknowledgement for vector 21
23-refund-partial           partial Refund against receipt 04

30-dispute                  Dispute against execution 03 / receipt 04 (reason=not-delivered)
31-dispute-evidence-payee   payee representment evidence (sequence 1)
32-dispute-evidence-payer   payer rebuttal evidence (sequence 2)
33-dispute-resolution-payee payee resolution, outcome=partial
34-dispute-resolution-arbiter  arbiter resolution, outcome=upheld, supersedes 33
35-reversal-dispute         Reversal cause=dispute for resolution 34
36-dispute-resolution-rejected  rejected example (separate dispute) — negative path
37-dispute-withdrawn        withdrawn example (role=payer, resolvedAmount=0)
```

Coverage: full + partial refund, representment (both sides), escalation → arbitration,
rejected, withdrawn.

## 8. Harness wiring

### 8.1 `generate.py`

- Add output path `DISP = SPEC / "disputes" / "test-vectors"` and the 5-entry
  `DISP_CTX`.
- Add an **`arbiter`** key to the deterministic key derivation, and an `arbiter` DID
  to `authority/test-vectors/dids.json`.
- Add a `generate_disputes()` block that builds each object dict, signs it with the
  correct key (payee / payer / wallet / arbiter) via
  `ac.sign_ecdsa_jcs_2022(obj, key, created)`, and writes via `write(DISP, ...)`.
  Reuse the existing receipt `04` / execution `03` ids and recompute their JCS digests
  for the `*Digest` fields.

### 8.2 `verify.py`

- Add a disputes section that loads the new vectors and runs the B / A / S checks via
  the existing `check(label, cond)` and `controller(obj)` helpers.

### 8.3 `validate.py`

- Register the disputes context in `_LOCAL`.
- Add a `DISPUTE_VECTORS` map (filename → `$def` type name) and run the four
  validation layers against the disputes bundle.

### 8.4 Docs

- `spec/disputes/index.html` — W3C ReSpec normative prose matching the payments
  bundle's style (RFC 2119 `<em class="rfc2119">`, `<dfn>` term definitions,
  `<pre class="json">` examples, an SVG lifecycle diagram, `[[DSA]]` / payments
  cross-references).
- `spec/disputes/README.md` — artifact table + vector index (matching the other
  bundles' READMEs).
- `spec/README.md` — one-line addition to the bundle list.
- `CLAUDE.md` — note the fourth bundle and its namespace under the existing sections.

## 9. Acceptance criteria

- `python spec/generate.py` regenerates all vectors including the new disputes bundle,
  deterministically.
- `python spec/verify.py` reports **PASS** with the new B / A / S checks active.
- `python spec/validate.py` reports **PASS** (Turtle / JSON-LD / JSON Schema / SHACL)
  for the disputes bundle, fully offline.
- The payments and authority bundles are unchanged except for the additive `arbiter`
  DID in `dids.json`.
- All thirteen test vectors validate and verify, covering full/partial refund,
  representment, escalation/arbitration, rejected, and withdrawn paths.
