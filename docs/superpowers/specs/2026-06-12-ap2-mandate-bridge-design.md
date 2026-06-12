# Design: AP2 mandate-model bridge (Intent + Cart) + optional `PurchaseConfirmation`

**Date:** 2026-06-12
**Status:** Design — proposed, no implementation committed
**Builds on:** [`2026-06-11-avp-sdjwt-vc-bridge-design.md`](2026-06-11-avp-sdjwt-vc-bridge-design.md) (the credential/encoding bridge) and its implementation in [`spec/interop.py`](../../../spec/interop.py) + bundle [`spec/interop-sd-jwt-vc/`](../../../spec/interop-sd-jwt-vc/).
**Bundles touched:** extends `spec/interop-sd-jwt-vc/` (new terms + functions + vectors); adds **one optional object** to `spec/payments/` (`PurchaseConfirmation`).
**Scope:** spec-level only — profile text, translator functions, schema/context/shape/vocab additions, signed test vectors. Does **not** touch the running app.

---

## 0. Crypto-baseline correction (read first)

The earlier bridge design (2026-06-11) and several READMEs describe AVP-Micro authority as `eddsa-jcs-2022` / **Ed25519**, and treat "VI keys are P-256, Ed25519 can't express them" as the load-bearing V→A gap. **That is stale.** The current `spec/` code secures every AVP-Micro object with **`ecdsa-jcs-2022` over P-256** (`spec/avp_crypto.py`: `did:key` uses the `p256-pub` multicodec `0x1200`; `spec/payments/schemas/avp-micro.schema.json` pins `"cryptosuite": "ecdsa-jcs-2022"`; `spec/interop.py` derives `cnf.jwk` as a P-256 JWK from the agent `did:key`).

Consequence for this design: **both stacks share the same curve.** AVP-Micro Data-Integrity authority and AP2/SD-JWT-VC `ES256` authority are both **P-256**. The identity bridge is therefore near-symmetric, the old "re-issue under Ed25519" degradation is gone, and `proof-preserving` mode works in both directions without a curve change. This design assumes P-256 throughout.

## 1. Goal

Let an agent's authority cross the **AP2 mandate model** ⇄ **AVP-Micro mandate/payment model** boundary, in both directions, **without any privileged operator (AP2 network, Credentials Provider, or the bridge) becoming a root of trust.** That neutrality is AVP-Micro's reason to exist and is the hard invariant of this work (§11).

The credential *encoding* bridge already exists. This design adds the layer above it: AP2's **two-mandate workflow** (`IntentMandate` + `CartMandate`) and the **fresh human approval** that AP2 can carry but AVP-Micro currently cannot.

Three concrete correspondences:

- **IntentMandate ⇄ `SpendingAuthorizationCredential`** — standing/delegated authority.
- **CartMandate ⇄ payee-signed `PaymentQuote`** (+ the per-purchase `PaymentAuthorization`) — priced commitment.
- **CartMandate human-present approval ⇄ (new) optional `PurchaseConfirmation`** — fresh per-purchase human intent.

## 2. Relationship to the existing SD-JWT-VC bridge

This design **reuses, does not fork**, the existing bridge:

| Concern | Provided by existing bridge | This design |
|---|---|---|
| JOSE ⇄ Data-Integrity encoding | `spec/interop.py` envelopes (`avp_vc`, `embeddedSdJwtVc`) | reuse verbatim |
| Identity (DID ⇄ `iss`/`sub`/`kid`/`cnf`), `did:web` for foreign issuer | §3 of prior design + `did_web_resolver` | reuse |
| Claim mapping (`maxPerTransaction`↔`limits.per_txn`, …) | `avp_to_claims` / `claims_to_avp_subject` | reuse + extend for intent fields |
| Status / revocation re-pointing | `status_to_token_list` / `token_list_to_status` | reuse |
| Bridge modes (`proof-preserving` / `co-issued` / `attested`) | `verify_imported` | reuse, applied to the new objects |
| L3 per-purchase action (`PaymentAuthorization` ↔ KB-JWT) | `*_presentation` helpers | reuse as the agent-action layer |
| **AP2 mandate semantics (Intent/Cart)** | — | **new (§5, §6)** |
| **Fresh human approval object** | — | **new (§7)** |
| **Itemized-cart ⇄ `serviceRequestHash` binding** | — | **new (§6.1)** |

AP2 mandates arrive on the wire as SD-JWT-VC (the Mastercard/Google "Verifiable Intent" encoding AP2 aligns with), so the existing transcoder is the carrier; what is missing is the **mandate-shape semantics** that sit *inside* those tokens.

## 3. The mismatch breakdown

| # | Dimension | AP2 | AVP-Micro | Gap nature |
|---|---|---|---|---|
| **M1** | Mandate cardinality & signers | `IntentMandate` (**user**-signed) + `CartMandate` (**merchant**-signed cart, **user**-approved) | `SpendingAuthorizationCredential` (**principal**-signed) + `PaymentQuote` (**payee**-signed) + `PaymentAuthorization` (**agent**-signed) | AP2 *fuses* merchant-attestation and user-approval into one `CartMandate`; AVP *splits* them across the payee-signed quote and the agent-signed auth. Mechanical re-staple (§6). |
| **M2** | Intent granularity | Item/SKU-level, natural-language intent, refundability | Amount/payee/category **policy**, machine-checkable (SHACL/OWL) | AVP expresses the *envelope* but not item-level "what to buy." Carry-and-flag, never enforce silently (§5, §10). |
| **M3** | Human-present freshness | `CartMandate` human-present = fresh **user** signature on the exact cart | Standing delegation — **no per-purchase human object** | The one genuine semantic gap. Closed by a new optional object (§7), never fabricated. |
| **M4** | Cart payload binding | Structured `CartContents` + line items | `PaymentQuote.serviceRequestHash` (opaque digest) | Define a canonical cart → `serviceRequestHash` so merchant signature and AVP receipt reconcile to the same bytes (§6.1). |

M1 and M4 are mechanical. M2 and M3 are the real impedance mismatches.

## 4. The correspondence model (conceptual spine)

Both specs describe the **same shape**: a verifiable chain *principal → (authorization) → agent-action → priced commitment*. The bridge is a set of **pure transcoders over that shared shape**, each `proof-preserving` by default (embed the foreign signed object; verify it in its native stack). Because every transcoder embeds rather than re-signs, the whole construction inherits VC/DID independence from the existing bridge — the bridge is never a signer of authority.

```
AP2:        IntentMandate ──────────────► CartMandate ──────────────► (PaymentMandate → network)
            (user-signed)                 (merchant-signed cart                (settlement, out of scope)
                                           + human-present user approval)
                │                              │            │
   ┌────────────┼──────────────────────────────┼────────────┼─────────────────┐
   ▼            ▼                              ▼            ▼                 (settlement
AVP:  SpendingAuthorizationCredential   PaymentQuote   PurchaseConfirmation    handled by AVP
      (principal-signed)                (payee-signed)  (NEW, user-signed,      PaymentExecution/
                                                         optional)             Receipt + rails)
                                              │
                                              ▼
                                        PaymentAuthorization
                                        (agent-signed; embeds DSA cred in vp)
```

## 5. IntentMandate ⇄ `SpendingAuthorizationCredential`

The existing `avp_to_claims` / `claims_to_avp_subject` already map the enforceable spending envelope. AP2's `IntentMandate` adds *shopping-intent* fields with no policy slot. Mapping:

| AP2 IntentMandate concept | AVP-Micro | Direction & treatment |
|---|---|---|
| allowed merchants | `credentialSubject.allowedPayees[]` (DIDs) | lossless both ways (via `did:web` for non-DID merchants) |
| price ceiling / max amount | `credentialSubject.maxPerTransaction` | lossless |
| currency | `credentialSubject.currency` | lossless |
| intent start / expiry | `validFrom` / `validUntil` | lossless |
| period cap (if any) | `credentialSubject.dailyLimit` | lossless |
| **requires user confirmation** (human-present required) | `iop:requiresPurchaseConfirmation: true` **and** narrows step-up to `requiresApprovalAbove: "0"` | lossless *intent*, enforced via §7 |
| **natural-language description** | `iop:intentDescription` (carried, not enforced) | **M2 — flag** `importAdvisory` |
| **item / SKU constraints** | `iop:itemConstraints` (carried, not enforced) | **M2 — flag** `importAdvisory` |
| required refundability | `iop:refundabilityRequired` (carried) | **M2 — flag** |

`requires_user_confirmation` is the load-bearing one: it is the AP2 signal that a **human-present `CartMandate`** (not autonomous) is expected downstream. We bind it to the new object in §7 by emitting `iop:requiresPurchaseConfirmation`, so an AVP verifier that imports such an intent **MUST** require a `PurchaseConfirmation` (§11). `interop.py` already emits an `interactive-l2` advisory on `intent_mode == "interactive"`; this design upgrades that from *advisory-only* to *advisory + a satisfiable requirement* once §7 exists.

New `iop:` terms: `intentDescription`, `itemConstraints` (`@container: @set`), `refundabilityRequired`, `requiresPurchaseConfirmation`, `embeddedIntentMandate` (the proof-preserving carrier of the original user-signed mandate, analogous to `embeddedSdJwtVc`).

## 6. CartMandate ⇄ payee-signed `PaymentQuote`

An AP2 `CartMandate` is two things stapled together: a **merchant attestation** of cart-and-price, and (human-present) a **user approval** of that exact cart. AVP-Micro *splits* these:

- **Merchant attestation → `PaymentQuote`** (already payee-signed; required `proof`, `ecdsa-jcs-2022`). Map: `merchant → payee`, `total.amount → amount`, `total.currency → currency`, `cart_expiry → expires`, `cart_id → quote.id`. The original merchant signature is preserved by embedding the source cart in `iop:embeddedCartMandate` (proof-preserving) or natively re-signed by the payee in `co-issued` mode.
- **User approval → `PurchaseConfirmation`** (§7).
- **Agent acceptance → `PaymentAuthorization`** (existing; binds `quote`, `quoteDigest`, `serviceRequestHash`, `nonce`, `expires`; embeds the DSA credential in `vp`).

### 6.1 Canonical cart binding (M4)

Define a normative `canonicalCart(cartContents) → bytes`: line items sorted by a stable key, all amounts as decimal strings (never floats — matches `avp_crypto.jcs` discipline), JCS-encoded. Then:

```
PaymentQuote.serviceRequestHash = content_digest(canonicalCart(cart))   # "sha-256:<b64url-nopad>"
```

Both the AVP quote and the AP2 cart thus reference the **same bytes**; the merchant signature, the agent's `serviceRequestHash` binding, and the eventual `PaymentReceipt.serviceOutputHash` all reconcile. `canonicalCart` lives in the interop bundle (it is bridge-specific, not core payments).

## 7. `PurchaseConfirmation` — the one new core object (closes M3)

**The problem:** AP2 human-present mode carries a *fresh user signature over the exact cart*. AVP-Micro has only standing delegation, so importing such a mandate today is lossy (`interop.py` flags it and moves on). The two wrong fixes are forgery (synthesize an approval) and dependence (force AVP to require AP2's token as authority). The right fix is to give that human approval a **native AVP home** that is **optional** and **additive**.

**Shape** (new `$def` in `spec/payments/schemas/avp-micro.schema.json`; new terms in `spec/payments/context/v1.jsonld` + `vocab/avp.ttl` + `shapes/avp-shapes.ttl`):

```jsonc
{
  "@context": [ /* the 4-entry signed context */ ],
  "id": "urn:avp:confirm:…",
  "type": "PurchaseConfirmation",
  "quote": "urn:avp:quote:…",            // the payee-signed quote being approved
  "quoteDigest": "sha-256:…",            // binds the exact quote bytes
  "payer": "did:key:…agent",             // the agent that will transact
  "payee": "did:key:…merchant",
  "amount": "112.40",
  "currency": "USD",
  "serviceRequestHash": "sha-256:…",     // the canonical cart fingerprint (§6.1)
  "confirmedBy": "did:key:…principal",   // THE HUMAN/principal — REQUIRED
  "authorization": "urn:avp:vc:spendauth:…",  // optional: the DSA credential it operates under
  "timestamp": "2026-06-12T…Z",
  "expires": "2026-06-12T…Z",
  "nonce": "…",
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2022",
             "verificationMethod": "did:key:…principal#…", "proofPurpose": "assertionMethod", … }
}
```

**The defining rule:** `proof.verificationMethod` MUST resolve to **`confirmedBy`** (the principal), *not* `payer` (the agent). That is exactly what makes it a *fresh human approval* rather than an agent action — and it is verifiable from the artifact alone. `confirmedBy` SHOULD be the issuer of the `SpendingAuthorizationCredential` in play (the principal who delegated), or an explicitly-allowed confirmer named therein.

**How it composes (optional by construction):** `PaymentAuthorization` gains an **optional** member `purchaseConfirmation` (an embedded `PurchaseConfirmation`, or a `{id, digest}` reference). Semantics:

- **Absent** → standing delegation / autonomous. AVP behaves exactly as today; the model is untouched. This is the default and the common case.
- **Present** → human-present. A verifier that requires fresh human intent (e.g. because the governing intent carried `iop:requiresPurchaseConfirmation`, or local policy demands it) MUST check: the confirmation is signed by `confirmedBy`; `confirmedBy` is the principal/allowed confirmer; `quoteDigest`, `serviceRequestHash`, `amount`, `currency` equal the authorization's; and it is unexpired.

**Bridge use:**
- **Import** AP2 human-present `CartMandate` → emit a `PurchaseConfirmation` whose `proof` is an **unsigned projection** and which carries the original AP2 user signature in `iop:embeddedCartUserAuth` (proof-preserving; authority verified via the embedded token + `did:web`), OR a native `co-issued` proof when the principal key is ours. Never the bridge's key (except explicit, named `attested` mode).
- **Export** AVP `PaymentAuthorization` **with** `purchaseConfirmation` → an AP2 human-present `CartMandate` (user-approval layer derives from the confirmation; merchant layer from the quote). **Without** it → an AP2 autonomous/intent-derived cart, explicitly marked *not a fresh human approval*.

This makes M3 **lossless in both directions** while adding nothing to AVP's trust model: `PurchaseConfirmation` is a native AVP object signed by the AVP principal's own DID, optional, and independently verifiable.

## 8. Envelopes & bridge modes

Unchanged from the existing bridge, now applied to Intent/Cart/Confirmation objects:

- **`proof-preserving` (default):** embed the original signed AP2 object (`iop:embeddedIntentMandate` / `iop:embeddedCartMandate` / `iop:embeddedCartUserAuth`); the outer AVP object is an **unsigned projection** (`MUST NOT` carry a `proof` — `verify_imported` already enforces no-downgrade). Authority = the embedded foreign proof, verified via `did:web`/P-256.
- **`co-issued`:** the controlling principal/merchant signs the native AVP object too (real `ecdsa-jcs-2022` proof) — no bridge in the path.
- **`attested`:** a **named, opt-in** bridge re-signs; relying parties must independently trust it. Last resort only.

## 9. Identity & status

- **Identity:** both sides P-256 (§0). AVP `did:key`/`did:web`; AP2 `iss`/`sub`/`kid`/`cnf.jwk`. Foreign AP2 issuers resolve via the **`did:web` convention** already in the profile (`did_web_resolver`). Holder binding: agent `cnf.jwk` ≡ `credentialSubject.id`'s P-256 key (existing). `PurchaseConfirmation` adds a *second* human-key binding (`confirmedBy`), resolved the same way.
- **Status/revocation:** reuse `BitstringStatusListEntry ⇄ Token Status List`, re-pointed never re-hosted — revocation stays with the principal/merchant.

## 10. What stays lossy (state it, don't hide it)

- **M2 — item/SKU/natural-language intent:** carried in `iop:*`, **not** machine-enforced by AVP policy; every import flags it in `importAdvisory`.
- **Human-present without a confirmation:** an AP2 human-present cart imported when no user signature is actually present cannot manufacture one — it imports as autonomous **with an advisory** (never a fabricated `PurchaseConfirmation`).
- Per house discipline, the translator annotates every such downgrade rather than dropping it silently.

## 11. Security & independence invariants (the MUSTs)

1. **No-downgrade.** Authority is the *embedded original* proof; the outer projection's (absent) signature is never a substitute. (Enforced today by `verify_imported`; extend to the new objects.)
2. **No-widening / intersection.** Where both stacks carry limits/expiry/replay fields, enforce the **most restrictive** intersection. A translation MUST never broaden authority.
3. **Human-present is typed, never inferred.** Fresh human intent exists **iff** a `PurchaseConfirmation` signed by `confirmedBy` (≠ the agent) is present and binds the exact cart. No object ⇒ autonomous. The bridge MUST NOT synthesize one.
4. **Bridge is not a trust root.** `proof-preserving`/`co-issued` add no trust; `attested` is explicit, named, revocable, opt-in.
5. **Authority roots in the principal/merchant DID, never AP2 infrastructure.** Imported IntentMandate authority roots in the **user** DID; CartMandate merchant attestation in the **merchant** DID; never in the AP2 network, Credentials Provider, or bridge.
6. **AVP authority stays natively verifiable when exported.** An exported AVP mandate/confirmation MUST remain verifiable purely from the embedded `ecdsa-jcs-2022` credential + the principal's DID, with no dependence on any AP2 verifier. *(This is the operational definition of "without losing VC/DID independence.")*
7. **`PurchaseConfirmation` is optional and additive.** Its presence MUST NOT be required by core AVP flows; standing delegation remains first-class.

## 12. Packaging & artifacts

- **Interop bundle (`spec/interop-sd-jwt-vc/`):** new `iop:` terms (§5, §7) in `context/v1.jsonld`, `vocab/interop.ttl`, `shapes/interop-shapes.ttl`, `schemas/interop.schema.json`; new translator functions in `spec/interop.py`:
  `intent_mandate_to_dsa` / `dsa_to_intent_mandate`, `cart_mandate_to_quote` / `quote_to_cart_mandate`, `canonical_cart`, `import_cart_user_auth` / `export_purchase_confirmation`, plus verify helpers — all `proof-preserving` default, mirroring the existing function pairs.
- **Payments bundle (`spec/payments/`):** the **one** core addition — `PurchaseConfirmation` `$def` + the optional `purchaseConfirmation` member on `PaymentAuthorization` in `schemas/avp-micro.schema.json`; terms in `context/v1.jsonld`; class/properties in `vocab/avp.ttl`; a shape in `shapes/avp-shapes.ttl`.
- **Vectors (`spec/interop-sd-jwt-vc/test-vectors/`):** round-trip Intent⇄DSA; Cart⇄Quote with cart-hash reconciliation; human-present import producing a `PurchaseConfirmation` (proof-preserving + co-issued); autonomous import (no confirmation, advised); the M2 lossy case. Plus a payments vector: a `PaymentAuthorization` carrying a `purchaseConfirmation`.
- **Harness:** `generate.py` emits the new vectors; `verify.py` covers the new round-trips and negative checks (forged confirmation signed by the agent key → reject; widened limit → reject; outer projection carrying a `proof` → reject); `validate.py` covers the new schema/SHACL/JSON-LD. `python spec/verify.py` and `python spec/validate.py` MUST report `PASS`.

## 13. Phasing

1. **v1 (one release):** §5 Intent mapping, §6 Cart mapping + §6.1 canonical cart, §7 `PurchaseConfirmation` (proof-preserving + co-issued), §11 MUSTs, full round-trip vectors incl. lossy flags. Bidirectional, lossless except the §10 cases.
2. **Co-issuance helpers** for principals/merchants we control (removes the bridge from the path).
3. **`attested` fallback** only if real verifiers can't do cross-stack crypto.

## 14. Decisions (resolved 2026-06-12)

- **D4 (layering): build on the existing SD-JWT-VC transcoder; add Intent/Cart semantics above it.** Do not fork the credential bridge. (§2)
- **D5 (`PurchaseConfirmation`): add it as an *optional* core Payments object** to close M3 losslessly both ways — the deliberate, user-approved "touch the core spec" choice (recommendation **B**). Optional + additive by construction (§7, §11.7).
- **D6 (canonical cart): define a normative `canonicalCart → serviceRequestHash`** so merchant signature and AVP receipt reconcile (§6.1).
- **D7 (crypto baseline): P-256 / `ecdsa-jcs-2022` on both sides** — the Ed25519 framing of the prior doc is retired (§0).

## 15. Open questions for review

- **Q1 — `confirmedBy` identity:** require `confirmedBy` to equal the DSA credential `issuer` (principal), or allow a named delegated confirmer listed in the credential? (Draft assumes: principal, or an explicitly-allowed confirmer.)
- **Q2 — carry vs. reference:** should `PaymentAuthorization.purchaseConfirmation` embed the full object or a `{id, digest}` reference by default? (Draft allows both; default embed for self-containment.)
- **Q3 — `requiresApprovalAbove: "0"` coupling:** is overloading the existing step-up field acceptable, or should `iop:requiresPurchaseConfirmation` stand alone without touching DSA semantics? (Draft does both; the `iop` flag is authoritative, the DSA narrowing is a courtesy for verifiers that don't read `iop`.)
- **Q4 — does AP2's `PaymentMandate` (the network-facing object) need any analogue here, or is it correctly out of scope** under the settlement boundary (the blog's "AVP sits above settlement")? (Draft: out of scope.)
