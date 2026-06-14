# Settlement rail profiles: card (Stripe) & bank/RTP — design note

**Date:** 2026-06-14
**Author:** Stephane Fellah / Geoknoesis LLC (with Claude Code)
**Status:** Draft for discussion — not yet normative

## 1. Summary

Extend the AVP-Micro **Settlement** bundle (`spec/settlement/`, namespace
`https://w3id.org/avp-micro/settlement/v1#`) with two new rail profiles over the existing
rail-agnostic core:

- **`rail-card-stripe`** — card settlement executed through a processor (Stripe as the worked
  example), using authorize-then-capture.
- **`rail-bank-rtp`** — instant bank credit transfers (FedNow / TCH RTP / SEPA Instant).

Nothing in the authorization layer (DSA + Payments) changes: a `PaymentAuthorization` already
commits to amount/quote/request and is settlement-agnostic. The work is entirely additive at the
settlement layer.

The single design driver is that these rails settle inside a **closed processor**, so their
`SettlementProof` cannot be self-verified against a public ledger the way the on-chain rails can.
The profiles therefore introduce an **attested** proof model, reusing the trust pattern the interop
bundle already formalizes as its "attested" mode.

## 2. Background — what already exists

The settlement bundle today ships three rail profiles — `rail-evm-stablecoin`, `rail-x402`,
`rail-lightning` — over a rail-neutral core:

- `SettlementInstruction` / `SettlementProof` (the rail-neutral envelope),
- `PayeeAccountBinding` (binds a payee DID to a destination account; today CAIP-10 / `did:pkh`),
- the escrow lifecycle `EscrowLock` → `EscrowRelease` / `EscrowRefund`,
- helpers in `settlement.py`: exact decimal→base-unit conversion, CAIP-2/10/19 parsing, the
  DID↔account binding rule, and the finality predicate (confirmation threshold / Lightning preimage).

On-chain `SettlementProof`s reference a public artifact — a transaction hash or a Lightning
preimage — that **any** verifier can independently check. That self-verifiability is the property
the new rails cannot provide.

## 3. The core asymmetry: self-verifiable vs attested finality

| | On-chain rails (today) | Processor rails (this note) |
|---|---|---|
| Where settlement happens | public ledger | closed processor (Stripe / bank network) |
| Finality evidence | tx hash + confirmations, or LN preimage | processor's internal record |
| Who can verify finality | anyone, against the chain | only via an **attestation** from a trusted party |
| Trust root for the proof | the chain itself | the **processor** or the **payee** (named, must be trusted) |

Consequence: a processor-rail `SettlementProof` is an **`AttestedSettlementProof`** — a
payee-signed (`ecdsa-jcs-2022`) object that *embeds* a processor result. Two attestation sub-modes,
mirroring the interop bundle's bridge modes:

- **processor-attested** — the processor itself emits a verifiable, publicly-key-signed receipt
  (e.g. a future Stripe-signed settlement receipt). The proof embeds it; the relying party verifies
  the processor's signature and must trust the processor as a finality oracle. *Ideal, but depends
  on processor capability.*
- **payee-attested** (always available) — the payee re-signs the processor's result into a
  Data Integrity proof. Trust roots in the **payee DID**. Stripe webhooks are **HMAC**-signed
  (shared secret, verifiable only by the endpoint holder), so today only this mode is realizable for
  Stripe without a public Stripe key; the HMAC event id is carried as *evidence*, not as the
  verifiable signature.

This is the central decision the profiles encode: **finality on these rails is a trust statement,
not a public fact, and the spec makes the trust root explicit and verifiable as far as the rail
allows.**

## 4. New rail identifiers (`vocab/rails.ttl`)

Add to the SKOS rail registry:

```
:rail-card-stripe  a :SettlementRail ; skos:prefLabel "Card via processor (Stripe)" ;
    :finalityModel :attested ; :supportsEscrow true .
:rail-bank-rtp     a :SettlementRail ; skos:prefLabel "Instant bank credit transfer (RTP)" ;
    :finalityModel :attested ; :supportsEscrow false .
```

Introduce a `:finalityModel` axis (`:onchain` | `:attested`) so a verifier can branch on how to
check a proof, and a `:supportsEscrow` flag (cards yes; push RTP no).

## 5. Account-identifier extension (`PayeeAccountBinding`)

CAIP-10 / `did:pkh` only name on-chain accounts. Extend the binding to carry processor/bank
instruments via URI schemes, **tokenized — never a raw PAN or full IBAN in a signed, shareable
object**:

- Stripe: `stripe:acct_<id>` (a Connect connected account) and/or a destination payment-method token.
- Bank/RTP: a creditor reference — prefer a tokenized/aliased form; if an IBAN is unavoidable, treat
  the binding as restricted-disclosure (see §10). A `bank:` scheme with `{scheme: sepa-instant|fednow|rtp, creditorAgent: <BIC>, creditorToken: <alias>}`.

The binding also names the **attesting processor** as a DID (e.g. `did:web:stripe.com`) so the
trust root is explicit in the object that authorizes the destination.

The anti-redirection rule is unchanged in spirit: a `SettlementProof` is only honored if its
attested destination matches the `PayeeAccountBinding` the payee signed.

## 6. `SettlementInstruction` profile

Add rail-specific, optional fields (the core stays as-is):

- `rail` — the rail IRI.
- `binding` — reference to the `PayeeAccountBinding`.
- `amount` + `currency` — **fiat is decimal ISO-4217** (e.g. `"1.00"` / `"USD"`), unlike on-chain
  base units. `settlement.py` would add a decimal→**minor-unit** conversion (Stripe charges in
  cents) analogous to the existing decimal→base-unit conversion.
- card: `captureMode` (`auth-capture` for escrow semantics, or `immediate`), `processorIntent`
  (e.g. `stripe:pi_<id>`).
- rtp: `scheme` (`sepa-instant` | `fednow` | `rtp`); no escrow fields.

## 7. `AttestedSettlementProof`

`type: ["SettlementProof", "AttestedSettlementProof"]`. Replaces the on-chain `chain` / `transaction`
/ `confirmations` fields with an `attestation` block:

```
"attestation": {
  "type": "ProcessorAttestation",
  "mode": "payee-attested" | "processor-attested",
  "processor": "did:web:stripe.com",     // the named trust root
  "reference": "stripe:pi_3Q…",          // PaymentIntent / end-to-end id
  "status": "succeeded",                 // captured (card) / settled (rtp)
  "evidence": "stripe-event:evt_1Q…",    // HMAC-signed webhook id (payee-attested)
  "observedAt": "2026-03-25T21:33:00Z"
}
```

**Finality predicate** (per rail, in `settlement.py`):
`final` ⇔ `attestation.status ∈ {succeeded/captured, settled}` **and** the attestation verifies
under its `mode` (processor signature, or payee Data Integrity proof) **and** the destination
matches the signed `PayeeAccountBinding`.

## 8. Escrow mapping

- **Card** maps cleanly: authorize/hold = `EscrowLock`, capture = `EscrowRelease`, void/expire =
  `EscrowRefund`. A Stripe `PaymentIntent` with `capture_method=manual` is exactly this lifecycle.
- **RTP** is push and irrevocable → **no native escrow**. Either omit escrow for `rail-bank-rtp`, or
  document a third-party holding-account pattern as out-of-band (not in the core profile).

## 9. Reverse value-flow (Disputes bundle)

- Card **refunds** and **chargebacks** map onto the existing Disputes bundle (`Refund`, `Reversal`,
  dispute lifecycle) — a card chargeback is a real-world instance of the `Dispute → DisputeResolution
  → Reversal` chain, with the network/processor as the de-facto arbiter.
- RTP **refunds** are a fresh credit transfer in the opposite direction → a new
  `SettlementInstruction`/`AttestedSettlementProof` pair, referenced by the `Reversal`.

## 10. Privacy & compliance boundary

- **Privacy:** card PANs and full bank identifiers must not appear in signed, shareable objects.
  Bindings carry **tokens/aliases**; where a raw identifier is unavoidable, the binding is marked
  restricted-disclosure and excluded from broadly-shared presentations.
- **Compliance:** PCI scope, KYC, and network rules stay in the settlement layer — **out of scope
  by design**. The processor (Stripe / bank) owns them. AVP-Micro governs *authorization* and binds
  the *proof*; it never touches card data or moves funds.

## 11. Relationship to Stripe's agent-payment work

Consistent with the project's SOTA analysis: Stripe's **MPP** is a settlement substrate and **ACP**
(OpenAI + Stripe) authorizes via a Stripe **Shared Payment Token**. The natural shape is:

> **AVP-Micro credential = the mandate** (may this agent spend, under what caps / payees / window) ·
> **Stripe = the rail** that executes · the **Shared Payment Token** is the instrument the agent
> presents, *governed by* the AVP-Micro authorization, with settlement reported back as an
> `AttestedSettlementProof`.

## 12. Illustrative objects (sketches — not yet signed vectors)

> `proofValue`s are placeholders. Real vectors would be produced by extending `generate.py` /
> `settlement.py`; the shapes below show field structure only.

**PayeeAccountBinding — Stripe connected account**
```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/data-integrity/v2",
    "https://w3id.org/spending-authority/v1","https://w3id.org/avp-micro/v1",
    "https://w3id.org/avp-micro/settlement/v1"],
  "id": "urn:avp:acct-binding:stripe", "type": "PayeeAccountBinding",
  "payee": "did:key:zDnaenNX…drxEN",
  "rail": "https://w3id.org/avp-micro/settlement/v1#rail-card-stripe",
  "account": "stripe:acct_1Nv8aXYz",
  "processor": "did:web:stripe.com",
  "proof": { "type":"DataIntegrityProof","cryptosuite":"ecdsa-jcs-2022",
    "verificationMethod":"did:key:zDnaenNX…drxEN#…","proofPurpose":"assertionMethod",
    "proofValue":"z…PLACEHOLDER" }
}
```

**SettlementInstruction — card, auth/capture (escrow)**
```json
{
  "@context": ["…/credentials/v2","…/data-integrity/v2","…/spending-authority/v1",
    "…/avp-micro/v1","…/avp-micro/settlement/v1"],
  "id":"urn:avp:settle-instr:card","type":"SettlementInstruction",
  "execution":"urn:avp:exec:777",
  "rail":"https://w3id.org/avp-micro/settlement/v1#rail-card-stripe",
  "binding":"urn:avp:acct-binding:stripe",
  "amount":"1.00","currency":"USD",
  "captureMode":"auth-capture","processorIntent":"stripe:pi_3QabcDef",
  "proof": { "cryptosuite":"ecdsa-jcs-2022","proofValue":"z…PLACEHOLDER (wallet)" }
}
```

**AttestedSettlementProof — card captured (payee-attested)**
```json
{
  "@context": ["…/credentials/v2","…/data-integrity/v2","…/spending-authority/v1",
    "…/avp-micro/v1","…/avp-micro/settlement/v1"],
  "id":"urn:avp:settle-proof:card","type":["SettlementProof","AttestedSettlementProof"],
  "instruction":"urn:avp:settle-instr:card",
  "instructionDigest":"sha-256:…",
  "execution":"urn:avp:exec:777",
  "rail":"https://w3id.org/avp-micro/settlement/v1#rail-card-stripe",
  "settledAmount":"1.00","currency":"USD",
  "attestation": { "type":"ProcessorAttestation","mode":"payee-attested",
    "processor":"did:web:stripe.com","reference":"stripe:pi_3QabcDef",
    "status":"succeeded","evidence":"stripe-event:evt_1QxyZ","observedAt":"2026-03-25T21:33:00Z" },
  "finality":"final","observedAt":"2026-03-25T21:33:01Z",
  "proof": { "cryptosuite":"ecdsa-jcs-2022","proofValue":"z…PLACEHOLDER (payee binds + attests)" }
}
```

**SettlementInstruction — bank/RTP (no escrow)**
```json
{
  "@context": ["…/credentials/v2","…/data-integrity/v2","…/spending-authority/v1",
    "…/avp-micro/v1","…/avp-micro/settlement/v1"],
  "id":"urn:avp:settle-instr:rtp","type":"SettlementInstruction",
  "execution":"urn:avp:exec:778",
  "rail":"https://w3id.org/avp-micro/settlement/v1#rail-bank-rtp",
  "binding":"urn:avp:acct-binding:rtp",
  "amount":"12.50","currency":"EUR","scheme":"sepa-instant",
  "proof": { "cryptosuite":"ecdsa-jcs-2022","proofValue":"z…PLACEHOLDER (wallet)" }
}
```

## 13. Harness / conformance impact

- `vocab/rails.ttl` — two rails + `:finalityModel` / `:supportsEscrow`.
- `schemas/` — `SettlementInstruction` (optional card/rtp fields), `AttestedSettlementProof`,
  extended `PayeeAccountBinding` (non-CAIP `account`, `processor`).
- `shapes/` — SHACL for the new shapes + finality-model branching.
- `settlement.py` — decimal→minor-unit conversion; `stripe:` / `bank:` identifier parsing; the
  attested finality predicate (verify processor sig **or** payee proof; match binding).
- `generate.py` — emit signed vectors (binding, card instruction+proof, rtp instruction+proof,
  card escrow lock/release, card refund via the Disputes chain).
- `verify.py` / `validate.py` — extend; both must still report **PASS**.
- Simulator (`sim.py` / `sim-scenarios.json`) — add card auth/capture and an RTP push scenario;
  still a simulated ledger, **no real funds move**.

## 14. Open decisions

1. **Processor as DID:** require `did:web:<processor>` for the attestation source? (Recommended —
   makes the trust root resolvable.)
2. **One `AttestedSettlementProof` type or per-rail subtypes?** (Recommend one shared type with a
   `mode`, keyed by `rail`.)
3. **RTP escrow:** omit entirely, or document the holding-account pattern as informative?
4. **Amount unit:** carry fiat as decimal (`amount`) and let `settlement.py` derive minor units, or
   also store `settledAmountMinor`? (Recommend decimal canonical + derived minor units.)
5. **Stripe evidence:** is an HMAC webhook id acceptable as `evidence`, or wait for a Stripe
   public-key receipt to enable `processor-attested`? (Start with `payee-attested`; upgrade later.)

## 15. Out of scope

No real money movement; no PCI/KYC handling; no change to DSA/Payments; no card-network membership.
The profiles describe *how an authorization binds to, and a proof attests, a processor settlement* —
not how to be a processor.

## 16. Next steps

1. Resolve §14 decisions.
2. Land `vocab` + `schemas` + `shapes` for the two rails and `AttestedSettlementProof`.
3. Extend `settlement.py` + `generate.py`; add vectors; keep `verify.py` / `validate.py` green.
4. Add simulator scenarios (card auth/capture, RTP push) + explainers in the demo.
