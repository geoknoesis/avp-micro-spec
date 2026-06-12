# Design: the authorization axis — capacity vs instance, semantic vs provenance relations

**Date:** 2026-06-12
**Status:** Accepted — refines [`2026-06-12-authorization-mandate-credential-orthogonality.md`](2026-06-12-authorization-mandate-credential-orthogonality.md).
**Bundles touched:** vocab + prose only (DSA, payments, interop). No wire-format change — this classifies and relates the objects that already exist.

---

## 0. What this adds

The orthogonality note separated *semantics* from *securing*. This note makes the **authorization
semantics themselves** precise along the axis that turned out to be load-bearing — **capacity vs
instance** — and fixes the relation vocabulary so that **authorization chains are never modeled with
provenance relations** (`derivedFrom`). It also disambiguates the overloaded word "intent" and records
the **sibling-profile** scope boundary.

## 1. The central axis: capacity vs instance

An *authorization* is one of exactly two kinds. The litmus is reuse: *can it legitimately be presented
more than once?*

| | **AuthorizationCapacity** | **AuthorizationInstance** |
|---|---|---|
| answers | who *may* authorize, within what bounds | what *was* authorized, here and now |
| reusable | **yes** — presented repeatedly | **no** — consumed once |
| properties | revocable, delegable, re-presentable, policy-like | nonce-bound, single-use, merchant-bound, liability-bearing |
| lifecycle | issued → presented → verified → revoked/expired | created → signed → bound → consumed → audited/disputed |
| AVP-Micro | `SpendingAuthorizationCredential` | `PaymentAuthorization`, `PurchaseConfirmation`, `SessionBudgetAuthorization` |

```
AuthorizationCapacity  enables ▶  AuthorizationInstance
AuthorizationInstance  exercises ▶ AuthorizationCapacity   (and conformsTo its bounds)
```

A `PaymentQuote`/`PaymentReceipt`/`PaymentOffer` is **not an authorization at all** — it is a
counterparty **commitment**. `PaymentExecution` is a settlement **fact**. They are deliberately left
*outside* the authorization hierarchy (the four-role model of the orthogonality note); only capacity and
instance are authorizations.

This axis is where the five hard concerns localize: **revocation** and **delegation** on capacity;
**replay**, **liability**, and **audit** on instance. Conflating the two (AP2's single "mandate") makes
each ambiguous.

## 2. Semantic relations, not provenance relations

Authorization-chain relations describe **normative dependence** between authorizations. They
<em>MUST NOT</em> reuse provenance relations (`prov:wasDerivedFrom`), which describe **artifact
transformation**. Overloading one relation across both axes is the exact conflation we are removing.

**Authorization (semantic) relations** — `dsa:` namespace:

| Relation | Domain → Range | Meaning | Realized in AVP by |
|---|---|---|---|
| `enables` | Capacity → Instance | the standing power makes the act possible | — (inverse of below) |
| `exercises` | Instance → Capacity | the act draws on this standing power | `PaymentAuthorization.vp` embedding the credential |
| `conformsTo` | Instance → Capacity | the act's terms are within the capacity's bounds (normative) | verifier check: amount ≤ `maxPerTransaction`, payee ∈ `allowedPayees`, … |
| `mustMatch` | Instance → Commitment field | a bound field equals the referenced commitment's | `quoteDigest`, `serviceRequestHash` byte-equality |

Conceptual chain (using AVP names): `PaymentAuthorization exercises/conformsTo SpendingAuthorizationCredential`;
`PaymentAuthorization mustMatch PaymentQuote`; `PurchaseConfirmation mustMatch PaymentQuote` and
`exercises` the same capacity.

**Provenance relations** — reserved for the bridge/securing layer only (PROV-O):

| Relation | Meaning |
|---|---|
| `prov:wasDerivedFrom` | the imported projection was transcoded from the embedded foreign original |
| `prov:used` / `prov:wasGeneratedBy` | a bridge activity consumed the source / produced the projection |
| `prov:wasAttributedTo` | (attested mode) the named bridge that re-signed |

So an imported `PaymentQuote` `prov:wasDerivedFrom` `securing.embedded`; it does **not**
`derivedFrom` anything in the authorization sense. The two relation families never mix.

## 3. "Intent" names two things

The word *intent* hides a descriptive thing and a normative thing. Separate them:

| Concept | Nature | AVP-Micro |
|---|---|---|
| `NaturalLanguageIntent` | descriptive, **non-enforced** — a desired outcome ("a red size-10 shoe under $120") | `iop:intentDescription`, `iop:itemConstraints` (carried, advised) |
| `IntentMandate` (AP2) | a **signed, bounded authorization** artifact — already normative | imported as a `SpendingAuthorizationCredential` |
| `SpendingAuthorization` | the enforceable spend-envelope **claim** carried by the IntentMandate | `credentialSubject` of that credential |

The correction to the earlier critique: AP2 is **not** wrong to treat a signed `IntentMandate` as
authorization — once signed and bounded, it *is* authorization capacity. The weakness is only that one
word covers both the descriptive desired-outcome (which AVP carries but never enforces, surfacing an
`importAdvisory`) and the normative spend envelope (which AVP extracts into the credential subject).

## 4. Scope: reference sibling profiles, do not absorb them

AP2 / AVP-Micro define **payment-adjacent authorization semantics** — capacity, instance, and their
chain to a payment. Everything else is a **sibling** profile this one *references*, never owns:

| Concern | Owner |
|---|---|
| carts, quotes, offers, items, fulfillment | a **Commerce** vocabulary |
| VC / SD-JWT / proof packaging, status, disclosure | a **Credential** profile |
| bridge / projection / attestation provenance | a **Provenance** profile (PROV-O) |
| replay, consumption, lifecycle state | a **Runtime** profile |

Pulling any of these *into* the payment spec would re-commit the separation-of-concerns violation we are
fixing. (The cart canonicalization for M4 stays minimal and binding-focused; a full cart model belongs to
Commerce.)

## 5. Decisions

- **D13** — `dsa:AuthorizationCapacity` and `dsa:AuthorizationInstance` are the two authorization kinds; the capacity/instance axis is central. `SpendingAuthorizationCredential` is capacity; `PaymentAuthorization`/`PurchaseConfirmation`/`SessionBudgetAuthorization` are instances.
- **D14** — commitments (`PaymentQuote`/`PaymentReceipt`/`PaymentOffer`) and facts (`PaymentExecution`) are **not** authorizations and are not placed in the authorization hierarchy.
- **D15** — authorization-chain relations (`exercises`, `conformsTo`, `enables`, `mustMatch`) are `dsa:` semantic properties; `prov:wasDerivedFrom`/`used`/`wasAttributedTo` are reserved for the securing/bridge layer. The two families MUST NOT be conflated.
- **D16** — "intent" is split: `iop:NaturalLanguageIntent` (descriptive, non-enforced) vs the `SpendingAuthorization` extracted from a signed `IntentMandate` (normative). A signed IntentMandate *is* authorization.
- **D17** — Commerce, Credential, Provenance, and Runtime are sibling profiles referenced by — not absorbed into — AP2/AVP-Micro.
- **D18 (deferred)** — a Runtime lifecycle/binding profile (single-use, consumption record, replay, the `mustMatch` chain made operational) is the next layer; tracked separately, out of scope here.
