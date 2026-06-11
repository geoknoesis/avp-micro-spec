# Interoperating with SD-JWT-VC agentic-payment schemes (Verifiable Intent / AP2)

**Date:** 2026-06-11
**Status:** Design — open decision, no implementation committed
**Bundles:** `spec/authority/` (DSA) primarily; `spec/payments/` for the carrier object
**Motivating question:** The major agentic-commerce trust layers (Mastercard/Google
**Verifiable Intent**, Google **AP2**) standardize on **SD-JWT VC + JOSE**, not the
W3C VC Data Model. AVP-Micro is W3C-VCDM / JSON-LD / Data Integrity / DID. How — and
how far — should we interoperate?

## 1. Finding (confirmed 2026-06-11)

Mastercard's **Agent Pay for Machines** (launched 2026-06-10) is a settlement +
on-chain-permissions network. Its trust/credential layer is **Verifiable Intent**
(Mastercard + Google, 2026-03-05, Apache-2.0, `verifiableintent.dev`,
`github.com/agent-intent/verifiable-intent`). Verifiable Intent's normative credential
format is **SD-JWT VC** (IETF OAuth WG), *not* W3C Verifiable Credentials:

| Dimension | Verifiable Intent / AP2 | AVP-Micro |
|---|---|---|
| Credential format | SD-JWT VC, three-layer `KB-SD-JWT` chain | W3C VC Data Model 2.0, JSON-LD |
| Proof / signing | `ES256` (ECDSA P-256), JOSE, `sd_hash` layer binding | Data Integrity `eddsa-jcs-2022` (Ed25519) |
| Typing | `vct` claim (SD-JWT-VC profile) | JSON-LD `@context` + `type` |
| Identifiers | `iss`/`sub` URIs, opaque `kid` — no DIDs | DIDs (`did:key` MTI) |
| Selective disclosure | Native (SD-JWT `_sd` digests) | Not built in (whole-credential proof) |
| W3C VCDM conformance | None claimed (informative ref only) | Normative |

Verifiable Intent's three layers: **L1** issuer SD-JWT binding user identity + key,
**L2** user `KB-SD-JWT` expressing purchase intent, **L3** agent `KB-SD-JWT`
(autonomous mode). Roadmap is *deeper* SD-JWT-VC integration (issuer discovery,
status, type resolution) — **not** migration to W3C VCDM.

**Consequence:** the two stacks share the *delegation-chain concept* (issuer →
user/principal → agent, cryptographically bound, selectively disclosable) but agree on
**no wire format, proof suite, or identifier scheme**. A `SpendingAuthorizationCredential`
cannot be verified by an SD-JWT-VC verifier, and an L1/L2/L3 chain cannot be verified by
an `eddsa-jcs-2022` verifier. This is the long-standing JSON-LD/Data-Integrity vs
JOSE/SD-JWT split, and the well-funded agentic-commerce incumbents have landed on the
JOSE side.

## 2. Why this matters

- **Distribution risk.** Mastercard + Google + 30 launch partners (Coinbase, Stripe,
  Adyen, Cloudflare, Ripple, Nordea, …) are pooling momentum on SD-JWT VC. AVP-Micro's
  W3C-VCDM purity is its neutrality story, but it is now the minority encoding in the
  highest-funded corner of the space.
- **Neutrality is still the differentiator.** None of these schemes is vendor-neutral at
  the *trust-anchor* level: VI anchors identity in an Issuer (FI / payment network) via
  `iss`/`sub`, not a DID any party can resolve independently. AVP-Micro's DID-anchored,
  any-issuer/any-verifier model remains genuinely distinct — *if* it can still talk to
  the SD-JWT ecosystem rather than being islanded by it.

## 3. The decision (pick one posture)

### (a) Stay pure W3C-VCDM; position as the neutral cross-camp layer
Change nothing in the securing mechanism. Document AVP-Micro as the open, DID-anchored
authorization grammar; treat VI/AP2 as a *settlement substrate* reached via an external
bridge owned by integrators, not the spec.
- **Pro:** one proof stack, zero new normative surface, cleanest neutrality narrative.
- **Con:** no first-party path into the largest ecosystem; "bridge" is hand-waved;
  risk of being islanded.

### (b) Define a normative VI/SD-JWT-VC ↔ AVP-Micro mapping profile
Keep W3C-VCDM as the only securing mechanism, but add a **non-securing interop profile**:
a normative, lossless-where-possible mapping between a `SpendingAuthorizationCredential`'s
policy fields (cap, `allowedPayees`, `expires`, currency, revocation/status) and the
equivalent SD-JWT-VC `vct`/claims, plus a reference translator and round-trip test
vectors. Identity bridges DID ⇄ `iss`/`sub`/`kid`.
- **Pro:** concrete, testable interop without diluting the core proof stack; keeps the
  "one proof, one identifier model" simplicity; demonstrates neutrality in practice.
- **Con:** mapping is partial — SD-JWT selective disclosure and `KB-SD-JWT` key-binding
  have no clean Data-Integrity analogue; identity bridge (opaque `iss`/`sub` ⇄ DID) is
  the hard, semantically-lossy part; we own the translator's correctness.

### (c) Add SD-JWT VC as a second securing mechanism for `SpendingAuthorizationCredential`
Make the credential expressible *either* as W3C-VCDM + `eddsa-jcs-2022` *or* as SD-JWT VC
(`ES256`, `vct`), so it round-trips natively into AP2/VI verifiers.
- **Pro:** maximally interop-forward; a single logical credential usable in both camps;
  native selective disclosure.
- **Con:** dilutes the "one proof stack" simplicity; doubles the securing surface
  (generate/verify/validate harness, MTI guidance, conformance matrix); pulls in DID ⇄
  `kid` identity duality everywhere; largest maintenance + spec-complexity cost.

## 4. Recommendation

**(b), with (a) as the fallback if integration partners do not materialize.** It is the
only option that produces *testable* interop (round-trip vectors) while preserving the
single Data-Integrity proof stack and the DID-anchored neutrality that is AVP-Micro's
reason to exist. (c) is the most powerful but should be deferred until there is a concrete
counterparty demanding native SD-JWT-VC issuance — otherwise we pay double securing-surface
cost speculatively. (a) alone understates the bridge work and risks islanding.

Defer commitment until we know whether a partner needs native AP2/VI issuance (→ (c)) or
only policy-level interchange (→ (b)).

## 5. Open questions before implementing (b)

1. **Identity bridge.** How does a DID-anchored issuer map to/from an `iss`/`sub` URI and
   an opaque agent `kid`? Is a DID-document-published `kid` enough, or do we need a
   registry/well-known mapping? This is the load-bearing unknown.
2. **Selective disclosure gap.** SD-JWT `_sd` digests vs whole-credential Data Integrity —
   do we mark SD-only fields as non-round-trippable, or add SD support to DSA (large)?
3. **Status / revocation.** Map AVP-Micro `BitstringStatusList` ⇄ SD-JWT-VC status
   mechanism (Token Status List). Likely clean; confirm.
4. **Layering.** VI's L1/L2/L3 (issuer/user/agent) vs AVP-Micro's
   issuer→`SpendingAuthorizationCredential`→`PaymentAuthorization`. Confirm the chain
   semantics line up before claiming a mapping.
5. **Scope boundary.** Bridge is spec-level only; per `CLAUDE.md` the running app stays
   out of scope.

## 6. Sources

- Verifiable Intent — Credential Format: `https://verifiableintent.dev/spec/credential-format/`
- `github.com/agent-intent/verifiable-intent`
- Mastercard Global — Verifiable Intent: `https://www.mastercard.com/global/en/news-and-trends/stories/2026/verifiable-intent.html`
- PYMNTS — open standard to verify AI agent transactions (2026-03)
- Fortune / PYMNTS — Agent Pay for Machines launch (2026-06-10)
