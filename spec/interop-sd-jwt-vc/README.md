# AVP-Micro ⇄ SD-JWT-VC interop profile

This bundle is a **bridge/binding, not part of the core protocol.** It defines a
normative, bidirectional mapping between an AVP-Micro
[`SpendingAuthorizationCredential`](../authority/) (optionally carried in a
[Payments](../payments/) `PaymentAuthorization`) and an **SD-JWT-VC mandate** of the
kind used by Mastercard/Google **Verifiable Intent** and Google **AP2**.

It depends on **both** core specs *and* an external one (SD-JWT VC), and it tracks
that external target — so it ships and versions separately from the protocol, while
sharing the `spec/`-root harness. Design rationale and the bridge-mode analysis are in
[`docs/superpowers/specs/2026-06-11-avp-sdjwt-vc-bridge-design.md`](../../docs/superpowers/specs/2026-06-11-avp-sdjwt-vc-bridge-design.md).

## Why a bridge is required (not a shared format)

A W3C Data Integrity proof signs the JCS-canonical **JSON-LD** bytes; an SD-JWT
signature signs the **JOSE** serialization. Translating claims from one envelope to
the other changes the signed bytes, so the original signature can never verify over
the translated form. Authority therefore crosses the boundary in one of three
**bridge modes**:

| Mode | Mechanism | Trust added |
|------|-----------|-------------|
| `proof-preserving` (default) | embed the original credential + proof; verifier checks **both** | none |
| `co-issued` | issuer natively signs both forms at creation | none |
| `attested` | a named bridge re-signs in the target format | bridge becomes a trust root (must be explicitly trusted) |

## Artifacts

| Artifact | Path | Status |
|----------|------|--------|
| Specification (W3C ReSpec) | [`index.html`](index.html) | normative |
| JSON-LD 1.1 context | [`context/v1.jsonld`](context/v1.jsonld) | normative |
| JSON Schema (both bridged forms) | [`schemas/interop.schema.json`](schemas/interop.schema.json) | conformance aid |
| SHACL shapes | [`shapes/interop-shapes.ttl`](shapes/interop-shapes.ttl) | conformance aid |
| RDFS/OWL ontology | [`vocab/interop.ttl`](vocab/interop.ttl) | conformance aid |
| Reference translator | [`../interop.py`](../interop.py), [`../sdjwt.py`](../sdjwt.py) | conformance aid |
| Signed round-trip test vectors | [`test-vectors/`](test-vectors/) | informative fixtures |

## Canonical URLs (registration pending)

- Context: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1` → `context/v1.jsonld`
- Vocabulary namespace: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#` (prefix `iop:`)

An imported (V→A) DSA credential keeps its native semantic type and adds the `iop:`
securing terms, so it uses the **4-entry** context array:

```json
["https://www.w3.org/ns/credentials/v2",
 "https://w3id.org/security/data-integrity/v2",
 "https://w3id.org/spending-authority/v1",
 "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1"]
```

## The model: authorization semantics × one securing descriptor

The profile keeps two axes strictly orthogonal (see the
[orthogonality design note](../../docs/superpowers/specs/2026-06-12-authorization-mandate-credential-orthogonality.md)):

- **Authorization semantics** — *what* is/was authorized. A bridged object is typed
  exactly like its native equivalent (`SpendingAuthorizationCredential`,
  `PaymentQuote`, `PurchaseConfirmation`, `PaymentAuthorization`); the type never
  encodes a carrier or proof choice. "Mandate" is AP2's word for an explicit signed
  *representation* of an authorization — it appears only in wire identifiers
  (`vct: mandate.*`), never as an AVP class.
- **Securing** — *how* the object's authority is secured across the stack boundary:
  the single **`iop:securing` descriptor** `{mode, carrier, embedded, sourceVct,
  attestingBridge?, importAdvisory?, profileVersion}`. `mode` is `proof-preserving`
  (outer object is an unsigned projection; the byte-faithful foreign original in
  `embedded` carries authority), `co-issued` (native proof and parallel embedded
  form), or `attested` (a named, trusted bridge re-signed). An object **without**
  `securing` is native. New carriers extend the `carrier` value set — not the class
  taxonomy.

The bridge pipeline is factored the same way:
`decode(carrier) → canonical claims`, `map(claims) → authorization semantics`,
`secure(object) → securing descriptor` — `secure()` is the only stage that knows the
mode.

## What this profile defines

- **Identity binding** — DID ⇄ `iss`/`sub`/`kid`/`cnf`. Export (A→V) is near-lossless
  (a DID is a URI); import (V→A) relies on a **did:web binding convention** so VI
  `iss`/`sub`/`kid` carry resolvable DIDs publishing the P-256 verification method.
- **Claim mapping** — `maxPerTransaction`↔`limits.per_txn`, `dailyLimit`↔`limits.per_day`,
  `allowedPayees`↔`allowed_payees`, `validFrom`/`validUntil`↔`nbf`/`exp`, etc.
- **Chain mapping** — VI L1/L2/L3 ⇄ DSA credential issuance + `PaymentAuthorization`.
  The one genuine gap (VI *interactive* L2 = fresh per-purchase human intent) is
  flagged, not silently dropped.
- **Status** — `BitstringStatusListEntry` ⇄ Token Status List; references re-pointed,
  never re-hosted, so the principal keeps revocation control.
- **Two envelopes** — A→V (an SD-JWT VC with `vct: mandate.spending-authority.avp+embedded`
  carrying `avp_vc`) and V→A (the native semantic object + `iop:securing` carrying the
  foreign original in `securing.embedded`).
- **Cross-stack verification MUSTs** — no-downgrade, algorithm pinning, explicit bridge
  trust, window intersection, status, holder binding.

## Validation

The bundle is wired into the shared `spec/`-root harness (no new third-party
dependency — the ES256/JOSE/SD-JWT primitives are implemented with `cryptography`,
already required, in [`../sdjwt.py`](../sdjwt.py), mirroring how
[`../avp_crypto.py`](../avp_crypto.py) implements `ecdsa-jcs-2022`):

```bash
python spec/generate.py    # (re)build vectors for all four bundles
python spec/verify.py      # crypto round-trip A→V→A and V→A→V + negative-security checks
python spec/validate.py    # Turtle / JSON-LD expansion / JSON Schema / SHACL for all four
```

Both `verify.py` and `validate.py` must report `PASS`. The translator
([`../interop.py`](../interop.py)) implements the claim mapping, both envelopes, and
the cross-stack verification rules; `generate.py` emits the `test-vectors/` below.

### Test vectors

| File | What it is |
|------|------------|
| `keys.json` | Deterministic P-256 test keys + the `did:web` resolver fixture |
| `01-export-sdjwtvc.json` | A→V export of the DSA credential (proof-preserving, `vct …+embedded`) |
| `02-imported-mandate.json` | A→V→A re-import: a `SpendingAuthorizationCredential` projection + `iop:securing` |
| `03-foreign-sdjwtvc.json` | A foreign Verifiable-Intent/AP2-style mandate (ES256, `did:web` issuer) |
| `04-imported-from-foreign.json` | V→A import of the foreign mandate |
| `05-coissued-mandate.json` | **Co-issued** mandate: native `ecdsa-jcs-2022` proof + parallel ES256 SD-JWT-VC (same P-256 key) |
| `06-l3-presentation.json` | A→V of a `PaymentAuthorization`: mandate SD-JWT + agent **key-binding JWT (L3)** |
| `07-imported-payment-authorization.json` | V→A import of the L3 presentation: a `PaymentAuthorization` projection + `iop:securing` (carrier `sd-jwt-vc+kb-jwt`) |
| `08-attested-mandate.json` | **Attested** mode: a named bridge re-signs (P-256 `did:key`); honored only if the bridge is trusted |
| `09-imported-interactive-l2.json` | Lossy case — **interactive L2**: import carries an `importAdvisory` |
| `10-imported-partial-sd.json` | Lossy case — **partial selective disclosure**: a withheld claim, flagged as a subset view |
| `11-foreign-intent-mandate.json` | A foreign **AP2 `IntentMandate`** (ES256, `did:web` user issuer; item-level intent) |
| `12-imported-intent-mandate.json` | V→A import of the IntentMandate → `SpendingAuthorizationCredential` projection + carried intent extras + M2 advisory |
| `13-foreign-cart-mandate.json` | A foreign **AP2 `CartMandate`** (ES256, `did:web` merchant; itemized cart) |
| `14-imported-cart-quote.json` | V→A import of the CartMandate → `PaymentQuote` projection (`requestHash` binds the canonical cart) |
| `15-human-present-confirmation.json` | V→A import of a human-present cart approval → `PurchaseConfirmation` projection |
| `16-autonomous-no-confirmation.json` | Autonomous import (no human-present approval) → **no** confirmation, advised via `importAdvisory` |
| `17-exported-cart-user-approval.json` | **Export** (A→V): a native `PurchaseConfirmation` projected to an AP2 human-present approval (signed by the principal's own P-256 key), then re-imported — the human-present case round-trips A→V→A |

The native principal-signed `PurchaseConfirmation` (`ecdsa-jcs-2022`) and a `PaymentAuthorization` carrying it are **payments-bundle** objects, so they live under [`../payments/test-vectors/`](../payments/test-vectors/) as `14b-purchase-confirmation.json` and `18-payment-authorization-confirmed.json`.

### AP2 mandate-model bridge

Bridges AP2's two-mandate model (`IntentMandate` + `CartMandate`) and its fresh
human approval to the AVP-Micro mandate/payment model, in both directions:

- **`IntentMandate` ⇄ DSA `SpendingAuthorizationCredential` (§5):** the enforceable
  spending envelope (amount/payee/currency/validity) maps losslessly; AP2's
  natural-language and item/SKU-level intent and refundability are carried in `iop:`
  extras (`intentDescription`, `itemConstraints`, `refundabilityRequired`,
  `requiresPurchaseConfirmation`) but **not** machine-enforced — every import flags
  this granularity loss (**M2**) in `iop:importAdvisory`.
- **`CartMandate` ⇄ payee-signed `PaymentQuote` (§6):** the merchant attestation
  projects to a `PaymentQuote` (+ `iop:securing` embedding the merchant-signed
  mandate); a normative `canonicalCart → requestHash` (**M4**) makes the
  merchant signature and the AVP quote reference the same bytes.
- **`PurchaseConfirmation` — one optional core object (§7):** the fresh human approval
  AP2 carries but AVP-Micro lacked. Its proof MUST be controlled by `confirmedBy` (the
  principal), never by the agent (`payer`); a confirmation forged by the agent is
  rejected. Optional and additive — absent ⇒ standing delegation / autonomous, the
  default; the **autonomous** import is explicitly advised rather than fabricating an
  approval. The case is **bidirectional**: `import_cart_user_confirmation` brings an AP2
  human-present approval *in* (as a `PurchaseConfirmation` projection whose
  `securing.embedded` carries the user-signed approval), and
  `export_purchase_confirmation` projects a native confirmation back *out* to an AP2
  approval signed by the principal's own P-256 key — so exported authority roots in the
  principal DID, not the bridge (§11.6). A `did:key` principal is resolved locally; a
  `did:web` principal via the resolver.

### Scope of the vectors

All three bridge modes and both layers are vectorised:

- **Mandate bridge** (DSA `SpendingAuthorizationCredential` ↔ SD-JWT-VC L1), both
  directions, `proof-preserving`.
- **`co-issued`** mode (native DI proof + parallel issuer-signed SD-JWT-VC) and
  **`attested`** mode (a named bridge re-signs; the verifier consults a trusted-bridge
  list — a crypto-valid object from an untrusted bridge is policy-rejected).
- **Per-purchase action layer** (`PaymentAuthorization` ↔ presentation with an agent
  **key-binding JWT / L3**, ES256, `sd_hash`-bound; a KB-JWT re-pointed at a different
  mandate fails).
- **Lossy cases surfaced, never dropped**: an **interactive-L2** mandate and a
  **partially-disclosed** mandate each import with an `iop:importAdvisory`; the partial
  import is genuinely a subset view (the withheld claim is absent from the subject).

### Offline validation

`validate.py` serves the stable external W3C contexts (`credentials/v2`,
`data-integrity/v2`) from [`../contexts/`](../contexts/) so JSON-LD expansion is offline
and deterministic — the `pyld` requests loader intermittently fails on w3.org's multiple
HTTP `Link` headers. Refresh those files from the canonical URLs if the contexts change.

## Securing mechanism

Two distinct stacks meet here. AVP-Micro objects use W3C Data Integrity
`DataIntegrityProof` with `ecdsa-jcs-2022` over `did:key` (P-256). SD-JWT-VC objects
use `ES256` (P-256) JOSE signatures with `cnf` holder binding. Both sign over the
same P-256 curve; the profile still never collapses the two envelopes — it carries each
in its native form and requires verifiers to check the one that bears the authority
(see the spec "Cross-stack verification" section).
