# AVP-Micro specifications

Two peer specifications form the core protocol:

- **[Delegated Spending Authority](authority/)** (`authority/`) — identity, the
  SpendingAuthorizationCredential, securing mechanisms, and the trust framework.
  Namespace `https://w3id.org/spending-authority/v1#`.
- **[AVP-Micro Payments](payments/)** (`payments/`) — quotes, authorizations,
  executions, receipts, and streaming, built on Delegated Spending Authority.
  Namespace `https://w3id.org/avp-micro/v1#`.

The Payments specification depends on DSA: every signed payment object includes
the DSA context (and DSA-defined terms such as `currency`, `nonce`, `expires`,
and the embedded `SpendingAuthorizationCredential`) alongside the Payments
context.

A third document, the **[AVP-Micro ⇄ SD-JWT-VC interop profile](interop-sd-jwt-vc/)**
(`interop-sd-jwt-vc/`, namespace `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`),
rides *alongside* the core protocol rather than inside it. It is a **bridge/binding,
not a third protocol pillar**: it maps the `SpendingAuthorizationCredential` and
`PaymentAuthorization` to and from the SD-JWT-VC credentials used by Mastercard/Google
**Verifiable Intent** and Google **AP2**. Because it depends on *both* core specs and
an external one — and tracks that external target — it is versioned and validated as
its own bundle (separate directory and namespace) while sharing the root harness, so
an external revision never churns the core specs. It is covered by `verify.py` and
`validate.py` like the core bundles. See the
[bridge design](../docs/superpowers/specs/2026-06-11-avp-sdjwt-vc-bridge-design.md).

## Relationship to network agent-payment schemes

AVP-Micro is the **trust and authorization layer**, not a payment network. It
standardizes *who may spend, under what terms, and how that authority is proven*
— using open W3C primitives (DIDs, Verifiable Credentials 2.0, JSON-LD, Data
Integrity proofs) — and leaves *value movement* to any settlement rail.

Network schemes for agent payments are emerging concurrently: Mastercard
**Agent Pay for Machines** (on-chain agent permissions on Polygon/Solana/Base +
card/stablecoin settlement), Visa equivalents, Coinbase **x402**, Stripe's
machine-payment protocol, and Google's **AP2** (mandate/credential-based).
AVP-Micro treats these as **settlement substrates it can sit above**, the same
way it treats Lightning or Interledger: a `PaymentAuthorization` carries a
portable, issuer-signed `SpendingAuthorizationCredential` that any party can
verify independently, after which settlement executes over the chosen rail.

What this layer adds over a single network's built-in permissions:

- **Vendor-neutral trust anchor.** Authority is proven by verifying an issuer's
  credential against a DID — not by trusting one network's ledger, token format,
  or settlement guarantee. Any issuer can grant; any verifier can check.
- **Portable across rails and networks.** One credential grammar spans competing
  schemes, so an agent's spending authority is not locked to a single network's
  substrate.
- **Standards-based, not proprietary.** Built entirely on ratified W3C specs
  (`eddsa-jcs-2022`, `BitstringStatusList`) with signed test vectors — no
  dependency on a network operator's SDK, tokenization service, or governance.

These schemes use a **different credential stack**, so interoperation requires a
bridge, not a shared format. Mastercard/Google **Verifiable Intent** (the trust
layer under Agent Pay for Machines, aligned with AP2) is built on **SD-JWT VC**
(IETF) — three-layer `KB-SD-JWT` chains signed with `ES256`, typed by `vct`, and
identified by `iss`/`sub` URIs and opaque `kid` values. It deliberately does
**not** conform to the W3C VC Data Model and does **not** use DIDs. AVP-Micro, by
contrast, secures W3C VC 2.0 / JSON-LD credentials with Data Integrity
(`eddsa-jcs-2022`) and identifies parties by DID. A `SpendingAuthorizationCredential`
therefore cannot be verified directly by an SD-JWT-VC verifier (or vice versa);
the authorization *semantics* (caps, allowed payees, time windows, revocation) are
network-independent and can be mapped across, but the *encoding and proof* must be
bridged. See the interop design note in
[`docs/superpowers/specs/`](../docs/superpowers/specs/) for the mapping/profile
options.

## Validate everything

```bash
pip install cryptography rdflib pyld jsonschema pyshacl requests referencing
python spec/generate.py    # (re)build the signed vectors for all three bundles
python spec/verify.py      # verify proofs + bindings + policy + interop round-trip
python spec/validate.py    # Turtle / JSON-LD / JSON Schema / SHACL for all three bundles
```

All checks must report `PASS`. `validate.py` runs **offline**: the stable external W3C
contexts (`credentials/v2`, `data-integrity/v2`) are vendored under `spec/contexts/`
and served by the local document loader, so JSON-LD expansion does not depend on
network access to w3.org.

## Shared harness (at `spec/` root)

| File | Purpose |
|------|---------|
| `avp_crypto.py` | Ed25519 key derivation, JCS canonicalization, `eddsa-jcs-2022` sign/verify |
| `sdjwt.py` | P-256 keys, ES256/JOSE, JWK, and SD-JWT compact primitives for the interop bundle (uses only `cryptography`) |
| `interop.py` | AVP-Micro ⇄ SD-JWT-VC translator: claim mapping, both envelopes, cross-stack verification |
| `generate.py` | Writes deterministic signed test vectors into `authority/`, `payments/`, and `interop-sd-jwt-vc/` `test-vectors/` |
| `verify.py` | Loads all vector bundles and verifies proofs, bindings, policy, and the interop round-trip |
| `validate.py` | Turtle parse, JSON-LD expansion (local context), JSON Schema, and SHACL validation across all three bundles |

## Securing mechanism

Mandatory-to-implement: W3C Data Integrity `DataIntegrityProof` with cryptosuite
`eddsa-jcs-2022`; `did:key` (Ed25519 / `Multikey`) is the mandatory-to-implement
DID method for interoperability testing. See the respective spec "Securing
mechanisms" sections.

## Canonical URLs (registration pending)

w3id.org redirects are a prerequisite for cross-implementation interoperability
that depends on network dereferencing. Until registration is complete, validation
uses local context files by explicit configuration:

- DSA context: `https://w3id.org/spending-authority/v1` → `authority/context/v1.jsonld`
- DSA namespace: `https://w3id.org/spending-authority/v1#`
- Payments context: `https://w3id.org/avp-micro/v1` → `payments/context/v1.jsonld`
- Payments namespace: `https://w3id.org/avp-micro/v1#`
- Service categories: `https://w3id.org/avp-micro/cat#` (scheme `…/cat/scheme/AgentServiceCategory`)
- Interop profile context: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1` → `interop-sd-jwt-vc/context/v1.jsonld`
- Interop profile namespace: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`
