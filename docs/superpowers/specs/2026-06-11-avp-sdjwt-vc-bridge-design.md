# Design: AVP-Micro ⇄ SD-JWT-VC (Verifiable Intent / AP2) bridge

**Date:** 2026-06-11
**Status:** Design — proposed, no implementation committed
**Depends on:** [interop design note](2026-06-11-interop-sdjwt-vc-verifiable-intent-design.md) (this is the detailed design for its recommended option **(b)**, plus the controlled-issuance variant **(c)**)
**Bundles:** ships as a **new peer bundle** `spec/interop-sd-jwt-vc/`; maps from `spec/authority/` (DSA credential) + `spec/payments/` (per-purchase carrier)
**Scope:** spec-level only — translators, profiles, test vectors. Does **not** touch the running app (`CLAUDE.md`).

## 1. Goal

Let an agent's spending authority cross the JSON-LD/Data-Integrity ⇄ JOSE/SD-JWT-VC line: a relying party on one stack can verify authority that originated on the other, **without a privileged intermediary becoming the root of trust** (that property is AVP-Micro's whole reason to exist). Concretely, three flows:

- **A→V (export):** an AVP-Micro `SpendingAuthorizationCredential` / `PaymentAuthorization` is presented to a Verifiable-Intent / AP2 verifier.
- **V→A (import):** a VI three-layer mandate chain is presented to an AVP-Micro verifier/wallet.
- **Co-issuance:** an issuer that controls the credential at creation emits *both* representations natively.

## 2. The one unavoidable constraint

A Data Integrity proof signs the **JCS-canonicalized JSON-LD bytes**. An SD-JWT signature signs the **JOSE serialization**. Translating the claims from one envelope to the other changes the bytes, so **the original signature can never verify over the translated form.** Every honest design choice flows from this. A bridge can do exactly one of:

| Archetype | What it does | Trust added | Neutrality |
|---|---|---|---|
| **(1) Attesting** | Verify source, then *re-issue* a new native credential signed by the bridge's own key | Bridge becomes a trusted issuer / SPOF | ✗ violates "no privileged operator" |
| **(2) Proof-preserving (embed + co-present)** | Wrap the *original* credential+proof inside the target envelope; verifier checks **both** | None — authority still roots in the original principal's key | ✓ bridge is a pure transcoder |
| **(3) Co-issuance** | Issuer signs both representations at creation over the same claims | None — no intermediary at all | ✓ cleanest, but only when you control issuance |

**Recommendation:** default to **(2)** for runtime bridging; use **(3)** wherever issuance is under our control (strictly better — no bridge in the path); offer **(1)** only as an explicitly-named, auditable fallback for verifiers that cannot yet do cross-stack crypto. The rest of this doc designs (2) and (3); (1) is a thin degenerate case of (2) where the embedded proof is dropped and the bridge signs.

## 3. Identity bridge (the load-bearing part)

The credential *claims* map almost trivially (§4). Identity does not, and the direction is asymmetric.

**AVP-Micro identity:** DID (`did:key` MTI, `did:web` natural), keys are `Multikey`/Ed25519 in the DID document, referenced by a verification-method DID URL (`did:…#frag`). Holder proof-of-possession is implicit: the agent's key *is* `credentialSubject.id`, and that same key signs the `PaymentAuthorization` — i.e. AVP-Micro already does SD-JWT-style **key binding**, just with DIDs + Data Integrity instead of `cnf` + KB-JWT.

**VI identity:** `iss` (issuer URI), `sub` (opaque subject), `kid` (opaque key id), holder key in `cnf.jwk`.

**A→V (clean, near-lossless):** a DID *is* a URI, so it drops straight into JOSE identifiers.
- `issuer` (DID) → `iss`
- `credentialSubject.id` (agent DID) → `sub`, and the agent's Ed25519 public key → `cnf.jwk` (OKP/Ed25519 JWK derived from the `did:key` multibase)
- verification-method DID URL → `kid`
A VI verifier that *chooses* to can still resolve these as DIDs; one that doesn't treats them as opaque URIs. No information lost.

**V→A (lossy — the real work):** `iss`/`sub` are opaque with no mandated key-resolution method, and VI keys are **P-256/ES256**, which `eddsa-jcs-2022` (Ed25519-only) cannot express. So importing requires *either*:
- (a) the VI issuer also publishes a **`did:web`** whose DID document contains the P-256 key as a `JsonWebKey`/`Multikey` verification method — then `iss`→DID and `kid`→verification-method resolve, and AVP-Micro verifies the embedded JOSE proof under archetype (2); **or**
- (b) AVP-Micro adds a P-256/JOSE securing option (large; out of scope here); **or**
- (c) the bridge re-issues under Ed25519 (archetype (1), with the trust cost).

**Decision (resolved — D2): adopt the `did:web` convention.** VI `iss`/`sub`/`kid` carry resolvable `did:web` DIDs whose DID documents publish the P-256 key as a `JsonWebKey` verification method. This is what makes V→A lossless under archetype (2) (the embedded JOSE proof is verified against the resolved P-256 method) instead of degrading to attesting (1). The convention is a normative part of the profile (§4) and a hard prerequisite for the bidirectional v1 scope (D3).

## 4. Claims / policy mapping (lossless both ways)

The spending *policy* is the same concept set on both sides; only the spelling differs. The bridge defines a dedicated credential type `vct: "mandate.spending-authority.avp"` (distinct from VI's existing checkout `vct`s) whose claims mirror DSA `credentialSubject`:

| Concept | AVP-Micro (DSA, real field) | SD-JWT-VC claim |
|---|---|---|
| Credential type | `type: [VerifiableCredential, SpendingAuthorizationCredential]` | `vct: "mandate.spending-authority.avp"` |
| Issuer (principal) | `issuer` (DID) | `iss` |
| Subject (agent) | `credentialSubject.id` (DID) | `sub` + `cnf.jwk` |
| Currency | `credentialSubject.currency` | `currency` |
| Per-transaction cap | `credentialSubject.maxPerTransaction` | `limits.per_txn` |
| Period cap | `credentialSubject.dailyLimit` | `limits.per_day` |
| Limit timezone | `credentialSubject.limitTimezone` | `limits.tz` |
| Step-up threshold | `credentialSubject.requiresApprovalAbove` | `limits.approval_above` |
| Allowed payees | `credentialSubject.allowedPayees[]` (DIDs) | `allowed_payees[]` |
| Allowed service types | `credentialSubject.allowedServiceTypes[]` (IRIs) | `allowed_service_types[]` |
| Validity start | `validFrom` | `nbf` |
| Validity end | `validUntil` | `exp` |
| Credential id | `id` | `jti` |
| Status / revocation | `credentialStatus` (BitstringStatusListEntry) | `status` (Token Status List) — see §6 |

Amounts stay **decimal strings** on both sides (never floats — same discipline as the spec). Payee/subject DIDs are carried verbatim as URI strings in the JOSE form. This table is the normative core of the profile; a reference translator implements it in both directions and round-trip vectors pin it (§8).

## 5. Chain / layer mapping

VI's three layers correspond to AVP-Micro objects as follows (the correspondence is exact for VI **autonomous mode**, which is the agent-payments case):

| VI layer | Signer | AVP-Micro analogue |
|---|---|---|
| **L1** — identity + holder-key binding | Issuer | `SpendingAuthorizationCredential` issuance (`issuer` → `credentialSubject` + key) |
| **L2** — purchase intent | User/principal | *Standing mode:* folded into the mandate (the delegation **is** the pre-authorized intent). *Interactive mode:* **no direct analogue** — AVP-Micro delegates ahead of time rather than per-purchase. |
| **L3** — agent action on a specific purchase | Agent (holder key) | `PaymentAuthorization` proof: the agent DID (= `credentialSubject.id`) signs over `quoteDigest`, `amount`, `serviceRequestHash`, `nonce`, `expires` |

The L1↔L3 binding in VI (`sd_hash` chaining the agent layer to the issuer layer) is mirrored in AVP-Micro by the `PaymentAuthorization` embedding the credential in its `vp` and being signed by the *same key* named as `credentialSubject.id`. So the cryptographic key-binding semantics line up; only the encoding differs.

**The one genuine semantic gap:** VI's *interactive* L2 (fresh per-purchase human approval) has no AVP-Micro counterpart, because AVP-Micro's trust model is standing delegation. The bridge MUST therefore mark interactive-L2 chains as **import-only with an advisory**: the resulting AVP-Micro mandate represents the delegated envelope, not a per-purchase human click, and a relying party that specifically requires fresh human intent cannot get that guarantee from the translated form. (For autonomous-mode VI, this gap does not arise.)

## 6. Status / revocation

- AVP-Micro: `BitstringStatusListEntry` → a hosted `BitstringStatusListCredential`.
- VI / SD-JWT-VC: IETF **Token Status List** (`status.status_list` → hosted status list token).

These are structurally the same (a bit index into a hosted compressed bitstring) and map cleanly. The bridge translates the reference but **does not re-host**: it points the target at the *original* issuer's status endpoint, so revocation continues to be controlled by the principal, not the bridge. A verifier MUST check whichever status mechanism its stack understands; if both references are present (co-issuance), checking either is sufficient and they MUST agree.

## 7. The embedding envelopes (archetype 2)

**A→V** — an SD-JWT VC carrying the original AVP-Micro VC as a protected, non-disclosable claim:

```text
vct: "mandate.spending-authority.avp+embedded"
iss/sub/cnf/nbf/exp/jti/limits/...      # the §4 mapping, for native VI processing
avp_vc:  "<base64url of the exact JCS-canonical SpendingAuthorizationCredential bytes, incl. its Data Integrity proof>"
```
The SD-JWT issuer signature provides JOSE-native typing, selective disclosure, and (via `cnf`) key binding; `avp_vc` carries the **authority**. A conforming A→V verifier MUST verify the embedded `eddsa-jcs-2022` proof over `avp_vc` and MUST NOT accept the outer JOSE signature *in lieu of* it (§9).

**V→A** — an AVP-Micro VC whose subject carries the original chain:

```text
type: [VerifiableCredential, SpendingAuthorizationCredential, EmbeddedSdJwtVcMandate]
credentialSubject: { id, currency, maxPerTransaction, ... }   # the §4 mapping
credentialSubject.embeddedSdJwtVc: "<the original SD-JWT-VC L1(~L2/L3) chain, compact serialization>"
proof: { ... }   # see trust-mode note below
```
In **co-issuance (3)** this outer `proof` is a real `eddsa-jcs-2022` proof by the principal's Ed25519 key over the same claims — no bridge, fully native. In **proof-preserving import (2)** there is no Ed25519 proof to be had (the principal only signed JOSE), so the AVP-Micro verifier instead verifies `embeddedSdJwtVc` directly via the §3 `did:web`/P-256 path; the outer object is an unsigned *projection* and MUST be flagged as such. In **attesting (1)** the bridge signs the outer object with its own key and is named in `proof.verificationMethod` as a bridge — relying parties must independently trust that bridge.

## 8. Packaging, artifacts & conformance

**Placement — a separate peer bundle, not folded into DSA or Payments.** The bridge depends on *both* core specs and on an external one (SD-JWT VC / VI), it is optional, it tracks a fast-moving external target, and it mints its own terms — so it ships as a third bundle in the spec family, clearly labelled an **interop profile / binding** (not a third protocol pillar):

- **Directory:** `spec/interop-sd-jwt-vc/` — peer to `spec/authority/` and `spec/payments/`, with its own `context/v1.jsonld`, JSON Schema, SHACL shapes, and round-trip `test-vectors/`.
- **Namespace:** `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`. Bridge-specific terms — `EmbeddedSdJwtVcMandate`, `embeddedSdJwtVc`, the `mandate.spending-authority.avp` `vct`, the did:web convention — live here, **never** in the DSA or Payments namespace.
- **Shared harness:** reuses the `spec/`-root harness (`avp_crypto.py`, `generate.py`, `verify.py`, `validate.py`); no separate tooling. `python spec/verify.py` and `python spec/validate.py` must report `PASS` with the bundle present.
- **Versioning:** pinned to the VI/AP2 revision it targets, so an external rev churns this bundle alone and never the core specs.

**Artifacts:**

1. **Profile** (normative): the §4 claim table, §3 identity rules (incl. the did:web/P-256 convention), §5 layer mapping, §6 status mapping, §7 envelopes.
2. **Reference translator** (a library, not a service — keep it out of the trust path): `avp_to_sdjwtvc(vc, mode)`, `sdjwtvc_to_avp(token, mode)`, and two cross-stack verify helpers.
3. **Round-trip test vectors** in `spec/interop-sd-jwt-vc/test-vectors/`: for each existing DSA/payments vector, an `…→sdjwtvc` form and a re-imported `…→avp` form, asserting (a) policy fields survive A→V→A *and* V→A→V unchanged, (b) the embedded original proof still verifies, (c) interactive-L2 and SD-partial-disclosure cases are correctly flagged non-round-trippable.
4. **Harness integration:** `generate.py`/`verify.py`/`validate.py` learn the third bundle; `python spec/verify.py` covers the bridge vectors and all checks still report `PASS`.

## 9. Security analysis (the MUSTs)

- **No-downgrade:** in archetype (2), a verifier MUST verify the *embedded original* proof for authority and MUST NOT treat the outer envelope signature as a substitute. The outer signature only attests transport/typing/holder-binding.
- **Algorithm pinning:** Ed25519 (Data Integrity) and ES256 (JOSE) MUST each be checked against the layer that legitimately uses it; never accept one alg where the other is expected (alg-confusion).
- **Bridge trust is explicit:** archetype (1) re-issuance makes the bridge a trust root; it MUST be a named, revocable issuer that relying parties opt into — never implicit. (2) and (3) add no trust and are preferred precisely for that reason.
- **Window intersection:** when both stacks carry validity/expiry (`validFrom/validUntil` vs `nbf/exp`) and replay fields (`nonce`/`jti`, `expires`), the verifier MUST enforce the **intersection** (most restrictive) — a translation must never widen authority.
- **Status preserved at source:** the bridge re-points but never re-hosts status (§6), so revocation stays with the principal.
- **Selective-disclosure honesty:** A→V can introduce SD only under re-issuance (1); under (2) the embedded VC is whole-credential, so "selective disclosure" of the embedded authority is not available and MUST NOT be implied. V→A of a *partially* disclosed SD-JWT yields a subset mandate that MUST be flagged as a partial view.

## 10. What stays lossy (state it, don't hide it)

- VI **interactive L2** (fresh per-purchase human intent) → no AVP-Micro equivalent (§5).
- VI **native selective disclosure** → no Data-Integrity equivalent without re-issuance (§9).
- **P-256 keys** → not expressible in `eddsa-jcs-2022`; V→A needs `did:web`+P-256 resolution or re-issuance (§3).
- Per the spec's own discipline, the bridge **`log()`s/annotates** every such downgrade rather than silently dropping it.

## 11. Phasing

Per **D3**, v1 ships **full bidirectional round-trip** — A→V and V→A must both be lossless under proof-preserving (2) before release. So phases 1–2 are bundled into the v1 deliverable rather than shipped separately:

1. **v1 (one release):**
   - Normative profile: §4 claim table, §3 identity rules **including the `did:web`/P-256 convention** (D2), §5 layer mapping, §6 status mapping, §7 envelopes.
   - Reference translator: `avp_to_sdjwtvc` + `sdjwtvc_to_avp` + both cross-stack verify helpers, all in proof-preserving mode (D1).
   - Round-trip vectors proving A→V→A *and* V→A→V preserve policy + verify the embedded original proof; lossy cases (§10) explicitly flagged.
   - Harness: `verify.py`/`validate.py` cover the bridge vectors; all report `PASS`.
2. **Co-issuance (3) issuer helper** — post-v1; for issuers we control, removes the bridge from the path entirely.
3. **Attesting fallback (1)** — last, and only if real verifiers can't do cross-stack crypto; ships as an explicitly-named, opt-in trust anchor.

## 12. Decisions (resolved 2026-06-11)

- **D1 (trust mode default): proof-preserving (2).** Bridge is a pure transcoder; verifiers check the embedded original proof. (3) is used wherever we control issuance; (1) only as a named, opt-in fallback. This is the neutrality-preserving choice and is now the design default throughout.
- **D2 (`did:web` convention): adopted.** VI `iss`/`sub`/`kid` carry resolvable `did:web` DIDs publishing P-256 verification methods, making V→A lossless under (2) (§3).
- **D3 (scope of v1): full bidirectional.** v1 blocks until A→V and V→A both round-trip losslessly (see §11); export-first phasing is rejected.
