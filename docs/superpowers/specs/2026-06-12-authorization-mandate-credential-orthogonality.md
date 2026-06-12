# Design: Authorization / Mandate / Credential orthogonality — the `SecuringDescriptor` model

**Date:** 2026-06-12
**Status:** Accepted — supersedes the `Embedded*` type taxonomy of the SD-JWT-VC bridge and the AP2 mandate bridge.
**Builds on:** [`2026-06-11-avp-sdjwt-vc-bridge-design.md`](2026-06-11-avp-sdjwt-vc-bridge-design.md), [`2026-06-12-ap2-mandate-bridge-design.md`](2026-06-12-ap2-mandate-bridge-design.md).
**Bundles touched:** `spec/interop-sd-jwt-vc/` only. The payments and authority bundles are already orthogonal and do not change.

---

## 1. The three primitives (and the axis that secures them)

| Primitive | What it is | Lifecycle | Reusable? |
|---|---|---|---|
| **Authorization** | The *semantic concept*: what is/was authorized, by whom, under what constraints. Two kinds: **capacity** (who *may* authorize: a standing envelope) and **instance** (what *was* authorized: one consumable act). | capacity: issued → presented → verified → revoked/expired. instance: created → signed → bound to context/cart/payment → consumed → audited/disputed. | capacity: yes. instance: no — consumed. |
| **Mandate** | An *explicit signed representation* of an authorization. AP2's word. Every AVP authorization object is a mandate in this sense, but AVP names its classes by their **semantics**, never by the representation. | that of the authorization it represents | — |
| **Credential** | A *verifiable container*: issuer, subject, proof, status/revocation, disclosure mechanism — and `claims:` the authorization. The container is not the authorization; `credentialSubject` **is** the mandate payload. | issued → presented → verified → revoked/expired | yes |

Plus one orthogonal axis that applies to *any* of the above:

| Axis | What it is |
|---|---|
| **SecuringDescriptor** | *How* the object's authority is secured when it crosses a stack boundary: which carrier encoded it, which proof governs, what was lost. Never part of the semantic `type`. |

Litmus test for capacity vs instance: *can the artifact legitimately be presented more than once?* Credential/capacity — yes (that is its purpose). Instance — no (nonce + expiry + one-time consumption).

### 1.1 Are payments always associated with a mandate?

In general payment systems, no — authorization is often implicit (card tap, wire instruction) and only sometimes reified (SEPA DD mandate, subscription). In **AVP-Micro, yes by construction**: no `PaymentExecution` exists without a signed `PaymentAuthorization` or `SessionBudgetAuthorization`. This is deliberate: in agentic commerce the human leaves the loop, so the explicit artifact is the only accountability boundary — it is the only way to answer *what exactly was authorized, by whom, under what constraints, within delegated authority or not, auditable or not*.

### 1.2 The level map (AP2 ⇄ AVP)

```
AP2 representation        AVP semantic class                         Kind
------------------        ------------------------------------       ----------
IntentMandate        ⇄    SpendingAuthorizationCredential            capacity   (credential-wrapped)
CartMandate          ⇄    PaymentQuote                               commitment (payee-signed)
  └ human approval   ⇄    PurchaseConfirmation                       instance   (principal-signed)
PaymentMandate       ⇄    PaymentAuthorization                       instance   (agent-signed)
  └ network leg      ⇄    (none — AVP sits above settlement; rails' business)
```

The derivation chain exists as **typed, digest-bound references**, not a new `derivedFrom` property:
`execution.authorization → authz.{quote, quoteDigest, vp[credential]}`; `confirmation.{quote, quoteDigest, authorization}`. Digest binding (`quoteDigest`, `serviceRequestHash`, `sessionDigest`) is what makes the chain auditable byte-for-byte.

### 1.3 Where the five hard concerns live

| Concern | Lives on | Why |
|---|---|---|
| Revocation | capacity | you revoke the *power*; instances expire or are consumed, never "revoked" |
| Delegation | capacity | capacity chains principal → agent; an instance is a leaf act |
| Replay prevention | instance | `nonce` + `expires` + one-time consumption; a credential is *meant* to be re-presented |
| Liability | instance | the signed act creates the obligation; capacity only proved who could |
| Audit / dispute | instance, traced to its capacity | audit "what was authorized", then walk to "what capacity backed it" |

Conflate capacity and instance in one "mandate" class (as AP2 does) and every row becomes ambiguous.

## 2. The defect this design removes: the cross-product taxonomy

The bridge had been minting one class per *(semantic type × carrier)* pair:

```
EmbeddedSdJwtVcMandate        = SpendingAuthorizationCredential × sd-jwt-vc
EmbeddedKbJwtAuthorization    = PaymentAuthorization            × sd-jwt-vc+kb-jwt
EmbeddedCartQuote             = PaymentQuote                    × sd-jwt-vc
EmbeddedCartUserConfirmation  = PurchaseConfirmation            × sd-jwt-vc
```

Each re-declared the same carrier fields (`bridgeMode`, `embedded<X>`, `sourceVct`, the no-downgrade rule) and smuggled a securing decision into the semantic `type`. N semantic types × M carriers ⇒ N×M classes, four copies of every rule, and a brittle schema. The carrier names were even per-pair (`embeddedSdJwtVc`, `embeddedKbJwtPresentation`, `embeddedCartMandate`, `embeddedCartUserAuth`) — four names for one concept.

## 3. The model

**Semantic `type` stays pure.** A bridged object is typed exactly as its native equivalent:
`["VerifiableCredential","SpendingAuthorizationCredential"]`, `["PaymentQuote"]`, `["PurchaseConfirmation"]`, `["PaymentAuthorization"]`. No `Embedded*` markers.

**One reusable securing descriptor**, attached as the `iop:securing` member:

```jsonc
"securing": {
  "mode": "proof-preserving",          // | "co-issued" | "attested"   (absent securing ⇒ native)
  "carrier": "sd-jwt-vc",              // | "sd-jwt-vc+kb-jwt"  — which foreign encoding is embedded
  "embedded": "<compact serialization>",  // the byte-faithful foreign signed object
  "sourceVct": "mandate.cart.ap2",     // provenance: the foreign type identifier
  "attestingBridge": "did:key:…",      // attested mode only
  "importAdvisory": ["…"],             // lossy conditions, surfaced never dropped
  "profileVersion": "0.1.0"
}
```

Rules, defined **once**:

- `mode = proof-preserving` ⇒ the outer object MUST NOT carry `proof` and MUST carry `securing.embedded` (no-downgrade: authority is the embedded original).
- `mode = co-issued` ⇒ native `proof` AND `securing.embedded` both present.
- `mode = attested` ⇒ native `proof` AND `securing.attestingBridge` present; honored only against a trust list.
- `securing` absent ⇒ **native** object; the core bundles apply unchanged. (This is why payments/authority bundles need no edits.)

**Capacity vs instance containment.** The `Credential{…, claims: Mandate}` nesting is the **capacity** pattern only (DSA credential wraps the spending envelope in `credentialSubject`). Instances (`PaymentAuthorization`, `PurchaseConfirmation`) are top-level signed objects carrying their own `proof` and *referencing* the capacity (`vp`, `authorization`) — they are never wrapped in a synthetic credential.

**The bridge pipeline is factored on the same axes:**

```
decode(carrier)  → canonical claims        # carrier axis only   (sdjwt decode, disclosures)
map(claims)      → authorization semantics  # semantic axis only  (claims ⇄ subject/quote/confirmation)
secure(object)   → SecuringDescriptor       # the ONLY stage that knows the mode
```

`secure()` being the only mode-aware stage is the operational proof that the securing choice never belongs in `type`.

## 4. Validation strategy (the trade-off, mitigated)

The fused classes were easy to target. Composition keeps targetability:

- **JSON Schema:** each interop `$def` is `allOf: [ <semantic shape>, {$ref: bridgeSecured} ]`. `bridgeSecured` (requires `securing`, holds the mode/proof conditionals) and `SecuringDescriptor` are written once.
- **SHACL:** one `SecuringDescriptorShape` with `sh:targetObjectsOf iop:securing` — no class marker needed on the nested node; semantic classes are validated by their own bundles for native objects and by the interop JSON Schema for projections.

## 5. Decisions

- **D8** — semantic `type` never encodes carrier/proof choices; the four `Embedded*` classes are removed (pre-registration, no compat shim).
- **D9** — one `iop:securing` descriptor (one `embedded` field + `carrier` discriminator) replaces `bridgeMode` + the four per-pair embedded fields; `importAdvisory` moves into it (it is bridge provenance, not authorization semantics).
- **D10** — "mandate" is used only for AP2/SD-JWT-VC *representations* (`vct: mandate.*` stays wire-compatible); AVP-side classes keep semantic *authorization* names.
- **D11** — AP2's intent extras (`intentDescription`, `itemConstraints`, `refundabilityRequired`, `requiresPurchaseConfirmation`) remain **top-level semantic claims** (they are carried authorization content, not securing metadata).
- **D12** — no `derivedFrom` property; the existing digest-bound references are the derivation chain.
