# AP2 Mandate-Model Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bridge AP2's two-mandate model (IntentMandate + CartMandate) bidirectionally with AVP-Micro's `SpendingAuthorizationCredential` / payee-signed `PaymentQuote` / `PaymentAuthorization`, and add one optional core object — `PurchaseConfirmation` — so AP2's human-present approval round-trips losslessly.

**Architecture:** Extend the existing `proof-preserving` SD-JWT-VC transcoder (`spec/interop.py` + `spec/interop-sd-jwt-vc/`). All new translators are pure functions tested first with pytest, then wired into the deterministic vector pipeline (`generate.py`) and the two harnesses (`verify.py` crypto/semantics, `validate.py` schema/SHACL/JSON-LD). Native signed objects live in the **payments** bundle (4-entry context, `ecdsa-jcs-2022`); imported unsigned projections live in the **interop** bundle (5-entry context, carrying the foreign proof) — the same split the codebase already uses for `PaymentAuthorization` vs `EmbeddedKbJwtAuthorization`.

**Tech Stack:** Python 3, `cryptography` (P-256/ES256), `pyld`, `pyshacl`, `jsonschema`, `rdflib`, `pytest`. Spec artifacts: JSON-LD 1.1 contexts, JSON Schema 2020-12, SHACL/Turtle, RDFS/OWL.

**Design reference:** [`docs/superpowers/specs/2026-06-12-ap2-mandate-bridge-design.md`](../specs/2026-06-12-ap2-mandate-bridge-design.md). Section numbers (§5–§11) below refer to it.

**Pre-flight:**
- Work happens on branch `feat/ap2-mandate-bridge` (already created off `master`).
- There are **uncommitted WIP changes** in the working tree (e.g. `spec/interop.py`, `spec/generate.py`, schemas). This plan builds *on top of* the current working tree. Each task commits **only its own files** with an explicit pathspec; never `git add -A`.
- Activate the venv before running anything: `cd c:\Users\steph\work\avp-micro-spec; .venv\Scripts\Activate.ps1` (PowerShell).
- Baseline check before starting: `python spec/verify.py; python spec/validate.py` should both print `PASS`. If not, stop and report — the WIP tree is already red.

---

## File structure

**Modify (payments bundle — the one core touch, §7, §12):**
- `spec/payments/schemas/avp-micro.schema.json` — add `PurchaseConfirmation` `$def`; add optional `purchaseConfirmation` member to `PaymentAuthorization`.
- `spec/payments/context/v1.jsonld` — add `PurchaseConfirmation`, `confirmedBy`, `purchaseConfirmation`.
- `spec/payments/vocab/avp.ttl` — add the class + properties.
- `spec/payments/shapes/avp-shapes.ttl` — add `avp:PurchaseConfirmationShape`.

**Modify (interop bundle, §5/§6/§7):**
- `spec/interop.py` — new translator functions (Groups A1–A4).
- `spec/interop-sd-jwt-vc/context/v1.jsonld` — new `iop:` terms + types.
- `spec/interop-sd-jwt-vc/vocab/interop.ttl` — ontology for the new terms.
- `spec/interop-sd-jwt-vc/schemas/interop.schema.json` — `EmbeddedCartQuote`, `EmbeddedCartUserConfirmation` `$defs`; extend `EmbeddedSdJwtVcMandate` with optional intent extras.
- `spec/interop-sd-jwt-vc/shapes/interop-shapes.ttl` — shapes for the new projection types (if the file has shapes; otherwise skip — see Task 13).
- `spec/interop-sd-jwt-vc/README.md` — document the new vectors/terms.

**Modify (harness):**
- `spec/generate.py` — emit new vectors.
- `spec/verify.py` — crypto/semantic checks for the new vectors.
- `spec/validate.py` — register new vectors + negative schema cases.

**Create:**
- `spec/test_interop_ap2.py` — pytest unit tests for all new translator functions.
- `spec/interop-sd-jwt-vc/test-vectors/11-foreign-intent-mandate.json` … `18-payment-authorization-confirmed.json` (emitted by `generate.py`).

---

## Naming contract (used consistently across tasks)

interop.py public functions added by this plan:

| Function | Purpose |
|---|---|
| `canonical_cart(cart) -> bytes` | JCS of a normalized AP2 cart (M4) |
| `cart_service_request_hash(cart) -> str` | `content_digest(canonical_cart(cart))` |
| `INTENT_VCT` (`"mandate.intent.ap2"`) | AP2 IntentMandate `vct` |
| `intent_extras(claims) -> tuple[dict, list]` | `(iop_extras, advisories)` from AP2 intent claims |
| `sdjwtvc_intent_to_avp(compact, mode) -> dict` | import IntentMandate → `EmbeddedSdJwtVcMandate` (+ intent extras) |
| `avp_to_intent_claims(vc) -> dict` | export DSA(+extras) → AP2 intent claim set |
| `cart_mandate_to_quote(compact, cart, mode) -> dict` | import CartMandate → `EmbeddedCartQuote` projection |
| `quote_to_cart_claims(quote) -> dict` | export PaymentQuote → AP2 cart claim set |
| `import_cart_user_confirmation(user_auth_compact, quote_digest, agent_did, payee, amount, currency, service_request_hash, confirmed_by, mode) -> dict` | import human-present approval → `EmbeddedCartUserConfirmation` projection |
| `verify_purchase_confirmation(conf, did_web_resolver=None) -> bool` | verify a `PurchaseConfirmation` (native or projection) |

Constants reused from interop.py: `VCT_PLAIN`, `INTEROP_CTX`, `INTEROP_PAY_CTX`, `iso_to_numericdate`, `numericdate_to_iso`, `avp_to_claims`, `claims_to_avp_subject`, `_effective_claims`, `_issuer_id`. New constant `INTEROP_PAY_CTX` is already defined (`[VC2, DI, DSA, AVP, IOP]`); reuse it for the 5-entry projections.

---

## Task 1: Canonical cart binding (M4)

**Files:**
- Modify: `spec/interop.py` (append a new section near the status-mapping helpers)
- Test: `spec/test_interop_ap2.py` (create)

- [ ] **Step 1: Write the failing test**

Create `spec/test_interop_ap2.py`:

```python
"""Unit tests for the AP2 mandate-model bridge translators (spec/interop.py)."""
import json

import avp_crypto as ac
import interop
import sdjwt


# ---- M4: canonical cart -> serviceRequestHash ----

def _cart():
    return {
        "merchant": "did:web:merchant.example",
        "currency": "USD",
        "items": [
            {"sku": "SKU-2", "qty": 1, "price": "12.00"},
            {"sku": "SKU-1", "qty": 3, "price": "4.00"},
        ],
        "total": {"amount": "24.00", "currency": "USD"},
        "cartExpiry": "2026-06-12T12:00:00Z",
    }


def test_canonical_cart_is_order_independent():
    a = _cart()
    b = json.loads(json.dumps(a))
    b["items"] = list(reversed(b["items"]))  # same items, different order
    assert interop.canonical_cart(a) == interop.canonical_cart(b)


def test_cart_service_request_hash_is_content_digest():
    h = interop.cart_service_request_hash(_cart())
    assert h.startswith("sha-256:")
    assert h == ac.content_digest(interop.canonical_cart(_cart()))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd c:\Users\steph\work\avp-micro-spec; python -m pytest spec/test_interop_ap2.py -q`
Expected: FAIL — `AttributeError: module 'interop' has no attribute 'canonical_cart'`

- [ ] **Step 3: Write minimal implementation**

In `spec/interop.py`, after the `token_list_to_status` function (the status-mapping section), add:

```python
# ---- AP2 cart canonicalization (M4) ----

def canonical_cart(cart: dict) -> bytes:
    """Normalize an AP2 CartContents to stable JCS bytes so an AVP serviceRequestHash
    and the AP2 cart reference the *same* bytes. Items are sorted by ("sku","qty","price")
    so wire order does not change the digest; amounts stay decimal strings (never floats)."""
    items = sorted(
        cart.get("items", []),
        key=lambda it: (str(it.get("sku", "")), str(it.get("qty", "")), str(it.get("price", ""))),
    )
    normalized = {
        "merchant": cart["merchant"],
        "currency": cart.get("currency") or cart.get("total", {}).get("currency"),
        "items": items,
        "total": cart.get("total"),
        "cartExpiry": cart.get("cartExpiry"),
    }
    return ac.jcs(normalized)


def cart_service_request_hash(cart: dict) -> str:
    return ac.content_digest(canonical_cart(cart))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add spec/interop.py spec/test_interop_ap2.py
git commit -m "feat(interop): canonical AP2 cart -> serviceRequestHash binding (M4)"
```

---

## Task 2: IntentMandate ⇄ DSA claim mapping (§5, M2)

**Files:**
- Modify: `spec/interop.py`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
# ---- §5: IntentMandate <-> DSA ----

def _intent_claims():
    return {
        "vct": interop.INTENT_VCT,
        "iss": "did:web:user.example",
        "sub": "did:key:zDnaeAGENT",
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}},
        "currency": "USD",
        "limits": {"per_txn": "120.00"},
        "allowed_payees": ["did:web:merchant.example"],
        "nbf": interop.iso_to_numericdate("2026-06-01T00:00:00Z"),
        "exp": interop.iso_to_numericdate("2026-06-30T00:00:00Z"),
        "jti": "urn:ap2:intent:001",
        # AP2 intent-specific (no DSA policy slot):
        "intent_description": "a red size-10 running shoe under $120",
        "item_constraints": ["color=red", "size=10"],
        "requires_refundability": True,
        "requires_user_confirmation": True,
    }


def test_intent_extras_carries_and_advises_nonenforceable_fields():
    extras, advisories = interop.intent_extras(_intent_claims())
    assert extras["intentDescription"] == "a red size-10 running shoe under $120"
    assert extras["itemConstraints"] == ["color=red", "size=10"]
    assert extras["refundabilityRequired"] is True
    assert extras["requiresPurchaseConfirmation"] is True
    # M2 must be surfaced, not silently enforced
    assert any("item-level" in a or "natural-language" in a for a in advisories)


def test_intent_import_is_dsa_projection_plus_extras():
    claims = _intent_claims()
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "did:web:user.example#key-1"}
    user = sdjwt.seed_p256("user-intent")
    compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(header, claims, user))
    vc = interop.sdjwtvc_intent_to_avp(compact, "proof-preserving")
    assert "SpendingAuthorizationCredential" in vc["type"]
    assert vc["credentialSubject"]["maxPerTransaction"] == "120.00"
    assert vc["credentialSubject"]["allowedPayees"] == ["did:web:merchant.example"]
    assert vc["requiresPurchaseConfirmation"] is True
    assert "proof" not in vc  # proof-preserving projection
    assert any("item-level" in a or "natural-language" in a for a in vc["importAdvisory"])


def test_intent_export_round_trips_policy_and_extras():
    vc = interop.sdjwtvc_intent_to_avp(
        sdjwt.sdjwt_compact(sdjwt.es256_sign(
            {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "did:web:user.example#key-1"},
            _intent_claims(), sdjwt.seed_p256("user-intent"))),
        "proof-preserving")
    back = interop.avp_to_intent_claims(vc)
    assert back["limits"]["per_txn"] == "120.00"
    assert back["intent_description"] == "a red size-10 running shoe under $120"
    assert back["requires_user_confirmation"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -q`
Expected: FAIL — `AttributeError: module 'interop' has no attribute 'INTENT_VCT'`

- [ ] **Step 3: Write minimal implementation**

In `spec/interop.py`, add near the top constants (after `VCT_EMBEDDED`):

```python
INTENT_VCT = "mandate.intent.ap2"
```

Then, after `claims_to_avp_subject`, add:

```python
# ---- §5: AP2 IntentMandate <-> DSA SpendingAuthorizationCredential ----

_INTENT_EXTRA_MAP = (
    ("intent_description", "intentDescription"),
    ("item_constraints", "itemConstraints"),
    ("requires_refundability", "refundabilityRequired"),
    ("requires_user_confirmation", "requiresPurchaseConfirmation"),
)


def intent_extras(claims: dict) -> tuple[dict, list]:
    """Map AP2 intent-specific claims to iop: extras and return import advisories for
    the fields AVP policy cannot machine-enforce (M2)."""
    extras: dict = {}
    for ap2_field, iop_field in _INTENT_EXTRA_MAP:
        if ap2_field in claims:
            extras[iop_field] = claims[ap2_field]
    advisories = []
    if "intent_description" in claims or "item_constraints" in claims:
        advisories.append(
            "ap2-intent-granularity: natural-language / item-level intent is carried in "
            "iop: extras but is NOT enforced by AVP spending policy (envelope only)")
    return extras, advisories


def sdjwtvc_intent_to_avp(compact: str, mode: str = "proof-preserving") -> dict:
    """Import an AP2 IntentMandate (SD-JWT-VC) as an EmbeddedSdJwtVcMandate plus the
    carried-but-unenforced intent extras. Reuses the §4 claim mapping for the envelope."""
    vc = sdjwtvc_to_avp(compact, mode)
    payload, _ = _effective_claims(compact)
    extras, advisories = intent_extras(payload)
    vc.update(extras)
    if advisories:
        vc["importAdvisory"] = list(vc.get("importAdvisory", [])) + advisories
    return vc


def avp_to_intent_claims(vc: dict) -> dict:
    """Export a DSA(+iop intent extras) credential back to AP2 intent claim set."""
    claims = avp_to_claims(vc)
    claims["vct"] = INTENT_VCT
    inverse = {iop: ap2 for ap2, iop in _INTENT_EXTRA_MAP}
    for iop_field, ap2_field in inverse.items():
        if iop_field in vc:
            claims[ap2_field] = vc[iop_field]
    return claims
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -q`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add spec/interop.py spec/test_interop_ap2.py
git commit -m "feat(interop): AP2 IntentMandate <-> DSA mapping with M2 advisories (§5)"
```

---

## Task 3: CartMandate ⇄ PaymentQuote projection (§6)

**Files:**
- Modify: `spec/interop.py`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
# ---- §6: CartMandate <-> PaymentQuote ----

def test_cart_import_projects_quote_and_binds_hash():
    merchant = sdjwt.seed_p256("merchant-cart")
    cart = _cart()
    claims = {
        "vct": "mandate.cart.ap2", "iss": "did:web:merchant.example",
        "sub": "did:key:zDnaeAGENT", "cart": cart,
        "exp": interop.iso_to_numericdate("2026-06-12T12:00:00Z"),
        "jti": "urn:ap2:cart:001",
    }
    compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "did:web:merchant.example#key-1"},
        claims, merchant))
    proj = interop.cart_mandate_to_quote(compact, cart, mode="proof-preserving")
    assert "EmbeddedCartQuote" in proj["type"]
    assert proj["payee"] == "did:web:merchant.example"
    assert proj["amount"] == "24.00"
    assert proj["currency"] == "USD"
    assert proj["serviceRequestHash"] == interop.cart_service_request_hash(cart)
    assert proj["embeddedCartMandate"] == compact
    assert "proof" not in proj  # proof-preserving projection


def test_quote_to_cart_claims_uses_same_hash_field():
    quote = {"payer": "did:key:zDnaeAGENT", "payee": "did:web:merchant.example",
             "amount": "24.00", "currency": "USD",
             "serviceRequestHash": "sha-256:abc", "expires": "2026-06-12T12:00:00Z"}
    c = interop.quote_to_cart_claims(quote)
    assert c["iss"] == "did:web:merchant.example"
    assert c["cart_hash"] == "sha-256:abc"
    assert c["total"] == {"amount": "24.00", "currency": "USD"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -q`
Expected: FAIL — `AttributeError: module 'interop' has no attribute 'cart_mandate_to_quote'`

- [ ] **Step 3: Write minimal implementation**

In `spec/interop.py`, after the intent section, add:

```python
# ---- §6: AP2 CartMandate <-> payee-signed PaymentQuote ----

CART_VCT = "mandate.cart.ap2"


def cart_mandate_to_quote(compact: str, cart: dict, *, mode: str = "proof-preserving") -> dict:
    """Import an AP2 CartMandate (merchant-signed) as an EmbeddedCartQuote projection.
    Authority stays in the embedded merchant signature (proof-preserving); the outer
    object is an unsigned projection whose serviceRequestHash binds the canonical cart."""
    payload, _ = _effective_claims(compact)
    total = cart.get("total", {})
    proj: dict = {
        "@context": list(INTEROP_PAY_CTX),
        "id": "urn:avp:quote:imported:" + str(payload.get("jti", "")),
        "type": ["PaymentQuote", "EmbeddedCartQuote"],
        "payer": payload.get("sub"),
        "payee": payload.get("iss"),
        "amount": total.get("amount"),
        "currency": total.get("currency") or cart.get("currency"),
        "serviceRequestHash": cart_service_request_hash(cart),
        "expires": numericdate_to_iso(payload["exp"]) if "exp" in payload else cart.get("cartExpiry"),
        "bridgeMode": mode,
        "embeddedCartMandate": compact,
        "profileVersion": PROFILE_VERSION,
    }
    return proj


def quote_to_cart_claims(quote: dict) -> dict:
    """Export a payee-signed PaymentQuote to an AP2 cart claim set (merchant attestation)."""
    return {
        "vct": CART_VCT,
        "iss": quote["payee"],
        "sub": quote["payer"],
        "cart_hash": quote["serviceRequestHash"],
        "total": {"amount": quote["amount"], "currency": quote["currency"]},
        "exp": iso_to_numericdate(quote["expires"]),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -q`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add spec/interop.py spec/test_interop_ap2.py
git commit -m "feat(interop): AP2 CartMandate <-> payee-signed PaymentQuote projection (§6)"
```

---

## Task 4: `PurchaseConfirmation` native object — schema, context, vocab, shape (§7)

This task adds the **core payments object** (signed by the principal). No translator yet — just the declarative artifacts + schema validation.

**Files:**
- Modify: `spec/payments/schemas/avp-micro.schema.json`
- Modify: `spec/payments/context/v1.jsonld`
- Modify: `spec/payments/vocab/avp.ttl`
- Modify: `spec/payments/shapes/avp-shapes.ttl`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
# ---- §7: PurchaseConfirmation native object ----

import json as _json
from pathlib import Path as _Path
from jsonschema import Draft202012Validator as _V
from referencing import Registry as _Reg, Resource as _Res
from referencing.jsonschema import DRAFT202012 as _D

_PAY_SCHEMA = _Path("spec/payments/schemas/avp-micro.schema.json")


def _pay_validator(defname):
    bundle = _json.loads(_PAY_SCHEMA.read_text(encoding="utf-8"))
    reg = _Reg().with_resource(uri=bundle["$id"], resource=_Res(contents=bundle, specification=_D))
    return _V({"$ref": f'{bundle["$id"]}#/$defs/{defname}'}, registry=reg,
              format_checker=_V.FORMAT_CHECKER)


def _purchase_confirmation():
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2",
                     "https://w3id.org/security/data-integrity/v2",
                     "https://w3id.org/spending-authority/v1",
                     "https://w3id.org/avp-micro/v1"],
        "id": "urn:avp:confirm:1", "type": "PurchaseConfirmation",
        "quote": "urn:avp:quote:789", "quoteDigest": "sha-256:abc",
        "payer": "did:key:zDnaeAGENT", "payee": "did:key:zDnaePAYEE",
        "amount": "24.00", "currency": "USD", "serviceRequestHash": "sha-256:cart",
        "confirmedBy": "did:key:zDnaePRINCIPAL",
        "timestamp": "2026-06-12T11:00:00Z", "expires": "2026-06-12T11:05:00Z",
        "nonce": "c-1",
        "proof": {"type": "DataIntegrityProof", "cryptosuite": "ecdsa-jcs-2022",
                  "created": "2026-06-12T11:00:00Z",
                  "verificationMethod": "did:key:zDnaePRINCIPAL#zDnaePRINCIPAL",
                  "proofPurpose": "assertionMethod", "proofValue": "zABC"},
    }


def test_purchase_confirmation_matches_schema():
    errs = list(_pay_validator("PurchaseConfirmation").iter_errors(_purchase_confirmation()))
    assert errs == []


def test_purchase_confirmation_requires_confirmedBy():
    bad = _purchase_confirmation()
    del bad["confirmedBy"]
    assert list(_pay_validator("PurchaseConfirmation").iter_errors(bad))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k purchase_confirmation -q`
Expected: FAIL — schema `$ref` to `#/$defs/PurchaseConfirmation` unresolvable (no such `$def`).

- [ ] **Step 3a: Add the schema `$def`**

In `spec/payments/schemas/avp-micro.schema.json`, inside `$defs`, after the `PaymentReceipt` block, add:

```json
    "PurchaseConfirmation": {
      "type": "object",
      "required": ["@context", "id", "type", "quote", "quoteDigest", "payer", "payee", "amount", "currency", "serviceRequestHash", "confirmedBy", "timestamp", "expires", "nonce", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": {
          "oneOf": [
            { "const": "PurchaseConfirmation" },
            { "type": "array", "contains": { "const": "PurchaseConfirmation" } }
          ]
        },
        "quote": { "$ref": "#/$defs/idValue" },
        "quoteDigest": { "$ref": "#/$defs/contentDigest" },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/positiveDecimal" },
        "currency": { "type": "string" },
        "serviceRequestHash": { "$ref": "#/$defs/contentDigest" },
        "confirmedBy": { "$ref": "#/$defs/did" },
        "authorization": { "$ref": "#/$defs/idValue" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "expires": { "$ref": "#/$defs/dateTime" },
        "nonce": { "type": "string", "minLength": 1 },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },
```

- [ ] **Step 3b: Add the context terms**

In `spec/payments/context/v1.jsonld`, inside the `@context` object, add the type alias next to the other type aliases (after `"UsageSessionExtension": "avp:UsageSessionExtension",`):

```json
    "PurchaseConfirmation": "avp:PurchaseConfirmation",
```

and add the property terms (after the `"vp": { "@id": "avp:vp" },` line):

```json
    "confirmedBy": { "@id": "avp:confirmedBy", "@type": "@id" },
    "purchaseConfirmation": { "@id": "avp:purchaseConfirmation" },
```

- [ ] **Step 3c: Add the ontology terms**

In `spec/payments/vocab/avp.ttl`, after the `avp:UsageSessionExtension` class block, add:

```turtle
avp:PurchaseConfirmation a owl:Class ;
  rdfs:label "Purchase confirmation"@en ;
  rdfs:comment "An OPTIONAL principal-signed approval of a specific quoted cart, signed by the human/principal (confirmedBy) rather than the agent. The native home for AP2 human-present cart approval."@en .
```

and in the object-properties section, after `avp:acceptedCredentialIssuers`:

```turtle
avp:confirmedBy a owl:ObjectProperty ; rdfs:label "confirmed by"@en ;
  rdfs:comment "DID of the principal/human who signed the PurchaseConfirmation (MUST control its proof)."@en .
avp:purchaseConfirmation a rdf:Property ; rdfs:label "purchase confirmation"@en ;
  rdfs:comment "An OPTIONAL embedded or referenced PurchaseConfirmation carried by a PaymentAuthorization."@en .
```

- [ ] **Step 3d: Add the SHACL shape**

In `spec/payments/shapes/avp-shapes.ttl`, after `avp:UsageSessionExtensionShape`, add:

```turtle
avp:PurchaseConfirmationShape
  a sh:NodeShape ;
  sh:targetClass avp:PurchaseConfirmation ;
  sh:property [ sh:path avp:quote ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:quoteDigest ; sh:node avp:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:confirmedBy ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:amount ; sh:node avp:PositiveDecimalAmount ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:serviceRequestHash ; sh:node avp:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:expiration ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:nonce ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .
```

> Note: `expires`/`nonce` map to the VC2 context terms `sec:expiration`/`sec:nonce` (the same mapping `PaymentAuthorization` uses — see how `avp-shapes.ttl` references `sec:expiration` and `sec:nonce`). Confirm by expanding the vector in Task 11.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -k purchase_confirmation -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add spec/payments/schemas/avp-micro.schema.json spec/payments/context/v1.jsonld spec/payments/vocab/avp.ttl spec/payments/shapes/avp-shapes.ttl spec/test_interop_ap2.py
git commit -m "feat(payments): add optional PurchaseConfirmation object (§7)"
```

---

## Task 5: PurchaseConfirmation builder + verifier (§7, §11.3)

**Files:**
- Modify: `spec/interop.py`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
# ---- §7/§11.3: PurchaseConfirmation builder + the "signed by the human, not the agent" rule ----

def _signed_confirmation(principal_label="principal", signer_label=None):
    principal = ac.seed_key(principal_label)
    signer = ac.seed_key(signer_label) if signer_label else principal
    conf = {
        "@context": ["https://www.w3.org/ns/credentials/v2",
                     "https://w3id.org/security/data-integrity/v2",
                     "https://w3id.org/spending-authority/v1",
                     "https://w3id.org/avp-micro/v1"],
        "id": "urn:avp:confirm:1", "type": "PurchaseConfirmation",
        "quote": "urn:avp:quote:789", "quoteDigest": "sha-256:abc",
        "payer": "did:key:zDnaeAGENT", "payee": ac.did_key(ac.seed_key("payee").public_key()),
        "amount": "24.00", "currency": "USD", "serviceRequestHash": "sha-256:cart",
        "confirmedBy": ac.did_key(principal.public_key()),
        "timestamp": "2026-06-12T11:00:00Z", "expires": "2026-06-12T11:05:00Z", "nonce": "c-1",
    }
    return ac.sign_ecdsa_jcs_2022(conf, signer, "2026-06-12T11:00:00Z")


def test_purchase_confirmation_verifies_when_signed_by_confirmedBy():
    assert interop.verify_purchase_confirmation(_signed_confirmation()) is True


def test_purchase_confirmation_rejected_when_signed_by_someone_else():
    # signer != confirmedBy  (e.g. forged by the agent) MUST be rejected
    forged = _signed_confirmation(principal_label="principal", signer_label="agent-forger")
    assert interop.verify_purchase_confirmation(forged) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k purchase_confirmation_verifies -q`
Expected: FAIL — `AttributeError: module 'interop' has no attribute 'verify_purchase_confirmation'`

- [ ] **Step 3: Write minimal implementation**

In `spec/interop.py`, after the cart section, add:

```python
# ---- §7: PurchaseConfirmation (fresh human approval) ----

def verify_purchase_confirmation(conf: dict, did_web_resolver: dict | None = None) -> bool:
    """Verify a PurchaseConfirmation. The defining rule (§11.3): authority is a fresh
    HUMAN approval, so the proof MUST be controlled by confirmedBy (the principal), never
    by the agent (payer). proof-preserving projections (no native proof) instead carry the
    original approval in iop:embeddedCartUserAuth, verified via did:web. Any error => False."""
    try:
        confirmed_by = conf.get("confirmedBy")
        if not confirmed_by or confirmed_by == conf.get("payer"):
            return False  # must name a principal distinct from the agent
        if "proof" in conf:  # native / co-issued
            vm = conf["proof"].get("verificationMethod", "")
            if vm.split("#", 1)[0] != confirmed_by:
                return False  # signer MUST be confirmedBy
            return ac.verify_ecdsa_jcs_2022(conf)
        # proof-preserving projection: verify the embedded AP2 user approval
        compact = conf.get("embeddedCartUserAuth")
        if not compact:
            return False
        jwk = (did_web_resolver or {}).get(confirmed_by)
        return jwk is not None and sdjwt.es256_verify(sdjwt.sdjwt_jws(compact),
                                                      sdjwt.p256_public_from_jwk(jwk))
    except Exception:
        return False


def import_cart_user_confirmation(user_auth_compact: str, *, quote_digest: str, agent_did: str,
                                  payee: str, amount: str, currency: str,
                                  service_request_hash: str, confirmed_by: str, quote: str,
                                  mode: str = "proof-preserving") -> dict:
    """Import an AP2 human-present cart approval as an EmbeddedCartUserConfirmation
    projection (unsigned; authority is the embedded user JWT)."""
    return {
        "@context": list(INTEROP_PAY_CTX),
        "id": "urn:avp:confirm:imported:" + quote_digest,
        "type": ["PurchaseConfirmation", "EmbeddedCartUserConfirmation"],
        "quote": quote, "quoteDigest": quote_digest,
        "payer": agent_did, "payee": payee, "amount": amount, "currency": currency,
        "serviceRequestHash": service_request_hash, "confirmedBy": confirmed_by,
        "bridgeMode": mode, "embeddedCartUserAuth": user_auth_compact,
        "profileVersion": PROFILE_VERSION,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -k purchase_confirmation -q`
Expected: PASS (4 passed — the two schema tests from Task 4 plus the two here)

- [ ] **Step 5: Commit**

```bash
git add spec/interop.py spec/test_interop_ap2.py
git commit -m "feat(interop): PurchaseConfirmation verify (signer==confirmedBy) + import projection (§7, §11.3)"
```

---

## Task 6: Optional `purchaseConfirmation` member on `PaymentAuthorization`

**Files:**
- Modify: `spec/payments/schemas/avp-micro.schema.json`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
def test_payment_authorization_accepts_optional_purchase_confirmation():
    # load the existing authz vector, attach a confirmation, must still validate
    authz = _json.loads(_Path("spec/payments/test-vectors/02-payment-authorization.json").read_text(encoding="utf-8"))
    authz["purchaseConfirmation"] = _purchase_confirmation()
    errs = list(_pay_validator("PaymentAuthorization").iter_errors(authz))
    assert errs == []


def test_payment_authorization_still_valid_without_confirmation():
    authz = _json.loads(_Path("spec/payments/test-vectors/02-payment-authorization.json").read_text(encoding="utf-8"))
    assert list(_pay_validator("PaymentAuthorization").iter_errors(authz)) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k optional_purchase_confirmation -q`
Expected: FAIL — `additionalProperties`/ref issue: `purchaseConfirmation` not allowed/typed (the schema has no such property, and while it is lenient about extras, the test asserts the nested object is *validated*; add it explicitly).

- [ ] **Step 3: Write minimal implementation**

In `spec/payments/schemas/avp-micro.schema.json`, inside `PaymentAuthorization.properties` (after the `"wallet"` property line), add:

```json
        "purchaseConfirmation": { "$ref": "#/$defs/PurchaseConfirmation" },
```

(Leave it out of `required` — it stays optional, §11.7.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -k purchase_confirmation -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add spec/payments/schemas/avp-micro.schema.json spec/test_interop_ap2.py
git commit -m "feat(payments): optional PaymentAuthorization.purchaseConfirmation member"
```

---

## Task 7: Interop context + ontology for the new `iop:` terms and projection types

**Files:**
- Modify: `spec/interop-sd-jwt-vc/context/v1.jsonld`
- Modify: `spec/interop-sd-jwt-vc/vocab/interop.ttl`
- Test: none directly (covered by JSON-LD expansion in Task 12); add a parse smoke test.

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
import rdflib as _rdflib


def test_interop_context_defines_new_terms():
    ctx = _json.loads(_Path("spec/interop-sd-jwt-vc/context/v1.jsonld").read_text(encoding="utf-8"))["@context"]
    for term in ("embeddedCartMandate", "embeddedCartUserAuth", "intentDescription",
                 "itemConstraints", "refundabilityRequired", "requiresPurchaseConfirmation",
                 "EmbeddedCartQuote", "EmbeddedCartUserConfirmation"):
        assert term in ctx, f"missing context term: {term}"


def test_interop_vocab_parses():
    g = _rdflib.Graph().parse("spec/interop-sd-jwt-vc/vocab/interop.ttl", format="turtle")
    assert len(g) > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k interop_context -q`
Expected: FAIL — `missing context term: embeddedCartMandate`

- [ ] **Step 3a: Extend the interop context**

In `spec/interop-sd-jwt-vc/context/v1.jsonld`, inside `@context`, add after `"EmbeddedKbJwtAuthorization": "iop:EmbeddedKbJwtAuthorization",`:

```json
    "EmbeddedCartQuote": "iop:EmbeddedCartQuote",
    "EmbeddedCartUserConfirmation": "iop:EmbeddedCartUserConfirmation",
```

and after `"profileVersion": { "@id": "iop:profileVersion" }` (add a comma to that line), add:

```json
    "embeddedCartMandate": { "@id": "iop:embeddedCartMandate" },
    "embeddedCartUserAuth": { "@id": "iop:embeddedCartUserAuth" },
    "embeddedIntentMandate": { "@id": "iop:embeddedIntentMandate" },
    "intentDescription": { "@id": "iop:intentDescription" },
    "itemConstraints": { "@id": "iop:itemConstraints", "@container": "@set" },
    "refundabilityRequired": { "@id": "iop:refundabilityRequired" },
    "requiresPurchaseConfirmation": { "@id": "iop:requiresPurchaseConfirmation" }
```

- [ ] **Step 3b: Extend the interop ontology**

In `spec/interop-sd-jwt-vc/vocab/interop.ttl`, append:

```turtle
iop:EmbeddedCartQuote a owl:Class ;
  rdfs:label "Embedded cart quote"@en ;
  rdfs:comment "A PaymentQuote projection of an AP2 CartMandate; authority is the embedded merchant signature (iop:embeddedCartMandate)."@en .
iop:EmbeddedCartUserConfirmation a owl:Class ;
  rdfs:label "Embedded cart user confirmation"@en ;
  rdfs:comment "A PurchaseConfirmation projection of an AP2 human-present cart approval; authority is the embedded user signature (iop:embeddedCartUserAuth)."@en .

iop:embeddedCartMandate a owl:DatatypeProperty ; rdfs:label "embedded cart mandate"@en ;
  rdfs:comment "Compact serialization of the original merchant-signed AP2 CartMandate."@en .
iop:embeddedCartUserAuth a owl:DatatypeProperty ; rdfs:label "embedded cart user auth"@en ;
  rdfs:comment "Compact serialization of the original user-signed AP2 cart approval."@en .
iop:embeddedIntentMandate a owl:DatatypeProperty ; rdfs:label "embedded intent mandate"@en ;
  rdfs:comment "Compact serialization of the original user-signed AP2 IntentMandate."@en .
iop:intentDescription a owl:DatatypeProperty ; rdfs:label "intent description"@en ;
  rdfs:comment "Natural-language purchase intent carried from an AP2 IntentMandate; NOT machine-enforced."@en .
iop:itemConstraints a owl:DatatypeProperty ; rdfs:label "item constraints"@en ;
  rdfs:comment "Item/SKU-level constraints carried from an AP2 IntentMandate; NOT machine-enforced."@en .
iop:refundabilityRequired a owl:DatatypeProperty ; rdfs:label "refundability required"@en .
iop:requiresPurchaseConfirmation a owl:DatatypeProperty ; rdfs:label "requires purchase confirmation"@en ;
  rdfs:comment "True when the source AP2 intent requires fresh human approval (a PurchaseConfirmation) per purchase."@en .
```

> Check the existing prefixes at the top of `interop.ttl`; if `owl:` is not declared there, add `@prefix owl: <http://www.w3.org/2002/07/owl#> .` Run the parse test to confirm.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -k "interop_context or interop_vocab" -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add spec/interop-sd-jwt-vc/context/v1.jsonld spec/interop-sd-jwt-vc/vocab/interop.ttl spec/test_interop_ap2.py
git commit -m "feat(interop): context + ontology terms for AP2 cart/intent/confirmation bridging"
```

---

## Task 8: Interop schema — projection `$defs` and intent extras

**Files:**
- Modify: `spec/interop-sd-jwt-vc/schemas/interop.schema.json`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
_IOP_SCHEMA = _Path("spec/interop-sd-jwt-vc/schemas/interop.schema.json")


def _iop_validator(defname):
    bundle = _json.loads(_IOP_SCHEMA.read_text(encoding="utf-8"))
    reg = _Reg().with_resource(uri=bundle["$id"], resource=_Res(contents=bundle, specification=_D))
    return _V({"$ref": f'{bundle["$id"]}#/$defs/{defname}'}, registry=reg,
              format_checker=_V.FORMAT_CHECKER)


def test_embedded_cart_quote_schema():
    merchant = sdjwt.seed_p256("merchant-cart")
    cart = _cart()
    compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "did:web:merchant.example#k"},
        {"vct": "mandate.cart.ap2", "iss": "did:web:merchant.example",
         "sub": "did:key:zDnaeAGENT", "exp": interop.iso_to_numericdate("2026-06-12T12:00:00Z"),
         "jti": "urn:ap2:cart:001"}, merchant))
    proj = interop.cart_mandate_to_quote(compact, cart, mode="proof-preserving")
    assert list(_iop_validator("EmbeddedCartQuote").iter_errors(proj)) == []


def test_embedded_cart_quote_rejects_proof_on_proof_preserving():
    merchant = sdjwt.seed_p256("merchant-cart")
    compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": "did:web:merchant.example#k"},
        {"vct": "mandate.cart.ap2", "iss": "did:web:merchant.example",
         "sub": "did:key:zDnaeAGENT", "exp": interop.iso_to_numericdate("2026-06-12T12:00:00Z"),
         "jti": "urn:ap2:cart:001"}, merchant))
    proj = interop.cart_mandate_to_quote(compact, _cart(), mode="proof-preserving")
    proj["proof"] = {"type": "DataIntegrityProof"}
    assert list(_iop_validator("EmbeddedCartQuote").iter_errors(proj))  # no-downgrade
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k embedded_cart_quote -q`
Expected: FAIL — `$ref` to `#/$defs/EmbeddedCartQuote` unresolvable.

- [ ] **Step 3a: Add `EmbeddedCartQuote` and `EmbeddedCartUserConfirmation` `$defs`**

In `spec/interop-sd-jwt-vc/schemas/interop.schema.json`, inside `$defs` (after `EmbeddedKbJwtAuthorization`), add:

```json
    "EmbeddedCartQuote": {
      "type": "object",
      "description": "A PaymentQuote projection of an AP2 CartMandate (V->A import). Authority is the embedded merchant signature; in proof-preserving mode the outer object carries no proof.",
      "required": ["@context", "type", "payer", "payee", "amount", "currency", "serviceRequestHash", "embeddedCartMandate", "bridgeMode"],
      "properties": {
        "@context": {
          "type": "array",
          "prefixItems": [
            { "const": "https://www.w3.org/ns/credentials/v2" },
            { "const": "https://w3id.org/security/data-integrity/v2" },
            { "const": "https://w3id.org/spending-authority/v1" },
            { "const": "https://w3id.org/avp-micro/v1" },
            { "const": "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1" }
          ],
          "minItems": 5, "maxItems": 5
        },
        "id": { "type": "string", "minLength": 1 },
        "type": {
          "type": "array",
          "allOf": [
            { "contains": { "const": "PaymentQuote" } },
            { "contains": { "const": "EmbeddedCartQuote" } }
          ]
        },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/decimal" },
        "currency": { "type": "string" },
        "serviceRequestHash": { "type": "string" },
        "expires": { "type": "string", "format": "date-time" },
        "embeddedCartMandate": { "$ref": "#/$defs/compactSdJwt" },
        "bridgeMode": { "type": "string", "enum": ["co-issued", "proof-preserving", "attested"] },
        "profileVersion": { "type": "string" },
        "proof": { "type": "object" }
      },
      "allOf": [
        {
          "if": { "properties": { "bridgeMode": { "const": "proof-preserving" } } },
          "then": { "not": { "required": ["proof"] } }
        }
      ]
    },
    "EmbeddedCartUserConfirmation": {
      "type": "object",
      "description": "A PurchaseConfirmation projection of an AP2 human-present cart approval (V->A import). Authority is the embedded user signature (iop:embeddedCartUserAuth).",
      "required": ["@context", "type", "quote", "quoteDigest", "payer", "payee", "amount", "currency", "serviceRequestHash", "confirmedBy", "embeddedCartUserAuth", "bridgeMode"],
      "properties": {
        "@context": {
          "type": "array",
          "prefixItems": [
            { "const": "https://www.w3.org/ns/credentials/v2" },
            { "const": "https://w3id.org/security/data-integrity/v2" },
            { "const": "https://w3id.org/spending-authority/v1" },
            { "const": "https://w3id.org/avp-micro/v1" },
            { "const": "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1" }
          ],
          "minItems": 5, "maxItems": 5
        },
        "id": { "type": "string", "minLength": 1 },
        "type": {
          "type": "array",
          "allOf": [
            { "contains": { "const": "PurchaseConfirmation" } },
            { "contains": { "const": "EmbeddedCartUserConfirmation" } }
          ]
        },
        "quote": { "type": "string" },
        "quoteDigest": { "type": "string" },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/decimal" },
        "currency": { "type": "string" },
        "serviceRequestHash": { "type": "string" },
        "confirmedBy": { "$ref": "#/$defs/did" },
        "embeddedCartUserAuth": { "$ref": "#/$defs/compactSdJwt" },
        "bridgeMode": { "type": "string", "enum": ["co-issued", "proof-preserving", "attested"] },
        "profileVersion": { "type": "string" },
        "proof": { "type": "object" }
      },
      "allOf": [
        {
          "if": { "properties": { "bridgeMode": { "const": "proof-preserving" } } },
          "then": { "not": { "required": ["proof"] } }
        }
      ]
    },
```

- [ ] **Step 3b: Allow intent extras on `EmbeddedSdJwtVcMandate`**

In the same file, inside `EmbeddedSdJwtVcMandate.properties` (after `"importAdvisory"`), add:

```json
        "intentDescription": { "type": "string" },
        "itemConstraints": { "type": "array", "items": { "type": "string" } },
        "refundabilityRequired": { "type": "boolean" },
        "requiresPurchaseConfirmation": { "type": "boolean" },
        "embeddedIntentMandate": { "$ref": "#/$defs/compactSdJwt" },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest spec/test_interop_ap2.py -k embedded_cart_quote -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add spec/interop-sd-jwt-vc/schemas/interop.schema.json spec/test_interop_ap2.py
git commit -m "feat(interop): schema for EmbeddedCartQuote, EmbeddedCartUserConfirmation, intent extras"
```

---

## Task 9: Full unit suite green + no-widening helper (§11.2)

Add the "translation never widens authority" intersection helper and a test, then confirm the whole new unit suite is green.

**Files:**
- Modify: `spec/interop.py`
- Test: `spec/test_interop_ap2.py`

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
def test_intersect_limits_takes_most_restrictive():
    a = {"per_txn": "120.00", "per_day": "500.00"}
    b = {"per_txn": "100.00"}
    out = interop.intersect_limits(a, b)
    assert out["per_txn"] == "100.00"   # stricter wins
    assert out["per_day"] == "500.00"   # only side that has it
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k intersect_limits -q`
Expected: FAIL — `AttributeError: module 'interop' has no attribute 'intersect_limits'`

- [ ] **Step 3: Write minimal implementation**

In `spec/interop.py`, after the PurchaseConfirmation section, add:

```python
from decimal import Decimal as _Decimal


def intersect_limits(a: dict, b: dict) -> dict:
    """§11.2 no-widening: when both stacks carry a limit, keep the most restrictive
    (minimum) value. A limit present on only one side is kept as-is."""
    out = dict(a)
    for k, v in b.items():
        if k in out:
            try:
                out[k] = v if _Decimal(v) < _Decimal(out[k]) else out[k]
            except (ValueError, ArithmeticError):
                out[k] = out[k]  # non-decimal limit (e.g. tz): keep the a-side value
        else:
            out[k] = v
    return out
```

- [ ] **Step 4: Run the entire new unit suite**

Run: `python -m pytest spec/test_interop_ap2.py -q`
Expected: PASS (all tests green — Tasks 1–9)

Also confirm nothing else broke:
Run: `python -m pytest spec/test_pricing.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add spec/interop.py spec/test_interop_ap2.py
git commit -m "feat(interop): no-widening limit intersection (§11.2) + green unit suite"
```

---

## Task 10: Generate the new test vectors

Emit deterministic vectors so `verify.py`/`validate.py` can exercise the bridge end-to-end. Append to `generate.py`'s interop section (after vector `10`).

**Files:**
- Modify: `spec/generate.py`
- Test: run `generate.py`, then assert files exist.

- [ ] **Step 1: Write the failing test**

Append to `spec/test_interop_ap2.py`:

```python
def test_new_vectors_exist():
    base = _Path("spec/interop-sd-jwt-vc/test-vectors")
    for name in ("11-foreign-intent-mandate.json", "12-imported-intent-mandate.json",
                 "13-foreign-cart-mandate.json", "14-imported-cart-quote.json",
                 "15-human-present-confirmation.json", "16-autonomous-no-confirmation.json"):
        assert (base / name).exists(), f"missing vector: {name}"
    pay = _Path("spec/payments/test-vectors")
    assert (pay / "14b-purchase-confirmation.json").exists()
    assert (pay / "18-payment-authorization-confirmed.json").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest spec/test_interop_ap2.py -k new_vectors_exist -q`
Expected: FAIL — `missing vector: 11-foreign-intent-mandate.json`

- [ ] **Step 3: Write the generation code**

In `spec/generate.py`, at the end of `main()` (after the `10-imported-partial-sd.json` block), add:

```python
    # ---- AP2 mandate-model bridge vectors (Intent + Cart + PurchaseConfirmation) ----
    ap2_user = sdjwt.seed_p256("ap2-user")
    ap2_merchant = sdjwt.seed_p256("ap2-merchant")
    DID_AP2_USER = "did:web:user.example"
    DID_AP2_MERCHANT = "did:web:merchant.example"
    # extend the did:web resolver written into keys.json so verify.py can resolve them
    keys_path = INTEROP / "keys.json"
    keys = json.loads(keys_path.read_text(encoding="utf-8"))
    keys["didWebResolver"][DID_AP2_USER] = sdjwt.p256_public_jwk(ap2_user.public_key())
    keys["didWebResolver"][DID_AP2_MERCHANT] = sdjwt.p256_public_jwk(ap2_merchant.public_key())
    keys_path.write_text(json.dumps(keys, indent=2) + "\n", encoding="utf-8")

    # 11: foreign AP2 IntentMandate (user-signed, ES256), with non-enforceable intent fields
    intent_claims = {
        "vct": interop.INTENT_VCT, "iss": DID_AP2_USER, "sub": DID_AGENT,
        "cnf": {"jwk": sdjwt.p256_public_jwk(agent.public_key())},
        "currency": "USD", "limits": {"per_txn": "120.00"},
        "allowed_payees": [DID_AP2_MERCHANT],
        "nbf": interop.iso_to_numericdate("2026-06-01T00:00:00Z"),
        "exp": interop.iso_to_numericdate("2026-06-30T00:00:00Z"),
        "jti": "urn:ap2:intent:001",
        "intent_description": "a red size-10 running shoe under $120",
        "item_constraints": ["color=red", "size=10"],
        "requires_refundability": True, "requires_user_confirmation": True,
    }
    intent_header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_AP2_USER + "#key-1"}
    intent_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(intent_header, intent_claims, ap2_user))
    write(INTEROP, "11-foreign-intent-mandate.json", {
        "_note": "A foreign AP2 IntentMandate (ES256, did:web user issuer; item-level intent).",
        "compact": intent_compact, "payload": intent_claims})

    # 12: V->A import of the IntentMandate -> EmbeddedSdJwtVcMandate + intent extras + advisory
    imported_intent = interop.sdjwtvc_intent_to_avp(intent_compact, "proof-preserving")
    write(INTEROP, "12-imported-intent-mandate.json", imported_intent)

    # 13: foreign AP2 CartMandate (merchant-signed, ES256) carrying the itemized cart
    cart = {"merchant": DID_AP2_MERCHANT, "currency": "USD",
            "items": [{"sku": "SHOE-RED-10", "qty": 1, "price": "112.40"}],
            "total": {"amount": "112.40", "currency": "USD"},
            "cartExpiry": "2026-06-12T12:00:00Z"}
    cart_claims = {"vct": interop.CART_VCT, "iss": DID_AP2_MERCHANT, "sub": DID_AGENT,
                   "cart": cart, "cart_hash": interop.cart_service_request_hash(cart),
                   "exp": interop.iso_to_numericdate("2026-06-12T12:00:00Z"),
                   "jti": "urn:ap2:cart:001"}
    cart_header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_AP2_MERCHANT + "#key-1"}
    cart_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(cart_header, cart_claims, ap2_merchant))
    write(INTEROP, "13-foreign-cart-mandate.json", {
        "_note": "A foreign AP2 CartMandate (ES256, did:web merchant; itemized cart).",
        "compact": cart_compact, "cart": cart, "payload": cart_claims})

    # 14: V->A import of the CartMandate -> EmbeddedCartQuote projection
    imported_cart = interop.cart_mandate_to_quote(cart_compact, cart, mode="proof-preserving")
    write(INTEROP, "14-imported-cart-quote.json", imported_cart)

    # 15: human-present approval imported -> EmbeddedCartUserConfirmation projection
    crh = interop.cart_service_request_hash(cart)
    user_auth_claims = {"iss": DID_AP2_USER, "sub": DID_AGENT, "cart_hash": crh,
                        "iat": interop.iso_to_numericdate("2026-06-12T11:00:00Z"),
                        "exp": interop.iso_to_numericdate("2026-06-12T11:05:00Z")}
    user_auth_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_AP2_USER + "#key-1"},
        user_auth_claims, ap2_user))
    confirmation = interop.import_cart_user_confirmation(
        user_auth_compact, quote_digest="sha-256:imported", agent_did=DID_AGENT,
        payee=DID_AP2_MERCHANT, amount="112.40", currency="USD",
        service_request_hash=crh, confirmed_by=DID_AP2_USER,
        quote="urn:avp:quote:imported:urn:ap2:cart:001", mode="proof-preserving")
    write(INTEROP, "15-human-present-confirmation.json", confirmation)

    # 16: autonomous import (intent with requires_user_confirmation=False) -> no confirmation,
    # an advisory documents that no fresh human approval exists (§10).
    autonomous_claims = dict(intent_claims)
    autonomous_claims["requires_user_confirmation"] = False
    autonomous_claims["jti"] = "urn:ap2:intent:auto:001"
    autonomous_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(intent_header, autonomous_claims, ap2_user))
    imported_auto = interop.sdjwtvc_intent_to_avp(autonomous_compact, "proof-preserving")
    imported_auto["importAdvisory"] = list(imported_auto.get("importAdvisory", [])) + [
        "autonomous: no human-present PurchaseConfirmation present; standing delegation only"]
    write(INTEROP, "16-autonomous-no-confirmation.json", imported_auto)

    # 14b (payments bundle): native PurchaseConfirmation (principal-signed, ecdsa-jcs-2022).
    # It is a PAYMENTS object (validated by the payments schema/shapes), so it lives under
    # payments/test-vectors/, not the interop bundle.
    native_conf = {
        "@context": PAY_CTX, "id": "urn:avp:confirm:native:1", "type": "PurchaseConfirmation",
        "quote": "urn:avp:quote:789", "quoteDigest": ac.jcs_digest(quote),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": amount, "currency": currency,
        "serviceRequestHash": srh, "confirmedBy": DID_ISSUER,
        "timestamp": "2026-03-25T21:29:50Z", "expires": "2026-03-25T21:35:00Z", "nonce": "conf-1",
    }
    native_conf = ac.sign_ecdsa_jcs_2022(native_conf, issuer, "2026-03-25T21:29:50Z")
    write(PAY, "14b-purchase-confirmation.json", native_conf)

    # 18: a PaymentAuthorization carrying the native PurchaseConfirmation (human-present)
    authz_confirmed = json.loads(json.dumps({k: v for k, v in authz.items() if k != "proof"}))
    authz_confirmed["id"] = "urn:avp:authz:confirmed:1"
    authz_confirmed["purchaseConfirmation"] = native_conf
    authz_confirmed = ac.sign_ecdsa_jcs_2022(authz_confirmed, agent, "2026-03-25T21:30:02Z")
    write(PAY, "18-payment-authorization-confirmed.json", authz_confirmed)
```

- [ ] **Step 4: Run generation, then the test**

Run: `python spec/generate.py`
Expected: prints `wrote interop-sd-jwt-vc/11-foreign-intent-mandate.json` … through `16`, plus `wrote payments/14b-purchase-confirmation.json` and `wrote payments/18-payment-authorization-confirmed.json`.
Run: `python -m pytest spec/test_interop_ap2.py -k new_vectors_exist -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add spec/generate.py spec/interop-sd-jwt-vc/test-vectors/ spec/payments/test-vectors/14b-purchase-confirmation.json spec/payments/test-vectors/18-payment-authorization-confirmed.json spec/test_interop_ap2.py
git commit -m "feat(vectors): AP2 intent/cart/confirmation round-trip + native confirmation vectors"
```

---

## Task 11: `verify.py` — crypto + semantic checks for the new vectors (§11)

**Files:**
- Modify: `spec/verify.py`
- Test: `python spec/verify.py` must print `PASS`.

- [ ] **Step 1: Add the checks**

In `spec/verify.py`, before the final `print()` / `_failed` summary block (i.e. just before `print()` near the end of `main()`), add:

```python
    print("AP2 mandate-model bridge:")
    intent_foreign = load(INTEROP, "11-foreign-intent-mandate.json")
    imported_intent = load(INTEROP, "12-imported-intent-mandate.json")
    cart_foreign = load(INTEROP, "13-foreign-cart-mandate.json")
    imported_cart = load(INTEROP, "14-imported-cart-quote.json")
    confirmation = load(INTEROP, "15-human-present-confirmation.json")
    autonomous = load(INTEROP, "16-autonomous-no-confirmation.json")
    native_conf = load(PAY, "14b-purchase-confirmation.json")
    authz_confirmed = load(PAY, "18-payment-authorization-confirmed.json")

    # IntentMandate import: policy envelope mapped, item-level intent carried + advised (M2)
    check("intent import keeps maxPerTransaction",
          imported_intent["credentialSubject"]["maxPerTransaction"] == "120.00")
    check("intent import carries non-enforceable item intent",
          imported_intent.get("intentDescription") is not None)
    check("intent import advises M2 granularity loss",
          any("ap2-intent-granularity" in a for a in imported_intent.get("importAdvisory", [])))
    check("intent import flags requiresPurchaseConfirmation",
          imported_intent.get("requiresPurchaseConfirmation") is True)
    check("intent import is a proof-preserving projection (no proof)",
          "proof" not in imported_intent)

    # CartMandate import: payee==merchant, hash binds canonical cart (M4)
    check("cart import payee == merchant issuer", imported_cart["payee"] == cart_foreign["payload"]["iss"])
    check("cart import serviceRequestHash binds canonical cart",
          imported_cart["serviceRequestHash"] == interop.cart_service_request_hash(cart_foreign["cart"]))
    check("cart import is a proof-preserving projection (no proof)", "proof" not in imported_cart)
    check("cart import embeds the merchant-signed mandate",
          imported_cart["embeddedCartMandate"] == cart_foreign["compact"])

    # PurchaseConfirmation: signer==confirmedBy rule (§11.3), forged-by-agent rejected
    check("native PurchaseConfirmation verifies", interop.verify_purchase_confirmation(native_conf))
    check("native confirmation signed by confirmedBy (the principal, not the agent)",
          controller(native_conf) == native_conf["confirmedBy"] != native_conf["payer"])
    check("imported human-present confirmation verifies via did:web",
          interop.verify_purchase_confirmation(confirmation, resolver))
    forged = json.loads(json.dumps(native_conf))
    forged["confirmedBy"] = forged["payer"]  # claim the agent confirmed
    check("confirmation with confirmedBy==payer is rejected", not interop.verify_purchase_confirmation(forged))

    # human-present binding equality with the authorization it rides on
    check("confirmed authz carries a PurchaseConfirmation", "purchaseConfirmation" in authz_confirmed)
    pc = authz_confirmed["purchaseConfirmation"]
    check("authz purchaseConfirmation binds same quoteDigest", pc["quoteDigest"] == authz_confirmed["quoteDigest"])
    check("authz purchaseConfirmation binds same serviceRequestHash",
          pc["serviceRequestHash"] == authz_confirmed["serviceRequestHash"])
    check("confirmed authz still verifies (agent proof)", ac.verify_ecdsa_jcs_2022(authz_confirmed))

    # autonomous import: NO confirmation, explicitly advised (§10)
    check("autonomous import has no PurchaseConfirmation",
          "EmbeddedCartUserConfirmation" not in autonomous.get("type", []))
    check("autonomous import advises absence of fresh human approval",
          any("autonomous" in a for a in autonomous.get("importAdvisory", [])))

    # no-widening intersection (§11.2)
    check("intersect_limits keeps the most restrictive",
          interop.intersect_limits({"per_txn": "120.00"}, {"per_txn": "100.00"})["per_txn"] == "100.00")
```

- [ ] **Step 2: Run verify**

Run: `python spec/verify.py`
Expected: the new `AP2 mandate-model bridge:` section prints all `[PASS]`, and the final line is `PASS: all checks passed.` (exit 0).

If any check fails, fix the underlying generator/translator (not the assertion) and re-run `python spec/generate.py; python spec/verify.py`.

- [ ] **Step 3: Commit**

```bash
git add spec/verify.py
git commit -m "test(verify): AP2 bridge crypto + semantic checks (signer binding, M2/M4, no-widening)"
```

---

## Task 12: `validate.py` — register new vectors, expansion, schema, SHACL (§12)

**Files:**
- Modify: `spec/validate.py`
- Test: `python spec/validate.py` must print `PASS`.

- [ ] **Step 1: Register the new vectors**

In `spec/validate.py`, extend `INTEROP_VECTORS` with the new projection vectors and their `$def`:

```python
    "12-imported-intent-mandate.json": "EmbeddedSdJwtVcMandate",
    "14-imported-cart-quote.json": "EmbeddedCartQuote",
    "15-human-present-confirmation.json": "EmbeddedCartUserConfirmation",
    "16-autonomous-no-confirmation.json": "EmbeddedSdJwtVcMandate",
```

Add the two new payments-bundle vectors to `PAY_VECTORS` (both live under `payments/test-vectors/`, validated by the payments schema/shapes):

```python
    "14b-purchase-confirmation.json": "PurchaseConfirmation",
    "18-payment-authorization-confirmed.json": "PaymentAuthorization",
```

- [ ] **Step 2: Add expansion `must_survive` anchors**

In `validate.py`'s `expand_check(INTEROP, INTEROP_VECTORS, {...}, require_proof=False)` map, add:

```python
        "12-imported-intent-mandate.json": [(IOP_NS + "intentDescription", "iop:intentDescription"),
                                            (IOP_NS + "importAdvisory", "iop:importAdvisory")],
        "14-imported-cart-quote.json": [(IOP_NS + "embeddedCartMandate", "iop:embeddedCartMandate")],
        "15-human-present-confirmation.json": [(IOP_NS + "embeddedCartUserAuth", "iop:embeddedCartUserAuth")],
```

- [ ] **Step 3: Add negative schema cases**

In `validate.py`, inside `negative_schema_check(INTEROP, "interop.schema.json", [...])`, add:

```python
        ("cart-quote proof on proof-preserving", "14-imported-cart-quote.json", "EmbeddedCartQuote",
         lambda obj: (obj.__setitem__("proof", {"type": "DataIntegrityProof"}), obj)[1]),
        ("cart-quote missing embeddedCartMandate", "14-imported-cart-quote.json", "EmbeddedCartQuote",
         lambda obj: (obj.pop("embeddedCartMandate", None), obj)[1]),
        ("confirmation missing confirmedBy", "15-human-present-confirmation.json", "EmbeddedCartUserConfirmation",
         lambda obj: (obj.pop("confirmedBy", None), obj)[1]),
```

And in `negative_schema_check(PAY, "avp-micro.schema.json", [...])`, add:

```python
        ("PurchaseConfirmation missing confirmedBy", "14b-purchase-confirmation.json", "PurchaseConfirmation",
         lambda obj: (obj.pop("confirmedBy", None), obj)[1]),
```

- [ ] **Step 4: Run validate**

Run: `python spec/validate.py`
Expected: new vectors appear under "JSON-LD expansion", "JSON Schema validation", and "SHACL validation" sections, all `[PASS]`; final line `PASS: all artifact checks passed.` (exit 0).

If SHACL fails on the native `PurchaseConfirmation` because `expires`/`nonce` don't map to `sec:expiration`/`sec:nonce`, inspect the expansion (`python -c "import json,sys; from pyld import jsonld; print(json.dumps(jsonld.expand(json.load(open('spec/payments/test-vectors/14b-purchase-confirmation.json'))),indent=2))"`) and align the shape paths in `avp-shapes.ttl` to the actual expanded IRIs.

- [ ] **Step 5: Commit**

```bash
git add spec/validate.py
git commit -m "test(validate): register AP2 bridge vectors + negative schema cases"
```

---

## Task 13: Interop SHACL shapes for the projections (if shapes are targeted)

`validate.py`'s `shacl_check(INTEROP, INTEROP_VECTORS, "interop-shapes.ttl")` validates **every** interop vector against the interop shapes graph. The new projection types need either a NodeShape or no targeted shape (SHACL passes a node with no matching `sh:targetClass`). Confirm whether `interop-shapes.ttl` targets by class.

**Files:**
- Modify: `spec/interop-sd-jwt-vc/shapes/interop-shapes.ttl`

- [ ] **Step 1: Inspect the existing shapes**

Run: `python -c "print(open('spec/interop-sd-jwt-vc/shapes/interop-shapes.ttl').read())"`
Decide: if it defines `sh:targetClass iop:EmbeddedSdJwtVcMandate` shapes, add parallel minimal shapes; if it only defines generic shapes, the new vectors already pass (Task 12 was green) and **this task is a no-op — skip to Step 3**.

- [ ] **Step 2: Add minimal shapes (only if Task 12 SHACL flagged the new vectors)**

Append to `spec/interop-sd-jwt-vc/shapes/interop-shapes.ttl` (adjust prefixes to match the file header):

```turtle
iop:EmbeddedCartQuoteShape
  a sh:NodeShape ;
  sh:targetClass iop:EmbeddedCartQuote ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path iop:embeddedCartMandate ; sh:nodeKind sh:Literal ; sh:minCount 1 ] .

iop:EmbeddedCartUserConfirmationShape
  a sh:NodeShape ;
  sh:targetClass iop:EmbeddedCartUserConfirmation ;
  sh:property [ sh:path avp:confirmedBy ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path iop:embeddedCartUserAuth ; sh:nodeKind sh:Literal ; sh:minCount 1 ] .
```

- [ ] **Step 3: Run the full artifact harness**

Run: `python spec/validate.py`
Expected: `PASS: all artifact checks passed.`

- [ ] **Step 4: Commit (only if files changed)**

```bash
git add spec/interop-sd-jwt-vc/shapes/interop-shapes.ttl
git commit -m "test(validate): SHACL shapes for AP2 projection types"
```

---

## Task 14: Full harness green + README + final commit

**Files:**
- Modify: `spec/interop-sd-jwt-vc/README.md`

- [ ] **Step 1: Run the complete suite**

Run (PowerShell):
```powershell
python spec/generate.py
python spec/verify.py
python spec/validate.py
python -m pytest spec/test_interop_ap2.py spec/test_pricing.py -q
```
Expected: `generate.py` writes all vectors; `verify.py` → `PASS: all checks passed.`; `validate.py` → `PASS: all artifact checks passed.`; pytest → all passed.

If any are red, fix the root cause and re-run all four (they are cheap and deterministic).

- [ ] **Step 2: Document the new vectors/terms**

In `spec/interop-sd-jwt-vc/README.md`, in the test-vectors table, add rows for vectors `11`–`16` (and the native `14b`), and add a short "AP2 mandate-model bridge" subsection summarizing: IntentMandate⇄DSA (§5), CartMandate⇄PaymentQuote (§6), the optional `PurchaseConfirmation` (§7), and that M2 (item-level intent) and the autonomous case are surfaced via `importAdvisory`. Mirror the existing table style.

- [ ] **Step 3: Commit**

```bash
git add spec/interop-sd-jwt-vc/README.md
git commit -m "docs(interop): document the AP2 mandate-model bridge vectors and terms"
```

- [ ] **Step 4: Final verification (evidence before claiming done)**

Run all four commands from Step 1 once more and paste the final summary lines. Only claim completion when `verify.py` and `validate.py` both print `PASS` and pytest is green.

---

## Self-review notes (author)

- **Spec coverage:** §5 → Task 2; §6 + §6.1 → Tasks 1, 3; §7 `PurchaseConfirmation` → Tasks 4, 5, 6; §8 envelopes/modes → reuse + Tasks 3/5/8 (`bridgeMode`); §9 identity/status → reuse (did:web resolver extended in Task 10); §10 lossy cases → Tasks 2 (M2 advisory), 10/11 (autonomous); §11 MUSTs → §11.2 Task 9, §11.3 Tasks 5/11, no-downgrade Tasks 8/12, §11.7 optional Task 6; §12 packaging → Tasks 7/8/10/12/13/14; §13 phasing v1 → whole plan.
- **Open questions (§15 of the design):** plan adopts the draft defaults — Q1 `confirmedBy` = principal (Task 5 rule `confirmedBy != payer`, signer == confirmedBy); Q3 keeps `iop:requiresPurchaseConfirmation` as the authoritative flag (Task 2) without overloading `requiresApprovalAbove` (simpler; revisit if you want the DSA-narrowing courtesy). Confirm Q1/Q3 before/at Task 5.
- **Type consistency:** `EmbeddedCartQuote`, `EmbeddedCartUserConfirmation`, `PurchaseConfirmation`, `intersect_limits`, `canonical_cart`, `cart_service_request_hash`, `INTENT_VCT`, `CART_VCT` are used identically across tasks and match the naming contract.
- **Vector placement:** the native `PurchaseConfirmation` is a payments object, so it is generated to `payments/test-vectors/14b-purchase-confirmation.json` (Task 10) and registered in `PAY_VECTORS` (Task 12); only the unsigned *projections* (`EmbeddedCartQuote`, `EmbeddedCartUserConfirmation`) live in the interop bundle. Consistent across Tasks 10/11/12.
