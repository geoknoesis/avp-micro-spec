"""Unit tests for the AP2 mandate-model bridge translators (spec/interop.py)."""
import json

import avp_crypto as ac
import interop
import sdjwt

# A real P-256 did:key for the agent subject: avp_to_claims derives cnf.jwk from it,
# so the export round-trip needs a resolvable key (not a placeholder).
_AGENT = ac.seed_key("agent")
_AGENT_DID = ac.did_key(_AGENT.public_key())


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


# ---- §5: IntentMandate <-> DSA ----

def _intent_claims():
    return {
        "vct": interop.INTENT_VCT,
        "iss": "did:web:user.example",
        "sub": _AGENT_DID,
        "cnf": {"jwk": sdjwt.p256_public_jwk(_AGENT.public_key())},
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
