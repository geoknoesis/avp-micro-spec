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


def test_payment_authorization_accepts_optional_purchase_confirmation():
    # load the existing authz vector, attach a confirmation, must still validate
    authz = _json.loads(_Path("spec/payments/test-vectors/02-payment-authorization.json").read_text(encoding="utf-8"))
    authz["purchaseConfirmation"] = _purchase_confirmation()
    errs = list(_pay_validator("PaymentAuthorization").iter_errors(authz))
    assert errs == []


def test_payment_authorization_still_valid_without_confirmation():
    authz = _json.loads(_Path("spec/payments/test-vectors/02-payment-authorization.json").read_text(encoding="utf-8"))
    assert list(_pay_validator("PaymentAuthorization").iter_errors(authz)) == []


# ---- interop context + ontology for the new iop: terms ----

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


# ---- interop schema: projection $defs + intent extras ----

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


# ---- §11.2: translation never widens authority ----

def test_intersect_limits_takes_most_restrictive():
    a = {"per_txn": "120.00", "per_day": "500.00"}
    b = {"per_txn": "100.00"}
    out = interop.intersect_limits(a, b)
    assert out["per_txn"] == "100.00"   # stricter wins
    assert out["per_day"] == "500.00"   # only side that has it


# ---- generated vectors exist ----

def test_new_vectors_exist():
    base = _Path("spec/interop-sd-jwt-vc/test-vectors")
    for name in ("11-foreign-intent-mandate.json", "12-imported-intent-mandate.json",
                 "13-foreign-cart-mandate.json", "14-imported-cart-quote.json",
                 "15-human-present-confirmation.json", "16-autonomous-no-confirmation.json"):
        assert (base / name).exists(), f"missing vector: {name}"
    pay = _Path("spec/payments/test-vectors")
    assert (pay / "14b-purchase-confirmation.json").exists()
    assert (pay / "18-payment-authorization-confirmed.json").exists()
