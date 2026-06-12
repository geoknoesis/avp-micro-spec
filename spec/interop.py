"""Reference translator for the AVP-Micro <-> SD-JWT-VC interop profile.

Implements the normative mapping of
``spec/interop-sd-jwt-vc/index.html``: the claim mapping (section "Claim mapping"),
the two embedding envelopes (export / import), and the cross-stack verification
rules. Default bridge mode is ``proof-preserving`` -- the bridge is a pure
transcoder that adds no trust; authority always roots in the original signer.

Scope of this reference: the *mandate* bridge (DSA SpendingAuthorizationCredential
<-> SD-JWT-VC mandate / L1). The per-purchase action layer (PaymentAuthorization /
L3) reuses the same identity binding and is out of scope for these v1 vectors.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import avp_crypto as ac
import sdjwt

VC2 = "https://www.w3.org/ns/credentials/v2"
DI = "https://w3id.org/security/data-integrity/v2"
DSA = "https://w3id.org/spending-authority/v1"
AVP = "https://w3id.org/avp-micro/v1"
IOP = "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1"
INTEROP_CTX = [VC2, DI, DSA, IOP]            # mandate (L1) bridge
INTEROP_PAY_CTX = [VC2, DI, DSA, AVP, IOP]   # PaymentAuthorization (L3) bridge

VCT_PLAIN = "mandate.spending-authority.avp"
VCT_EMBEDDED = "mandate.spending-authority.avp+embedded"
PROFILE_VERSION = "0.1.0"

_ISO = "%Y-%m-%dT%H:%M:%SZ"


def iso_to_numericdate(s: str) -> int:
    return int(datetime.strptime(s, _ISO).replace(tzinfo=timezone.utc).timestamp())


def numericdate_to_iso(n: int) -> str:
    return datetime.fromtimestamp(int(n), tz=timezone.utc).strftime(_ISO)


def _issuer_id(vc: dict) -> str:
    iss = vc["issuer"]
    return iss["id"] if isinstance(iss, dict) else iss


# ---- status mapping (BitstringStatusListEntry <-> Token Status List) ----

def status_to_token_list(entry: dict) -> dict:
    return {"status_list": {"idx": int(entry["statusListIndex"]),
                            "uri": entry["statusListCredential"]}}


def token_list_to_status(status: dict) -> dict:
    sl = status["status_list"]
    return {
        "id": f'{sl["uri"]}#{sl["idx"]}',
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": str(sl["idx"]),
        "statusListCredential": sl["uri"],
    }


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


# ---- claim mapping (section "Claim mapping") ----

def avp_to_claims(vc: dict) -> dict:
    """DSA SpendingAuthorizationCredential -> SD-JWT-VC mandate claim set."""
    subj = vc["credentialSubject"]
    claims: dict = {"iss": _issuer_id(vc), "sub": subj["id"]}
    if "currency" in subj:
        claims["currency"] = subj["currency"]
    limits = {}
    for avp_field, jose_field in (("maxPerTransaction", "per_txn"),
                                  ("dailyLimit", "per_day"),
                                  ("limitTimezone", "tz"),
                                  ("requiresApprovalAbove", "approval_above")):
        if avp_field in subj:
            limits[jose_field] = subj[avp_field]
    if limits:
        claims["limits"] = limits
    if "allowedPayees" in subj:
        claims["allowed_payees"] = list(subj["allowedPayees"])
    if "allowedServiceTypes" in subj:
        claims["allowed_service_types"] = list(subj["allowedServiceTypes"])
    if "validFrom" in vc:
        claims["nbf"] = iso_to_numericdate(vc["validFrom"])
    if "validUntil" in vc:
        claims["exp"] = iso_to_numericdate(vc["validUntil"])
    if "id" in vc:
        claims["jti"] = vc["id"]
    if "credentialStatus" in vc:
        claims["status"] = status_to_token_list(vc["credentialStatus"])
    # holder key binding: cnf = agent did:key public key as an EC P-256 JWK
    claims["cnf"] = {"jwk": sdjwt.p256_public_jwk(ac.public_from_did_key(subj["id"]))}
    return claims


def claims_to_avp_subject(payload: dict) -> dict:
    subj: dict = {"id": payload["sub"]}
    if "currency" in payload:
        subj["currency"] = payload["currency"]
    limits = payload.get("limits", {})
    for jose_field, avp_field in (("per_txn", "maxPerTransaction"),
                                  ("per_day", "dailyLimit"),
                                  ("tz", "limitTimezone"),
                                  ("approval_above", "requiresApprovalAbove")):
        if jose_field in limits:
            subj[avp_field] = limits[jose_field]
    if "allowed_payees" in payload:
        subj["allowedPayees"] = list(payload["allowed_payees"])
    if "allowed_service_types" in payload:
        subj["allowedServiceTypes"] = list(payload["allowed_service_types"])
    return subj


# ---- export: AVP-Micro -> SD-JWT-VC (section "Export") ----

def avp_to_sdjwtvc(vc: dict, sign_priv, kid: str, *, embedded: bool = True) -> str:
    """Produce an SD-JWT-VC compact serialization carrying the AVP-Micro mandate.

    ``embedded=True`` (proof-preserving default): authority is carried in the
    non-disclosable ``avp_vc`` claim (the original ecdsa-jcs-2022 (P-256)-secured
    credential); ``sign_priv`` signs only the envelope. ``embedded=False`` is the
    attested profile where ``sign_priv`` is the bridge issuer of record.
    """
    claims = avp_to_claims(vc)
    claims["vct"] = VCT_EMBEDDED if embedded else VCT_PLAIN
    if embedded:
        # byte-faithful carrier of the original secured credential
        claims["avp_vc"] = ac.b64url_nopad(ac.jcs(vc))
    header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": kid}
    return sdjwt.sdjwt_compact(sdjwt.es256_sign(header, claims, sign_priv))


# ---- import: SD-JWT-VC -> AVP-Micro (section "Import") ----

def _effective_claims(compact: str):
    """Merge presented disclosures into the issuer payload; report withheld SD claims.

    Returns (effective_claims, n_withheld). A selectively-disclosable claim whose
    disclosure is not presented stays a digest in ``_sd`` and never appears in the
    effective claim set -- i.e. the import is a subset view.
    """
    issuer_jws, disclosures, _kb = sdjwt.split_presentation(compact)
    payload = sdjwt.jws_payload(issuer_jws)
    effective = {k: v for k, v in payload.items() if k not in ("_sd", "_sd_alg")}
    presented = set()
    for d in disclosures:
        arr = json.loads(sdjwt.b64u_decode(d))
        if isinstance(arr, list) and len(arr) == 3:
            effective[arr[1]] = arr[2]
            presented.add(sdjwt.disclosure_digest(d))
    withheld = [h for h in payload.get("_sd", []) if h not in presented]
    return effective, len(withheld)


def sdjwtvc_to_avp(compact: str, mode: str = "proof-preserving") -> dict:
    payload, n_withheld = _effective_claims(compact)
    vc: dict = {
        "@context": list(INTEROP_CTX),
        "type": ["VerifiableCredential", "SpendingAuthorizationCredential",
                 "EmbeddedSdJwtVcMandate"],
        "issuer": payload["iss"],
        "credentialSubject": claims_to_avp_subject(payload),
        "bridgeMode": mode,
        "sourceVct": payload.get("vct"),
        "embeddedSdJwtVc": compact,
        "profileVersion": PROFILE_VERSION,
    }
    if "jti" in payload:
        vc["id"] = payload["jti"]
    if "nbf" in payload:
        vc["validFrom"] = numericdate_to_iso(payload["nbf"])
    if "exp" in payload:
        vc["validUntil"] = numericdate_to_iso(payload["exp"])
    if "status" in payload:
        vc["credentialStatus"] = token_list_to_status(payload["status"])
    # Surface, never silently drop, the inherently non-round-trippable conditions.
    advisories = []
    if n_withheld:
        advisories.append(
            f"partial-selective-disclosure: {n_withheld} claim(s) withheld; subset view, "
            "not a complete mandate")
    if payload.get("intent_mode") == "interactive":
        advisories.append(
            "interactive-l2: fresh per-purchase human intent has no standing-delegation "
            "analogue and is not preserved by this import")
    if advisories:
        vc["importAdvisory"] = advisories
    # proof-preserving: outer object is an unsigned projection (no proof added)
    return vc


# ---- cross-stack verification (section "Cross-stack verification") ----

def verify_exported(compact: str, envelope_pub) -> bool:
    """Verify an exported SD-JWT-VC: envelope ES256 AND (no-downgrade) the embedded
    original ecdsa-jcs-2022 (P-256) authority, with holder binding. Any parse/verify
    error is a verification failure, never an exception."""
    try:
        jws = sdjwt.sdjwt_jws(compact)
        if not sdjwt.es256_verify(jws, envelope_pub):
            return False
        payload = sdjwt.jws_payload(jws)
        if "avp_vc" in payload:  # embedded profile: authority is the embedded proof
            secured = json.loads(sdjwt.b64u_decode(payload["avp_vc"]))
            if not ac.verify_ecdsa_jcs_2022(secured):
                return False
            if secured["credentialSubject"]["id"] != payload["sub"]:  # holder binding
                return False
        return True
    except Exception:
        return False


def verify_imported(vc: dict, did_web_resolver: dict) -> bool:
    """Verify an EmbeddedSdJwtVcMandate per the bridge-mode rules. Any parse/verify
    error is a verification failure, never an exception."""
    try:
        return _verify_imported(vc, did_web_resolver)
    except Exception:
        return False


def _verify_imported(vc: dict, did_web_resolver: dict) -> bool:
    mode = vc.get("bridgeMode")
    compact = vc.get("embeddedSdJwtVc", "")
    jws = sdjwt.sdjwt_jws(compact)
    payload = sdjwt.jws_payload(jws)
    if mode == "proof-preserving":
        if "proof" in vc:  # no-downgrade: must be an unsigned projection
            return False
        # outer projection must agree with the embedded chain
        if payload["sub"] != vc["credentialSubject"]["id"] or payload["iss"] != vc["issuer"]:
            return False
        if "avp_vc" in payload:
            # AVP-origin: authority is the embedded ecdsa-jcs-2022 (P-256)-secured credential
            secured = json.loads(sdjwt.b64u_decode(payload["avp_vc"]))
            if not ac.verify_ecdsa_jcs_2022(secured):
                return False
            return secured["credentialSubject"]["id"] == vc["credentialSubject"]["id"] \
                and _issuer_id(secured) == vc["issuer"]
        # foreign origin: authority is the embedded ES256, resolved via did:web
        jwk = did_web_resolver.get(vc["issuer"])  # did:web binding convention
        if jwk is None:
            return False
        return sdjwt.es256_verify(jws, sdjwt.p256_public_from_jwk(jwk))
    if mode == "attested":
        if "attestingBridge" not in vc or "proof" not in vc:
            return False
        return ac.verify_ecdsa_jcs_2022(vc)
    if mode == "co-issued":
        # authority is the native outer Data Integrity proof; the embedded SD-JWT-VC
        # is a parallel representation the same issuer signed with the same P-256 key
        # it uses for the ecdsa-jcs-2022 Data Integrity proof.
        if "proof" not in vc or not ac.verify_ecdsa_jcs_2022(vc):
            return False
        jwk = did_web_resolver.get(payload.get("iss"))
        if jwk is not None and not sdjwt.es256_verify(jws, sdjwt.p256_public_from_jwk(jwk)):
            return False
        return True
    return False


# ---- per-purchase action layer (L3 / PaymentAuthorization) ----

def payment_authorization_to_presentation(authz: dict, mandate_compact: str, agent_priv) -> str:
    """A->V of a PaymentAuthorization: present the mandate SD-JWT plus an agent-signed
    key-binding JWT (L3) carrying the per-purchase economic terms."""
    issuer_jws = sdjwt.sdjwt_jws(mandate_compact)
    sd_input = issuer_jws + "~"  # zero disclosures
    kb_payload = {
        "iat": iso_to_numericdate(authz["timestamp"]),
        "aud": authz.get("wallet"),
        "nonce": authz["nonce"],
        "sd_hash": sdjwt.sd_hash(sd_input),
        "txn": {
            "quote": authz.get("quote"),
            "quote_digest": authz.get("quoteDigest"),
            "payee": authz["payee"],
            "amount": authz["amount"],
            "currency": authz["currency"],
            "service_request_hash": authz.get("serviceRequestHash"),
            "settlement_method": authz.get("settlementMethod"),
            "settlement_target": authz.get("settlementTarget"),
            "exp": iso_to_numericdate(authz["expires"]),
        },
    }
    kbjwt = sdjwt.es256_sign({"alg": "ES256", "typ": "kb+jwt"}, kb_payload, agent_priv)
    return sd_input + kbjwt


def presentation_to_payment_authorization(presentation: str, mode: str = "proof-preserving") -> dict:
    """V->A: reconstruct a PaymentAuthorization from a {mandate + KB-JWT} presentation."""
    parts = presentation.split("~")
    mp = sdjwt.jws_payload(parts[0])
    kb = sdjwt.jws_payload(parts[-1])
    txn = kb["txn"]
    authz: dict = {
        "@context": list(INTEROP_PAY_CTX),
        "id": "urn:avp:authz:imported:" + str(kb["nonce"]),
        "type": ["PaymentAuthorization", "EmbeddedKbJwtAuthorization"],
        "payer": mp["sub"],
        "payee": txn["payee"],
        "amount": txn["amount"],
        "currency": txn["currency"],
        "settlementMethod": txn.get("settlement_method"),
        "settlementTarget": txn.get("settlement_target"),
        "serviceRequestHash": txn.get("service_request_hash"),
        "timestamp": numericdate_to_iso(kb["iat"]),
        "expires": numericdate_to_iso(txn["exp"]),
        "nonce": kb["nonce"],
        "wallet": kb.get("aud"),
        "bridgeMode": mode,
        "embeddedKbJwtPresentation": presentation,
        "profileVersion": PROFILE_VERSION,
    }
    if txn.get("quote") is not None:
        authz["quote"] = txn["quote"]
    if txn.get("quote_digest") is not None:
        authz["quoteDigest"] = txn["quote_digest"]
    return authz


def verify_presentation(presentation: str, did_web_resolver: dict | None = None) -> bool:
    """Verify an L3 presentation: mandate authority + holder key-binding JWT + sd_hash.
    Any parse/verify error is a verification failure, never an exception."""
    try:
        parts = presentation.split("~")
        issuer_jws, kbjwt = parts[0], parts[-1]
        mp = sdjwt.jws_payload(issuer_jws)
        # 1. mandate (L1) authority
        if "avp_vc" in mp:
            secured = json.loads(sdjwt.b64u_decode(mp["avp_vc"]))
            if not ac.verify_ecdsa_jcs_2022(secured):
                return False
        else:
            jwk = (did_web_resolver or {}).get(mp.get("iss"))
            if jwk is None or not sdjwt.es256_verify(issuer_jws, sdjwt.p256_public_from_jwk(jwk)):
                return False
        # 2. holder key-binding JWT (L3) signed by the cnf holder key (the agent)
        holder = sdjwt.p256_public_from_jwk(mp["cnf"]["jwk"])
        if not sdjwt.es256_verify(kbjwt, holder):
            return False
        # 3. sd_hash binds the KB-JWT to exactly this mandate
        kb = sdjwt.jws_payload(kbjwt)
        return kb.get("sd_hash") == sdjwt.sd_hash(issuer_jws + "~")
    except Exception:
        return False
