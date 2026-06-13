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
INTENT_VCT = "mandate.intent.ap2"
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


# ---- securing descriptor: the one securing/bridge axis ----
#
# Semantic ``type`` stays pure (authorization semantics only); HOW an object's
# authority is secured when it crosses the stack boundary lives in the single
# ``iop:securing`` descriptor. Absence of ``securing`` means native. The bridge
# pipeline is factored decode(carrier) -> map(claims) -> secure(object); secure()
# is the only stage that knows the mode.

CARRIER_SDJWT = "sd-jwt-vc"
CARRIER_SDJWT_KB = "sd-jwt-vc+kb-jwt"


def secure(obj: dict, *, mode: str, embedded: str | None = None, carrier: str | None = None,
           source_vct: str | None = None, attesting_bridge: str | None = None,
           advisories: list | None = None) -> dict:
    """Attach the iop:securing descriptor to a semantically-typed object."""
    d: dict = {"mode": mode}
    if carrier:
        d["carrier"] = carrier
    if embedded:
        d["embedded"] = embedded
    if source_vct:
        d["sourceVct"] = source_vct
    if attesting_bridge:
        d["attestingBridge"] = attesting_bridge
    if advisories:
        d["importAdvisory"] = list(advisories)
    d["profileVersion"] = PROFILE_VERSION
    out = dict(obj)
    out["securing"] = d
    return out


def add_advisories(obj: dict, advisories: list) -> dict:
    """Append import advisories to an already-secured object (bridge provenance)."""
    sec = obj.setdefault("securing", {})
    sec["importAdvisory"] = list(sec.get("importAdvisory", [])) + list(advisories)
    return obj


# ---- AP2 cart canonicalization (M4) ----

def canonical_cart(cart: dict) -> bytes:
    """Normalize an AP2 CartContents to stable JCS bytes so an AVP requestHash
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


def cart_request_hash(cart: dict) -> str:
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
    if "allowedCategories" in subj:
        claims["allowed_categories"] = list(subj["allowedCategories"])
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
    if "allowed_categories" in payload:
        subj["allowedCategories"] = list(payload["allowed_categories"])
    return subj


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
    """Import an AP2 IntentMandate (SD-JWT-VC) as a SpendingAuthorizationCredential
    projection plus the carried-but-unenforced intent extras. The extras are semantic
    claims and stay top-level; the advisories are bridge provenance."""
    vc = sdjwtvc_to_avp(compact, mode)
    payload, _ = _effective_claims(compact)
    extras, advisories = intent_extras(payload)
    vc.update(extras)
    if advisories:
        add_advisories(vc, advisories)
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


# ---- §6: AP2 CartMandate <-> payee-signed PaymentQuote ----

CART_VCT = "mandate.cart.ap2"


def cart_mandate_to_quote(compact: str, cart: dict, *, mode: str = "proof-preserving") -> dict:
    """Import an AP2 CartMandate (merchant-signed) as a PaymentQuote projection.
    Authority stays in the embedded merchant signature (proof-preserving); the outer
    object is an unsigned projection whose requestHash binds the canonical cart."""
    payload, _ = _effective_claims(compact)                      # decode
    total = cart.get("total", {})
    proj: dict = {                                               # map
        "@context": list(INTEROP_PAY_CTX),
        "id": "urn:avp:quote:imported:" + str(payload.get("jti", "")),
        "type": ["PaymentQuote"],
        "payer": payload.get("sub"),
        "payee": payload.get("iss"),
        "amount": total.get("amount"),
        "currency": total.get("currency") or cart.get("currency"),
        "requestHash": cart_request_hash(cart),
        "expires": numericdate_to_iso(payload["exp"]) if "exp" in payload else cart.get("cartExpiry"),
    }
    return secure(proj, mode=mode, carrier=CARRIER_SDJWT, embedded=compact,   # secure
                  source_vct=payload.get("vct"))


def quote_to_cart_claims(quote: dict) -> dict:
    """Export a payee-signed PaymentQuote to an AP2 cart claim set (merchant attestation)."""
    return {
        "vct": CART_VCT,
        "iss": quote["payee"],
        "sub": quote["payer"],
        "cart_hash": quote["requestHash"],
        "total": {"amount": quote["amount"], "currency": quote["currency"]},
        "exp": iso_to_numericdate(quote["expires"]),
    }


# ---- §7: PurchaseConfirmation (fresh human approval) ----

def verify_purchase_confirmation(conf: dict, did_web_resolver: dict | None = None) -> bool:
    """Verify a PurchaseConfirmation. The defining rule (§11.3): authority is a fresh
    HUMAN approval, so the proof MUST be controlled by confirmedBy (the principal), never
    by the agent (payer). proof-preserving projections (no native proof) instead carry the
    original approval in securing.embedded, verified against confirmedBy's key --
    resolved locally for a did:key principal, or via did:web. Any error => False."""
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
        compact = (conf.get("securing") or {}).get("embedded")
        if not compact:
            return False
        jwk = (did_web_resolver or {}).get(confirmed_by)
        if jwk is not None:
            pub = sdjwt.p256_public_from_jwk(jwk)
        elif confirmed_by.startswith("did:key:"):
            pub = ac.public_from_did_key(confirmed_by)  # principal DID resolves locally
        else:
            return False
        jws = sdjwt.sdjwt_jws(compact)
        if not sdjwt.es256_verify(jws, pub):
            return False
        # SECURITY: bind the approval to THIS confirmation -- the principal (iss=confirmedBy)
        # approved the exact cart (cart_hash==requestHash) on behalf of the exact agent
        # (sub==payer). Without this, a genuine approval for cart X authorizes any cart Y.
        emb = sdjwt.jws_payload(jws)
        return emb.get("iss") == confirmed_by \
            and emb.get("sub") == conf.get("payer") \
            and emb.get("cart_hash") == conf.get("requestHash")
    except Exception:
        return False


def import_cart_user_confirmation(user_auth_compact: str, *, quote_digest: str, agent_did: str,
                                  payee: str, amount: str, currency: str,
                                  request_hash: str, confirmed_by: str, quote: str,
                                  mode: str = "proof-preserving") -> dict:
    """Import an AP2 human-present cart approval as a PurchaseConfirmation projection
    (unsigned; authority is the embedded user JWT in securing.embedded)."""
    proj = {
        "@context": list(INTEROP_PAY_CTX),
        "id": "urn:avp:confirm:imported:" + quote_digest,
        "type": ["PurchaseConfirmation"],
        "quote": quote, "quoteDigest": quote_digest,
        "payer": agent_did, "payee": payee, "amount": amount, "currency": currency,
        "requestHash": request_hash, "confirmedBy": confirmed_by,
    }
    return secure(proj, mode=mode, carrier=CARRIER_SDJWT, embedded=user_auth_compact)


def export_purchase_confirmation(conf: dict) -> dict:
    """Export a PurchaseConfirmation (native or projection) to an AP2 human-present
    cart-approval claim set: the principal (confirmedBy) attests, over the exact cart
    (requestHash), that the agent (payer) may transact. The inverse of
    import_cart_user_confirmation -- together they make the §7 human-present case
    lossless in both directions. The claims are signed by the principal's own key
    (both stacks are P-256), so the exported approval roots in the principal DID, not
    the bridge (§11.6)."""
    claims = {
        "iss": conf["confirmedBy"],
        "sub": conf["payer"],
        "cart_hash": conf["requestHash"],
    }
    if "timestamp" in conf:
        claims["iat"] = iso_to_numericdate(conf["timestamp"])
    if "expires" in conf:
        claims["exp"] = iso_to_numericdate(conf["expires"])
    return claims


# ---- §11.2: no-widening limit intersection ----

from decimal import Decimal as _Decimal


def intersect_limits(a: dict, b: dict) -> dict:
    """§11.2 no-widening: when both stacks carry a limit, keep the most restrictive
    (minimum) value. A limit present on only one side is kept as-is."""
    out = dict(a)
    for k, v in b.items():
        if k in out:
            try:
                dv, da = _Decimal(v), _Decimal(out[k])
                if dv < 0:            # invalid (negative) limit: never widen toward it
                    continue
                if da < 0 or dv < da:  # take b-side if a-side invalid, or b is tighter
                    out[k] = v
            except (ValueError, ArithmeticError):
                pass  # non-decimal limit (e.g. tz): keep the a-side value
        else:
            out[k] = v
    return out


def _le(a, b) -> bool:
    """Decimal a <= b; non-decimal / unparseable values are incomparable (False)."""
    try:
        return _Decimal(a) <= _Decimal(b)
    except (ValueError, ArithmeticError, TypeError):
        return False


def _subject_within(outer: dict, inner: dict) -> bool:
    """No-widening (§11.2): True iff `outer` grants no more authority than `inner`.
    Ensures a bridged / projected credentialSubject can never broaden the embedded,
    authoritative mandate it claims to represent (numeric limits <=, payee/category
    sets subset, currency equal)."""
    for fld in ("maxPerTransaction", "dailyLimit", "requiresApprovalAbove"):
        if fld in outer and not (fld in inner and _le(outer[fld], inner[fld])):
            return False
    if "currency" in outer and outer.get("currency") != inner.get("currency"):
        return False
    for listfld in ("allowedPayees", "allowedCategories"):
        if listfld in outer and not set(outer[listfld]).issubset(set(inner.get(listfld, []))):
            return False
    return True


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
    sd_digests = set(payload.get("_sd", []))
    effective = {k: v for k, v in payload.items() if k not in ("_sd", "_sd_alg")}
    presented = set()
    for d in disclosures:
        digest = sdjwt.disclosure_digest(d)
        # SECURITY: only honor disclosures the issuer committed to in `_sd`. A disclosure
        # whose digest is absent is attacker-injected (not issuer-signed) and could
        # override inline claims to widen authority -- it MUST NOT be merged.
        if digest not in sd_digests:
            continue
        arr = json.loads(sdjwt.b64u_decode(d))
        if isinstance(arr, list) and len(arr) == 3:
            effective[arr[1]] = arr[2]
            presented.add(digest)
    withheld = [h for h in payload.get("_sd", []) if h not in presented]
    return effective, len(withheld)


def sdjwtvc_to_avp(compact: str, mode: str = "proof-preserving") -> dict:
    """V->A import, factored decode -> map -> secure. The result is typed purely by
    its authorization semantics; all bridge metadata lives in ``securing``."""
    payload, n_withheld = _effective_claims(compact)            # decode (carrier axis)
    vc: dict = {                                                 # map (semantic axis)
        "@context": list(INTEROP_CTX),
        "type": ["VerifiableCredential", "SpendingAuthorizationCredential"],
        "issuer": payload["iss"],
        "credentialSubject": claims_to_avp_subject(payload),
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
    # proof-preserving: outer object is an unsigned projection (no proof added)
    return secure(vc, mode=mode, carrier=CARRIER_SDJWT, embedded=compact,   # secure
                  source_vct=payload.get("vct"), advisories=advisories)


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
    """Verify an imported (bridged) credential per its securing-descriptor mode. Any
    parse/verify error is a verification failure, never an exception."""
    try:
        return _verify_imported(vc, did_web_resolver)
    except Exception:
        return False


def _verify_imported(vc: dict, did_web_resolver: dict) -> bool:
    sec = vc.get("securing") or {}
    mode = sec.get("mode")
    compact = sec.get("embedded", "")
    jws = sdjwt.sdjwt_jws(compact)
    payload = sdjwt.jws_payload(jws)
    eff, _ = _effective_claims(compact)  # issuer-committed claims (forged disclosures dropped)
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
            if secured["credentialSubject"]["id"] != vc["credentialSubject"]["id"] \
                    or _issuer_id(secured) != vc["issuer"]:
                return False
            # no-widening: the projection MUST NOT grant more than the embedded credential
            return _subject_within(vc["credentialSubject"], secured["credentialSubject"])
        # foreign origin: authority is the embedded ES256, resolved via did:web
        jwk = did_web_resolver.get(vc["issuer"])  # did:web binding convention
        if jwk is None:
            return False
        if not sdjwt.es256_verify(jws, sdjwt.p256_public_from_jwk(jwk)):
            return False
        # no-widening: the projection MUST NOT broaden the embedded mandate's claims
        return _subject_within(vc["credentialSubject"], claims_to_avp_subject(eff))
    if mode == "attested":
        if "attestingBridge" not in sec or "proof" not in vc:
            return False
        if not ac.verify_ecdsa_jcs_2022(vc):
            return False
        # no-widening: a trusted bridge re-attests but MUST NOT broaden the embedded mandate
        return _subject_within(vc["credentialSubject"], claims_to_avp_subject(eff))
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
            "request_hash": authz.get("requestHash"),
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
        "type": ["PaymentAuthorization"],
        "payer": mp["sub"],
        "payee": txn["payee"],
        "amount": txn["amount"],
        "currency": txn["currency"],
        "settlementMethod": txn.get("settlement_method"),
        "settlementTarget": txn.get("settlement_target"),
        "requestHash": txn.get("request_hash"),
        "timestamp": numericdate_to_iso(kb["iat"]),
        "expires": numericdate_to_iso(txn["exp"]),
        "nonce": kb["nonce"],
        "wallet": kb.get("aud"),
    }
    if txn.get("quote") is not None:
        authz["quote"] = txn["quote"]
    if txn.get("quote_digest") is not None:
        authz["quoteDigest"] = txn["quote_digest"]
    return secure(authz, mode=mode, carrier=CARRIER_SDJWT_KB, embedded=presentation,
                  source_vct=mp.get("vct"))


def verify_presentation(presentation: str, did_web_resolver: dict | None = None,
                        *, expected_nonce: str | None = None,
                        expected_aud: str | None = None) -> bool:
    """Verify an L3 presentation: mandate authority + holder key-binding JWT + sd_hash.
    A production verifier MUST pass `expected_nonce` (a fresh per-request challenge) and
    `expected_aud` (its own identifier); when supplied they are enforced to defeat replay
    and audience-misdirection of the key-binding JWT. Any parse/verify error is a
    verification failure, never an exception."""
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
        kb = sdjwt.jws_payload(kbjwt)
        # 3. sd_hash binds the KB-JWT to exactly this mandate
        if kb.get("sd_hash") != sdjwt.sd_hash(issuer_jws + "~"):
            return False
        # 4. freshness / audience: reject replayed or misdirected key-binding JWTs
        if expected_nonce is not None and kb.get("nonce") != expected_nonce:
            return False
        if expected_aud is not None and kb.get("aud") != expected_aud:
            return False
        return True
    except Exception:
        return False
