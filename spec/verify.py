"""Reference verifier for the AVP-Micro split test vectors (both bundles)."""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path
import json

import avp_crypto as ac
import pricing
import interop
import sdjwt
import settlement as st
import status as stx

SPEC = Path(__file__).parent
AUTH = SPEC / "authority" / "test-vectors"
PAY = SPEC / "payments" / "test-vectors"
INTEROP = SPEC / "interop-sd-jwt-vc" / "test-vectors"
DISP = SPEC / "disputes" / "test-vectors"
SETTLE = SPEC / "settlement" / "test-vectors"
TXP = SPEC / "transport" / "test-vectors"
_failed = []


def load(base: Path, name: str) -> dict:
    return json.loads((base / name).read_text(encoding="utf-8"))


def check(label: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        _failed.append(label)


def controller(obj):
    return obj["proof"]["verificationMethod"].split("#", 1)[0]


def main() -> int:
    dids = load(AUTH, "dids.json")
    agent, payee = dids["payerAgent"], dids["payeeService"]
    issuer, wallet = dids["principalIssuer"], dids["walletService"]

    spendauth = load(AUTH, "spending-authorization-credential.json")
    merchant = load(AUTH, "merchant-credential.json")
    capability = load(AUTH, "payment-capability-credential.json")
    offer = load(PAY, "00-payment-offer.json")
    quote = load(PAY, "01-payment-quote.json")
    authz = load(PAY, "02-payment-authorization.json")
    execution = load(PAY, "03-payment-execution.json")
    receipt = load(PAY, "04-payment-receipt.json")

    print("Proof verification (ecdsa-jcs-2022):")
    for label, obj in [("spending-authorization credential", spendauth),
                       ("merchant credential", merchant),
                       ("payment-capability credential", capability),
                       ("offer", offer),
                       ("quote", quote), ("authorization", authz),
                       ("execution", execution), ("receipt", receipt)]:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))

    print("Discovery & revocation coverage:")
    check("offer signed by payee", controller(offer) == payee)
    check("offer quoteEndpoint present", bool(offer.get("quoteEndpoint")))
    check("credential carries credentialStatus (revocation)",
          spendauth.get("credentialStatus", {}).get("type") == "BitstringStatusListEntry")

    print("Verification-method binding:")
    check("spending-authorization credential signed by issuer", controller(spendauth) == issuer)
    check("merchant credential signed by issuer", controller(merchant) == issuer)
    check("payment-capability credential signed by wallet", controller(capability) == wallet)
    check("quote signed by payee", controller(quote) == payee)
    check("authorization signed by payer", controller(authz) == agent)
    check("execution signed by wallet", controller(execution) == wallet)
    check("receipt signed by payee", controller(receipt) == payee)

    print("Quote binding & economic-term equality:")
    check("authz.payer == quote.payer", authz["payer"] == quote["payer"])
    check("authz.payee == quote.payee", authz["payee"] == quote["payee"])
    check("quoteDigest matches resolved quote", authz["quoteDigest"] == ac.jcs_digest(quote))
    for term in ("amount", "currency", "settlementMethod", "settlementTarget"):
        check(f"authz.{term} == quote.{term}", authz[term] == quote[term])
    check("requestHash byte-equal", authz["requestHash"] == quote["requestHash"])
    check("authz.timestamp before quote.expires (quote not expired at authorization)",
          authz["timestamp"] < quote["expires"])

    print("Credential / policy:")
    subj = spendauth["credentialSubject"]
    check("credentialSubject.id == payer", subj["id"] == authz["payer"])
    check("authz.payer controls the auth proof", controller(authz) == subj["id"])
    check("amount <= maxPerTransaction", Decimal(authz["amount"]) <= Decimal(subj["maxPerTransaction"]))
    check("payee in allowedPayees", authz["payee"] in subj.get("allowedPayees", []))
    check("currency matches credential", authz["currency"] == subj.get("currency"))
    check("maxPerTransaction <= dailyLimit (well-formed limits)",
          Decimal(subj["maxPerTransaction"]) <= Decimal(subj["dailyLimit"]))
    check("credential validity window well-formed (validFrom < validUntil)",
          spendauth["validFrom"] < spendauth["validUntil"])
    check("credential active at authorization (validFrom <= timestamp <= validUntil)",
          spendauth["validFrom"] <= authz["timestamp"] <= spendauth["validUntil"])

    print("Credential status & freshness (Bitstring Status List):")
    sl_active = load(AUTH, "status-list-active.json")
    sl_revoked = load(AUTH, "status-list-revoked.json")
    _sidx = int(spendauth["credentialStatus"]["statusListIndex"])
    check("status list (active) proof verifies", ac.verify_ecdsa_jcs_2022(sl_active))
    check("status list (revoked) proof verifies", ac.verify_ecdsa_jcs_2022(sl_revoked))
    check("status lists signed by the credential issuer",
          controller(sl_active) == issuer and controller(sl_revoked) == issuer)
    check("active status list is the one the credentialStatus points to",
          sl_active["id"] == spendauth["credentialStatus"]["statusListCredential"])
    check("active list: credential bit is 0 (not revoked)",
          not stx.is_revoked(sl_active["credentialSubject"]["encodedList"], _sidx))
    check("revoked list: credential bit is 1 (revoked)",
          stx.is_revoked(sl_revoked["credentialSubject"]["encodedList"], _sidx))
    check("status list freshness window well-formed (validFrom < validUntil)",
          sl_active["validFrom"] < sl_active["validUntil"])
    check("active status list valid at authorization time",
          sl_active["validFrom"] <= authz["timestamp"] <= sl_active["validUntil"])
    check("revocation published after the authorization (revoked mid-flight)",
          sl_revoked["validFrom"] > authz["timestamp"])

    print("Execution & receipt linkage:")
    check("execution.authorization == authz.id", execution.get("authorization") == authz["id"])
    check("execution.amount == authz.amount", execution["amount"] == authz["amount"])
    check("execution.currency == authz.currency", execution["currency"] == authz["currency"])
    check("execution.status completed", execution["status"] == "completed")
    check("execution signer == authz.wallet (execution binding)", controller(execution) == authz.get("wallet"))
    check("receipt.quote == quote.id", receipt.get("quote") == quote["id"])
    check("receipt.execution == execution.id", receipt.get("execution") == execution["id"])
    check("receipt.amount == authz.amount", receipt["amount"] == authz["amount"])
    check("receipt.amount == execution.amount (delivery matches settlement)",
          receipt["amount"] == execution["amount"])
    check("receipt.status fulfilled", receipt["status"] == "fulfilled")

    print("Streaming / session metering:")
    session = load(PAY, "05-usage-session.json")
    session_budget = load(PAY, "06-session-budget-authorization.json")
    accrual = load(PAY, "07-usage-accrual.json")
    session_exec = load(PAY, "08-payment-execution-session.json")
    session_receipt = load(PAY, "09-payment-receipt-session.json")
    for label, obj in [("session", session), ("session-budget", session_budget),
                       ("accrual", accrual), ("session execution", session_exec),
                       ("session receipt", session_receipt)]:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))
    check("session signed by payee", controller(session) == payee)
    check("session-budget signed by payer", controller(session_budget) == agent)
    check("accrual signed by payee", controller(accrual) == payee)
    check("session execution signed by wallet", controller(session_exec) == wallet)
    check("session receipt signed by payee", controller(session_receipt) == payee)
    check("sessionDigest matches resolved session", session_budget["sessionDigest"] == ac.jcs_digest(session))
    check("budget.usageSession == session.id", session_budget["usageSession"] == session["id"])
    check("budget payer/payee match session",
          session_budget["payer"] == session["payer"] and session_budget["payee"] == session["payee"])
    check("committedAmount <= session.maxAmount",
          Decimal(session_budget["committedAmount"]) <= Decimal(session["maxAmount"]))
    check("accrual.session == session.id", accrual["session"] == session["id"])
    check("accrual currency matches session", accrual["currency"] == session["currency"])
    check("accrual <= maxAmount", Decimal(accrual["amountAccrued"]) <= Decimal(session["maxAmount"]))
    pm = session["pricingModel"]
    if "meterReading" in accrual:
        dim = pm.get("dimension") or session.get("meterType")
        expected = pricing.evaluate(pm, {dim: accrual["meterReading"]})
        check("accrual consistent with evaluator pricing",
              Decimal(accrual["amountAccrued"]) == expected)
    check("session exec references budget auth",
          session_exec.get("sessionBudgetAuthorization") == session_budget["id"])
    check("session exec signer == budget.wallet (execution binding)",
          controller(session_exec) == session_budget.get("wallet"))
    check("session exec amount <= committedAmount",
          Decimal(session_exec["amount"]) <= Decimal(session_budget["committedAmount"]))
    check("session exec currency == budget.currency",
          session_exec["currency"] == session_budget["currency"])
    check("session receipt references session", session_receipt.get("usageSession") == session["id"])
    check("session receipt amount == execution amount", session_receipt["amount"] == session_exec["amount"])
    check("session receipt.status fulfilled", session_receipt["status"] == "fulfilled")

    print("Session extension & re-authorization:")
    extension = load(PAY, "10-usage-session-extension.json")
    session_budget2 = load(PAY, "11-session-budget-authorization-2.json")
    check("extension proof", ac.verify_ecdsa_jcs_2022(extension))
    check("re-auth budget proof", ac.verify_ecdsa_jcs_2022(session_budget2))
    check("extension signed by payee", controller(extension) == payee)
    check("re-auth budget signed by payer", controller(session_budget2) == agent)
    check("extension references session", extension["usageSession"] == session["id"])
    check("extension sessionDigest matches session", extension["sessionDigest"] == ac.jcs_digest(session))
    check("newMaxAmount > original maxAmount", Decimal(extension["newMaxAmount"]) > Decimal(session["maxAmount"]))
    check("newExpires later than original expires", extension["newExpires"] > session["expires"])
    check("re-auth committedAmount <= newMaxAmount",
          Decimal(session_budget2["committedAmount"]) <= Decimal(extension["newMaxAmount"]))
    check("re-auth references same session", session_budget2["usageSession"] == session["id"])
    # replay prevention: payer-signed authorization nonces MUST be unique
    _authz_nonces = [authz["nonce"], session_budget["nonce"], session_budget2["nonce"]]
    check("authorization nonces are unique (no replay)",
          len(_authz_nonces) == len(set(_authz_nonces)))

    print("Pricing-model evaluation conformance:")
    conformance = load(PAY, "pricing-conformance.json")
    for case in conformance["cases"]:
        consistent = True
        try:
            pricing.assert_single_currency(case["pricingModel"])
        except pricing.PricingError:
            consistent = False
        check(f"pricing case '{case['name']}' single-currency", consistent)
        got = pricing.evaluate(case["pricingModel"], case["usage"])
        check(f"pricing case '{case['name']}' == {case['expected']}",
              str(got) == case["expected"])

    # adversarial: the evaluator MUST reject silent under-charging and invalid usage
    def _pricing_raises(model, usage):
        try:
            pricing.evaluate(model, usage)
            return False
        except pricing.PricingError:
            return True
    check("graduated TieredRate without an open-ended tier is rejected (no silent undercharge)",
          _pricing_raises(
              {"type": "TieredRate", "dimension": "dim:Requests", "unit": "qudtu:NUM",
               "tierMode": "graduated", "currency": "USD",
               "tiers": [{"upTo": "100", "amount": "1.0"}, {"upTo": "200", "amount": "0.5"}]},
              {"dim:Requests": "300"}))
    check("negative usage quantity is rejected (no negative charge)",
          _pricing_raises(
              {"type": "PerUnit", "dimension": "dim:Requests", "unit": "qudtu:NUM",
               "amount": "0.10", "currency": "USD"},
              {"dim:Requests": "-100"}))

    print("Interop (SD-JWT-VC bridge):")
    keys = load(INTEROP, "keys.json")
    resolver = keys["didWebResolver"]
    export = load(INTEROP, "01-export-sdjwtvc.json")
    imported = load(INTEROP, "02-imported-mandate.json")
    foreign = load(INTEROP, "03-foreign-sdjwtvc.json")
    imported_foreign = load(INTEROP, "04-imported-from-foreign.json")
    bridge_pub = sdjwt.p256_public_from_jwk(keys["bridgeExporter"]["jwk"])
    vi_pub = sdjwt.p256_public_from_jwk(keys["viIssuer"]["jwk"])

    # A->V export: envelope ES256 + embedded ecdsa-jcs-2022 (P-256) authority + holder binding
    check("export verifies (envelope + embedded authority)",
          interop.verify_exported(export["compact"], bridge_pub))
    mapped = interop.avp_to_claims(spendauth)
    payload = sdjwt.jws_payload(sdjwt.sdjwt_jws(export["compact"]))
    check("A->V claim mapping lossless", all(payload.get(k) == v for k, v in mapped.items()))
    check("export carries non-disclosable avp_vc authority", "avp_vc" in payload)

    # A->V->A round-trip preserves the credential subject exactly
    check("A->V->A credentialSubject preserved",
          imported["credentialSubject"] == spendauth["credentialSubject"])
    check("imported(02) is proof-preserving projection (no proof)",
          imported["securing"]["mode"] == "proof-preserving" and "proof" not in imported)
    check("imported(02) semantic type stays pure (no carrier markers)",
          all("Embedded" not in t for t in imported["type"]))
    check("imported(02) verifies via embedded authority",
          interop.verify_imported(imported, resolver))

    # V-origin foreign mandate (ES256) and its proof-preserving import
    check("foreign mandate ES256 verifies (did:web issuer)",
          sdjwt.es256_verify(sdjwt.sdjwt_jws(foreign["compact"]), vi_pub))
    check("imported-from-foreign(04) verifies via did:web binding",
          interop.verify_imported(imported_foreign, resolver))
    check("imported(04) is proof-preserving projection (no proof)",
          imported_foreign["securing"]["mode"] == "proof-preserving" and "proof" not in imported_foreign)

    # V->A->V round-trip preserves the mandate claims
    reexport = interop.avp_to_claims(imported_foreign)
    fp = foreign["payload"]
    check("V->A->V claims preserved",
          all(reexport.get(k) == fp.get(k)
              for k in ("iss", "sub", "currency", "limits", "allowed_payees", "nbf", "exp")))

    # Negatives: tamper the embedded chain, and downgrade attempts
    t = json.loads(json.dumps(imported))
    seg = sdjwt.sdjwt_jws(t["securing"]["embedded"]).split(".")
    seg[1] = ("A" if seg[1][0] != "A" else "B") + seg[1][1:]
    t["securing"]["embedded"] = ".".join(seg) + "~"
    check("tampered embedded chain fails import", not interop.verify_imported(t, resolver))
    t2 = json.loads(json.dumps(imported))
    t2["proof"] = {"type": "DataIntegrityProof"}
    check("proof on a proof-preserving object is rejected (no-downgrade)",
          not interop.verify_imported(t2, resolver))
    t3 = json.loads(json.dumps(imported_foreign))
    t3["issuer"] = "did:web:attacker.example"
    check("swapped issuer fails (unresolvable did:web)", not interop.verify_imported(t3, resolver))

    print("Interop co-issued + L3 (per-purchase) bridge:")
    coissued = load(INTEROP, "05-coissued-mandate.json")
    check("co-issued mandate verifies (native proof + parallel ES256)",
          interop.verify_imported(coissued, resolver))
    check("co-issued carries a native Data Integrity proof",
          "proof" in coissued and ac.verify_ecdsa_jcs_2022(coissued))
    check("co-issued is also a valid bare DSA credential (issuer-signed)",
          controller(coissued) == issuer)

    presentation = load(INTEROP, "06-l3-presentation.json")["presentation"]
    imported_authz = load(INTEROP, "07-imported-payment-authorization.json")
    check("L3 presentation verifies (mandate authority + KB-JWT + sd_hash)",
          interop.verify_presentation(presentation, resolver))
    check("L3 V->A reconstructs PaymentAuthorization economic terms", all(
        imported_authz.get(k) == authz.get(k) for k in
        ("payer", "payee", "amount", "currency", "quote", "quoteDigest",
         "requestHash", "settlementMethod", "settlementTarget",
         "nonce", "wallet", "timestamp", "expires")))
    check("imported authz is a proof-preserving projection (no proof)",
          imported_authz["securing"]["mode"] == "proof-preserving" and "proof" not in imported_authz)
    check("imported authz carrier is the KB-JWT presentation",
          imported_authz["securing"]["carrier"] == "sd-jwt-vc+kb-jwt"
          and imported_authz["securing"]["embedded"] == presentation)
    pp = presentation.split("~")
    kbseg = pp[-1].split(".")
    kbseg[1] = ("A" if kbseg[1][0] != "A" else "B") + kbseg[1][1:]
    check("tampered key-binding JWT fails",
          not interop.verify_presentation("~".join(pp[:-1]) + "~" + ".".join(kbseg), resolver))
    check("KB-JWT re-bound to a different mandate fails (sd_hash)",
          not interop.verify_presentation(foreign["compact"] + pp[-1], resolver))

    print("Interop attested mode + lossy-case advisories:")
    trusted_bridges = set(keys.get("trustedBridges", []))
    attested = load(INTEROP, "08-attested-mandate.json")
    check("attested mandate cryptographically verifies (bridge re-signature)",
          interop.verify_imported(attested, resolver))
    check("attested outer proof signed by the attesting bridge",
          controller(attested) == attested["securing"]["attestingBridge"])
    check("attested honored only when attestingBridge is trusted (policy)",
          attested["securing"]["attestingBridge"] in trusted_bridges)
    # A crypto-valid attested object from an UNTRUSTED bridge must be policy-rejected.
    rogue_key = ac.seed_key("rogue-bridge")
    rogue = json.loads(json.dumps(attested))
    rogue.pop("proof", None)
    rogue["issuer"] = rogue["securing"]["attestingBridge"] = ac.did_key(rogue_key.public_key())
    rogue = ac.sign_ecdsa_jcs_2022(rogue, rogue_key, "2026-04-01T00:02:00Z")
    check("rogue attested object verifies cryptographically", interop.verify_imported(rogue, resolver))
    check("...but is rejected by policy (bridge not trusted)",
          rogue["securing"]["attestingBridge"] not in trusted_bridges)

    il2 = load(INTEROP, "09-imported-interactive-l2.json")
    check("interactive-L2 import carries an advisory (not silently dropped)",
          any("interactive-l2" in a for a in il2["securing"].get("importAdvisory", [])))
    check("interactive-L2 underlying mandate still verifies", interop.verify_imported(il2, resolver))

    partial = load(INTEROP, "10-imported-partial-sd.json")
    check("partial-disclosure import flagged as a subset view",
          any("partial-selective-disclosure" in a for a in partial["securing"].get("importAdvisory", [])))
    check("withheld claim absent from imported subject (currency)",
          "currency" not in partial["credentialSubject"])
    check("partial-disclosure mandate signature still verifies", interop.verify_imported(partial, resolver))

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
          any("ap2-intent-granularity" in a for a in imported_intent["securing"].get("importAdvisory", [])))
    check("intent import flags requiresPurchaseConfirmation",
          imported_intent.get("requiresPurchaseConfirmation") is True)
    check("intent import is a proof-preserving projection (no proof)",
          "proof" not in imported_intent)

    # CartMandate import: payee==merchant, hash binds canonical cart (M4)
    check("cart import payee == merchant issuer", imported_cart["payee"] == cart_foreign["payload"]["iss"])
    check("cart import requestHash binds canonical cart",
          imported_cart["requestHash"] == interop.cart_request_hash(cart_foreign["cart"]))
    check("cart import is a proof-preserving projection (no proof)", "proof" not in imported_cart)
    check("cart import embeds the merchant-signed mandate",
          imported_cart["securing"]["embedded"] == cart_foreign["compact"])
    check("cart import semantic type stays pure (PaymentQuote only)",
          imported_cart["type"] == ["PaymentQuote"])

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
    check("authz purchaseConfirmation binds same requestHash",
          pc["requestHash"] == authz_confirmed["requestHash"])
    check("confirmed authz still verifies (agent proof)", ac.verify_ecdsa_jcs_2022(authz_confirmed))

    # EXPORT direction (§7): native confirmation -> AP2 approval -> re-import, all P-256
    exported = load(INTEROP, "17-exported-cart-user-approval.json")
    back = interop.export_purchase_confirmation(native_conf)
    check("export maps confirmedBy -> AP2 iss (principal attests)", back["iss"] == native_conf["confirmedBy"])
    check("export maps payer -> AP2 sub (on behalf of the agent)", back["sub"] == native_conf["payer"])
    check("export maps requestHash -> AP2 cart_hash",
          back["cart_hash"] == native_conf["requestHash"])
    reimported = exported["reimportedProjection"]
    check("export round-trip preserves requestHash",
          reimported["requestHash"] == native_conf["requestHash"])
    check("export round-trip preserves confirmedBy", reimported["confirmedBy"] == native_conf["confirmedBy"])
    check("re-imported approval verifies (did:key principal resolves locally)",
          interop.verify_purchase_confirmation(reimported))

    # autonomous import: NO confirmation, explicitly advised (§10)
    check("autonomous import has no PurchaseConfirmation",
          "PurchaseConfirmation" not in autonomous.get("type", []))
    check("autonomous import advises absence of fresh human approval",
          any("autonomous" in a for a in autonomous["securing"].get("importAdvisory", [])))

    # no-widening intersection (§11.2)
    check("intersect_limits keeps the most restrictive",
          interop.intersect_limits({"per_txn": "120.00"}, {"per_txn": "100.00"})["per_txn"] == "100.00")
    check("intersect_limits ignores a negative (invalid) limit",
          interop.intersect_limits({"per_txn": "100.00"}, {"per_txn": "-5.00"})["per_txn"] == "100.00")

    print("Interop security (adversarial — must all be rejected):")
    # C1: a disclosure NOT committed in the issuer `_sd` must not be honored / widen authority
    _foreign = load(INTEROP, "03-foreign-sdjwtvc.json")["compact"]
    _forged_d = sdjwt.make_disclosure("salt-attack", "limits", {"per_txn": "9999.00"})
    _inj = interop.sdjwtvc_to_avp(_foreign.rstrip("~") + "~" + _forged_d + "~", "proof-preserving")
    check("forged (unbound) disclosure does not widen import",
          _inj["credentialSubject"].get("maxPerTransaction") != "9999.00")
    # no-widening: a hand-crafted proof-preserving projection broader than the embedded is rejected
    _hand = interop.sdjwtvc_to_avp(_foreign, "proof-preserving")
    _hand["credentialSubject"]["maxPerTransaction"] = "9999.00"
    check("hand-widened proof-preserving projection is rejected",
          not interop.verify_imported(_hand, resolver))
    # C3: a trusted bridge re-attesting with broadened limits is rejected
    _att = load(INTEROP, "08-attested-mandate.json")
    _w = json.loads(json.dumps({k: v for k, v in _att.items() if k != "proof"}))
    _w["credentialSubject"]["maxPerTransaction"] = "9999.00"
    _w = ac.sign_ecdsa_jcs_2022(_w, ac.seed_key("bridge-attestor"), "2026-04-01T00:05:00Z")
    check("widened attested re-signature is rejected (no-widening)",
          not interop.verify_imported(_w, resolver))
    # C2: a genuine human approval for one cart MUST NOT authorize a different cart
    _conf = load(INTEROP, "15-human-present-confirmation.json")
    _sub = json.loads(json.dumps(_conf))
    _sub["requestHash"] = "sha-256:" + "A" * 43
    check("cart-substituted PurchaseConfirmation is rejected",
          not interop.verify_purchase_confirmation(_sub, resolver))
    # C5: algorithm pinning — an alg:none header must not verify
    _vi = sdjwt.seed_p256("vi-issuer")
    _jws = sdjwt.es256_sign({"alg": "ES256", "typ": "x"}, {"a": 1}, _vi)
    _none = sdjwt.b64u_encode(json.dumps({"alg": "none"}).encode()) + "." + _jws.split(".", 1)[1]
    check("alg:none JWS is rejected (algorithm pinned to ES256)",
          not sdjwt.es256_verify(_none, sdjwt.p256_public_from_jwk(keys["viIssuer"]["jwk"])))
    # C4: key-binding JWT freshness — a non-matching expected nonce is rejected
    _pres = load(INTEROP, "06-l3-presentation.json")["presentation"]
    _kb_nonce = sdjwt.jws_payload(_pres.split("~")[-1]).get("nonce")
    check("L3 presentation accepts the matching nonce",
          interop.verify_presentation(_pres, resolver, expected_nonce=_kb_nonce))
    check("L3 presentation rejects a stale/replayed nonce",
          not interop.verify_presentation(_pres, resolver, expected_nonce="n-stale-replay"))

    print("Refunds, reversals & dispute lifecycle:")
    arbiter = dids["arbiter"]
    refund = load(DISP, "20-refund.json")
    rev_refund = load(DISP, "21-reversal-refund.json")
    rev_ack = load(DISP, "22-reversal-ack.json")
    refund2 = load(DISP, "23-refund-partial.json")
    dispute = load(DISP, "30-dispute.json")
    ev_payee = load(DISP, "31-dispute-evidence-payee.json")
    ev_payer = load(DISP, "32-dispute-evidence-payer.json")
    res_payee = load(DISP, "33-dispute-resolution-payee.json")
    res_arb = load(DISP, "34-dispute-resolution-arbiter.json")
    rev_dispute = load(DISP, "35-reversal-dispute.json")
    dispute_r = load(DISP, "36-dispute-rejected.json")
    res_rej = load(DISP, "37-dispute-resolution-rejected.json")
    dispute_w = load(DISP, "38-dispute-withdrawn.json")
    res_wd = load(DISP, "39-dispute-resolution-withdrawn.json")

    # B1: every dispute object's proof verifies
    for label, obj in [("20 refund", refund), ("21 reversal(refund)", rev_refund),
                       ("22 reversal-ack", rev_ack), ("23 refund partial", refund2),
                       ("30 dispute", dispute), ("31 evidence(payee)", ev_payee),
                       ("32 evidence(payer)", ev_payer), ("33 resolution(payee)", res_payee),
                       ("34 resolution(arbiter)", res_arb), ("35 reversal(dispute)", rev_dispute),
                       ("36 dispute(rejected)", dispute_r), ("37 resolution(rejected)", res_rej),
                       ("38 dispute(withdrawn)", dispute_w), ("39 resolution(withdrawn)", res_wd)]:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))

    # B2: signer binding
    check("refund signed by payee", controller(refund) == payee)
    check("refund-partial signed by payee", controller(refund2) == payee)
    check("reversal(refund) signed by wallet", controller(rev_refund) == wallet)
    check("reversal-ack signed by payer", controller(rev_ack) == agent)
    check("dispute signed by payer", controller(dispute) == agent)
    check("evidence(payee) signer == submittedBy == payee",
          controller(ev_payee) == ev_payee["submittedBy"] == payee)
    check("evidence(payer) signer == submittedBy == payer",
          controller(ev_payer) == ev_payer["submittedBy"] == agent)
    check("resolution(payee) signed by payee (resolvedBy)",
          controller(res_payee) == payee == res_payee["resolvedBy"])
    check("resolution(arbiter) signed by arbiter (resolvedBy)",
          controller(res_arb) == arbiter == res_arb["resolvedBy"])
    check("reversal(dispute) signed by wallet", controller(rev_dispute) == wallet)
    check("resolution(rejected) signed by payee", controller(res_rej) == payee)
    check("resolution(withdrawn) signed by payer (resolvedBy)",
          controller(res_wd) == agent == res_wd["resolvedBy"])
    check("reversal(refund) wallet == original execution wallet",
          controller(rev_refund) == controller(session_exec))
    check("reversal(dispute) wallet == original execution wallet",
          controller(rev_dispute) == controller(session_exec))

    # B3: digest binding (pinned to the exact referenced signed object)
    check("refund.receiptDigest matches receipt(09)",
          refund["receiptDigest"] == ac.jcs_digest(session_receipt))
    check("dispute.executionDigest matches execution(08)",
          dispute["executionDigest"] == ac.jcs_digest(session_exec))
    check("evidence binds dispute digest", ev_payee["disputeDigest"] == ac.jcs_digest(dispute))
    check("payer evidence binds dispute digest", ev_payer["disputeDigest"] == ac.jcs_digest(dispute))
    check("payee resolution binds dispute digest", res_payee["disputeDigest"] == ac.jcs_digest(dispute))
    check("arbiter resolution binds dispute digest", res_arb["disputeDigest"] == ac.jcs_digest(dispute))
    check("arbiter supersedesDigest matches payee resolution",
          res_arb["supersedesDigest"] == ac.jcs_digest(res_payee))
    check("disputes do not use the refund-only 'goodwill' reason",
          all(d.get("reason") != "disp:goodwill" for d in (dispute, dispute_r, dispute_w)))
    check("reversal(refund).refundDigest matches refund",
          rev_refund["refundDigest"] == ac.jcs_digest(refund))
    check("reversal(dispute).resolutionDigest matches arbiter resolution",
          rev_dispute["resolutionDigest"] == ac.jcs_digest(res_arb))
    check("reversal-ack.reversalDigest matches reversal",
          rev_ack["reversalDigest"] == ac.jcs_digest(rev_refund))

    # B3 extra: secondary disputes' digest bindings
    check("rejected resolution binds its dispute digest",
          res_rej["disputeDigest"] == ac.jcs_digest(dispute_r))
    check("withdrawn resolution binds its dispute digest",
          res_wd["disputeDigest"] == ac.jcs_digest(dispute_w))

    # B4 + B5: party / currency consistency with the original
    check("refund parties match original receipt",
          refund["payer"] == session_receipt["payer"] and refund["payee"] == session_receipt["payee"])
    check("dispute parties match original receipt",
          dispute["payer"] == session_receipt["payer"] and dispute["payee"] == session_receipt["payee"])
    check("refund currency matches original", refund["currency"] == session_receipt["currency"])
    check("dispute currency matches original", dispute["currency"] == session_receipt["currency"])

    # B4 extra: party consistency for the secondary disputes/refund
    check("refund2 parties match original receipt",
          refund2["payer"] == session_receipt["payer"] and refund2["payee"] == session_receipt["payee"])
    check("rejected dispute parties match original receipt",
          dispute_r["payer"] == receipt["payer"] and dispute_r["payee"] == receipt["payee"])
    check("withdrawn dispute parties match original receipt",
          dispute_w["payer"] == receipt["payer"] and dispute_w["payee"] == receipt["payee"])

    # B5 extra: currency consistency along the resolution/reversal chain
    check("refund2 currency matches original", refund2["currency"] == session_receipt["currency"])
    check("payee resolution currency matches dispute", res_payee["currency"] == dispute["currency"])
    check("arbiter resolution currency matches dispute", res_arb["currency"] == dispute["currency"])
    check("dispute reversal currency matches dispute", rev_dispute["currency"] == dispute["currency"])
    check("refund reversal currency matches refund", rev_refund["currency"] == refund["currency"])

    # A1 + A4: amount bounds
    orig08 = Decimal(session_exec["amount"])  # 0.048
    check("refund amount <= original", Decimal(refund["amount"]) <= orig08)
    check("dispute disputedAmount <= original", Decimal(dispute["disputedAmount"]) <= orig08)
    check("payee resolvedAmount <= disputedAmount",
          Decimal(res_payee["resolvedAmount"]) <= Decimal(dispute["disputedAmount"]))
    check("arbiter resolvedAmount <= disputedAmount",
          Decimal(res_arb["resolvedAmount"]) <= Decimal(dispute["disputedAmount"]))

    # A3: reversal amount equals its trigger
    check("reversal(refund) amount == refund amount", rev_refund["amount"] == refund["amount"])
    check("reversal(dispute) amount == arbiter resolvedAmount",
          rev_dispute["amount"] == res_arb["resolvedAmount"])

    # A2: no over-refund against one original execution (sum of settled reversals)
    settled08 = sum(Decimal(r["amount"]) for r in (rev_refund, rev_dispute)
                    if r.get("execution") == session_exec["id"] and r["status"] in ("completed", "partial"))
    check("cumulative settled returns <= original (exec 08)", settled08 <= orig08)

    # S1: a dispute-caused reversal references an upheld/partial resolution
    check("reversal(dispute) cause=dispute and resolution outcome is upheld/partial",
          rev_dispute["cause"] == "dispute" and res_arb["outcome"] in ("upheld", "partial"))
    # S2: arbiter resolution supersedes a payee resolution; arbiter == dispute.arbiter
    check("arbiter resolution supersedes a payee resolution",
          res_arb.get("supersedes") == res_payee["id"] and res_payee["resolverRole"] == "payee")
    check("arbiter == dispute.arbiter", res_arb["resolvedBy"] == dispute["arbiter"])
    # S3: withdrawn -> role=payer and resolvedAmount 0
    check("withdrawn resolved by payer, amount 0",
          res_wd["resolverRole"] == "payer" and Decimal(res_wd["resolvedAmount"]) == 0)
    # S4: rejected -> resolvedAmount 0 and no reversal references it
    check("rejected resolvedAmount 0", Decimal(res_rej["resolvedAmount"]) == 0)
    check("no reversal references the rejected resolution",
          all(r.get("resolution") != res_rej["id"] for r in (rev_refund, rev_dispute)))
    # S5: evidence sequence unique and role matches submitter
    check("evidence sequences unique",
          ev_payee["sequence"] != ev_payer["sequence"])
    check("evidence roles match submitter",
          ev_payee["role"] == "payee" and ev_payer["role"] == "payer")

    print("On-chain settlement binding:")
    binding = load(SETTLE, "40-payee-account-binding.json")
    instr_evm = load(SETTLE, "41-settlement-instruction-evm.json")
    proof_evm = load(SETTLE, "42-settlement-proof-evm.json")
    instr_x402 = load(SETTLE, "43-settlement-instruction-x402.json")
    proof_x402 = load(SETTLE, "44-settlement-proof-x402.json")
    instr_ln = load(SETTLE, "45-settlement-instruction-lightning.json")
    lock_ln = load(SETTLE, "46-escrow-lock-lightning.json")
    proof_ln = load(SETTLE, "47-settlement-proof-lightning.json")
    release_ln = load(SETTLE, "48-escrow-release-lightning.json")
    instr_evm_esc = load(SETTLE, "49-settlement-instruction-evm-escrow.json")
    lock_evm = load(SETTLE, "50-escrow-lock-evm.json")
    proof_evm_refund = load(SETTLE, "51-settlement-proof-evm-refund.json")
    refund_evm = load(SETTLE, "52-escrow-refund-evm.json")
    instr_rev = load(SETTLE, "53-reverse-settlement-instruction.json")
    proof_rev = load(SETTLE, "54-reverse-settlement-proof.json")
    binding_agent = load(SETTLE, "55-payee-account-binding-agent.json")
    binding_evm = load(SETTLE, "56-payee-account-binding-evm.json")

    settle_objs = [("40 binding", binding), ("41 instr(evm)", instr_evm),
                   ("42 proof(evm)", proof_evm), ("43 instr(x402)", instr_x402),
                   ("44 proof(x402)", proof_x402), ("45 instr(ln)", instr_ln),
                   ("46 lock(ln)", lock_ln), ("47 proof(ln)", proof_ln),
                   ("48 release(ln)", release_ln), ("49 instr(evm-esc)", instr_evm_esc),
                   ("50 lock(evm)", lock_evm), ("51 proof(evm-refund)", proof_evm_refund),
                   ("52 refund(evm)", refund_evm), ("53 instr(reverse)", instr_rev),
                   ("54 proof(reverse)", proof_rev), ("55 binding(agent)", binding_agent),
                   ("56 binding(evm)", binding_evm)]
    for label, obj in settle_objs:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))

    # signer binding: each PayeeAccountBinding is signed by its subject; wallet signs the rest.
    check("x402 payee-account binding signed by its subject (payee)",
          controller(binding) == binding["subject"] == payee)
    check("evm payee-account binding signed by its subject (payee)",
          controller(binding_evm) == binding_evm["subject"] == payee)
    check("agent-account binding signed by its subject (agent)",
          controller(binding_agent) == binding_agent["subject"])
    for label, obj in settle_objs:
        if obj in (binding, binding_agent, binding_evm):
            continue
        check(f"{label} signed by wallet", controller(obj) == wallet)

    # instruction <-> authorization binding: economic terms AND the parties. A forward
    # settlement MUST pay the AUTHORIZED payee, funded by the authorized payer -- else a
    # wallet could redirect funds to an account it controls.
    for label, instr in [("evm", instr_evm), ("x402", instr_x402), ("ln", instr_ln),
                         ("evm-esc", instr_evm_esc)]:
        check(f"instr({label}).authorization == authz.id", instr["authorization"] == authz["id"])
        check(f"instr({label}).authorizationDigest matches authz",
              instr["authorizationDigest"] == ac.jcs_digest(authz))
        check(f"instr({label}).amount == authz.amount", instr["amount"] == authz["amount"])
        check(f"instr({label}).currency == authz.currency", instr["currency"] == authz["currency"])
        check(f"instr({label}).payee == authz.payee (settle the authorized payee)",
              instr["payee"] == authz["payee"])
        check(f"instr({label}).payer == authz.payer", instr["payer"] == authz["payer"])

    # base-unit invariant: stablecoin rails == amount x 10^decimals; Lightning via rate.
    for label, instr in [("evm", instr_evm), ("x402", instr_x402), ("evm-esc", instr_evm_esc)]:
        check(f"instr({label}).amountBase == amount x 10^decimals",
              instr["amountBase"] == st.to_base_units(instr["amount"], st.decimals_for_asset(instr["asset"])))
    check("instr(ln).amountBase == usd_to_msat(amount, rate)",
          instr_ln["amountBase"] == st.usd_to_msat(instr_ln["amount"], instr_ln["rate"]))

    # payeeAccount binding: each CAIP-10 forward instruction's destination account MUST be
    # bound to its payee (== authz.payee) by a PayeeAccountBinding the payee SIGNED (the
    # signer==subject checks above + subject==authz.payee tie the on-chain account to the
    # authorized payee, so a wallet cannot point payeeAccount at an account it controls).
    for label, instr, bnd in [("evm", instr_evm, binding_evm), ("x402", instr_x402, binding),
                              ("evm-esc", instr_evm_esc, binding_evm)]:
        check(f"instr({label}) references its payeeAccountBinding",
              instr.get("payeeAccountBinding") == bnd["id"])
        check(f"instr({label}) payeeAccount bound to payee via that binding",
              st.account_binding_ok(instr, bnd))
        check(f"instr({label}) binding subject == authz.payee",
              bnd["subject"] == authz["payee"])
    check("instr(reverse) payeeAccount bound via the agent binding",
          st.account_binding_ok(instr_rev, binding_agent)
          and instr_rev.get("payeeAccountBinding") == binding_agent["id"])
    # Lightning destinations are signed BOLT11 invoices, authenticated by the invoice
    # itself, not by a CAIP-10 DID<->account binding (see Account binding section).
    check("instr(ln) uses a Lightning destination (exempt from CAIP-10 binding)",
          instr_ln["rail"] == "stl:rail-lightning" and not instr_ln["payeeAccount"].startswith("eip155:"))

    # finality: the threshold MUST meet the rail floor (no self-set downgrade), and
    # finality_ok is given the rail so a `preimage` cannot smuggle a confirmation-rail proof
    # past the check; Lightning finalizes via preimage==payment_hash.
    for label, instr, proof in [("evm", instr_evm, proof_evm), ("x402", instr_x402, proof_x402),
                               ("evm-refund", instr_evm_esc, proof_evm_refund),
                               ("reverse", instr_rev, proof_rev),
                               ("ln", instr_ln, proof_ln)]:
        check(f"instr({label}).confirmationThreshold >= rail floor (no downgrade)",
              instr["confirmationThreshold"] >= st.rail_threshold_floor(instr["rail"]))
        check(f"proof({label}) final per its rail",
              st.finality_ok(proof, instr["confirmationThreshold"], rail=instr["rail"]))

    # proof <-> instruction binding: id + digest + settled amount AND chain + asset, so a
    # proof asserting a different (cheaper / attacker) chain or asset cannot satisfy it.
    for label, instr, proof in [("evm", instr_evm, proof_evm), ("x402", instr_x402, proof_x402),
                               ("ln", instr_ln, proof_ln),
                               ("evm-refund", instr_evm_esc, proof_evm_refund),
                               ("reverse", instr_rev, proof_rev)]:
        check(f"proof({label}).instruction == instr.id", proof["instruction"] == instr["id"])
        check(f"proof({label}).instructionDigest matches instr",
              proof["instructionDigest"] == ac.jcs_digest(instr))
        check(f"proof({label}).settledAmountBase == instr.amountBase",
              proof["settledAmountBase"] == instr["amountBase"])
        check(f"proof({label}).chain == instr.chain", proof["chain"] == instr["chain"])
        check(f"proof({label}).asset == instr.asset", proof["asset"] == instr["asset"])

    # escrow resolution: a release/refund MUST bind its lock AND a FINAL settlement proof
    # that settles the SAME instruction the lock locked; and a lock MUST NOT be both
    # released and refunded (on-chain escrow is single-spend; the AVP records mirror it).
    check("ln release binds its lock", release_ln["lockDigest"] == ac.jcs_digest(lock_ln))
    check("ln release binds the LN settlement proof",
          release_ln["settlementProofDigest"] == ac.jcs_digest(proof_ln))
    check("ln lock references the escrow instruction", lock_ln["instruction"] == instr_ln["id"])
    check("ln release proof settles the lock's instruction",
          proof_ln["instruction"] == lock_ln["instruction"])
    check("ln release proof is final", proof_ln["finality"] == "final")
    check("evm refund binds its lock", refund_evm["lockDigest"] == ac.jcs_digest(lock_evm))
    check("evm refund binds the refund proof",
          refund_evm["settlementProofDigest"] == ac.jcs_digest(proof_evm_refund))
    check("evm refund proof settles the lock's instruction",
          proof_evm_refund["instruction"] == lock_evm["instruction"])
    check("evm refund proof is final", proof_evm_refund["finality"] == "final")
    check("evm refund reason is timeout", refund_evm["reason"] == "timeout")
    _rel_locks = {r["lock"] for r in (release_ln,)}
    _ref_locks = {r["lock"] for r in (refund_evm,)}
    check("no escrow lock is both released and refunded (single resolution)",
          _rel_locks.isdisjoint(_ref_locks))

    # on-chain reversal: a compensating transfer with payer/payee swapped vs the original
    check("reverse instruction swaps payer/payee vs the original payment",
          instr_rev["payer"] == instr_evm["payee"] and instr_rev["payee"] == instr_evm["payer"])

    print("Attested (closed-processor) settlement rails -- card (Stripe) & bank/RTP:")
    binding_card = load(SETTLE, "57-processor-account-binding-card.json")
    instr_card = load(SETTLE, "58-settlement-instruction-card.json")
    proof_card = load(SETTLE, "59-settlement-proof-card.json")
    binding_rtp = load(SETTLE, "60-processor-account-binding-rtp.json")
    instr_rtp = load(SETTLE, "61-settlement-instruction-rtp.json")
    proof_rtp = load(SETTLE, "62-settlement-proof-rtp.json")
    binding_paypal = load(SETTLE, "63-processor-account-binding-paypal.json")
    instr_paypal = load(SETTLE, "64-settlement-instruction-paypal.json")
    proof_paypal = load(SETTLE, "65-settlement-proof-paypal.json")
    binding_visa = load(SETTLE, "66-processor-account-binding-visa-direct.json")
    instr_visa = load(SETTLE, "67-settlement-instruction-visa-direct.json")
    proof_visa = load(SETTLE, "68-settlement-proof-visa-direct.json")
    # adyen (card), zum (bank), mc-send (push-to-card) -- same attested shape, loaded by tag
    _more = {tag: (load(SETTLE, f"{n}-processor-account-binding-{tag}.json"),
                   load(SETTLE, f"{n + 1}-settlement-instruction-{tag}.json"),
                   load(SETTLE, f"{n + 2}-settlement-proof-{tag}.json"))
             for tag, n in (("adyen", 69), ("zum", 72), ("mc-send", 75))}

    # signers: bindings + attested proofs are PAYEE-signed (payee-attested); the wallet
    # still signs the instructions. (Unlike on-chain proofs, which the wallet signs.)
    attested = [("57 binding(card)", binding_card, payee), ("58 instr(card)", instr_card, wallet),
                ("59 proof(card)", proof_card, payee), ("60 binding(rtp)", binding_rtp, payee),
                ("61 instr(rtp)", instr_rtp, wallet), ("62 proof(rtp)", proof_rtp, payee),
                ("63 binding(paypal)", binding_paypal, payee), ("64 instr(paypal)", instr_paypal, wallet),
                ("65 proof(paypal)", proof_paypal, payee),
                ("66 binding(visa-direct)", binding_visa, payee), ("67 instr(visa-direct)", instr_visa, wallet),
                ("68 proof(visa-direct)", proof_visa, payee)]
    for tag, (b, i, p) in _more.items():
        attested += [(f"binding({tag})", b, payee), (f"instr({tag})", i, wallet), (f"proof({tag})", p, payee)]
    for label, obj, signer in attested:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))
        check(f"{label} signed by expected key", controller(obj) == signer)

    for label, binding, instr, proof in ([("card", binding_card, instr_card, proof_card),
                                          ("rtp", binding_rtp, instr_rtp, proof_rtp),
                                          ("paypal", binding_paypal, instr_paypal, proof_paypal),
                                          ("visa-direct", binding_visa, instr_visa, proof_visa)]
                                         + [(tag, b, i, p) for tag, (b, i, p) in _more.items()]):
        # binding: payee-signed, subject == the AUTHORIZED payee (anti-redirection root),
        # naming a did:web processor as the trust root, on the instruction's rail.
        check(f"{label} processor-account binding signed by its subject (payee==authz.payee)",
              controller(binding) == binding["subject"] == payee == authz["payee"])
        check(f"{label} binding names a did:web processor on the instruction's rail",
              binding["processor"].startswith("did:web:") and binding["rail"] == instr["rail"])
        # instruction <-> authorization binding (economic terms + parties).
        check(f"instr({label}).authorization == authz.id", instr["authorization"] == authz["id"])
        check(f"instr({label}).authorizationDigest matches authz",
              instr["authorizationDigest"] == ac.jcs_digest(authz))
        check(f"instr({label}).amount/currency == authz",
              instr["amount"] == authz["amount"] and instr["currency"] == authz["currency"])
        check(f"instr({label}).payee/payer == authz",
              instr["payee"] == authz["payee"] and instr["payer"] == authz["payer"])
        # anti-redirection: settle only to the bound account, on the same rail.
        check(f"instr({label}) destination bound to the authorized payee",
              st.attested_binding_ok(instr, binding))
        # proof <-> instruction binding + attested finality.
        check(f"proof({label}).instruction == instr.id", proof["instruction"] == instr["id"])
        check(f"proof({label}).instructionDigest matches instr",
              proof["instructionDigest"] == ac.jcs_digest(instr))
        check(f"proof({label}).settledAmount/currency == instr",
              proof["settledAmount"] == instr["amount"] and proof["currency"] == instr["currency"])
        check(f"proof({label}) is an attested-finality rail", st.is_attested_rail(proof["rail"]))
        check(f"proof({label}) final per its embedded attestation", st.attested_finality_ok(proof))
        check(f"proof({label}) is payee-attested by the payee (the proof signer)",
              proof["attestation"]["mode"] == "payee-attested" and controller(proof) == authz["payee"])
    # card maps to auth/capture (escrow); RTP is push/irrevocable (no escrow).
    check("card instruction uses auth-capture (escrow) semantics",
          instr_card["mode"] == "escrow" and instr_card["captureMode"] == "auth-capture")
    check("rtp instruction is a direct push (no escrow)", instr_rtp["mode"] == "direct")

    print("Transport & protocol binding:")
    service = load(TXP, "00-service-description.json")
    challenge = load(TXP, "10-payment-challenge.json")
    body_402 = load(TXP, "11-challenge-402-body.json")
    submission = load(TXP, "20-authorization-submission.json")
    problem = load(TXP, "30-problem-details.json")
    flow = load(TXP, "40-exchange-402-flow.json")
    over_cap = load(TXP, "41-exchange-over-cap.json")

    for label, obj in [("service-description", service), ("payment-challenge", challenge),
                       ("authorization-submission", submission)]:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))
    check("service description signed by payee", controller(service) == payee)
    check("payment challenge signed by payee", controller(challenge) == payee)
    check("authorization submission signed by payer agent", controller(submission) == agent)

    # discovery advertises the mandatory endpoints
    for ep in ("quote", "authorize", "execute", "receipt", "settlementStatus"):
        check(f"service advertises '{ep}' endpoint", ep in service.get("endpoints", {}))
    check("service advertises the transport bundle version",
          service.get("supportedBundles", {}).get("https://w3id.org/avp-micro/transport/v1") is not None)

    # challenge binds the resolved quote (IRI + content digest)
    check("challenge.quote == quote.id", challenge["quote"] == quote["id"])
    check("challenge.quoteDigest matches resolved quote", challenge["quoteDigest"] == ac.jcs_digest(quote))
    check("402 body carries the byte-identical quote", body_402["quote"] == quote)
    check("402 body carries the byte-identical challenge", body_402["challenge"] == challenge)
    check("challenge's quote binds the same request as the submitted authorization "
          "(quote.requestHash == authz.requestHash)",
          quote["requestHash"] == authz["requestHash"])
    check("challenge not expired at issuance (timestamp < expires)",
          challenge["timestamp"] < challenge["expires"])

    # submission binds the authorization and echoes the challenge nonce (freshness)
    check("submission.authorization == authz.id", submission["authorization"] == authz["id"])
    check("submission.authorizationDigest matches resolved authorization",
          submission["authorizationDigest"] == ac.jcs_digest(authz))
    check("submission echoes the challenge nonce (freshness binding)",
          submission["challenge"] == challenge["challenge"])
    check("submission.payer == authz.payer", submission["payer"] == authz["payer"])

    # problem-details type resolves to a concept in the transport error scheme
    errors_ttl = (SPEC / "transport" / "vocab" / "errors.ttl").read_text(encoding="utf-8")
    check("problem-details type is a transport error IRI",
          problem["type"].startswith("https://w3id.org/avp-micro/transport/v1#"))
    check("problem-details type resolves to a SKOS concept in txp:ErrorScheme",
          (problem["type"].rsplit("#", 1)[1] + " a skos:Concept") in errors_ttl)
    check("problem-details status is an HTTP status int", isinstance(problem["status"], int))

    # example HTTP exchanges embed the canonical signed objects byte-for-byte
    flow_steps = flow["steps"]
    check("402-flow step 1 response is the canonical 402 body", flow_steps[0]["response"]["body"] == body_402)
    check("402-flow step 1 status is 402", flow_steps[0]["response"]["status"] == 402)
    check("402-flow step 2 request carries the canonical submission",
          flow_steps[1]["request"]["body"] == submission)
    check("402-flow step 2 response is the canonical receipt", flow_steps[1]["response"]["body"] == receipt)
    check("402-flow step 2 status is 200", flow_steps[1]["response"]["status"] == 200)
    check("over-cap exchange response is the canonical problem-details",
          over_cap["steps"][0]["response"]["body"] == problem)
    check("over-cap exchange status is 402", over_cap["steps"][0]["response"]["status"] == 402)

    # additional flow exchanges (explicit-quote, streaming, async settlement, idempotency)
    exec_c = load(PAY, "03-payment-execution.json")
    sess_c = load(PAY, "05-usage-session.json")
    accrual_c = load(PAY, "07-usage-accrual.json")
    sess_receipt_c = load(PAY, "09-payment-receipt-session.json")
    settle_proof_c = load(SETTLE, "42-settlement-proof-evm.json")
    qflow = load(TXP, "42-exchange-quote-flow.json")
    stream = load(TXP, "43-exchange-streaming.json")
    asett = load(TXP, "44-exchange-async-settlement.json")
    idem = load(TXP, "45-exchange-idempotency.json")

    check("quote-flow embeds the canonical quote, execution, and receipt",
          qflow["steps"][0]["response"]["body"] == quote
          and qflow["steps"][1]["response"]["body"] == exec_c
          and qflow["steps"][2]["response"]["body"] == receipt)
    check("quote-flow receipt binds the execution", receipt["execution"] == exec_c["id"])
    check("streaming opens the session and closes with the session receipt",
          stream["steps"][0]["response"]["body"] == sess_c
          and stream["steps"][3]["response"]["body"] == sess_receipt_c)
    check("streaming reports a usage accrual", stream["steps"][2]["response"]["body"] == accrual_c)
    check("async settlement returns a Location and polls to a final proof",
          bool(asett["steps"][0]["response"]["headers"].get("Location"))
          and asett["steps"][1]["response"]["body"] == exec_c
          and asett["steps"][2]["response"]["body"] == settle_proof_c)
    check("async settlement final proof has finality=final", settle_proof_c["finality"] == "final")
    _k0 = idem["steps"][0]["request"]["headers"]["Idempotency-Key"]
    check("idempotency replay returns the same execution under the same key",
          idem["steps"][1]["request"]["headers"]["Idempotency-Key"] == _k0
          and idem["steps"][0]["response"]["body"] == exec_c
          and idem["steps"][1]["response"]["body"] == exec_c)
    _conf = idem["steps"][2]
    check("idempotency conflict: same key + different body -> 409",
          _conf["request"]["headers"]["Idempotency-Key"] == _k0
          and _conf["request"]["body"] != idem["steps"][0]["request"]["body"]
          and _conf["response"]["status"] == 409)
    check("idempotency conflict body is an idempotency-conflict ProblemDetails",
          _conf["response"]["body"]["type"].rsplit("#", 1)[-1] == "idempotency-conflict")
    check("the conflict submission is a valid, distinct signed AuthorizationSubmission",
          ac.verify_ecdsa_jcs_2022(_conf["request"]["body"]))

    # transport hardening: signed errors (A4) + anti-replay (A3)
    prob_signed = load(TXP, "47-problem-details-signed.json")
    replay = load(TXP, "46-exchange-replay.json")
    errors_ttl2 = (SPEC / "transport" / "vocab" / "errors.ttl").read_text(encoding="utf-8")
    check("signed ProblemDetails proof verifies", ac.verify_ecdsa_jcs_2022(prob_signed))
    check("signed ProblemDetails is signed by the payee", controller(prob_signed) == payee)
    check("signed ProblemDetails type resolves in txp:ErrorScheme",
          (prob_signed["type"].rsplit("#", 1)[-1] + " a skos:Concept") in errors_ttl2)
    _r1, _r2 = replay["steps"][0], replay["steps"][1]
    check("replay re-presents the same submission (consumed nonce)",
          _r1["request"]["body"] == _r2["request"]["body"])
    check("replay first attempt succeeds (200, nonce consumed)", _r1["response"]["status"] == 200)
    check("replay second attempt is refused 409", _r2["response"]["status"] == 409)
    _rb = _r2["response"]["body"]
    check("replay 409 body is a signed nonce-reuse ProblemDetails",
          _rb["type"].rsplit("#", 1)[-1] == "nonce-reuse" and ac.verify_ecdsa_jcs_2022(_rb))
    check("replay 409 carries a WWW-Authenticate error param",
          'error="nonce-reuse"' in _r2["response"]["headers"].get("WWW-Authenticate", ""))

    print("Negative control (tamper detection):")
    tampered = json.loads(json.dumps(authz))
    tampered["amount"] = "0.05"
    check("tampered amount breaks the payer signature", not ac.verify_ecdsa_jcs_2022(tampered))
    # JCS conformance: RFC 8785 requires U+2028/U+2029 escaped (interop across impls)
    check("JCS escapes U+2028/U+2029 (RFC 8785)",
          (chr(92) + "u2028").encode() in ac.jcs({"x": chr(0x2028) + chr(0x2029)})
          and b"\xe2\x80\xa8" not in ac.jcs({"x": chr(0x2028)}))

    print()
    if _failed:
        print(f"FAIL: {len(_failed)} check(s) failed: {_failed}")
        return 1
    print("PASS: all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
