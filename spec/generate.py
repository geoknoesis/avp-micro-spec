"""Generate AVP-Micro test vectors for both peer specs (deterministic).

Writes the Delegated Spending Authority bundle (authority/test-vectors/) and the
AVP-Micro Payments bundle (payments/test-vectors/). DSA objects use the 3-entry
@context; payment objects use the 4-entry @context so the embedded credential
and the shared `currency` term resolve.
"""
from __future__ import annotations

import json
from pathlib import Path

import avp_crypto as ac
import interop
import sdjwt

SPEC = Path(__file__).parent
AUTH = SPEC / "authority" / "test-vectors"
PAY = SPEC / "payments" / "test-vectors"
INTEROP = SPEC / "interop-sd-jwt-vc" / "test-vectors"

VC2 = "https://www.w3.org/ns/credentials/v2"
DI = "https://w3id.org/security/data-integrity/v2"
DSA = "https://w3id.org/spending-authority/v1"
AVP = "https://w3id.org/avp-micro/v1"
DSA_CTX = [VC2, DI, DSA]
PAY_CTX = [VC2, DI, DSA, AVP]

issuer = ac.seed_key("issuer-acme-corp")
agent = ac.seed_key("agent-buyer-01")
payee = ac.seed_key("service-tool-api")
wallet = ac.seed_key("wallet-acme")

DID_ISSUER = ac.did_key(issuer.public_key())
DID_AGENT = ac.did_key(agent.public_key())
DID_PAYEE = ac.did_key(payee.public_key())
DID_WALLET = ac.did_key(wallet.public_key())


def write(base: Path, name: str, obj: dict) -> None:
    base.mkdir(parents=True, exist_ok=True)
    (base / name).write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {base.name}/{name}")


def main() -> None:
    amount, currency = "0.001", "USD"
    settlement_method = "internal-ledger"
    settlement_target = "https://wallet.example.com/tool-api-addr"

    # ---- Authority bundle ----
    spendauth = {
        "@context": DSA_CTX,
        "id": "urn:dsa:vc:spendauth:456",
        "type": ["VerifiableCredential", "SpendingAuthorizationCredential"],
        "issuer": DID_ISSUER,
        "validFrom": "2026-03-25T20:00:00Z",
        "validUntil": "2026-06-25T20:00:00Z",
        "credentialStatus": {
            "id": "https://issuer.example/status/3#94567",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "94567",
            "statusListCredential": "https://issuer.example/status/3",
        },
        "credentialSubject": {
            "id": DID_AGENT,
            "currency": "USD",
            "maxPerTransaction": "0.05",
            "dailyLimit": "5.00",
            "allowedPayees": [DID_PAYEE],
        },
    }
    spendauth = ac.sign_ecdsa_jcs_2022(spendauth, issuer, "2026-03-25T20:00:01Z")
    write(AUTH, "spending-authorization-credential.json", spendauth)

    merchant = {
        "@context": DSA_CTX,
        "id": "urn:dsa:vc:merchant:001",
        "type": ["VerifiableCredential", "MerchantCredential"],
        "issuer": DID_ISSUER,
        "credentialSubject": {"id": DID_PAYEE, "merchantName": "Tool API Inc.",
                               "categories": ["cat:ChatCompletionApi"]},
    }
    merchant = ac.sign_ecdsa_jcs_2022(merchant, issuer, "2026-03-25T20:00:02Z")
    write(AUTH, "merchant-credential.json", merchant)

    capability = {
        "@context": DSA_CTX,
        "id": "urn:dsa:vc:capability:001",
        "type": ["VerifiableCredential", "PaymentCapabilityCredential"],
        "issuer": DID_WALLET,
        "credentialSubject": {"id": DID_AGENT, "account": "https://wallet.example.com/alice",
                               "currency": "USD"},
    }
    capability = ac.sign_ecdsa_jcs_2022(capability, wallet, "2026-03-25T20:00:03Z")
    write(AUTH, "payment-capability-credential.json", capability)

    # Trust-config example (NOT a signed wire message).
    write(AUTH, "trusted-issuers.json", {
        "_note": "Example wallet trust configuration; not a signed message.",
        "trustedIssuers": [
            {"issuer": DID_ISSUER,
             "issuerScope": {"currency": "USD", "maxPerTransaction": "0.05",
                             "maxDailyTotal": "5.00",
                             "allowedServiceTypes": ["cat:ChatCompletionApi"]}}
        ],
    })

    write(AUTH, "dids.json", {
        "_warning": "TEST KEYS ONLY. Seeds are derived deterministically; do not reuse.",
        "principalIssuer": DID_ISSUER, "payerAgent": DID_AGENT,
        "payeeService": DID_PAYEE, "walletService": DID_WALLET,
    })

    # ---- Payments bundle ----
    service_request = {"method": "POST", "target": "https://provider.com/tool-api/run",
                       "body": {"tool": "summarize", "input": "doc-42"}}
    write(PAY, "service-request.json", service_request)
    srh = ac.content_digest(ac.jcs(service_request))

    # Payee advertisement (SHOULD be signed; not a binding commitment).
    offer = {
        "@context": PAY_CTX, "id": "urn:avp:offer:1", "type": "PaymentOffer",
        "payee": DID_PAYEE,
        "pricingModel": {"type": "PerCall", "amount": amount, "currency": currency},
        "quoteEndpoint": "https://provider.com/tool-api/quote",
        "acceptedSettlementMethods": [settlement_method],
        "acceptedCredentialIssuers": [DID_ISSUER],
        "categories": ["cat:ChatCompletionApi"],
        "offerValidity": "2026-03-25T23:00:00Z",
    }
    offer = ac.sign_ecdsa_jcs_2022(offer, payee, "2026-03-25T21:29:00Z")
    write(PAY, "00-payment-offer.json", offer)

    # Multi-dimensional offer (Lambda-like): per-request + per-GB-second, with free tiers.
    offer_compute = {
        "@context": PAY_CTX, "id": "urn:avp:offer:compute", "type": "PaymentOffer",
        "payee": DID_PAYEE,
        "pricingModel": {
            "type": "CompositePricing", "currency": currency, "components": [
                {"type": "Allowance", "dimension": "dim:Requests",
                 "unit": "qudtu:NUM", "freeQuantity": "1000000"},
                {"type": "PerUnit", "dimension": "dim:Requests",
                 "unit": "qudtu:NUM", "amount": "0.0000002"},
                {"type": "PerUnit", "dimension": "dim:ComputeMemoryTime",
                 "unit": "aunit:GigaByteSecond", "amount": "0.0000166667"},
            ],
        },
        "quoteEndpoint": "https://provider.com/fn-api/quote",
        "acceptedSettlementMethods": [settlement_method],
        "acceptedCredentialIssuers": [DID_ISSUER],
        "categories": ["cat:EphemeralRuntimeSessions"],
        "offerValidity": "2026-03-25T23:00:00Z",
    }
    offer_compute = ac.sign_ecdsa_jcs_2022(offer_compute, payee, "2026-03-25T21:29:01Z")
    write(PAY, "12-payment-offer-compute.json", offer_compute)

    # Tiered offer (S3-like): graduated per-GB-month storage rate.
    offer_storage = {
        "@context": PAY_CTX, "id": "urn:avp:offer:storage", "type": "PaymentOffer",
        "payee": DID_PAYEE,
        "pricingModel": {
            "type": "TieredRate", "dimension": "dim:StorageDuration",
            "unit": "aunit:GigaByteMonth", "tierMode": "graduated", "currency": currency,
            "tiers": [
                {"upTo": "51200", "amount": "0.023"},
                {"upTo": "512000", "amount": "0.022"},
                {"amount": "0.021"},
            ],
        },
        "quoteEndpoint": "https://provider.com/object-store/quote",
        "acceptedSettlementMethods": [settlement_method],
        "acceptedCredentialIssuers": [DID_ISSUER],
        "categories": ["cat:BulkDatasetsAndSnapshots"],
        "offerValidity": "2026-03-25T23:00:00Z",
    }
    offer_storage = ac.sign_ecdsa_jcs_2022(offer_storage, payee, "2026-03-25T21:29:02Z")
    write(PAY, "13-payment-offer-storage.json", offer_storage)

    # Conformance vectors: (pricingModel, usage) -> expected amount. Verified against
    # the reference evaluator (spec/pricing.py).
    pricing_conformance = {
        "_note": "Pricing-evaluation conformance fixtures; not signed wire messages.",
        "cases": [
            {"name": "per-call single", "currency": "USD",
             "pricingModel": {"type": "PerCall", "amount": "0.001", "currency": "USD"},
             "usage": {}, "expected": "0.00100000"},
            {"name": "per-unit linear", "currency": "USD",
             "pricingModel": {"type": "PerUnit", "dimension": "dim:Requests",
                              "unit": "qudtu:NUM", "amount": "0.0000002", "currency": "USD"},
             "usage": {"dim:Requests": "1000000"}, "expected": "0.20000000"},
            {"name": "tiered graduated", "currency": "USD",
             "pricingModel": offer_storage["pricingModel"],
             "usage": {"dim:StorageDuration": "600000"}, "expected": "13163.20000000"},
            {"name": "composite lambda-like with allowance", "currency": "USD",
             "pricingModel": offer_compute["pricingModel"],
             "usage": {"dim:Requests": "3000000", "dim:ComputeMemoryTime": "600000"},
             "expected": "10.40002000"},
        ],
    }
    write(PAY, "pricing-conformance.json", pricing_conformance)

    quote = {
        "@context": PAY_CTX, "id": "urn:avp:quote:789", "type": "PaymentQuote",
        "payer": DID_AGENT, "payee": DID_PAYEE, "serviceRequestHash": srh,
        "amount": amount, "currency": currency, "settlementMethod": settlement_method,
        "settlementTarget": settlement_target, "expires": "2026-03-25T21:35:00Z",
    }
    quote = ac.sign_ecdsa_jcs_2022(quote, payee, "2026-03-25T21:30:00Z")
    write(PAY, "01-payment-quote.json", quote)

    vp = {"@context": PAY_CTX, "type": "VerifiablePresentation",
          "verifiableCredential": [spendauth]}
    authz = {
        "@context": PAY_CTX, "id": "urn:avp:authz:999", "type": "PaymentAuthorization",
        "quote": "urn:avp:quote:789", "quoteDigest": ac.jcs_digest(quote),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": amount, "currency": currency,
        "settlementMethod": settlement_method, "settlementTarget": settlement_target,
        "serviceRequestHash": srh, "timestamp": "2026-03-25T21:30:02Z",
        "expires": "2026-03-25T21:31:02Z", "nonce": "n-39102",
        "wallet": DID_WALLET, "vp": vp,
    }
    authz = ac.sign_ecdsa_jcs_2022(authz, agent, "2026-03-25T21:30:02Z")
    write(PAY, "02-payment-authorization.json", authz)

    execution = {
        "@context": PAY_CTX, "id": "urn:avp:exec:555", "type": "PaymentExecution",
        "authorization": "urn:avp:authz:999", "amount": amount, "currency": currency,
        "status": "completed", "settlementRef": "internal-ledger://txn/abc123",
        "timestamp": "2026-03-25T21:30:03Z",
    }
    execution = ac.sign_ecdsa_jcs_2022(execution, wallet, "2026-03-25T21:30:03Z")
    write(PAY, "03-payment-execution.json", execution)

    service_output = {"summary": "...", "tokens": 211}
    receipt = {
        "@context": PAY_CTX, "id": "urn:avp:receipt:222", "type": "PaymentReceipt",
        "quote": "urn:avp:quote:789", "execution": "urn:avp:exec:555",
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": amount, "currency": currency,
        "status": "fulfilled",
        "serviceOutputHash": ac.content_digest(ac.jcs(service_output)),
        "fulfilledAt": "2026-03-25T21:30:05Z",
    }
    receipt = ac.sign_ecdsa_jcs_2022(receipt, payee, "2026-03-25T21:30:05Z")
    write(PAY, "04-payment-receipt.json", receipt)

    # Streaming chain
    session = {
        "@context": PAY_CTX, "id": "urn:avp:session:001", "type": "UsageSession",
        "payer": DID_AGENT, "payee": DID_PAYEE, "currency": currency,
        "pricingModel": {"type": "PerUnit", "dimension": "dim:SensorSamples",
                         "unit": "aunit:Datapoint", "amount": "0.001"},
        "maxAmount": "0.50", "meterType": "dim:SensorSamples", "meterUnit": "aunit:Datapoint",
        "settlementMethod": settlement_method, "settlementTarget": settlement_target,
        "settlementMode": "deferred", "timestamp": "2026-03-25T21:40:00Z",
        "expires": "2026-03-25T22:00:00Z",
    }
    session = ac.sign_ecdsa_jcs_2022(session, payee, "2026-03-25T21:40:00Z")
    write(PAY, "05-usage-session.json", session)

    session_budget = {
        "@context": PAY_CTX, "id": "urn:avp:session-auth:aa",
        "type": "SessionBudgetAuthorization", "usageSession": "urn:avp:session:001",
        "sessionDigest": ac.jcs_digest(session), "payer": DID_AGENT, "payee": DID_PAYEE,
        "committedAmount": "0.50", "currency": currency,
        "timestamp": "2026-03-25T21:40:05Z", "expires": "2026-03-25T21:41:05Z",
        "nonce": "sess-n-88421", "wallet": DID_WALLET,
        "vp": {"@context": PAY_CTX, "type": "VerifiablePresentation",
               "verifiableCredential": [spendauth]},
    }
    session_budget = ac.sign_ecdsa_jcs_2022(session_budget, agent, "2026-03-25T21:40:05Z")
    write(PAY, "06-session-budget-authorization.json", session_budget)

    accrual = {
        "@context": PAY_CTX, "id": "urn:avp:usage:123", "type": "UsageAccrual",
        "session": "urn:avp:session:001", "accrualKind": "cumulative",
        "meterReading": "48", "amountAccrued": "0.048", "currency": currency,
        "sequence": 3, "timestamp": "2026-03-25T21:45:00Z",
    }
    accrual = ac.sign_ecdsa_jcs_2022(accrual, payee, "2026-03-25T21:45:00Z")
    write(PAY, "07-usage-accrual.json", accrual)

    session_exec = {
        "@context": PAY_CTX, "id": "urn:avp:exec:sess-1", "type": "PaymentExecution",
        "sessionBudgetAuthorization": "urn:avp:session-auth:aa", "amount": "0.048",
        "currency": currency, "status": "completed",
        "settlementRef": "internal-ledger://txn/sess-001", "timestamp": "2026-03-25T21:58:30Z",
    }
    session_exec = ac.sign_ecdsa_jcs_2022(session_exec, wallet, "2026-03-25T21:58:30Z")
    write(PAY, "08-payment-execution-session.json", session_exec)

    session_receipt = {
        "@context": PAY_CTX, "id": "urn:avp:receipt:sess-final", "type": "PaymentReceipt",
        "usageSession": "urn:avp:session:001", "execution": "urn:avp:exec:sess-1",
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.048", "currency": currency,
        "status": "fulfilled",
        "totalMeterReading": "48", "fulfilledAt": "2026-03-25T21:58:00Z",
    }
    session_receipt = ac.sign_ecdsa_jcs_2022(session_receipt, payee, "2026-03-25T21:58:00Z")
    write(PAY, "09-payment-receipt-session.json", session_receipt)

    extension = {
        "@context": PAY_CTX, "id": "urn:avp:session-ext:e1", "type": "UsageSessionExtension",
        "usageSession": "urn:avp:session:001", "sessionDigest": ac.jcs_digest(session),
        "newMaxAmount": "1.00", "newExpires": "2026-03-25T22:30:00Z",
        "timestamp": "2026-03-25T21:59:00Z",
    }
    extension = ac.sign_ecdsa_jcs_2022(extension, payee, "2026-03-25T21:59:00Z")
    write(PAY, "10-usage-session-extension.json", extension)

    session_budget2 = {
        "@context": PAY_CTX, "id": "urn:avp:session-auth:bb",
        "type": "SessionBudgetAuthorization", "usageSession": "urn:avp:session:001",
        "sessionDigest": ac.jcs_digest(session), "payer": DID_AGENT, "payee": DID_PAYEE,
        "committedAmount": "1.00", "currency": currency,
        "timestamp": "2026-03-25T21:59:05Z", "expires": "2026-03-25T22:30:00Z",
        "nonce": "sess-n-88422", "wallet": DID_WALLET,
        "vp": {"@context": PAY_CTX, "type": "VerifiablePresentation",
               "verifiableCredential": [spendauth]},
    }
    session_budget2 = ac.sign_ecdsa_jcs_2022(session_budget2, agent, "2026-03-25T21:59:05Z")
    write(PAY, "11-session-budget-authorization-2.json", session_budget2)

    # ---- Interop (SD-JWT-VC) bundle ----
    # Two P-256 (ES256) test keys: a bridge that signs export envelopes, and a
    # foreign issuer modelling a Verifiable-Intent / AP2 origin, resolved by DID.
    bridge = sdjwt.seed_p256("bridge-exporter")
    vi_issuer = sdjwt.seed_p256("vi-issuer")
    # Same-key co-issuance: the co-issued SD-JWT is signed with the DSA issuer's OWN
    # P-256 key -- the same key behind its did:key ecdsa-jcs-2022 verification method,
    # just presented under a did:web identifier for the JOSE side.
    coissuer_p256 = issuer
    attestor = ac.seed_key("bridge-attestor")  # re-issues in attested mode (P-256 did:key)
    DID_BRIDGE = "did:web:bridge.example"
    DID_VI_ISSUER = "did:web:issuer.example"
    DID_COISSUER = "did:web:acme.example"
    DID_ATTESTOR = ac.did_key(attestor.public_key())
    bridge_jwk = sdjwt.p256_public_jwk(bridge.public_key())
    vi_issuer_jwk = sdjwt.p256_public_jwk(vi_issuer.public_key())
    coissuer_jwk = sdjwt.p256_public_jwk(coissuer_p256.public_key())

    write(INTEROP, "keys.json", {
        "_warning": "TEST KEYS ONLY. P-256 scalars are derived deterministically; do not reuse.",
        "bridgeExporter": {"did": DID_BRIDGE, "kid": DID_BRIDGE + "#key-1", "jwk": bridge_jwk},
        "viIssuer": {"did": DID_VI_ISSUER, "kid": DID_VI_ISSUER + "#key-1", "jwk": vi_issuer_jwk},
        "coIssuer": {"did": DID_COISSUER, "kid": DID_COISSUER + "#es", "jwk": coissuer_jwk,
                     "note": "Same P-256 key as the did:key DSA issuer's verification method "
                             "(one principal, two DID forms); the co-issued ES256 SD-JWT is "
                             "signed with that same key."},
        "attestingBridge": {"did": DID_ATTESTOR},
        # did:web binding convention: iss -> resolvable P-256 verification method
        "didWebResolver": {DID_BRIDGE: bridge_jwk, DID_VI_ISSUER: vi_issuer_jwk, DID_COISSUER: coissuer_jwk},
        # explicit trust list a verifier MUST consult before honoring an attested object
        "trustedBridges": [DID_ATTESTOR],
    })

    # A->V: export the real DSA SpendingAuthorizationCredential (proof-preserving;
    # authority carried in avp_vc, envelope signed by the bridge).
    export_compact = interop.avp_to_sdjwtvc(spendauth, bridge, DID_BRIDGE + "#key-1", embedded=True)
    write(INTEROP, "01-export-sdjwtvc.json", {
        "_note": "A->V export of authority/spending-authorization-credential.json (proof-preserving, vct ...+embedded).",
        "securingMode": "proof-preserving",
        "envelopeSigner": DID_BRIDGE + "#key-1",
        "compact": export_compact,
        "payload": sdjwt.jws_payload(sdjwt.sdjwt_jws(export_compact)),
    })

    # A->V->A: re-import the export back into an EmbeddedSdJwtVcMandate.
    imported = interop.sdjwtvc_to_avp(export_compact, "proof-preserving")
    write(INTEROP, "02-imported-mandate.json", imported)

    # Foreign V-origin mandate (ES256 by the VI issuer; no avp_vc -- the signature
    # IS the authority), modelling a Verifiable-Intent / AP2 credential.
    foreign_claims = {
        "vct": interop.VCT_PLAIN,
        "iss": DID_VI_ISSUER,
        "sub": DID_AGENT,
        "cnf": {"jwk": sdjwt.p256_public_jwk(agent.public_key())},
        "currency": "USD",
        "limits": {"per_txn": "0.10", "per_day": "10.00"},
        "allowed_payees": [DID_PAYEE],
        "nbf": interop.iso_to_numericdate("2026-04-01T00:00:00Z"),
        "exp": interop.iso_to_numericdate("2026-07-01T00:00:00Z"),
        "jti": "urn:vi:mandate:foreign:001",
        "status": {"status_list": {"idx": 12, "uri": "https://issuer.example/status/9"}},
    }
    foreign_header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_VI_ISSUER + "#key-1"}
    foreign_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(foreign_header, foreign_claims, vi_issuer))
    write(INTEROP, "03-foreign-sdjwtvc.json", {
        "_note": "A foreign Verifiable-Intent / AP2-style SD-JWT-VC mandate (ES256, did:web issuer).",
        "compact": foreign_compact,
        "payload": foreign_claims,
    })

    # V->A: import the foreign mandate (proof-preserving; authority is the embedded
    # ES256 verified against the issuer's did:web P-256 key).
    imported_foreign = interop.sdjwtvc_to_avp(foreign_compact, "proof-preserving")
    write(INTEROP, "04-imported-from-foreign.json", imported_foreign)

    # Co-issued: the same principal signs both forms with the SAME P-256 key. The outer
    # EmbeddedSdJwtVcMandate carries a native ecdsa-jcs-2022 proof (P-256 did:key issuer)
    # AND an embedded SD-JWT-VC the issuer signed in ES256 with that same key (did:web).
    # Authority is the outer proof; the embedded form is a parallel representation.
    ci_claims = {
        "vct": interop.VCT_PLAIN, "iss": DID_COISSUER, "sub": DID_AGENT,
        "cnf": {"jwk": sdjwt.p256_public_jwk(agent.public_key())},
        "currency": "USD", "limits": {"per_txn": "0.05", "per_day": "5.00"},
        "allowed_payees": [DID_PAYEE],
        "nbf": interop.iso_to_numericdate("2026-03-25T20:00:00Z"),
        "exp": interop.iso_to_numericdate("2026-06-25T20:00:00Z"),
        "jti": "urn:dsa:vc:spendauth:456",
        "status": {"status_list": {"idx": 94567, "uri": "https://issuer.example/status/3"}},
    }
    ci_header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_COISSUER + "#es"}
    ci_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(ci_header, ci_claims, coissuer_p256))
    coissued = {
        "@context": list(interop.INTEROP_CTX),
        "id": "urn:dsa:vc:spendauth:coissued:456",
        "type": ["VerifiableCredential", "SpendingAuthorizationCredential"],
        "issuer": DID_ISSUER,
        "validFrom": "2026-03-25T20:00:00Z", "validUntil": "2026-06-25T20:00:00Z",
        "credentialStatus": spendauth["credentialStatus"],
        "credentialSubject": spendauth["credentialSubject"],
    }
    coissued = interop.secure(coissued, mode="co-issued", carrier=interop.CARRIER_SDJWT,
                              embedded=ci_compact, source_vct=interop.VCT_PLAIN)
    coissued = ac.sign_ecdsa_jcs_2022(coissued, issuer, "2026-03-25T20:00:06Z")
    write(INTEROP, "05-coissued-mandate.json", coissued)

    # L3 / per-purchase: A->V present the PaymentAuthorization as the mandate SD-JWT
    # plus an agent-signed key-binding JWT (ES256) carrying the economic terms.
    presentation = interop.payment_authorization_to_presentation(authz, export_compact, agent)
    write(INTEROP, "06-l3-presentation.json", {
        "_note": "A->V of payments/02-payment-authorization.json: mandate SD-JWT + agent key-binding JWT (L3).",
        "securingMode": "proof-preserving",
        "presentation": presentation,
        "kbJwtPayload": sdjwt.jws_payload(presentation.split("~")[-1]),
    })

    # V->A: reconstruct the PaymentAuthorization from the presentation.
    imported_authz = interop.presentation_to_payment_authorization(presentation, "proof-preserving")
    write(INTEROP, "07-imported-payment-authorization.json", imported_authz)

    # Attested: a named bridge verifies the foreign mandate and re-issues it in
    # AVP-Micro form signed by its OWN key. The bridge becomes the trust root; a
    # verifier MUST have DID_ATTESTOR on its trusted-bridge list (see keys.json).
    attested = interop.sdjwtvc_to_avp(foreign_compact, "attested")
    attested["id"] = "urn:dsa:vc:spendauth:attested:001"
    attested["issuer"] = DID_ATTESTOR
    attested["securing"]["attestingBridge"] = DID_ATTESTOR
    attested = ac.sign_ecdsa_jcs_2022(attested, attestor, "2026-04-01T00:01:00Z")
    write(INTEROP, "08-attested-mandate.json", attested)

    # Lossy case 1 -- interactive L2: a foreign mandate that expresses fresh
    # per-purchase human intent (intent_mode=interactive). Import MUST flag it.
    il2_claims = {
        "vct": interop.VCT_PLAIN, "iss": DID_VI_ISSUER, "sub": DID_AGENT,
        "cnf": {"jwk": sdjwt.p256_public_jwk(agent.public_key())},
        "currency": "USD", "limits": {"per_txn": "0.10", "per_day": "10.00"},
        "allowed_payees": [DID_PAYEE], "intent_mode": "interactive",
        "nbf": interop.iso_to_numericdate("2026-04-01T00:00:00Z"),
        "exp": interop.iso_to_numericdate("2026-07-01T00:00:00Z"),
        "jti": "urn:vi:mandate:interactive:001",
    }
    il2_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(foreign_header, il2_claims, vi_issuer))
    imported_il2 = interop.sdjwtvc_to_avp(il2_compact, "proof-preserving")
    write(INTEROP, "09-imported-interactive-l2.json", imported_il2)

    # Lossy case 2 -- partial selective disclosure: a foreign mandate where
    # `currency` and `allowed_payees` are selectively disclosable, presented with the
    # `currency` disclosure WITHHELD. Import yields a subset view and MUST flag it.
    d_payees = sdjwt.make_disclosure("salt-allowed-payees", "allowed_payees", [DID_PAYEE])
    d_currency = sdjwt.make_disclosure("salt-currency", "currency", "USD")
    sd_claims = {
        "vct": interop.VCT_PLAIN, "iss": DID_VI_ISSUER, "sub": DID_AGENT,
        "cnf": {"jwk": sdjwt.p256_public_jwk(agent.public_key())},
        "limits": {"per_txn": "0.10", "per_day": "10.00"},
        "_sd": [sdjwt.disclosure_digest(d_payees), sdjwt.disclosure_digest(d_currency)],
        "_sd_alg": "sha-256",
        "nbf": interop.iso_to_numericdate("2026-04-01T00:00:00Z"),
        "exp": interop.iso_to_numericdate("2026-07-01T00:00:00Z"),
        "jti": "urn:vi:mandate:sd:001",
    }
    sd_jws = sdjwt.es256_sign(foreign_header, sd_claims, vi_issuer)
    # present allowed_payees, WITHHOLD currency
    partial_presentation = sd_jws + "~" + d_payees + "~"
    imported_partial = interop.sdjwtvc_to_avp(partial_presentation, "proof-preserving")
    write(INTEROP, "10-imported-partial-sd.json", imported_partial)

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
    imported_auto = interop.add_advisories(imported_auto, [
        "autonomous: no human-present PurchaseConfirmation present; standing delegation only"])
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

    # 17 (interop bundle): EXPORT direction -- a native AVP PurchaseConfirmation projected
    # back out to an AP2 human-present cart approval, signed by the SAME principal key (both
    # stacks are P-256), then re-imported to show the §7 case round-trips A->V->A losslessly.
    exported_claims = interop.export_purchase_confirmation(native_conf)
    exported_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_ISSUER + "#" + DID_ISSUER.split(":")[-1]},
        exported_claims, issuer))
    reimported = interop.import_cart_user_confirmation(
        exported_compact, quote_digest=native_conf["quoteDigest"], agent_did=native_conf["payer"],
        payee=native_conf["payee"], amount=native_conf["amount"], currency=native_conf["currency"],
        service_request_hash=native_conf["serviceRequestHash"],
        confirmed_by=native_conf["confirmedBy"], quote=native_conf["quote"], mode="proof-preserving")
    write(INTEROP, "17-exported-cart-user-approval.json", {
        "_note": "EXPORT (A->V): a native PurchaseConfirmation projected to an AP2 human-present "
                 "cart approval (ES256, signed by the principal's own key), then re-imported to "
                 "show the human-present case round-trips losslessly.",
        "exportedClaims": exported_claims,
        "compact": exported_compact,
        "reimportedProjection": reimported})


if __name__ == "__main__":
    main()
