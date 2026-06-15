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
import settlement as st
import sdjwt
import status as stx

SPEC = Path(__file__).parent
AUTH = SPEC / "authority" / "test-vectors"
PAY = SPEC / "payments" / "test-vectors"
INTEROP = SPEC / "interop-sd-jwt-vc" / "test-vectors"
DISP = SPEC / "disputes" / "test-vectors"

VC2 = "https://www.w3.org/ns/credentials/v2"
DI = "https://w3id.org/security/data-integrity/v2"
DSA = "https://w3id.org/spending-authority/v1"
AVP = "https://w3id.org/avp-micro/v1"
DSA_CTX = [VC2, DI, DSA]
PAY_CTX = [VC2, DI, DSA, AVP]
DISP_URL = "https://w3id.org/avp-micro/disputes/v1"
DISP_CTX = [VC2, DI, DSA, AVP, DISP_URL]
SETTLE_URL = "https://w3id.org/avp-micro/settlement/v1"
SETTLE_CTX = [VC2, DI, DSA, AVP, SETTLE_URL]
SETTLE = SPEC / "settlement" / "test-vectors"
TXP_URL = "https://w3id.org/avp-micro/transport/v1"
TXP_CTX = [VC2, DI, DSA, AVP, TXP_URL]
TXP = SPEC / "transport" / "test-vectors"
RAIL_EVM = SETTLE_URL + "#rail-evm-stablecoin"
RAIL_X402 = SETTLE_URL + "#rail-x402"

issuer = ac.seed_key("issuer-acme-corp")
agent = ac.seed_key("agent-buyer-01")
payee = ac.seed_key("service-tool-api")
wallet = ac.seed_key("wallet-acme")
arbiter = ac.seed_key("arbiter-org")

DID_ISSUER = ac.did_key(issuer.public_key())
DID_AGENT = ac.did_key(agent.public_key())
DID_PAYEE = ac.did_key(payee.public_key())
DID_WALLET = ac.did_key(wallet.public_key())
DID_ARBITER = ac.did_key(arbiter.public_key())


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

    # Bitstring Status List v1.0: the actual status list the SAC's credentialStatus points
    # to, in two states. The active list has every bit 0; the revoked list sets the SAC's
    # index and is published AFTER the authorization (a credential revoked mid-flight).
    _sac_status = spendauth["credentialStatus"]
    _sac_idx = int(_sac_status["statusListIndex"])
    status_active = {
        "@context": [VC2, DI],
        "id": _sac_status["statusListCredential"],
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": DID_ISSUER,
        "validFrom": "2026-03-25T19:00:00Z",
        "validUntil": "2026-06-25T20:00:00Z",
        "credentialSubject": {
            "id": _sac_status["statusListCredential"] + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": stx.encode_status_list(set()),
        },
    }
    status_active = ac.sign_ecdsa_jcs_2022(status_active, issuer, "2026-03-25T19:00:01Z")
    write(AUTH, "status-list-active.json", status_active)

    status_revoked = {
        "@context": [VC2, DI],
        "id": _sac_status["statusListCredential"] + "?ts=2026-03-26",
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": DID_ISSUER,
        "validFrom": "2026-03-26T09:00:00Z",
        "validUntil": "2026-06-25T20:00:00Z",
        "credentialSubject": {
            "id": _sac_status["statusListCredential"] + "#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": stx.encode_status_list({_sac_idx}),
        },
    }
    status_revoked = ac.sign_ecdsa_jcs_2022(status_revoked, issuer, "2026-03-26T09:00:01Z")
    write(AUTH, "status-list-revoked.json", status_revoked)

    merchant = {
        "@context": DSA_CTX,
        "id": "urn:dsa:vc:merchant:001",
        "type": ["VerifiableCredential", "MerchantCredential"],
        "issuer": DID_ISSUER,
        "validFrom": "2026-03-25T20:00:00Z",
        "validUntil": "2026-09-25T20:00:00Z",
        "credentialStatus": {
            "id": "https://issuer.example/status/3#1042",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "1042",
            "statusListCredential": "https://issuer.example/status/3",
        },
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
        "validFrom": "2026-03-25T20:00:00Z",
        "validUntil": "2026-09-25T20:00:00Z",
        "credentialStatus": {
            "id": "https://wallet.example.com/status/1#77",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "77",
            "statusListCredential": "https://wallet.example.com/status/1",
        },
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
                             "allowedCategories": ["cat:ChatCompletionApi"]}}
        ],
    })

    write(AUTH, "dids.json", {
        "_warning": "TEST KEYS ONLY. Seeds are derived deterministically; do not reuse.",
        "principalIssuer": DID_ISSUER, "payerAgent": DID_AGENT,
        "payeeService": DID_PAYEE, "walletService": DID_WALLET,
        "arbiter": DID_ARBITER,
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
        "payer": DID_AGENT, "payee": DID_PAYEE, "requestHash": srh,
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
        "requestHash": srh, "timestamp": "2026-03-25T21:30:02Z",
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
        "outputHash": ac.content_digest(ac.jcs(service_output)),
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

    # ---- Disputes bundle (refunds, reversals, dispute lifecycle) ----
    # Reverse value-flow. Voluntary refunds + the adversarial dispute lifecycle
    # converge on a wallet-signed Reversal. Originals reused from the bundle above:
    #   one-off:   execution(urn:avp:exec:555)/receipt(urn:avp:receipt:222) = 0.001
    #   streaming: session_exec(urn:avp:exec:sess-1)/session_receipt(...sess-final) = 0.048

    # 20: voluntary partial refund against the streaming receipt (payee-signed intent)
    refund = {
        "@context": DISP_CTX, "id": "urn:avp:refund:01", "type": "Refund",
        "receipt": "urn:avp:receipt:sess-final", "receiptDigest": ac.jcs_digest(session_receipt),
        "execution": "urn:avp:exec:sess-1", "executionDigest": ac.jcs_digest(session_exec),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.010", "currency": currency,
        "reason": "disp:incorrect-amount",
        "note": "Refunding 10 miscounted sensor samples.",
        "timestamp": "2026-03-26T09:00:00Z",
    }
    refund = ac.sign_ecdsa_jcs_2022(refund, payee, "2026-03-26T09:00:00Z")
    write(DISP, "20-refund.json", refund)

    # 21: wallet-signed settlement fact for the refund (cause=refund)
    reversal_refund = {
        "@context": DISP_CTX, "id": "urn:avp:reversal:01", "type": "Reversal",
        "cause": "refund",
        "refund": "urn:avp:refund:01", "refundDigest": ac.jcs_digest(refund),
        "execution": "urn:avp:exec:sess-1", "executionDigest": ac.jcs_digest(session_exec),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.010", "currency": currency,
        "status": "completed", "settlementRef": "internal-ledger://txn/refund-01",
        "timestamp": "2026-03-26T09:05:00Z",
    }
    reversal_refund = ac.sign_ecdsa_jcs_2022(reversal_refund, wallet, "2026-03-26T09:05:00Z")
    write(DISP, "21-reversal-refund.json", reversal_refund)

    # 22: optional payer-signed acknowledgement of funds received
    reversal_ack = {
        "@context": DISP_CTX, "id": "urn:avp:reversal-ack:01", "type": "ReversalAcknowledgement",
        "reversal": "urn:avp:reversal:01", "reversalDigest": ac.jcs_digest(reversal_refund),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.010", "currency": currency,
        "receivedAt": "2026-03-26T09:10:00Z",
    }
    reversal_ack = ac.sign_ecdsa_jcs_2022(reversal_ack, agent, "2026-03-26T09:10:00Z")
    write(DISP, "22-reversal-ack.json", reversal_ack)

    # 23: a second partial refund (receipt-only binding; intent without settlement yet)
    refund2 = {
        "@context": DISP_CTX, "id": "urn:avp:refund:02", "type": "Refund",
        "receipt": "urn:avp:receipt:sess-final", "receiptDigest": ac.jcs_digest(session_receipt),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.008", "currency": currency,
        "reason": "disp:goodwill", "note": "Goodwill credit for slow response.",
        "timestamp": "2026-03-26T09:20:00Z",
    }
    refund2 = ac.sign_ecdsa_jcs_2022(refund2, payee, "2026-03-26T09:20:00Z")
    write(DISP, "23-refund-partial.json", refund2)

    # 30: payer opens a dispute against the streaming charge (proposes an arbiter)
    dispute = {
        "@context": DISP_CTX, "id": "urn:avp:dispute:01", "type": "Dispute",
        "execution": "urn:avp:exec:sess-1", "executionDigest": ac.jcs_digest(session_exec),
        "receipt": "urn:avp:receipt:sess-final", "receiptDigest": ac.jcs_digest(session_receipt),
        "payer": DID_AGENT, "payee": DID_PAYEE, "disputedAmount": "0.020", "currency": currency,
        "reason": "disp:not-delivered",
        "claim": "Sensor stream dropped ~40% of samples after 21:50; charged for undelivered data.",
        "arbiter": DID_ARBITER,
        "timestamp": "2026-03-26T10:00:00Z", "respondBy": "2026-03-29T10:00:00Z",
    }
    dispute = ac.sign_ecdsa_jcs_2022(dispute, agent, "2026-03-26T10:00:00Z")
    write(DISP, "30-dispute.json", dispute)

    # 31: payee representment evidence (sequence 1)
    ev_payee = {
        "@context": DISP_CTX, "id": "urn:avp:dispute-evidence:01", "type": "DisputeEvidence",
        "dispute": "urn:avp:dispute:01", "disputeDigest": ac.jcs_digest(dispute),
        "submittedBy": DID_PAYEE, "role": "payee", "sequence": 1,
        "evidenceType": "delivery-log",
        "contentDigest": ac.content_digest(ac.jcs({"samples_delivered": 48})),
        "uri": "https://provider.com/evidence/stream-log-001",
        "statement": "Delivery log shows 48 samples accepted by the client endpoint.",
        "timestamp": "2026-03-26T11:00:00Z",
    }
    ev_payee = ac.sign_ecdsa_jcs_2022(ev_payee, payee, "2026-03-26T11:00:00Z")
    write(DISP, "31-dispute-evidence-payee.json", ev_payee)

    # 32: payer rebuttal evidence (sequence 2)
    ev_payer = {
        "@context": DISP_CTX, "id": "urn:avp:dispute-evidence:02", "type": "DisputeEvidence",
        "dispute": "urn:avp:dispute:01", "disputeDigest": ac.jcs_digest(dispute),
        "submittedBy": DID_AGENT, "role": "payer", "sequence": 2,
        "evidenceType": "client-trace",
        "contentDigest": ac.content_digest(ac.jcs({"samples_persisted": 29})),
        "statement": "Client trace persisted only 29 samples; gaps align with the 21:50 window.",
        "timestamp": "2026-03-26T12:00:00Z",
    }
    ev_payer = ac.sign_ecdsa_jcs_2022(ev_payer, agent, "2026-03-26T12:00:00Z")
    write(DISP, "32-dispute-evidence-payer.json", ev_payer)

    # 33: payee resolution (partial)
    res_payee = {
        "@context": DISP_CTX, "id": "urn:avp:dispute-resolution:01", "type": "DisputeResolution",
        "dispute": "urn:avp:dispute:01", "disputeDigest": ac.jcs_digest(dispute),
        "resolvedBy": DID_PAYEE, "resolverRole": "payee",
        "outcome": "partial", "resolvedAmount": "0.010", "currency": currency,
        "note": "Offer to credit half the disputed window as goodwill.",
        "timestamp": "2026-03-27T09:00:00Z",
    }
    res_payee = ac.sign_ecdsa_jcs_2022(res_payee, payee, "2026-03-27T09:00:00Z")
    write(DISP, "33-dispute-resolution-payee.json", res_payee)

    # 34: arbiter resolution (upheld), superseding the payee resolution (escalation)
    res_arbiter = {
        "@context": DISP_CTX, "id": "urn:avp:dispute-resolution:02", "type": "DisputeResolution",
        "dispute": "urn:avp:dispute:01", "disputeDigest": ac.jcs_digest(dispute),
        "resolvedBy": DID_ARBITER, "resolverRole": "arbiter",
        "outcome": "upheld", "resolvedAmount": "0.015", "currency": currency,
        "supersedes": "urn:avp:dispute-resolution:01", "supersedesDigest": ac.jcs_digest(res_payee),
        "note": "Arbiter finds 75% of the disputed window undelivered; awards 0.015.",
        "timestamp": "2026-03-28T09:00:00Z",
    }
    res_arbiter = ac.sign_ecdsa_jcs_2022(res_arbiter, arbiter, "2026-03-28T09:00:00Z")
    write(DISP, "34-dispute-resolution-arbiter.json", res_arbiter)

    # 35: wallet-signed settlement fact for the upheld dispute (cause=dispute = chargeback)
    reversal_dispute = {
        "@context": DISP_CTX, "id": "urn:avp:reversal:02", "type": "Reversal",
        "cause": "dispute",
        "resolution": "urn:avp:dispute-resolution:02", "resolutionDigest": ac.jcs_digest(res_arbiter),
        "execution": "urn:avp:exec:sess-1", "executionDigest": ac.jcs_digest(session_exec),
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.015", "currency": currency,
        "status": "completed", "settlementRef": "internal-ledger://txn/chargeback-01",
        "timestamp": "2026-03-28T10:00:00Z",
    }
    reversal_dispute = ac.sign_ecdsa_jcs_2022(reversal_dispute, wallet, "2026-03-28T10:00:00Z")
    write(DISP, "35-reversal-dispute.json", reversal_dispute)

    # 36 + 37: a separate dispute that is REJECTED (no reversal)
    dispute_r = {
        "@context": DISP_CTX, "id": "urn:avp:dispute:02", "type": "Dispute",
        "receipt": "urn:avp:receipt:222", "receiptDigest": ac.jcs_digest(receipt),
        "execution": "urn:avp:exec:555", "executionDigest": ac.jcs_digest(execution),
        "payer": DID_AGENT, "payee": DID_PAYEE, "disputedAmount": "0.001", "currency": currency,
        "reason": "disp:quality", "claim": "Summary quality was poor.",
        "arbiter": DID_ARBITER, "timestamp": "2026-03-26T14:00:00Z",
    }
    dispute_r = ac.sign_ecdsa_jcs_2022(dispute_r, agent, "2026-03-26T14:00:00Z")
    write(DISP, "36-dispute-rejected.json", dispute_r)

    res_rejected = {
        "@context": DISP_CTX, "id": "urn:avp:dispute-resolution:03", "type": "DisputeResolution",
        "dispute": "urn:avp:dispute:02", "disputeDigest": ac.jcs_digest(dispute_r),
        "resolvedBy": DID_PAYEE, "resolverRole": "payee",
        "outcome": "rejected", "resolvedAmount": "0", "currency": currency,
        "note": "Output matched the agreed scope; subjective quality is not a billing defect.",
        "timestamp": "2026-03-27T14:00:00Z",
    }
    res_rejected = ac.sign_ecdsa_jcs_2022(res_rejected, payee, "2026-03-27T14:00:00Z")
    write(DISP, "37-dispute-resolution-rejected.json", res_rejected)

    # 38 + 39: a separate dispute that is WITHDRAWN by the payer (no reversal)
    dispute_w = {
        "@context": DISP_CTX, "id": "urn:avp:dispute:03", "type": "Dispute",
        "receipt": "urn:avp:receipt:222", "receiptDigest": ac.jcs_digest(receipt),
        "payer": DID_AGENT, "payee": DID_PAYEE, "disputedAmount": "0.001", "currency": currency,
        "reason": "disp:duplicate", "claim": "Possible duplicate of an earlier charge.",
        "timestamp": "2026-03-26T15:00:00Z",
    }
    dispute_w = ac.sign_ecdsa_jcs_2022(dispute_w, agent, "2026-03-26T15:00:00Z")
    write(DISP, "38-dispute-withdrawn.json", dispute_w)

    res_withdrawn = {
        "@context": DISP_CTX, "id": "urn:avp:dispute-resolution:04", "type": "DisputeResolution",
        "dispute": "urn:avp:dispute:03", "disputeDigest": ac.jcs_digest(dispute_w),
        "resolvedBy": DID_AGENT, "resolverRole": "payer",
        "outcome": "withdrawn", "resolvedAmount": "0", "currency": currency,
        "note": "Reconciled internally; not a duplicate. Withdrawing.",
        "timestamp": "2026-03-27T15:00:00Z",
    }
    res_withdrawn = ac.sign_ecdsa_jcs_2022(res_withdrawn, agent, "2026-03-27T15:00:00Z")
    write(DISP, "39-dispute-resolution-withdrawn.json", res_withdrawn)

    # ---- Settlement bundle (on-chain settlement binding) ----
    # Rides on Payments by reference: a SettlementInstruction binds the existing
    # PaymentAuthorization (urn:avp:authz:999, 0.001 USD) to a concrete rail; a
    # SettlementProof carries the chain-native transaction + finality. Chain data
    # (tx hashes, heights, preimages) are DETERMINISTIC FIXTURES -- nothing is broadcast.
    authz_digest = ac.jcs_digest(authz)
    usdc = st.RAILS["evm-stablecoin"]["asset"]
    evm_threshold = st.RAILS["evm-stablecoin"]["threshold"]

    # EVM payee: the AUTHORIZED payee (did:key DID_PAYEE) bound to its chain account by
    # a payee-signed PayeeAccountBinding. Settlement MUST pay the authorized payee, so the
    # instruction names that payee and the binding proves which account is theirs (a
    # did:pkh that is NOT the authorized payee would let a wallet redirect funds).
    evm_addr = st.fake_address("payee-evm")
    evm_account = "eip155:8453:" + evm_addr
    binding_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:payee-binding:evm", "type": "PayeeAccountBinding",
        "subject": DID_PAYEE, "account": evm_account, "chain": "eip155:8453",
    }
    binding_evm = ac.sign_ecdsa_jcs_2022(binding_evm, payee, "2026-03-25T21:29:20Z")
    write(SETTLE, "56-payee-account-binding-evm.json", binding_evm)

    # 41: EVM stablecoin SettlementInstruction (direct), did:pkh payee.
    instr_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:evm", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-evm-stablecoin", "chain": "eip155:8453",
        "payeeAccount": evm_account, "asset": usdc,
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": evm_threshold, "mode": "direct",
        "payeeAccountBinding": binding_evm["id"],
        "nonce": "settle-evm-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_evm = ac.sign_ecdsa_jcs_2022(instr_evm, wallet, "2026-03-25T21:30:10Z")
    write(SETTLE, "41-settlement-instruction-evm.json", instr_evm)

    # 42: EVM SettlementProof (final at >= threshold confirmations).
    proof_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:evm", "type": "SettlementProof",
        "instruction": instr_evm["id"], "instructionDigest": ac.jcs_digest(instr_evm),
        "execution": execution["id"], "chain": "eip155:8453",
        "transaction": st.fake_tx("evm-direct"),
        "settledAmountBase": instr_evm["amountBase"], "asset": usdc,
        "blockHeight": 19000000, "confirmations": evm_threshold, "finality": "final",
        "observedAt": "2026-03-25T21:33:00Z",
    }
    proof_evm = ac.sign_ecdsa_jcs_2022(proof_evm, wallet, "2026-03-25T21:33:00Z")
    write(SETTLE, "42-settlement-proof-evm.json", proof_evm)

    # x402 uses a did:key payee (the existing DID_PAYEE) + a PayeeAccountBinding
    # (binding archetype (b)): the payee signs that it controls a CAIP-10 account.
    x402_addr = st.fake_address("payee-x402")
    x402_account = "eip155:8453:" + x402_addr

    # 40: PayeeAccountBinding (payee-signed).
    binding = {
        "@context": SETTLE_CTX, "id": "urn:avp:payee-binding:x402", "type": "PayeeAccountBinding",
        "subject": DID_PAYEE, "account": x402_account, "chain": "eip155:8453",
    }
    binding = ac.sign_ecdsa_jcs_2022(binding, payee, "2026-03-25T21:29:30Z")
    write(SETTLE, "40-payee-account-binding.json", binding)

    # 43: x402 SettlementInstruction (direct) referencing the binding.
    instr_x402 = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:x402", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-x402", "chain": "eip155:8453",
        "payeeAccount": x402_account, "asset": usdc,
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": st.RAILS["x402"]["threshold"], "mode": "direct",
        "payeeAccountBinding": binding["id"],
        "nonce": "settle-x402-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_x402 = ac.sign_ecdsa_jcs_2022(instr_x402, wallet, "2026-03-25T21:30:11Z")
    write(SETTLE, "43-settlement-instruction-x402.json", instr_x402)

    # 44: x402 SettlementProof (final).
    proof_x402 = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:x402", "type": "SettlementProof",
        "instruction": instr_x402["id"], "instructionDigest": ac.jcs_digest(instr_x402),
        "execution": execution["id"], "chain": "eip155:8453",
        "transaction": st.fake_tx("x402-direct"),
        "settledAmountBase": instr_x402["amountBase"], "asset": usdc,
        "blockHeight": 19000005, "confirmations": st.RAILS["x402"]["threshold"], "finality": "final",
        "observedAt": "2026-03-25T21:33:30Z",
    }
    proof_x402 = ac.sign_ecdsa_jcs_2022(proof_x402, wallet, "2026-03-25T21:33:30Z")
    write(SETTLE, "44-settlement-proof-x402.json", proof_x402)

    # Lightning: USD quote settled in msat at an agreed USD/BTC rate; escrow is the
    # native hold-invoice. payee is the did:key DID_PAYEE bound to a node pubkey.
    ln_asset = st.RAILS["lightning"]["asset"]
    ln_chain = "bip122:000000000019d6689c085ae165831e93"
    ln_rate = "100000"  # USD per BTC (fixture)
    ln_base = st.usd_to_msat(amount, ln_rate)  # 0.001 USD @ 100000 -> 1000 msat
    ln_node = "02" + st.fake_address("payee-ln-node")[2:]  # 33-byte-ish pubkey fixture
    ln_invoice = "lnbc10n1p" + st.fake_preimage("ln-invoice")[:40]
    ln_payment_hash = st.fake_payment_hash("ln-hold")
    ln_preimage = st.fake_preimage("ln-hold")

    # 45: Lightning SettlementInstruction (escrow / hold-invoice).
    instr_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:ln", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-lightning", "chain": ln_chain,
        "payeeAccount": ln_invoice, "asset": ln_asset,
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency, "amountBase": ln_base, "rate": ln_rate,
        "confirmationThreshold": st.RAILS["lightning"]["threshold"], "mode": "escrow",
        "nonce": "settle-ln-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_ln = ac.sign_ecdsa_jcs_2022(instr_ln, wallet, "2026-03-25T21:30:12Z")
    write(SETTLE, "45-settlement-instruction-lightning.json", instr_ln)

    # 46: EscrowLock (hold-invoice held).
    lock_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-lock:ln", "type": "EscrowLock",
        "instruction": instr_ln["id"], "instructionDigest": ac.jcs_digest(instr_ln),
        "lockRef": "ln-hold:" + ln_payment_hash, "lockedAmountBase": ln_base, "asset": ln_asset,
        "timeout": "2026-03-25T22:30:00Z",
    }
    lock_ln = ac.sign_ecdsa_jcs_2022(lock_ln, wallet, "2026-03-25T21:30:40Z")
    write(SETTLE, "46-escrow-lock-lightning.json", lock_ln)

    # 47: Lightning SettlementProof (preimage reveal == finality; no confirmations).
    proof_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:ln", "type": "SettlementProof",
        "instruction": instr_ln["id"], "instructionDigest": ac.jcs_digest(instr_ln),
        "execution": execution["id"], "chain": ln_chain,
        "transaction": ln_payment_hash, "preimage": ln_preimage,
        "settledAmountBase": ln_base, "asset": ln_asset, "finality": "final",
        "observedAt": "2026-03-25T21:34:00Z",
    }
    proof_ln = ac.sign_ecdsa_jcs_2022(proof_ln, wallet, "2026-03-25T21:34:00Z")
    write(SETTLE, "47-settlement-proof-lightning.json", proof_ln)

    # 48: EscrowRelease (settles the hold-invoice to the payee, carrying the proof).
    release_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-release:ln", "type": "EscrowRelease",
        "lock": lock_ln["id"], "lockDigest": ac.jcs_digest(lock_ln),
        "settlementProof": proof_ln["id"], "settlementProofDigest": ac.jcs_digest(proof_ln),
    }
    release_ln = ac.sign_ecdsa_jcs_2022(release_ln, wallet, "2026-03-25T21:34:10Z")
    write(SETTLE, "48-escrow-release-lightning.json", release_ln)

    # EVM escrow with a TIMEOUT -> refund to the payer (the EscrowRefund path).
    # 49: EVM escrow SettlementInstruction.
    instr_evm_esc = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:evm-escrow", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-evm-stablecoin", "chain": "eip155:8453",
        "payeeAccount": evm_account, "asset": usdc,
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": evm_threshold, "mode": "escrow",
        "payeeAccountBinding": binding_evm["id"],
        "nonce": "settle-evm-esc-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_evm_esc = ac.sign_ecdsa_jcs_2022(instr_evm_esc, wallet, "2026-03-25T21:30:13Z")
    write(SETTLE, "49-settlement-instruction-evm-escrow.json", instr_evm_esc)

    # 50: EscrowLock (escrow contract holds the funds).
    lock_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-lock:evm", "type": "EscrowLock",
        "instruction": instr_evm_esc["id"], "instructionDigest": ac.jcs_digest(instr_evm_esc),
        "lockRef": st.fake_address("escrow-contract") + ":42", "lockedAmountBase": instr_evm_esc["amountBase"],
        "asset": usdc, "timeout": "2026-03-25T21:45:00Z",
    }
    lock_evm = ac.sign_ecdsa_jcs_2022(lock_evm, wallet, "2026-03-25T21:31:00Z")
    write(SETTLE, "50-escrow-lock-evm.json", lock_evm)

    # 51: SettlementProof for the refund transaction (funds returned to payer; final).
    proof_evm_refund = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:evm-refund", "type": "SettlementProof",
        "instruction": instr_evm_esc["id"], "instructionDigest": ac.jcs_digest(instr_evm_esc),
        "chain": "eip155:8453", "transaction": st.fake_tx("evm-refund"),
        "settledAmountBase": instr_evm_esc["amountBase"], "asset": usdc,
        "blockHeight": 19000100, "confirmations": evm_threshold, "finality": "final",
        "observedAt": "2026-03-25T21:46:00Z",
    }
    proof_evm_refund = ac.sign_ecdsa_jcs_2022(proof_evm_refund, wallet, "2026-03-25T21:46:00Z")
    write(SETTLE, "51-settlement-proof-evm-refund.json", proof_evm_refund)

    # 52: EscrowRefund (timeout -> refund to payer), carrying the refund proof.
    refund_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-refund:evm", "type": "EscrowRefund",
        "lock": lock_evm["id"], "lockDigest": ac.jcs_digest(lock_evm),
        "settlementProof": proof_evm_refund["id"], "settlementProofDigest": ac.jcs_digest(proof_evm_refund),
        "reason": "timeout",
    }
    refund_evm = ac.sign_ecdsa_jcs_2022(refund_evm, wallet, "2026-03-25T21:46:10Z")
    write(SETTLE, "52-escrow-refund-evm.json", refund_evm)

    # On-chain REVERSAL = a compensating transfer (payer<->payee swapped). A disputes
    # Reversal's settlementRef would point at proof 54. Here we generate the swapped
    # instruction + proof; the disputes bundle is NOT modified.
    # 53: reverse SettlementInstruction (payee now pays the agent back).
    agent_evm_account = "eip155:8453:" + st.fake_address("agent-evm")
    instr_rev = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:reverse", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-evm-stablecoin", "chain": "eip155:8453",
        "payeeAccount": agent_evm_account, "asset": usdc,
        "payer": DID_PAYEE, "payee": DID_AGENT,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": evm_threshold, "mode": "direct",
        "payeeAccountBinding": "urn:avp:payee-binding:agent",
        "nonce": "settle-reverse-1", "expires": "2026-03-26T10:00:00Z",
    }
    instr_rev = ac.sign_ecdsa_jcs_2022(instr_rev, wallet, "2026-03-26T09:05:00Z")
    write(SETTLE, "53-reverse-settlement-instruction.json", instr_rev)

    # 54: reverse SettlementProof.
    proof_rev = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:reverse", "type": "SettlementProof",
        "instruction": instr_rev["id"], "instructionDigest": ac.jcs_digest(instr_rev),
        "chain": "eip155:8453", "transaction": st.fake_tx("evm-reverse"),
        "settledAmountBase": instr_rev["amountBase"], "asset": usdc,
        "blockHeight": 19000200, "confirmations": evm_threshold, "finality": "final",
        "observedAt": "2026-03-26T09:08:00Z",
    }
    proof_rev = ac.sign_ecdsa_jcs_2022(proof_rev, wallet, "2026-03-26T09:08:00Z")
    write(SETTLE, "54-reverse-settlement-proof.json", proof_rev)

    # 55: PayeeAccountBinding for the agent's EVM account. The on-chain reversal (53/54)
    # pays the agent back, so the agent DID must be bound to its receiving CAIP-10 account.
    binding_agent = {
        "@context": SETTLE_CTX, "id": "urn:avp:payee-binding:agent", "type": "PayeeAccountBinding",
        "subject": DID_AGENT, "account": agent_evm_account, "chain": "eip155:8453",
    }
    binding_agent = ac.sign_ecdsa_jcs_2022(binding_agent, agent, "2026-03-26T09:04:00Z")
    write(SETTLE, "55-payee-account-binding-agent.json", binding_agent)

    # ---- Attested (closed-processor) rails: card via Stripe + bank/RTP ----
    # Same authorization (urn:avp:authz:999, 0.001 USD), but the rail settles inside a
    # private processor, so finality is NOT publicly verifiable. The proof is an
    # AttestedSettlementProof: the payee re-signs (payee-attested) an embedded processor
    # attestation. Anti-redirection holds via a payee-signed ProcessorAccountBinding whose
    # subject == the authorized payee. References (stripe:pi_*, rtp e2e ids) are FIXTURES.

    # 57: ProcessorAccountBinding -- payee proves it controls a Stripe connected account.
    binding_card = {
        "@context": SETTLE_CTX, "id": "urn:avp:proc-binding:card", "type": "ProcessorAccountBinding",
        "subject": DID_PAYEE, "account": "stripe:acct_1Nv8aXAVPdemo01",
        "processor": "did:web:stripe.com", "rail": "stl:rail-card-stripe",
    }
    binding_card = ac.sign_ecdsa_jcs_2022(binding_card, payee, "2026-03-25T21:29:40Z")
    write(SETTLE, "57-processor-account-binding-card.json", binding_card)

    # 58: card AttestedSettlementInstruction (escrow == authorize/capture).
    instr_card = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:card", "type": "AttestedSettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-card-stripe", "payeeAccountBinding": binding_card["id"],
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "mode": "escrow", "captureMode": "auth-capture",
        "processorIntent": "stripe:pi_3QavpDemoCard01",
        "nonce": "settle-card-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_card = ac.sign_ecdsa_jcs_2022(instr_card, wallet, "2026-03-25T21:30:20Z")
    write(SETTLE, "58-settlement-instruction-card.json", instr_card)

    # 59: card AttestedSettlementProof (captured; payee-attested over the Stripe result).
    proof_card = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:card", "type": "AttestedSettlementProof",
        "instruction": instr_card["id"], "instructionDigest": ac.jcs_digest(instr_card),
        "execution": execution["id"], "rail": "stl:rail-card-stripe",
        "settledAmount": amount, "currency": currency,
        "attestation": {
            "type": "ProcessorAttestation", "mode": "payee-attested",
            "processor": "did:web:stripe.com", "reference": "stripe:pi_3QavpDemoCard01",
            "status": "captured", "evidence": "stripe-event:evt_1QavpDemoCard",
            "observedAt": "2026-03-25T21:33:40Z",
        },
        "finality": "final", "observedAt": "2026-03-25T21:33:41Z",
    }
    proof_card = ac.sign_ecdsa_jcs_2022(proof_card, payee, "2026-03-25T21:33:41Z")
    write(SETTLE, "59-settlement-proof-card.json", proof_card)

    # 60: ProcessorAccountBinding for an instant-bank (RTP/FedNow) creditor token.
    binding_rtp = {
        "@context": SETTLE_CTX, "id": "urn:avp:proc-binding:rtp", "type": "ProcessorAccountBinding",
        "subject": DID_PAYEE, "account": "bank:fednow:token:ACME-PAYEE-001",
        "processor": "did:web:bank.example", "rail": "stl:rail-bank-rtp",
    }
    binding_rtp = ac.sign_ecdsa_jcs_2022(binding_rtp, payee, "2026-03-25T21:29:50Z")
    write(SETTLE, "60-processor-account-binding-rtp.json", binding_rtp)

    # 61: RTP AttestedSettlementInstruction (direct -- push transfer, NO escrow).
    instr_rtp = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:rtp", "type": "AttestedSettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-bank-rtp", "payeeAccountBinding": binding_rtp["id"],
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "mode": "direct", "scheme": "fednow",
        "nonce": "settle-rtp-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_rtp = ac.sign_ecdsa_jcs_2022(instr_rtp, wallet, "2026-03-25T21:30:21Z")
    write(SETTLE, "61-settlement-instruction-rtp.json", instr_rtp)

    # 62: RTP AttestedSettlementProof (settled; payee-attested over the bank's pacs.002).
    proof_rtp = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:rtp", "type": "AttestedSettlementProof",
        "instruction": instr_rtp["id"], "instructionDigest": ac.jcs_digest(instr_rtp),
        "execution": execution["id"], "rail": "stl:rail-bank-rtp",
        "settledAmount": amount, "currency": currency,
        "attestation": {
            "type": "ProcessorAttestation", "mode": "payee-attested",
            "processor": "did:web:bank.example", "reference": "rtp:e2e:20260325-ACME-0001",
            "status": "settled", "evidence": "iso20022:pacs.002:msgid-7f3a",
            "observedAt": "2026-03-25T21:34:20Z",
        },
        "finality": "final", "observedAt": "2026-03-25T21:34:21Z",
    }
    proof_rtp = ac.sign_ecdsa_jcs_2022(proof_rtp, payee, "2026-03-25T21:34:21Z")
    write(SETTLE, "62-settlement-proof-rtp.json", proof_rtp)

    # 63: ProcessorAccountBinding -- payee proves it controls a PayPal account.
    binding_paypal = {
        "@context": SETTLE_CTX, "id": "urn:avp:proc-binding:paypal", "type": "ProcessorAccountBinding",
        "subject": DID_PAYEE, "account": "paypal:payerid:ACMEPAYEE0001",
        "processor": "did:web:paypal.com", "rail": "stl:rail-paypal",
    }
    binding_paypal = ac.sign_ecdsa_jcs_2022(binding_paypal, payee, "2026-03-25T21:30:00Z")
    write(SETTLE, "63-processor-account-binding-paypal.json", binding_paypal)

    # 64: PayPal AttestedSettlementInstruction (direct -- immediate wallet capture, no escrow).
    instr_paypal = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:paypal", "type": "AttestedSettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-paypal", "payeeAccountBinding": binding_paypal["id"],
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "mode": "direct", "processorIntent": "paypal:order:5O190127TN364715T",
        "nonce": "settle-paypal-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_paypal = ac.sign_ecdsa_jcs_2022(instr_paypal, wallet, "2026-03-25T21:30:40Z")
    write(SETTLE, "64-settlement-instruction-paypal.json", instr_paypal)

    # 65: PayPal AttestedSettlementProof (COMPLETED; payee-attested over the PayPal capture).
    proof_paypal = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:paypal", "type": "AttestedSettlementProof",
        "instruction": instr_paypal["id"], "instructionDigest": ac.jcs_digest(instr_paypal),
        "execution": execution["id"], "rail": "stl:rail-paypal",
        "settledAmount": amount, "currency": currency,
        "attestation": {
            "type": "ProcessorAttestation", "mode": "payee-attested",
            "processor": "did:web:paypal.com", "reference": "paypal:capture:3C679366HH9089937",
            "status": "completed", "evidence": "paypal-webhook:PAYMENT.CAPTURE.COMPLETED:WH-1",
            "observedAt": "2026-03-25T21:34:40Z",
        },
        "finality": "final", "observedAt": "2026-03-25T21:34:41Z",
    }
    proof_paypal = ac.sign_ecdsa_jcs_2022(proof_paypal, payee, "2026-03-25T21:34:41Z")
    write(SETTLE, "65-settlement-proof-paypal.json", proof_paypal)

    # 66: ProcessorAccountBinding -- payee proves it controls the receiving card credential.
    binding_visa = {
        "@context": SETTLE_CTX, "id": "urn:avp:proc-binding:visa-direct", "type": "ProcessorAccountBinding",
        "subject": DID_PAYEE, "account": "card:token:visa:411111xxxxxx1111",
        "processor": "did:web:visa.com", "rail": "stl:rail-visa-direct",
    }
    binding_visa = ac.sign_ecdsa_jcs_2022(binding_visa, payee, "2026-03-25T21:30:05Z")
    write(SETTLE, "66-processor-account-binding-visa-direct.json", binding_visa)

    # 67: Visa Direct AttestedSettlementInstruction (direct credit push, OCT; NO escrow).
    instr_visa = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:visa-direct", "type": "AttestedSettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-visa-direct", "payeeAccountBinding": binding_visa["id"],
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "mode": "direct", "processorIntent": "visa-direct:oct-request:OCT-20260325-0001",
        "nonce": "settle-visa-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_visa = ac.sign_ecdsa_jcs_2022(instr_visa, wallet, "2026-03-25T21:30:45Z")
    write(SETTLE, "67-settlement-instruction-visa-direct.json", instr_visa)

    # 68: Visa Direct AttestedSettlementProof (OCT approved; payee-attested over the network result).
    proof_visa = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:visa-direct", "type": "AttestedSettlementProof",
        "instruction": instr_visa["id"], "instructionDigest": ac.jcs_digest(instr_visa),
        "execution": execution["id"], "rail": "stl:rail-visa-direct",
        "settledAmount": amount, "currency": currency,
        "attestation": {
            "type": "ProcessorAttestation", "mode": "payee-attested",
            "processor": "did:web:visa.com", "reference": "visa-direct:oct:9876543210123456",
            "status": "approved", "evidence": "visa-direct:response:actionCode=00",
            "observedAt": "2026-03-25T21:34:45Z",
        },
        "finality": "final", "observedAt": "2026-03-25T21:34:46Z",
    }
    proof_visa = ac.sign_ecdsa_jcs_2022(proof_visa, payee, "2026-03-25T21:34:46Z")
    write(SETTLE, "68-settlement-proof-visa-direct.json", proof_visa)

    # Remaining closed-processor rails, all the same attested shape:
    #   - Adyen: card-via-processor (auth/capture), like Stripe -> did:web:adyen.com
    #   - Zum Rails: bank rails (Interac/EFT/ACH/RTP), like bank-RTP -> did:web:zumrails.com
    #   - Mastercard Send: push-to-card (MoneySend), like Visa Direct -> did:web:mastercard.com
    # (rail, processor, account, instr-extra, proof reference, proof status, vector trio)
    _more_rails = [
        ("adyen", "stl:rail-card-adyen", "did:web:adyen.com", "adyen:acct:CGSXXXX001",
         {"mode": "escrow", "captureMode": "auth-capture", "processorIntent": "adyen:psp_8915XYZADYEN01"},
         "adyen:psp_8915XYZADYEN01", "captured"),
        ("zum", "stl:rail-bank-zum", "did:web:zumrails.com", "zum:funds-transfer:ACME-PAYEE-01",
         {"mode": "direct", "scheme": "interac"},
         "zum:txn:9f3a-interac-0001", "settled"),
        ("mc-send", "stl:rail-mc-send", "did:web:mastercard.com", "card:token:mc:555544xxxxxx4444",
         {"mode": "direct", "processorIntent": "mc-send:request:MS-20260325-0001"},
         "mc-send:ref:7766554433221100", "approved"),
    ]
    _seq = 69
    for tag, rail_iri, proc, acct, extra, ref, status in _more_rails:
        b = {
            "@context": SETTLE_CTX, "id": "urn:avp:proc-binding:" + tag, "type": "ProcessorAccountBinding",
            "subject": DID_PAYEE, "account": acct, "processor": proc, "rail": rail_iri,
        }
        b = ac.sign_ecdsa_jcs_2022(b, payee, "2026-03-25T21:30:06Z")
        write(SETTLE, f"{_seq}-processor-account-binding-{tag}.json", b)
        ins = {
            "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:" + tag, "type": "AttestedSettlementInstruction",
            "authorization": authz["id"], "authorizationDigest": authz_digest,
            "rail": rail_iri, "payeeAccountBinding": b["id"],
            "payer": DID_AGENT, "payee": DID_PAYEE, "amount": amount, "currency": currency,
            **extra, "nonce": "settle-" + tag + "-1", "expires": "2026-03-25T22:00:00Z",
        }
        ins = ac.sign_ecdsa_jcs_2022(ins, wallet, "2026-03-25T21:30:46Z")
        write(SETTLE, f"{_seq + 1}-settlement-instruction-{tag}.json", ins)
        pr = {
            "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:" + tag, "type": "AttestedSettlementProof",
            "instruction": ins["id"], "instructionDigest": ac.jcs_digest(ins),
            "execution": execution["id"], "rail": rail_iri,
            "settledAmount": amount, "currency": currency,
            "attestation": {
                "type": "ProcessorAttestation", "mode": "payee-attested", "processor": proc,
                "reference": ref, "status": status, "evidence": tag + "-evidence:" + ref,
                "observedAt": "2026-03-25T21:34:50Z",
            },
            "finality": "final", "observedAt": "2026-03-25T21:34:51Z",
        }
        pr = ac.sign_ecdsa_jcs_2022(pr, payee, "2026-03-25T21:34:51Z")
        write(SETTLE, f"{_seq + 2}-settlement-proof-{tag}.json", pr)
        _seq += 3

    # ---- Transport & protocol binding bundle ----
    # Wraps the canonical payments objects. Reload them from disk so the digests
    # bound here match the exact bytes validate.py / verify.py will read.
    quote_c = json.loads((PAY / "01-payment-quote.json").read_text(encoding="utf-8"))
    authz_c = json.loads((PAY / "02-payment-authorization.json").read_text(encoding="utf-8"))
    receipt_c = json.loads((PAY / "04-payment-receipt.json").read_text(encoding="utf-8"))
    offer_c = json.loads((PAY / "00-payment-offer.json").read_text(encoding="utf-8"))

    service = {
        "@context": TXP_CTX,
        "id": "urn:avp:txp:service:tool-api",
        "type": "ServiceDescription",
        "payee": DID_PAYEE,
        "offers": [offer_c["id"]],
        "endpoints": {
            "quote": "https://api.example.com/avp/quote",
            "authorize": "https://api.example.com/avp/authorize",
            "execute": "https://api.example.com/avp/execute",
            "receipt": "https://api.example.com/avp/receipt/{id}",
            "settlementStatus": "https://api.example.com/avp/settlement/{id}",
            "session": "https://api.example.com/avp/session",
            "accruals": "https://api.example.com/avp/session/{id}/accruals",
            "close": "https://api.example.com/avp/session/{id}/close",
            "extend": "https://api.example.com/avp/session/{id}/extend",
        },
        "acceptedCredentialIssuers": [DID_ISSUER],
        "acceptedSettlementRails": [RAIL_EVM, RAIL_X402],
        "supportedBundles": {
            AVP: "0.1.0",
            DISP_URL: "0.1.0",
            SETTLE_URL: "0.1.0",
            TXP_URL: "0.1.0",
        },
        "timestamp": "2026-03-25T21:29:00Z",
    }
    service = ac.sign_ecdsa_jcs_2022(service, payee, "2026-03-25T21:29:00Z")
    write(TXP, "00-service-description.json", service)

    challenge = {
        "@context": TXP_CTX,
        "id": "urn:avp:txp:challenge:abc123",
        "type": "PaymentChallenge",
        "payee": DID_PAYEE,
        "quote": quote_c["id"],
        "quoteDigest": ac.jcs_digest(quote_c),
        "challenge": "txp-nonce-7f3a9c2e",
        "authorizeEndpoint": "https://api.example.com/avp/resource/premium",
        "acceptedSettlementRails": [RAIL_EVM, RAIL_X402],
        "timestamp": "2026-03-25T21:31:00Z",
        "expires": "2026-03-25T21:36:00Z",
    }
    challenge = ac.sign_ecdsa_jcs_2022(challenge, payee, "2026-03-25T21:31:00Z")
    write(TXP, "10-payment-challenge.json", challenge)

    # The actual HTTP 402 body: the signed challenge plus the referenced quote.
    body_402 = {"challenge": challenge, "quote": quote_c}
    write(TXP, "11-challenge-402-body.json", body_402)

    submission = {
        "@context": TXP_CTX,
        "id": "urn:avp:txp:submission:def456",
        "type": "AuthorizationSubmission",
        "payer": DID_AGENT,
        "authorization": authz_c["id"],
        "authorizationDigest": ac.jcs_digest(authz_c),
        "challenge": challenge["challenge"],
        "idempotencyKey": "idemp-2026-03-25-0001",
        "callbackUrl": "https://agent.example.com/avp/callback",
        "timestamp": "2026-03-25T21:32:00Z",
    }
    submission = ac.sign_ecdsa_jcs_2022(submission, agent, "2026-03-25T21:32:00Z")
    write(TXP, "20-authorization-submission.json", submission)

    problem = {
        "type": TXP_URL + "#over-cap",
        "title": "Amount exceeds per-transaction cap",
        "status": 402,
        "detail": "The authorized amount 0.10 exceeds the credential maxPerTransaction 0.05.",
        "field": "amount",
    }
    write(TXP, "30-problem-details.json", problem)

    flow = {
        "description": "Core HTTP 402 challenge flow: gated GET -> 402 challenge -> authorized retry -> 200 + receipt.",
        "steps": [
            {
                "request": {"method": "GET", "path": "/resource/premium",
                            "headers": {"Accept": "application/avp-micro+json"}},
                "response": {"status": 402,
                             "headers": {"WWW-Authenticate": 'AVP-Micro challenge="' + challenge["challenge"] + '"',
                                         "Content-Type": "application/avp-micro+json"},
                             "body": body_402},
            },
            {
                "request": {"method": "GET", "path": "/resource/premium",
                            "headers": {"Authorization": "AVP-Micro " + submission["id"],
                                        "Idempotency-Key": submission["idempotencyKey"],
                                        "Content-Type": "application/avp-micro+json"},
                            "body": submission},
                "response": {"status": 200,
                             "headers": {"Content-Type": "application/avp-micro+json"},
                             "body": receipt_c},
            },
        ],
    }
    write(TXP, "40-exchange-402-flow.json", flow)

    over_cap = {
        "description": "Policy rejection: authorized amount exceeds the credential cap -> 402 + ProblemDetails.",
        "steps": [
            {
                "request": {"method": "GET", "path": "/resource/premium",
                            "headers": {"Authorization": "AVP-Micro " + submission["id"],
                                        "Idempotency-Key": "idemp-2026-03-25-0002",
                                        "Content-Type": "application/avp-micro+json"}},
                "response": {"status": 402,
                             "headers": {"Content-Type": "application/problem+json",
                                         "WWW-Authenticate": 'AVP-Micro error="over-cap"'},
                             "body": problem},
            },
        ],
    }
    write(TXP, "41-exchange-over-cap.json", over_cap)

    # ---- additional flow exchanges (explicit-quote, streaming, async, idempotency) ----
    exec_c = json.loads((PAY / "03-payment-execution.json").read_text(encoding="utf-8"))
    sess_c = json.loads((PAY / "05-usage-session.json").read_text(encoding="utf-8"))
    budget_c = json.loads((PAY / "06-session-budget-authorization.json").read_text(encoding="utf-8"))
    accrual_c = json.loads((PAY / "07-usage-accrual.json").read_text(encoding="utf-8"))
    sess_receipt_c = json.loads((PAY / "09-payment-receipt-session.json").read_text(encoding="utf-8"))
    settle_proof_c = json.loads((SETTLE / "42-settlement-proof-evm.json").read_text(encoding="utf-8"))
    JCT = {"Content-Type": "application/avp-micro+json"}
    PCT = {"Content-Type": "application/problem+json"}

    quote_flow = {
        "description": "Explicit (non-gated) flow: request a quote, submit the authorization, fetch the receipt.",
        "steps": [
            {"request": {"method": "POST", "path": "/quote",
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": quote_c}},
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": submission["idempotencyKey"]},
                         "body": submission},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "GET", "path": "/receipt/" + receipt_c["id"],
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": receipt_c}},
        ],
    }
    write(TXP, "42-exchange-quote-flow.json", quote_flow)

    streaming = {
        "description": "Streaming session: open, commit a budget, report accruals, then close and settle.",
        "steps": [
            {"request": {"method": "POST", "path": "/session", "headers": JCT},
             "response": {"status": 200, "headers": JCT, "body": sess_c}},
            {"request": {"method": "POST", "path": "/session/" + sess_c["id"] + "/budget",
                         "headers": JCT, "body": budget_c},
             "response": {"status": 200, "headers": JCT, "body": sess_c}},
            {"request": {"method": "GET", "path": "/session/" + sess_c["id"] + "/accruals",
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": accrual_c}},
            {"request": {"method": "POST", "path": "/session/" + sess_c["id"] + "/close", "headers": JCT},
             "response": {"status": 200, "headers": JCT, "body": sess_receipt_c}},
        ],
    }
    write(TXP, "43-exchange-streaming.json", streaming)

    settle_loc = "/settlement/" + settle_proof_c["id"]
    async_settle = {
        "description": "Async settlement: execute returns 200 + Location; poll /settlement/{id} until the proof is final.",
        "steps": [
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": submission["idempotencyKey"]},
                         "body": submission},
             "response": {"status": 200, "headers": {**JCT, "Location": settle_loc}, "body": exec_c}},
            {"request": {"method": "GET", "path": settle_loc,
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "GET", "path": settle_loc,
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": settle_proof_c}},
        ],
    }
    write(TXP, "44-exchange-async-settlement.json", async_settle)

    # a genuinely distinct, validly-signed submission for the conflict step
    submission_alt = json.loads(json.dumps(submission))
    submission_alt.pop("proof", None)
    submission_alt["id"] = "urn:avp:txp:submission:def457"
    submission_alt["callbackUrl"] = "https://agent.example.com/avp/callback-2"
    submission_alt = ac.sign_ecdsa_jcs_2022(submission_alt, agent, "2026-03-25T21:33:00Z")
    conflict = {
        "type": TXP_URL + "#idempotency-conflict",
        "title": "Idempotency key reused with a different request",
        "status": 409,
        "detail": "The Idempotency-Key was already used for a different AuthorizationSubmission.",
        "field": "Idempotency-Key",
    }
    idem = {
        "description": "Idempotency: a repeated key returns the same execution; a different body under the same key is a 409 conflict.",
        "steps": [
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": "idemp-2026-03-25-0001"}, "body": submission},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": "idemp-2026-03-25-0001"}, "body": submission},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": "idemp-2026-03-25-0001"}, "body": submission_alt},
             "response": {"status": 409, "headers": PCT, "body": conflict}},
        ],
    }
    write(TXP, "45-exchange-idempotency.json", idem)

    # ---- transport hardening: signed errors (A4) + anti-replay (A3) ----
    # A signed error is just the problem JSON + an ecdsa-jcs-2022 proof (JCS-based; no @context).
    problem_signed = {
        "type": TXP_URL + "#challenge-expired",
        "title": "Payment challenge expired",
        "status": 422,
        "detail": "The PaymentChallenge is past its expiry; request a fresh 402.",
        "field": "challenge",
    }
    problem_signed = ac.sign_ecdsa_jcs_2022(problem_signed, payee, "2026-03-25T21:37:00Z")
    write(TXP, "47-problem-details-signed.json", problem_signed)

    # Anti-replay: re-presenting a consumed challenge nonce is refused with a signed 409.
    problem_replay = {
        "type": TXP_URL + "#nonce-reuse",
        "title": "Challenge nonce already used",
        "status": 409,
        "detail": "This challenge nonce was already consumed; request a fresh 402.",
        "field": "challenge",
    }
    problem_replay = ac.sign_ecdsa_jcs_2022(problem_replay, payee, "2026-03-25T21:38:00Z")
    replay = {
        "description": "Anti-replay: re-presenting a consumed challenge nonce is refused with a signed 409 nonce-reuse.",
        "steps": [
            {"request": {"method": "GET", "path": "/resource/premium",
                         "headers": {"Authorization": "AVP-Micro " + submission["id"],
                                     "Idempotency-Key": submission["idempotencyKey"],
                                     "Content-Type": "application/avp-micro+json"},
                         "body": submission},
             "response": {"status": 200, "headers": JCT, "body": receipt_c}},
            {"request": {"method": "GET", "path": "/resource/premium",
                         "headers": {"Authorization": "AVP-Micro " + submission["id"],
                                     "Content-Type": "application/avp-micro+json"},
                         "body": submission},
             "response": {"status": 409,
                          "headers": {**PCT, "WWW-Authenticate": 'AVP-Micro error="nonce-reuse"'},
                          "body": problem_replay}},
        ],
    }
    write(TXP, "46-exchange-replay.json", replay)

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

    # A->V->A: re-import the export back into a SpendingAuthorizationCredential projection (+ securing).
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
    # The outer credential carries a native ecdsa-jcs-2022 proof (P-256 did:key issuer)
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

    # 12: V->A import of the IntentMandate -> SpendingAuthorizationCredential projection + intent extras + advisory
    imported_intent = interop.sdjwtvc_intent_to_avp(intent_compact, "proof-preserving")
    write(INTEROP, "12-imported-intent-mandate.json", imported_intent)

    # 13: foreign AP2 CartMandate (merchant-signed, ES256) carrying the itemized cart
    cart = {"merchant": DID_AP2_MERCHANT, "currency": "USD",
            "items": [{"sku": "SHOE-RED-10", "qty": 1, "price": "112.40"}],
            "total": {"amount": "112.40", "currency": "USD"},
            "cartExpiry": "2026-06-12T12:00:00Z"}
    cart_claims = {"vct": interop.CART_VCT, "iss": DID_AP2_MERCHANT, "sub": DID_AGENT,
                   "cart": cart, "cart_hash": interop.cart_request_hash(cart),
                   "exp": interop.iso_to_numericdate("2026-06-12T12:00:00Z"),
                   "jti": "urn:ap2:cart:001"}
    cart_header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_AP2_MERCHANT + "#key-1"}
    cart_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(cart_header, cart_claims, ap2_merchant))
    write(INTEROP, "13-foreign-cart-mandate.json", {
        "_note": "A foreign AP2 CartMandate (ES256, did:web merchant; itemized cart).",
        "compact": cart_compact, "cart": cart, "payload": cart_claims})

    # 14: V->A import of the CartMandate -> PaymentQuote projection (+ securing)
    imported_cart = interop.cart_mandate_to_quote(cart_compact, cart, mode="proof-preserving")
    write(INTEROP, "14-imported-cart-quote.json", imported_cart)

    # 15: human-present approval imported -> PurchaseConfirmation projection (+ securing)
    crh = interop.cart_request_hash(cart)
    user_auth_claims = {"iss": DID_AP2_USER, "sub": DID_AGENT, "cart_hash": crh,
                        "iat": interop.iso_to_numericdate("2026-06-12T11:00:00Z"),
                        "exp": interop.iso_to_numericdate("2026-06-12T11:05:00Z")}
    user_auth_compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": DID_AP2_USER + "#key-1"},
        user_auth_claims, ap2_user))
    confirmation = interop.import_cart_user_confirmation(
        user_auth_compact, quote_digest="sha-256:imported", agent_did=DID_AGENT,
        payee=DID_AP2_MERCHANT, amount="112.40", currency="USD",
        request_hash=crh, confirmed_by=DID_AP2_USER,
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
        "requestHash": srh, "confirmedBy": DID_ISSUER,
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
        request_hash=native_conf["requestHash"],
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
