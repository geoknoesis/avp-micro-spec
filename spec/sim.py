"""AVP-Micro protocol simulator.

Runs the signed-message flow end to end -- offer/quote/authorization/execution/
receipt and the streaming/session variant -- with real ``ecdsa-jcs-2022`` proofs
and full wallet-side policy enforcement, against a SIMULATED settlement ledger.
No real money: settlement is the only step that would move funds, and it is the
one part the specification scopes out, so it is stubbed by an in-memory ledger of
play balances. Everything above settlement runs for real.

Use cases are defined DECLARATIVELY in ``sim-scenarios.json`` (a list of scenario
objects) and executed by ``run_scenario``. Run all of them as a harness:

    python spec/sim.py            # prints PASS/FAIL per scenario, exit non-zero on failure

or drive them from pytest (``spec/test_sim.py``).

Scenario schema (all amounts are decimal strings; roles are free-form names, each
gets a deterministic P-256 key + did:key):

    {
      "name": str, "description": str,
      "policy": {                      # the principal-signed SpendingAuthorizationCredential
        "currency": "USD",
        "maxPerTransaction": "5.00",
        "dailyLimit": "20.00",         # optional
        "allowedPayees": ["payee"],    # roles; omitted => any payee
        "allowedCategories": [iri],    # optional
        "requiresConfirmation": false  # optional; demands a fresh PurchaseConfirmation
      },
      "balances": {"agent": "100.00"}, # simulated ledger, keyed by role
      "now": "2026-06-12T10:00:00Z",
      "quoteTtl": 300, "authTtl": 60,  # optional seconds
      "steps": [ {"action": ..., ...} ],
      "finalBalances": {"agent": "99.00", "payee": "1.00"}   # optional assertion
    }

Step actions: quote, authorize, execute, receipt, confirm, replay, advance_clock,
corrupt_authz, tamper_quote, open_session, budget_authorize, accrue, extend,
close_session. Each step's ``expect`` is "ok", {"reject": code}, or
{"status": s, "settled": amount}. Rejection codes are listed in REJECTIONS below.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import avp_crypto as ac
import interop
import sdjwt

ISO = "%Y-%m-%dT%H:%M:%SZ"
PAY_CTX = ["https://www.w3.org/ns/credentials/v2",
           "https://w3id.org/security/data-integrity/v2",
           "https://w3id.org/spending-authority/v1",
           "https://w3id.org/avp-micro/v1"]
DSA_CTX = PAY_CTX[:3]

# every wallet rejection the simulator can emit (the runtime-enforcement vocabulary)
REJECTIONS = {
    "badSignature", "badCredential", "holderMismatch", "quoteMismatch",
    "amountMismatch", "currencyMismatch", "overCap", "payeeNotAllowed",
    "categoryNotAllowed", "dailyLimitExceeded", "expired", "nonceReuse",
    "doubleSpend", "budgetExceeded", "missingConfirmation", "forgedConfirmation",
    "overRefund", "noReversalBasis",
}


class Reject(Exception):
    """A wallet policy/verification rejection (no settlement occurs)."""
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _controller(obj: dict) -> str:
    return obj["proof"]["verificationMethod"].split("#", 1)[0]


def _d(x) -> Decimal:
    return Decimal(str(x))


# ---- world primitives -------------------------------------------------------

class Clock:
    def __init__(self, start: str):
        self.t = datetime.strptime(start, ISO).replace(tzinfo=timezone.utc)

    def now(self) -> str:
        return self.t.strftime(ISO)

    def plus(self, seconds: int) -> str:
        return (self.t + timedelta(seconds=seconds)).strftime(ISO)

    def advance(self, seconds: int):
        self.t += timedelta(seconds=seconds)

    def after(self, iso: str) -> bool:
        return self.t > datetime.strptime(iso, ISO).replace(tzinfo=timezone.utc)

    def date(self) -> str:
        return self.t.strftime("%Y-%m-%d")


class SettlementRail:
    """The pluggable settlement backend -- the one seam where real money would move.
    The simulator uses SimulatedLedger (play balances); a deployment swaps in a real
    rail or testnet adapter exposing the same settle(payer, payee, amount, key) ->
    (settlementRef, settledAmount). The simulator never instantiates a real rail."""
    def settle(self, payer, payee, amount, key):
        raise NotImplementedError


class SimulatedLedger(SettlementRail):
    """Simulated settlement rail. Play balances only; never touches real funds.
    settle() is idempotent on the settlement key (retry-safe) and supports partials."""
    def __init__(self, balances: dict):
        self.bal = {k: _d(v) for k, v in balances.items()}
        self._refs: dict = {}
        self._n = 0

    def settle(self, payer: str, payee: str, amount: str, key: str):
        if key in self._refs:
            return self._refs[key], Decimal(0)          # idempotent: already settled
        amt = _d(amount)
        avail = self.bal.get(payer, Decimal(0))
        settled = amt if avail >= amt else max(avail, Decimal(0))
        self.bal[payer] = avail - settled
        self.bal[payee] = self.bal.get(payee, Decimal(0)) + settled
        self._n += 1
        ref = f"sim:settle:{self._n}"
        self._refs[key] = ref
        return ref, settled


class Actor:
    """A protocol participant: a deterministic P-256 key and its did:key."""
    def __init__(self, role: str):
        self.role = role
        self.key = ac.seed_key("sim:" + role)
        self.did = ac.did_key(self.key.public_key())

    def sign(self, doc: dict, created: str) -> dict:
        return ac.sign_ecdsa_jcs_2022(doc, self.key, created)


# ---- the world: actors, credential, ledger, enforcement state ---------------

class World:
    def __init__(self, sc: dict):
        self.sc = sc
        self.clock = Clock(sc["now"])
        self.quote_ttl = int(sc.get("quoteTtl", 300))
        self.auth_ttl = int(sc.get("authTtl", 60))
        self._actors: dict = {}
        self.ledger = SimulatedLedger(sc.get("balances", {}))
        self.resolver: dict = {}            # did:web -> P-256 JWK, for bridged authority
        self.ctx: dict = {}                 # last quote/authz/confirmation/session...
        self.nonces: set = set()            # replay protection
        self.executed: set = set()          # one-off single-use (consumed instances)
        self.daily: list = []               # (date, settled) for dailyLimit windows
        self.session_committed = Decimal(0)
        self.session_accrued = Decimal(0)
        self.session_units = Decimal(0)
        self.credential = self._issue_credential()

    def actor(self, role: str) -> Actor:
        if role not in self._actors:
            self._actors[role] = Actor(role)
        return self._actors[role]

    def _issue_credential(self) -> dict:
        if self.sc.get("credential", {}).get("source") == "ap2-intent":
            return self._import_ap2_intent()
        p = self.sc.get("policy", {})
        subj = {"id": self.actor("agent").did, "currency": p.get("currency", "USD")}
        if "maxPerTransaction" in p:
            subj["maxPerTransaction"] = p["maxPerTransaction"]
        if "dailyLimit" in p:
            subj["dailyLimit"] = p["dailyLimit"]
        if "allowedPayees" in p:
            subj["allowedPayees"] = [self.actor(r).did for r in p["allowedPayees"]]
        if "allowedCategories" in p:
            subj["allowedServiceCategories"] = list(p["allowedCategories"])
        cred = {
            "@context": DSA_CTX,
            "id": "urn:sim:vc:spendauth",
            "type": ["VerifiableCredential", "SpendingAuthorizationCredential"],
            "issuer": self.actor("principal").did,
            "validFrom": self.clock.now(),
            "validUntil": self.clock.plus(365 * 24 * 3600),
            "credentialSubject": subj,
        }
        return self.actor("principal").sign(cred, self.clock.now())

    def _import_ap2_intent(self) -> dict:
        """The agent's authority is an AP2 IntentMandate (ES256, did:web user issuer),
        imported proof-preservingly into a SpendingAuthorizationCredential projection.
        The wallet verifies it via the embedded foreign signature + did:web resolver --
        authority roots in the user DID, never in the bridge."""
        p = self.sc.get("policy", {})
        user, agent = self.actor("user"), self.actor("agent")
        user_did = "did:web:user.sim"
        self.resolver[user_did] = sdjwt.p256_public_jwk(user.key.public_key())
        limits = {}
        if "maxPerTransaction" in p:
            limits["per_txn"] = p["maxPerTransaction"]
        if "dailyLimit" in p:
            limits["per_day"] = p["dailyLimit"]
        claims = {
            "vct": interop.INTENT_VCT, "iss": user_did, "sub": agent.did,
            "cnf": {"jwk": sdjwt.p256_public_jwk(agent.key.public_key())},
            "currency": p.get("currency", "USD"), "limits": limits,
            "nbf": interop.iso_to_numericdate(self.clock.now()),
            "exp": interop.iso_to_numericdate(self.clock.plus(365 * 24 * 3600)),
            "jti": "urn:sim:ap2:intent:1",
        }
        if "allowedPayees" in p:
            claims["allowed_payees"] = [self.actor(r).did for r in p["allowedPayees"]]
        if p.get("requiresConfirmation"):
            claims["requires_user_confirmation"] = True
        header = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": user_did + "#k"}
        compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(header, claims, user.key))
        self.ctx["intentCompact"] = compact
        return interop.sdjwtvc_intent_to_avp(compact, "proof-preserving")

    # -- policy view from the SIGNED credential (faithful enforcement) --
    @property
    def policy(self) -> dict:
        return self.credential["credentialSubject"]

    @property
    def requires_confirmation(self) -> bool:
        return bool(self.sc.get("policy", {}).get("requiresConfirmation"))


# ---- object builders --------------------------------------------------------

def _request_hash(request: dict) -> str:
    return ac.content_digest(ac.jcs(request))


def build_quote(world: World, step: dict) -> dict:
    payee_role = step.get("payee", "payee")
    world.last_payee_role = payee_role
    request = step.get("request", {"resource": "demo", "n": 1})
    amount = step["amount"]
    payee = world.actor(payee_role)
    quote = {
        "@context": PAY_CTX, "id": "urn:sim:quote:" + str(len(world.ctx)),
        "type": "PaymentQuote",
        "payer": world.actor("agent").did, "payee": payee.did,
        "requestHash": _request_hash(request),
        "amount": amount, "currency": step.get("currency", world.policy.get("currency", "USD")),
        "settlementMethod": "sim-ledger", "settlementTarget": "sim:" + payee_role,
        "expires": world.clock.plus(world.quote_ttl),
        "_payeeRole": payee_role,                       # sim bookkeeping (not signed-over semantics)
    }
    if "category" in step:
        quote["category"] = step["category"]
    return payee.sign(quote, world.clock.now())


def build_authorization(world: World, step: dict) -> dict:
    quote = world.ctx["quote"]
    nonce = step.get("nonce", "n-" + str(len(world.nonces) + len(world.ctx)))
    authz = {
        "@context": PAY_CTX, "id": "urn:sim:authz:" + nonce, "type": "PaymentAuthorization",
        "quote": quote["id"], "quoteDigest": ac.jcs_digest({k: v for k, v in quote.items() if not k.startswith("_")}),
        "payer": world.actor("agent").did, "payee": quote["payee"],
        "amount": quote["amount"], "currency": quote["currency"],
        "settlementMethod": quote["settlementMethod"], "settlementTarget": quote["settlementTarget"],
        "requestHash": quote["requestHash"],
        "timestamp": world.clock.now(), "expires": world.clock.plus(world.auth_ttl),
        "nonce": nonce, "wallet": world.actor("wallet").did,
        "vp": {"@context": PAY_CTX, "type": "VerifiablePresentation",
               "verifiableCredential": [world.credential]},
    }
    if "category" in step:
        authz["category"] = step["category"]
    for k, v in step.get("tamper", {}).items():           # agent signs a (possibly bad) request
        authz[k] = v
    return world.actor("agent").sign(authz, world.clock.now())


def build_imported_confirmation(world: World, step: dict) -> dict:
    """An AP2 human-present cart approval (ES256, did:web user) imported as a
    PurchaseConfirmation projection -- authority is the embedded user signature."""
    quote = world.ctx["quote"]
    user = world.actor("user")
    user_did = "did:web:user.sim"
    world.resolver[user_did] = sdjwt.p256_public_jwk(user.key.public_key())
    user_auth = {"iss": user_did, "sub": world.actor("agent").did, "cart_hash": quote["requestHash"],
                 "iat": interop.iso_to_numericdate(world.clock.now()),
                 "exp": interop.iso_to_numericdate(world.clock.plus(world.auth_ttl))}
    compact = sdjwt.sdjwt_compact(sdjwt.es256_sign(
        {"alg": "ES256", "typ": "dc+sd-jwt", "kid": user_did + "#k"}, user_auth, user.key))
    clean = {k: v for k, v in quote.items() if not k.startswith("_")}
    return interop.import_cart_user_confirmation(
        compact, quote_digest=ac.jcs_digest(clean), agent_did=world.actor("agent").did,
        payee=quote["payee"], amount=quote["amount"], currency=quote["currency"],
        request_hash=quote["requestHash"], confirmed_by=user_did, quote=quote["id"],
        mode="proof-preserving")


def build_confirmation(world: World, step: dict) -> dict:
    if step.get("source") == "ap2-user":
        return build_imported_confirmation(world, step)
    quote = world.ctx["quote"]
    signer_role = step.get("by", "principal")             # "agent" => forged
    conf = {
        "@context": PAY_CTX, "id": "urn:sim:confirm:1", "type": "PurchaseConfirmation",
        "quote": quote["id"], "quoteDigest": ac.jcs_digest({k: v for k, v in quote.items() if not k.startswith("_")}),
        "payer": world.actor("agent").did, "payee": quote["payee"],
        "amount": quote["amount"], "currency": quote["currency"],
        "requestHash": quote["requestHash"],
        "confirmedBy": world.actor("principal").did,       # the authority is always the principal
        "timestamp": world.clock.now(), "expires": world.clock.plus(world.auth_ttl), "nonce": "c-1",
    }
    return world.actor(signer_role).sign(conf, world.clock.now())


# ---- the wallet: verification + policy enforcement + settlement -------------

def _verify_confirmation(world: World, conf: dict, authz: dict):
    if conf.get("confirmedBy") == conf["payer"]:          # must name a principal != the agent
        raise Reject("forgedConfirmation")
    if "securing" in conf:                                # AP2-imported projection
        if not interop.verify_purchase_confirmation(conf, world.resolver):
            raise Reject("forgedConfirmation")
    else:                                                 # native: signer MUST be confirmedBy
        if _controller(conf) != conf["confirmedBy"] or not ac.verify_ecdsa_jcs_2022(conf):
            raise Reject("forgedConfirmation")
    if conf["quoteDigest"] != authz["quoteDigest"] or conf["requestHash"] != authz["requestHash"] \
            or conf["amount"] != authz["amount"] or conf["currency"] != authz["currency"]:
        raise Reject("missingConfirmation")
    if "expires" in conf and world.clock.after(conf["expires"]):
        raise Reject("expired")


def wallet_process(world: World, authz: dict) -> dict:
    quote = world.ctx["quote"]
    # 1. agent signature
    if not ac.verify_ecdsa_jcs_2022(authz):
        raise Reject("badSignature")
    # 2. embedded credential authority: a native principal proof, or -- when the
    #    authority is an AP2-bridged (proof-preserving) projection -- the embedded
    #    foreign signature verified against the issuer's did:web key.
    cred = authz["vp"]["verifiableCredential"][0]
    if "securing" in cred:
        if not interop.verify_imported(cred, world.resolver):
            raise Reject("badCredential")
    elif not ac.verify_ecdsa_jcs_2022(cred):
        raise Reject("badCredential")
    subj = cred["credentialSubject"]
    # 3. holder binding: the agent that signed is the credential subject and the payer
    if subj["id"] != authz["payer"] or _controller(authz) != authz["payer"]:
        raise Reject("holderMismatch")
    # 4. quote binding
    clean_quote = {k: v for k, v in quote.items() if not k.startswith("_")}
    if authz["quoteDigest"] != ac.jcs_digest(clean_quote):
        raise Reject("quoteMismatch")
    if authz["payee"] != quote["payee"] or authz["requestHash"] != quote["requestHash"]:
        raise Reject("quoteMismatch")
    if authz["amount"] != quote["amount"] or authz["currency"] != quote["currency"]:
        raise Reject("amountMismatch")
    # 5. economic policy from the signed credential
    if authz["currency"] != subj.get("currency"):
        raise Reject("currencyMismatch")
    if "maxPerTransaction" in subj and _d(authz["amount"]) > _d(subj["maxPerTransaction"]):
        raise Reject("overCap")
    if "allowedPayees" in subj and authz["payee"] not in subj["allowedPayees"]:
        raise Reject("payeeNotAllowed")
    if "allowedServiceCategories" in subj and authz.get("category") not in subj["allowedServiceCategories"]:
        raise Reject("categoryNotAllowed")
    if "dailyLimit" in subj:
        today = sum((amt for d, amt in world.daily if d == world.clock.date()), Decimal(0))
        if today + _d(authz["amount"]) > _d(subj["dailyLimit"]):
            raise Reject("dailyLimitExceeded")
    # 6. freshness + single use
    if world.clock.after(authz["expires"]):
        raise Reject("expired")
    if authz["nonce"] in world.nonces:
        raise Reject("nonceReuse")
    if authz["id"] in world.executed:
        raise Reject("doubleSpend")
    # 7. human-present, if demanded
    if world.requires_confirmation:
        conf = world.ctx.get("confirmation")
        if not conf:
            raise Reject("missingConfirmation")
        _verify_confirmation(world, conf, authz)
    # 8. settle (simulated rail) and emit the wallet-signed execution
    payer_role, payee_role = "agent", quote["_payeeRole"]
    ref, settled = world.ledger.settle(payer_role, payee_role, authz["amount"], authz["id"])
    world.nonces.add(authz["nonce"])
    world.executed.add(authz["id"])
    if settled > 0:
        world.daily.append((world.clock.date(), settled))
    status = "completed" if settled == _d(authz["amount"]) else ("partial" if settled > 0 else "failed")
    execution = {
        "@context": PAY_CTX, "id": "urn:sim:exec:" + authz["nonce"], "type": "PaymentExecution",
        "authorization": authz["id"], "amount": str(settled), "currency": authz["currency"],
        "status": status, "settlementRef": ref, "timestamp": world.clock.now(),
    }
    signed = world.actor("wallet").sign(execution, world.clock.now())
    world.ctx["execution"] = signed
    return signed


# ---- streaming / session ----------------------------------------------------

def open_session(world: World, step: dict) -> dict:
    payee = world.actor(step.get("payee", "payee"))
    session = {
        "@context": PAY_CTX, "id": "urn:sim:session:1", "type": "UsageSession",
        "payer": world.actor("agent").did, "payee": payee.did,
        "currency": world.policy.get("currency", "USD"),
        "pricingModel": step.get("pricingModel", {"type": "PerCall", "amount": "0.001", "currency": "USD"}),
        "maxAmount": step["budget"], "settlementMethod": "sim-ledger",
        "settlementTarget": "sim:" + step.get("payee", "payee"),
        "timestamp": world.clock.now(), "expires": world.clock.plus(3600),
        "_payeeRole": step.get("payee", "payee"),
    }
    world.session_accrued = Decimal(0)
    world.session_units = Decimal(0)
    return payee.sign(session, world.clock.now())


def budget_authorize(world: World, step: dict) -> dict:
    session = world.ctx["session"]
    clean = {k: v for k, v in session.items() if not k.startswith("_")}
    sba = {
        "@context": PAY_CTX, "id": "urn:sim:sba:" + step["amount"], "type": "SessionBudgetAuthorization",
        "usageSession": session["id"], "sessionDigest": ac.jcs_digest(clean),
        "payer": world.actor("agent").did, "payee": session["payee"],
        "committedAmount": step["amount"], "currency": session["currency"],
        "nonce": "sba-" + step["amount"],
        "vp": {"@context": PAY_CTX, "type": "VerifiablePresentation",
               "verifiableCredential": [world.credential]},
    }
    sba = world.actor("agent").sign(sba, world.clock.now())
    if not ac.verify_ecdsa_jcs_2022(sba):
        raise Reject("badSignature")
    world.session_committed = _d(step["amount"])          # wallet records the committed budget
    return sba


def accrue(world: World, step: dict) -> dict:
    session = world.ctx["session"]
    payee = world.actor(session["_payeeRole"])
    proposed = world.session_accrued + _d(step["amount"])
    if proposed > world.session_committed:
        raise Reject("budgetExceeded")                    # wallet halts metering at the cap
    world.session_accrued = proposed
    accrual = {
        "@context": PAY_CTX, "id": "urn:sim:accrual:" + step["amount"], "type": "UsageAccrual",
        "session": session["id"], "accrualKind": "incremental",
        "amountAccrued": step["amount"], "currency": session["currency"],
        "timestamp": world.clock.now(),
    }
    if "units" in step:                                   # metered units (e.g. tokens) for this batch
        world.session_units += _d(step["units"])
        accrual["meterReading"] = str(step["units"])
        accrual["totalMeterReading"] = str(world.session_units)
        dim = (session.get("pricingModel") or {}).get("dimension")
        if dim:
            accrual["dimension"] = dim
    return payee.sign(accrual, world.clock.now())


def extend(world: World, step: dict) -> dict:
    session = world.ctx["session"]
    payee = world.actor(session["_payeeRole"])
    session["maxAmount"] = step["newBudget"]              # extension raises the cap...
    session = payee.sign({k: v for k, v in session.items() if k != "proof"}, world.clock.now())
    session["_payeeRole"] = payee.role
    world.ctx["session"] = session                        # ...and needs a fresh budget_authorize
    return session


def close_session(world: World, step: dict) -> dict:
    session = world.ctx["session"]
    ref, settled = world.ledger.settle("agent", session["_payeeRole"], str(world.session_accrued),
                                       "session:" + session["id"])
    execution = world.actor("wallet").sign({
        "@context": PAY_CTX, "id": "urn:sim:exec:session", "type": "PaymentExecution",
        "sessionBudgetAuthorization": "urn:sim:sba", "amount": str(settled),
        "currency": session["currency"], "status": "completed" if settled > 0 else "failed",
        "settlementRef": ref, "timestamp": world.clock.now(),
    }, world.clock.now())
    world.ctx["sessionExecution"] = execution
    return execution


# ---- post-settlement: refunds, reversals, and the dispute lifecycle ---------
#
# These run AFTER a settled payment (the scenario pays first). On the play ledger,
# a Refund and a dispute Reversal move money back payee -> agent; the Dispute,
# DisputeEvidence, and DisputeResolution are signed records/decisions with no
# direct ledger effect. Object shapes mirror the disputes bundle of the spec.

def _orig_payee_role(world: World) -> str:
    return getattr(world, "last_payee_role", "payee")


def build_refund(world: World, step: dict) -> dict:
    ex = world.ctx["execution"]
    amount = step["amount"]
    refunded = world.ctx.get("_refunded", Decimal(0))
    if _d(amount) + refunded > _d(ex["amount"]):
        raise Reject("overRefund")                         # cannot refund more than was settled
    payee_role = _orig_payee_role(world)
    world.ledger.settle(payee_role, "agent", amount, "refund:" + str(len(world.ctx)))  # money back
    world.ctx["_refunded"] = refunded + _d(amount)
    refund = {
        "@context": PAY_CTX, "id": "urn:sim:refund:" + str(len(world.ctx)), "type": "Refund",
        "receipt": (world.ctx.get("receipt") or {}).get("id"),
        "execution": ex["id"], "executionDigest": ac.jcs_digest(ex),
        "payer": world.actor("agent").did, "payee": world.actor(payee_role).did,
        "amount": amount, "currency": ex["currency"],
        "reason": step.get("reason", "disp:goodwill"), "timestamp": world.clock.now(),
    }
    return world.actor(payee_role).sign(refund, world.clock.now())


def build_reversal(world: World, step: dict) -> dict:
    ex = world.ctx["execution"]
    cause = step.get("cause", "refund")
    if cause == "dispute":
        res = world.ctx.get("resolution")
        if not res or res["outcome"] not in ("upheld", "partial"):
            raise Reject("noReversalBasis")                # no chargeback unless the dispute was (partly) upheld
        amount = res["resolvedAmount"]
        world.ledger.settle(_orig_payee_role(world), "agent", amount, "reversal:" + str(len(world.ctx)))
        basis = {"cause": "dispute", "resolution": res["id"], "resolutionDigest": ac.jcs_digest(res)}
    else:                                                  # the refund already moved the money; this records it
        rf = world.ctx["refund"]
        amount = rf["amount"]
        basis = {"cause": "refund", "refund": rf["id"], "refundDigest": ac.jcs_digest(rf)}
    reversal = {
        "@context": PAY_CTX, "id": "urn:sim:reversal:" + str(len(world.ctx)), "type": "Reversal",
        **basis, "execution": ex["id"], "executionDigest": ac.jcs_digest(ex),
        "payer": world.actor("agent").did, "payee": world.actor(_orig_payee_role(world)).did,
        "amount": amount, "currency": ex["currency"], "status": "completed",
        "settlementRef": "sim:reversal:" + str(len(world.ctx)), "timestamp": world.clock.now(),
    }
    return world.actor("wallet").sign(reversal, world.clock.now())


def build_reversal_ack(world: World, step: dict) -> dict:
    rv = world.ctx["reversal"]
    ack = {
        "@context": PAY_CTX, "id": "urn:sim:reversal-ack:1", "type": "ReversalAcknowledgement",
        "reversal": rv["id"], "reversalDigest": ac.jcs_digest(rv),
        "payer": world.actor("agent").did, "payee": rv["payee"],
        "amount": rv["amount"], "currency": rv["currency"], "receivedAt": world.clock.now(),
    }
    return world.actor("agent").sign(ack, world.clock.now())


def build_dispute(world: World, step: dict) -> dict:
    ex = world.ctx["execution"]
    rc = world.ctx.get("receipt") or {}
    disp = {
        "@context": PAY_CTX, "id": "urn:sim:dispute:1", "type": "Dispute",
        "execution": ex["id"], "executionDigest": ac.jcs_digest(ex),
        "receipt": rc.get("id"), "payer": world.actor("agent").did,
        "payee": world.actor(_orig_payee_role(world)).did,
        "disputedAmount": step.get("disputedAmount", ex["amount"]), "currency": ex["currency"],
        "reason": step.get("reason", "disp:not-delivered"), "claim": step.get("claim", "Disputed charge."),
        "timestamp": world.clock.now(),
    }
    if step.get("arbiter"):
        disp["arbiter"] = world.actor("arbiter").did
    return world.actor("agent").sign(disp, world.clock.now())


def build_evidence(world: World, step: dict) -> dict:
    disp = world.ctx["dispute"]
    role = step.get("role", "payee")
    signer = world.actor(role if role != "payer" else "agent")
    ev = {
        "@context": PAY_CTX, "id": "urn:sim:evidence:" + str(len(world.ctx)), "type": "DisputeEvidence",
        "dispute": disp["id"], "disputeDigest": ac.jcs_digest(disp),
        "submittedBy": signer.did, "role": role, "sequence": step.get("sequence", 1),
        "evidenceType": step.get("evidenceType", "delivery-log"),
        "statement": step.get("statement", "Evidence."), "timestamp": world.clock.now(),
    }
    return signer.sign(ev, world.clock.now())


def build_resolution(world: World, step: dict) -> dict:
    disp = world.ctx["dispute"]
    role = step.get("resolverRole", "payee")
    signer = world.actor(role if role in ("payee", "arbiter") else "payee")
    res = {
        "@context": PAY_CTX, "id": "urn:sim:resolution:" + str(len(world.ctx)), "type": "DisputeResolution",
        "dispute": disp["id"], "disputeDigest": ac.jcs_digest(disp),
        "resolvedBy": signer.did, "resolverRole": role,
        "outcome": step["outcome"], "resolvedAmount": step.get("resolvedAmount", "0"),
        "currency": disp["currency"], "timestamp": world.clock.now(),
    }
    return signer.sign(res, world.clock.now())


# ---- step handlers + the declarative runner ---------------------------------

def _store(world, key, obj):
    world.ctx[key] = obj
    return obj


HANDLERS = {
    "quote": lambda w, s: {"ok": True, "_set": ("quote", build_quote(w, s))},
    "authorize": lambda w, s: {"ok": True, "_set": ("authz", build_authorization(w, s))},
    "confirm": lambda w, s: {"ok": True, "_set": ("confirmation", build_confirmation(w, s))},
    "execute": lambda w, s: _do_execute(w, s),
    "replay": lambda w, s: _do_execute(w, s),             # resubmit the standing authz
    "receipt": lambda w, s: {"ok": True, "_set": ("receipt", _build_receipt(w))},
    "advance_clock": lambda w, s: w.clock.advance(int(s["seconds"])) or {"ok": True},
    "corrupt_authz": lambda w, s: {"ok": True, "_corrupt_authz": True},
    "tamper_quote": lambda w, s: _tamper_quote(w, s),
    "open_session": lambda w, s: {"ok": True, "_set": ("session", open_session(w, s))},
    "budget_authorize": lambda w, s: {"ok": True, "_set": ("sba", budget_authorize(w, s))},
    "accrue": lambda w, s: {"ok": True, "_set": ("accrual", accrue(w, s))},
    "extend": lambda w, s: {"ok": True, "_set": ("session", extend(w, s))},
    "close_session": lambda w, s: {"status": close_session(w, s)["status"]},
    "refund": lambda w, s: {"ok": True, "_set": ("refund", build_refund(w, s))},
    "reversal": lambda w, s: {"ok": True, "_set": ("reversal", build_reversal(w, s))},
    "reversal_ack": lambda w, s: {"ok": True, "_set": ("reversalAck", build_reversal_ack(w, s))},
    "dispute": lambda w, s: {"ok": True, "_set": ("dispute", build_dispute(w, s))},
    "dispute_evidence": lambda w, s: {"ok": True, "_set": ("evidence", build_evidence(w, s))},
    "dispute_resolution": lambda w, s: {"ok": True, "_set": ("resolution", build_resolution(w, s))},
}


def _build_receipt(world):
    quote = world.ctx["quote"]
    return world.actor(quote["_payeeRole"]).sign({
        "@context": PAY_CTX, "id": "urn:sim:receipt:1", "type": "PaymentReceipt",
        "quote": quote["id"], "payee": quote["payee"], "payer": world.actor("agent").did,
        "amount": quote["amount"], "currency": quote["currency"], "status": "fulfilled",
        "timestamp": world.clock.now(),
    }, world.clock.now())


def _tamper_quote(world, step):
    for k, v in step["set"].items():        # mutate the quote AFTER the authz committed its digest
        world.ctx["quote"][k] = v
    return {"ok": True}


def _do_execute(world, step):
    authz = world.ctx["authz"]
    if step.get("_corrupted"):
        pass
    execution = wallet_process(world, authz)
    return {"status": execution["status"], "settled": execution["amount"]}


_OBJECT_OF = {
    "quote": "quote", "authorize": "authz", "confirm": "confirmation",
    "execute": "execution", "replay": "execution", "receipt": "receipt",
    "open_session": "session", "budget_authorize": "sba", "accrue": "accrual",
    "close_session": "sessionExecution",
    "refund": "refund", "reversal": "reversal", "reversal_ack": "reversalAck",
    "dispute": "dispute", "dispute_evidence": "evidence", "dispute_resolution": "resolution",
}


def _execute_step(world: World, step: dict):
    """Run one step against the world; return (outcome_dict, emitted_object_or_None).
    A Reject is turned into an outcome, not raised -- the runner decides if it was
    expected."""
    action = step["action"]
    if action == "corrupt_authz":                          # post-signing corruption breaks the proof
        seg = world.ctx["authz"]["proof"]["proofValue"]
        world.ctx["authz"]["proof"]["proofValue"] = "z" + ("A" if seg[1] != "A" else "B") + seg[2:]
        return {"outcome": "ok"}, None
    try:
        res = HANDLERS[action](world, step) or {"ok": True}
        if isinstance(res, dict) and "_set" in res:
            _store(world, *res["_set"])
        outcome = {"outcome": "ok", **{k: v for k, v in res.items() if not k.startswith("_")}}
    except Reject as r:
        outcome = {"outcome": "reject", "code": r.code}
    obj = world.ctx.get(_OBJECT_OF.get(action)) if _OBJECT_OF.get(action) else None
    return outcome, obj


def _matches(expect, got) -> bool:
    if expect == "ok":
        return got["outcome"] == "ok"
    if "reject" in expect:
        return got["outcome"] == "reject" and got.get("code") == expect["reject"]
    if got["outcome"] != "ok":
        return False
    if "status" in expect and got.get("status") != expect["status"]:
        return False
    if "settled" in expect and _d(got.get("settled", 0)) != _d(expect["settled"]):
        return False
    return True


def run_scenario(sc: dict) -> None:
    """Execute a declarative scenario; raise AssertionError on any unmet expectation."""
    world = World(sc)
    for i, step in enumerate(sc["steps"]):
        outcome, _ = _execute_step(world, step)
        assert _matches(step.get("expect", "ok"), outcome), \
            f"{sc['name']} step {i} ({step['action']}): expected {step.get('expect', 'ok')}, got {outcome}"
    _check_final(sc, world)


def _bal(d: dict) -> dict:
    return {k: str(v) for k, v in d.items()}


def run_traced(sc: dict) -> dict:
    """Execute a scenario and return a structured trace (for UIs/tooling): each step's
    outcome, the signed message it emitted, the clock, and the ledger after it -- plus
    the spending-authority credential and the overall pass/fail. Never raises."""
    world = World(sc)
    start = _bal(world.ledger.bal)
    trace, all_ok = [], True
    for i, step in enumerate(sc["steps"]):
        outcome, obj = _execute_step(world, step)
        matched = _matches(step.get("expect", "ok"), outcome)
        all_ok = all_ok and matched
        trace.append({
            "i": i, "action": step["action"],
            "params": {k: v for k, v in step.items() if k not in ("action", "expect")},
            "expect": step.get("expect", "ok"), "outcome": outcome, "matched": matched,
            "object": obj, "clock": world.clock.now(), "balances": _bal(world.ledger.bal),
            "session": {"accrued": str(world.session_accrued), "committed": str(world.session_committed),
                        "units": str(world.session_units), "dimension": (world.ctx.get("session") or {}).get("pricingModel", {}).get("dimension")},
        })
    final_ok = all(world.ledger.bal.get(r, Decimal(0)) == _d(v)
                   for r, v in sc.get("finalBalances", {}).items())
    return {
        "name": sc["name"], "description": sc.get("description", ""),
        "policy": sc.get("policy", {}), "credential": world.credential,
        "imported": sc.get("credential", {}).get("source") == "ap2-intent",
        "resolver": sorted(world.resolver.keys()),
        "start": start, "final": _bal(world.ledger.bal), "finalBalances": sc.get("finalBalances", {}),
        "trace": trace, "ok": all_ok and final_ok,
    }


def _check_final(sc, world):
    for role, expected in sc.get("finalBalances", {}).items():
        got = world.ledger.bal.get(role, Decimal(0))
        assert got == _d(expected), f"{sc['name']} final balance {role}: {got} != {expected}"


# ---- scenario loading + CLI -------------------------------------------------

SCENARIOS = Path(__file__).parent / "sim-scenarios.json"


def load_scenarios() -> list:
    return json.loads(SCENARIOS.read_text(encoding="utf-8"))


def main() -> int:
    failed = []
    scenarios = load_scenarios()
    print(f"AVP-Micro protocol simulator -- {len(scenarios)} declarative use cases\n")
    for sc in scenarios:
        try:
            run_scenario(sc)
            print(f"  [PASS] {sc['name']} -- {sc.get('description', '')}")
        except AssertionError as e:
            failed.append(sc["name"])
            print(f"  [FAIL] {sc['name']}: {e}")
    print()
    if failed:
        print(f"FAIL: {len(failed)} scenario(s) failed: {failed}")
        return 1
    print(f"PASS: all {len(scenarios)} scenarios behaved as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
