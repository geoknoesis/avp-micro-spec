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

Step actions: issue, revoke, quote, authorize, execute, receipt, confirm, replay,
advance_clock, corrupt_authz, tamper_quote, open_session, budget_authorize, accrue,
extend, close_session. ``issue`` (re)mints the SpendingAuthorizationCredential the
agent holds -- it accepts ``subject`` (the role whose key the credential is bound to;
a non-agent role models a wrong-key delegation), ``expired`` (a credential whose
validity window has already passed), ``validFor`` seconds, ``revoked``, or
``source: "ap2-intent"`` (the user issues an AP2 IntentMandate the agent imports).
``revoke`` adds the standing credential to the wallet's revocation set. The on-chain
settlement-binding steps -- payee_binding, settle_instruct, settle_proof, escrow_lock,
escrow_release, escrow_refund, reverse_settle_instruct, reverse_settle_proof -- bind a
PaymentAuthorization to a concrete rail (``rail``: evm-stablecoin / x402 / lightning;
``mode``: direct / escrow; ``archetype``: pkh / binding) and carry a chain-native proof;
the wallet enforces DID<->account binding, finality, and proof<->instruction binding.
Each step's ``expect`` is "ok", {"reject": code}, or {"status": s, "settled": amount}.
Rejection codes are listed in REJECTIONS below.
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
import settlement as stl

ISO = "%Y-%m-%dT%H:%M:%SZ"
PAY_CTX = ["https://www.w3.org/ns/credentials/v2",
           "https://w3id.org/security/data-integrity/v2",
           "https://w3id.org/spending-authority/v1",
           "https://w3id.org/avp-micro/v1"]
DSA_CTX = PAY_CTX[:3]
SETTLE_CTX = PAY_CTX + ["https://w3id.org/avp-micro/settlement/v1"]

# Rail -> CAIP-2 chain id (the test-fixture chains the settlement bundle uses).
RAIL_CHAIN = {
    "evm-stablecoin": "eip155:8453",
    "x402": "eip155:8453",
    "lightning": "bip122:000000000019d6689c085ae165831e93",
}
LN_RATE = "100000"  # USD per BTC (fixture rate for the Lightning profile)

# every wallet rejection the simulator can emit (the runtime-enforcement vocabulary)
REJECTIONS = {
    "badSignature", "badCredential", "credentialExpired", "credentialRevoked",
    "holderMismatch", "quoteMismatch",
    "amountMismatch", "currencyMismatch", "overCap", "payeeNotAllowed",
    "categoryNotAllowed", "dailyLimitExceeded", "expired", "nonceReuse",
    "doubleSpend", "budgetExceeded", "missingConfirmation", "forgedConfirmation",
    "overRefund", "noReversalBasis",
    "accountRedirection", "settlementNotFinal", "settlementMismatch",
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
        self.revoked: set = set()           # credential ids the principal has revoked
        self.credential = build_credential(self, {})   # the standing authority (precondition)

    def actor(self, role: str) -> Actor:
        if role not in self._actors:
            self._actors[role] = Actor(role)
        return self._actors[role]

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


# ---- credential issuance ----------------------------------------------------

def build_credential(world: World, step: dict) -> dict:
    """Issue the SpendingAuthorizationCredential the agent holds. Default issuance
    mirrors the scenario policy and binds the credential to the agent's key. An
    ``issue`` step may override the ``subject`` (a non-agent role models a wrong-key
    delegation), force an already-``expired`` validity window or a custom ``validFor``,
    or select ``source: "ap2-intent"`` -- the user issues an AP2 IntentMandate that is
    imported proof-preservingly. The principal is always the issuer; authority roots in
    the principal (native) or the user DID (AP2), never in any intermediary."""
    if (step.get("source") or world.sc.get("credential", {}).get("source")) == "ap2-intent":
        return world._import_ap2_intent()
    p = world.sc.get("policy", {})
    subj = {"id": world.actor(step.get("subject", "agent")).did, "currency": p.get("currency", "USD")}
    if "maxPerTransaction" in p:
        subj["maxPerTransaction"] = p["maxPerTransaction"]
    if "dailyLimit" in p:
        subj["dailyLimit"] = p["dailyLimit"]
    if "allowedPayees" in p:
        subj["allowedPayees"] = [world.actor(r).did for r in p["allowedPayees"]]
    if "allowedCategories" in p:
        subj["allowedServiceCategories"] = list(p["allowedCategories"])
    if step.get("expired"):
        valid_from, valid_until = world.clock.plus(-7200), world.clock.plus(-1)
    else:
        valid_from = world.clock.now()
        valid_until = world.clock.plus(int(step.get("validFor", 365 * 24 * 3600)))
    cred = {
        "@context": DSA_CTX,
        "id": "urn:sim:vc:spendauth",
        "type": ["VerifiableCredential", "SpendingAuthorizationCredential"],
        "issuer": world.actor("principal").did,
        "validFrom": valid_from, "validUntil": valid_until,
        "credentialSubject": subj,
    }
    return world.actor("principal").sign(cred, world.clock.now())


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


def wallet_verify(world: World, authz: dict) -> dict:
    """Verify + enforce policy on an authorization; return the credential subject.
    Raises Reject on any failure. Does NOT settle or consume the authorization --
    the caller's settlement step (execute, or a settlement-binding proof) does that."""
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
    # 2b. credential lifecycle: not revoked by the principal, and within its validity window
    if cred.get("id") in world.revoked:
        raise Reject("credentialRevoked")
    if "validUntil" in cred and world.clock.after(cred["validUntil"]):
        raise Reject("credentialExpired")
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
    return subj


def wallet_process(world: World, authz: dict) -> dict:
    """Verify, then settle on the simulated rail and emit the wallet-signed execution."""
    quote = world.ctx["quote"]
    wallet_verify(world, authz)
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


# ---- on-chain settlement binding --------------------------------------------
#
# The Payments bundle scopes OUT the money-moving step; the settlement bundle binds
# a PaymentAuthorization to a concrete rail (EVM stablecoin / x402 / Lightning) with
# signed SettlementInstruction + SettlementProof objects, an optional escrow lifecycle,
# and an on-chain reversal (compensating transfer). Chain data (tx hashes, preimages,
# confirmations) are DETERMINISTIC FIXTURES from settlement.py -- nothing is broadcast.
# In the simulator these steps ARE the settlement: the wallet verifies the binding
# (DID<->account anti-redirection, finality, proof<->instruction, settled == instructed)
# and only then moves play money on the simulated ledger.

def _amount_base(rail: str, amount: str):
    """(amountBase, rate-or-None) for a rail. Lightning quotes USD, settles msat at LN_RATE."""
    if rail == "lightning":
        return stl.usd_to_msat(amount, LN_RATE), LN_RATE
    asset = stl.RAILS[rail]["asset"]
    return stl.to_base_units(amount, stl.decimals_for_asset(asset)), None


def _settle_onchain(world: World, instr: dict) -> Decimal:
    """Move play money agent -> payee to reflect a verified on-chain settlement, and
    consume the underlying authorization (single use)."""
    payee_role = _orig_payee_role(world)
    _ref, settled = world.ledger.settle("agent", payee_role, instr["amount"], "settle:" + instr["id"])
    authz = world.ctx.get("authz") or {}
    if authz.get("nonce"):
        world.nonces.add(authz["nonce"])
    if authz.get("id"):
        world.executed.add(authz["id"])
    if settled > 0:
        world.daily.append((world.clock.date(), settled))
    world.ctx["_settled"] = str(settled)
    return settled


def build_payee_binding(world: World, step: dict) -> dict:
    """The payee signs a PayeeAccountBinding asserting it controls a CAIP-10 account on a
    chain (binding archetype (b)); the wallet later checks the instruction pays only that."""
    payee = world.actor(_orig_payee_role(world))
    chain = RAIL_CHAIN[step.get("rail", "x402")]
    account = chain + ":" + stl.fake_address("payee-acct:" + payee.role)
    world.ctx["_payeeAccount"] = account
    binding = {
        "@context": SETTLE_CTX, "id": "urn:sim:payee-binding:1", "type": "PayeeAccountBinding",
        "subject": payee.did, "account": account, "chain": chain,
    }
    return payee.sign(binding, world.clock.now())


def _do_settle_instruct(world: World, step: dict) -> dict:
    """The wallet binds the standing PaymentAuthorization to a concrete rail. It re-verifies
    the authorization, then refuses to instruct a payment to an account that is not bound to
    the payee DID (anti-redirection)."""
    authz = world.ctx["authz"]
    rail = step.get("rail", "evm-stablecoin")
    chain = RAIL_CHAIN[rail]
    mode = step.get("mode", "direct")
    payee_role = _orig_payee_role(world)
    payee = world.actor(payee_role)
    amount_base, rate = _amount_base(rail, authz["amount"])
    binding = world.ctx.get("binding")
    archetype = step.get("archetype", "binding")
    if step.get("redirect"):                              # attacker account, not bound to the payee
        account, payee_did, binding_ref = chain + ":" + stl.fake_address("attacker"), payee.did, None
    elif archetype == "pkh":                              # binding archetype (a): the DID *is* the account
        addr = stl.fake_address("payee-pkh:" + payee_role)
        account, payee_did, binding_ref = chain + ":" + addr, "did:pkh:" + chain + ":" + addr, None
    else:                                                 # binding archetype (b): PayeeAccountBinding
        account = world.ctx.get("_payeeAccount") or (chain + ":" + stl.fake_address("payee-acct:" + payee_role))
        payee_did, binding_ref = payee.did, (binding or {}).get("id")
    instr = {
        "@context": SETTLE_CTX, "id": "urn:sim:settle-instr:" + step.get("nonce", "1"),
        "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": ac.jcs_digest(authz),
        "rail": "stl:rail-" + rail, "chain": chain,
        "payeeAccount": account, "asset": stl.RAILS[rail]["asset"],
        "payer": world.actor("agent").did, "payee": payee_did,
        "amount": authz["amount"], "currency": authz["currency"], "amountBase": amount_base,
        "confirmationThreshold": stl.RAILS[rail]["threshold"], "mode": mode,
        "nonce": "settle-" + step.get("nonce", "1"), "expires": world.clock.plus(1800),
    }
    if rate:
        instr["rate"] = rate
    if binding_ref:
        instr["payeeAccountBinding"] = binding_ref
    instr = world.actor("wallet").sign(instr, world.clock.now())
    wallet_verify(world, authz)                           # the authorization must still be valid + in policy
    # anti-redirection on the confirmation rails: pay only the account bound to the payee DID.
    # Lightning binds via the hold-invoice itself, so the DID<->account rule does not apply.
    if rail != "lightning" and not stl.account_binding_ok(instr, binding):
        raise Reject("accountRedirection")
    world.ctx["_settleRail"] = rail
    world.ctx["instruction"] = instr
    return {"ok": True}


def _do_settle_proof(world: World, step: dict) -> dict:
    """The rail returns a SettlementProof. The wallet checks it binds the instruction, is final,
    and settles the instructed amount; a direct-mode proof then moves the money."""
    instr = world.ctx["instruction"]
    rail = world.ctx.get("_settleRail", "evm-stablecoin")
    threshold = instr["confirmationThreshold"]
    settled_base = str(int(instr["amountBase"]) - 1) if step.get("underpaid") else instr["amountBase"]
    proof = {
        "@context": SETTLE_CTX, "id": "urn:sim:settle-proof:" + step.get("nonce", "1"),
        "type": "SettlementProof",
        "instruction": instr["id"], "instructionDigest": ac.jcs_digest(instr),
        "chain": instr["chain"], "settledAmountBase": settled_base, "asset": instr["asset"],
        "finality": step.get("finality", "final"), "observedAt": world.clock.now(),
    }
    if rail == "lightning":                               # preimage reveal == finality (no confirmations)
        label = "ln:" + instr["id"]
        proof["preimage"] = stl.fake_preimage(label)
        proof["transaction"] = stl.fake_payment_hash(label)   # == sha256(preimage)
    else:
        proof["transaction"] = stl.fake_tx(instr["id"] + ":" + step.get("nonce", "1"))
        proof["confirmations"] = int(step.get("confirmations", threshold))
        proof["blockHeight"] = 19000000
    proof = world.actor("wallet").sign(proof, world.clock.now())
    if proof["instruction"] != instr["id"] or proof["instructionDigest"] != ac.jcs_digest(instr):
        raise Reject("settlementMismatch")
    if not stl.finality_ok(proof, threshold):
        raise Reject("settlementNotFinal")
    if proof["settledAmountBase"] != instr["amountBase"]:
        raise Reject("settlementMismatch")
    world.ctx["settleProof"] = proof
    if instr.get("mode") == "direct":                     # escrow waits for an explicit release
        settled = _settle_onchain(world, instr)
        return {"status": "completed" if settled == _d(instr["amount"]) else "partial", "settled": str(settled)}
    return {"ok": True}


def _do_escrow_lock(world: World, step: dict) -> dict:
    instr = world.ctx["instruction"]
    rail = world.ctx.get("_settleRail", "evm-stablecoin")
    prefix = "ln-hold:" if rail == "lightning" else "escrow:"
    lock = {
        "@context": SETTLE_CTX, "id": "urn:sim:escrow-lock:1", "type": "EscrowLock",
        "instruction": instr["id"], "instructionDigest": ac.jcs_digest(instr),
        "lockRef": prefix + stl.fake_address("lock:" + instr["id"])[:18],
        "lockedAmountBase": instr["amountBase"], "asset": instr["asset"],
        "timeout": world.clock.plus(900),
    }
    world.ctx["lock"] = world.actor("wallet").sign(lock, world.clock.now())
    return {"ok": True}


def _do_escrow_release(world: World, step: dict) -> dict:
    """Release the hold to the payee, binding the lock and the final settlement proof."""
    lock, proof, instr = world.ctx["lock"], world.ctx["settleProof"], world.ctx["instruction"]
    if proof["instructionDigest"] != ac.jcs_digest(instr):
        raise Reject("settlementMismatch")
    rel = {
        "@context": SETTLE_CTX, "id": "urn:sim:escrow-release:1", "type": "EscrowRelease",
        "lock": lock["id"], "lockDigest": ac.jcs_digest(lock),
        "settlementProof": proof["id"], "settlementProofDigest": ac.jcs_digest(proof),
    }
    world.ctx["release"] = world.actor("wallet").sign(rel, world.clock.now())
    settled = _settle_onchain(world, instr)
    return {"status": "completed" if settled == _d(instr["amount"]) else "partial", "settled": str(settled)}


def _do_escrow_refund(world: World, step: dict) -> dict:
    """Escrow timed out: the held funds return to the payer; the payee is never paid."""
    lock, proof = world.ctx["lock"], world.ctx["settleProof"]
    ref = {
        "@context": SETTLE_CTX, "id": "urn:sim:escrow-refund:1", "type": "EscrowRefund",
        "lock": lock["id"], "lockDigest": ac.jcs_digest(lock),
        "settlementProof": proof["id"], "settlementProofDigest": ac.jcs_digest(proof),
        "reason": step.get("reason", "timeout"),
    }
    world.ctx["escrowRefund"] = world.actor("wallet").sign(ref, world.clock.now())
    return {"ok": True}


# ---- attested (closed-processor) settlement: card via Stripe + bank/RTP ------
# These rails settle inside a private processor, so finality is ATTESTED, not on-chain.
# The wallet builds an AttestedSettlementInstruction (decimal fiat -- no chain/asset/base
# units) bound to a payee-signed ProcessorAccountBinding, and the payee returns an
# AttestedSettlementProof embedding the processor's result (payee-attested). The
# anti-redirection, amount, and parties checks mirror the on-chain rails.

_ATTESTED_RAIL_ID = {"card-stripe": "stl:rail-card-stripe", "bank-rtp": "stl:rail-bank-rtp",
                     "paypal": "stl:rail-paypal", "visa-direct": "stl:rail-visa-direct"}
_ATTESTED_PROCESSOR = {"card-stripe": "did:web:stripe.com", "bank-rtp": "did:web:bank.example",
                       "paypal": "did:web:paypal.com", "visa-direct": "did:web:visa.com"}
_ATTESTED_REF_PREFIX = {"card-stripe": "stripe:pi_", "bank-rtp": "rtp:e2e:", "paypal": "paypal:capture:",
                        "visa-direct": "visa-direct:oct:"}


def _do_processor_binding(world: World, step: dict) -> dict:
    """The payee signs a ProcessorAccountBinding for its processor/bank account -- the
    closed-processor analogue of a PayeeAccountBinding."""
    rail = step.get("rail", "card-stripe")
    payee = world.actor(_orig_payee_role(world))
    prefix = "stripe:acct_" if rail == "card-stripe" else "bank:token:"
    binding = {
        "@context": SETTLE_CTX, "id": "urn:sim:proc-binding:1", "type": "ProcessorAccountBinding",
        "subject": payee.did, "account": prefix + stl.fake_address("acct:" + payee.role)[2:14],
        "processor": _ATTESTED_PROCESSOR[rail], "rail": _ATTESTED_RAIL_ID[rail],
    }
    world.ctx["procBinding"] = payee.sign(binding, world.clock.now())
    return {"ok": True}


def _do_attested_instruct(world: World, step: dict) -> dict:
    """Bind the standing authorization to a closed-processor rail; refuse to settle to an
    account not bound to the payee DID (anti-redirection)."""
    authz = world.ctx["authz"]
    rail = step.get("rail", "card-stripe")
    payee = world.actor(_orig_payee_role(world))
    if step.get("redirect"):                          # binding owned by an attacker, not the payee
        attacker = world.actor("agent")
        binding = payee.sign({
            "@context": SETTLE_CTX, "id": "urn:sim:proc-binding:redir", "type": "ProcessorAccountBinding",
            "subject": attacker.did, "account": "stripe:acct_attacker",
            "processor": _ATTESTED_PROCESSOR[rail], "rail": _ATTESTED_RAIL_ID[rail],
        }, world.clock.now())
    else:
        binding = world.ctx.get("procBinding")
    instr = {
        "@context": SETTLE_CTX, "id": "urn:sim:settle-instr:" + step.get("nonce", "1"),
        "type": "AttestedSettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": ac.jcs_digest(authz),
        "rail": _ATTESTED_RAIL_ID[rail], "payeeAccountBinding": (binding or {}).get("id"),
        "payer": world.actor("agent").did, "payee": payee.did,
        "amount": authz["amount"], "currency": authz["currency"],
        "mode": step.get("mode", "direct"),
        "nonce": "settle-" + step.get("nonce", "1"), "expires": world.clock.plus(1800),
    }
    if rail == "card-stripe":
        instr["captureMode"] = step.get("captureMode", "auth-capture")
        instr["processorIntent"] = "stripe:pi_" + step.get("nonce", "1")
    elif rail == "bank-rtp":
        instr["scheme"] = step.get("scheme", "fednow")
    # paypal (and other wallet processors): direct immediate capture, no card/bank fields
    instr = world.actor("wallet").sign(instr, world.clock.now())
    wallet_verify(world, authz)                        # the authorization must still be valid + in policy
    if not stl.attested_binding_ok(instr, binding):    # settle only to the payee-bound account
        raise Reject("accountRedirection")
    world.ctx["_settleRail"] = rail
    world.ctx["instruction"] = instr
    return {"ok": True}


def _do_attested_proof(world: World, step: dict) -> dict:
    """The payee returns an AttestedSettlementProof embedding the processor's result; the
    wallet checks the binding, attested finality, and settled amount, then moves money
    (card capture / RTP credit)."""
    instr = world.ctx["instruction"]
    rail = world.ctx.get("_settleRail", "card-stripe")
    payee = world.actor(_orig_payee_role(world))
    _default_status = {"card-stripe": "captured", "bank-rtp": "settled", "paypal": "completed",
                       "visa-direct": "approved"}
    status = step.get("status", _default_status.get(rail, "settled"))
    ref_prefix = _ATTESTED_REF_PREFIX.get(rail, "ref:")
    proof = {
        "@context": SETTLE_CTX, "id": "urn:sim:settle-proof:" + step.get("nonce", "1"),
        "type": "AttestedSettlementProof",
        "instruction": instr["id"], "instructionDigest": ac.jcs_digest(instr),
        "rail": instr["rail"], "settledAmount": instr["amount"], "currency": instr["currency"],
        "attestation": {
            "type": "ProcessorAttestation", "mode": "payee-attested",
            "processor": _ATTESTED_PROCESSOR[rail], "reference": ref_prefix + step.get("nonce", "1"),
            "status": status, "evidence": "processor-evidence:" + step.get("nonce", "1"),
            "observedAt": world.clock.now(),
        },
        "finality": step.get("finality", "final"), "observedAt": world.clock.now(),
    }
    proof = payee.sign(proof, world.clock.now())       # payee-attested: the payee signs the proof
    if proof["instruction"] != instr["id"] or proof["instructionDigest"] != ac.jcs_digest(instr):
        raise Reject("settlementMismatch")
    if not stl.attested_finality_ok(proof):
        raise Reject("settlementNotFinal")
    if proof["settledAmount"] != instr["amount"]:
        raise Reject("settlementMismatch")
    world.ctx["settleProof"] = proof
    settled = _settle_onchain(world, instr)            # capture (card) / credit (RTP) moves money
    return {"status": "completed" if settled == _d(instr["amount"]) else "partial", "settled": str(settled)}


def _do_reverse_instruct(world: World, step: dict) -> dict:
    """A compensating on-chain transfer (payer/payee swapped) -- the settlement-layer image of
    a disputes Reversal. The original settlement must have happened."""
    orig, authz = world.ctx["instruction"], world.ctx["authz"]
    instr = {
        "@context": SETTLE_CTX, "id": "urn:sim:settle-instr:reverse", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": ac.jcs_digest(authz),
        "rail": orig["rail"], "chain": orig["chain"],
        "payeeAccount": orig["chain"] + ":" + stl.fake_address("agent-evm"), "asset": orig["asset"],
        "payer": orig["payee"], "payee": orig["payer"],   # swapped vs the original
        "amount": orig["amount"], "currency": orig["currency"], "amountBase": orig["amountBase"],
        "confirmationThreshold": orig["confirmationThreshold"], "mode": "direct",
        "nonce": "settle-reverse-1", "expires": world.clock.plus(3600),
    }
    if not (instr["payer"] == orig["payee"] and instr["payee"] == orig["payer"]):
        raise Reject("settlementMismatch")
    world.ctx["reverseInstruction"] = world.actor("wallet").sign(instr, world.clock.now())
    return {"ok": True}


def _do_reverse_proof(world: World, step: dict) -> dict:
    instr, orig = world.ctx["reverseInstruction"], world.ctx["instruction"]
    threshold = instr["confirmationThreshold"]
    proof = {
        "@context": SETTLE_CTX, "id": "urn:sim:settle-proof:reverse", "type": "SettlementProof",
        "instruction": instr["id"], "instructionDigest": ac.jcs_digest(instr),
        "chain": instr["chain"], "transaction": stl.fake_tx("reverse:" + instr["id"]),
        "settledAmountBase": instr["amountBase"], "asset": instr["asset"],
        "blockHeight": 19000200, "confirmations": threshold, "finality": "final",
        "observedAt": world.clock.now(),
    }
    proof = world.actor("wallet").sign(proof, world.clock.now())
    if not stl.finality_ok(proof, threshold) or proof["settledAmountBase"] != instr["amountBase"]:
        raise Reject("settlementMismatch")
    world.ctx["reverseProof"] = proof
    world.ledger.settle(_orig_payee_role(world), "agent", orig["amount"], "reverse:" + instr["id"])
    return {"status": "completed", "settled": orig["amount"]}


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
    "issue": lambda w, s: _do_issue(w, s),
    "revoke": lambda w, s: _do_revoke(w, s),
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
    "payee_binding": lambda w, s: {"ok": True, "_set": ("binding", build_payee_binding(w, s))},
    "processor_binding": lambda w, s: _do_processor_binding(w, s),
    "attested_instruct": lambda w, s: _do_attested_instruct(w, s),
    "attested_proof": lambda w, s: _do_attested_proof(w, s),
    "settle_instruct": lambda w, s: _do_settle_instruct(w, s),
    "settle_proof": lambda w, s: _do_settle_proof(w, s),
    "escrow_lock": lambda w, s: _do_escrow_lock(w, s),
    "escrow_release": lambda w, s: _do_escrow_release(w, s),
    "escrow_refund": lambda w, s: _do_escrow_refund(w, s),
    "reverse_settle_instruct": lambda w, s: _do_reverse_instruct(w, s),
    "reverse_settle_proof": lambda w, s: _do_reverse_proof(w, s),
    "refund": lambda w, s: {"ok": True, "_set": ("refund", build_refund(w, s))},
    "reversal": lambda w, s: {"ok": True, "_set": ("reversal", build_reversal(w, s))},
    "reversal_ack": lambda w, s: {"ok": True, "_set": ("reversalAck", build_reversal_ack(w, s))},
    "dispute": lambda w, s: {"ok": True, "_set": ("dispute", build_dispute(w, s))},
    "dispute_evidence": lambda w, s: {"ok": True, "_set": ("evidence", build_evidence(w, s))},
    "dispute_resolution": lambda w, s: {"ok": True, "_set": ("resolution", build_resolution(w, s))},
}


def _do_issue(world, step):
    """The principal (or, for AP2, the user) issues the credential to the agent. This
    makes delegation a first-class, walked step; the wallet's checks on it surface
    downstream (holderMismatch, credentialExpired, credentialRevoked)."""
    world.credential = build_credential(world, step)
    world.ctx["issued"] = world.credential
    if step.get("revoked"):
        world.revoked.add(world.credential.get("id"))
    return {"ok": True}


def _do_revoke(world, step):
    """The principal revokes the standing credential; later charges under it are refused."""
    world.revoked.add(world.credential.get("id"))
    return {"ok": True}


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
    "issue": "issued",
    "quote": "quote", "authorize": "authz", "confirm": "confirmation",
    "execute": "execution", "replay": "execution", "receipt": "receipt",
    "open_session": "session", "budget_authorize": "sba", "accrue": "accrual",
    "close_session": "sessionExecution",
    "payee_binding": "binding", "processor_binding": "procBinding",
    "attested_instruct": "instruction", "attested_proof": "settleProof",
    "settle_instruct": "instruction", "settle_proof": "settleProof",
    "escrow_lock": "lock", "escrow_release": "release", "escrow_refund": "escrowRefund",
    "reverse_settle_instruct": "reverseInstruction", "reverse_settle_proof": "reverseProof",
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
