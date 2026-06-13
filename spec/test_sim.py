"""Run every declarative simulator scenario, and check the simulator emits
spec-conformant messages (so the runtime behaviour and the wire format agree)."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

import sim

_PAY_SCHEMA = Path("spec/payments/schemas/avp-micro.schema.json")
_SETTLE_SCHEMA = Path("spec/settlement/schemas/settlement.schema.json")
_SCENARIOS = sim.load_scenarios()
_BY_NAME = {s["name"]: s for s in _SCENARIOS}


def _validator(schema_path, defname):
    bundle = json.loads(schema_path.read_text(encoding="utf-8"))
    reg = Registry().with_resource(uri=bundle["$id"], resource=Resource(contents=bundle, specification=DRAFT202012))
    return Draft202012Validator({"$ref": f'{bundle["$id"]}#/$defs/{defname}'}, registry=reg,
                                format_checker=Draft202012Validator.FORMAT_CHECKER)


def _pay_validator(defname):
    return _validator(_PAY_SCHEMA, defname)


def _objects_by_action(scenario_name):
    res = sim.run_traced(_BY_NAME[scenario_name])
    return {rec["action"]: rec["object"] for rec in res["trace"] if rec["object"]}


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=[s["name"] for s in _SCENARIOS])
def test_scenario_behaves_as_specified(scenario):
    sim.run_scenario(scenario)


def test_simulator_covers_the_documented_use_cases():
    # a complete set: at least one happy path, the streaming variant, human-present,
    # and a spread of rejections across the runtime-enforcement vocabulary.
    names = {s["name"] for s in _SCENARIOS}
    assert "one-off-happy-path" in names and "streaming-happy" in names
    rejections = {tuple(st["expect"]["reject"] for st in s["steps"]
                        if isinstance(st.get("expect"), dict) and "reject" in st["expect"])
                  for s in _SCENARIOS}
    covered = {code for group in rejections for code in group}
    for code in ("overCap", "payeeNotAllowed", "dailyLimitExceeded", "expired",
                 "nonceReuse", "quoteMismatch", "amountMismatch", "currencyMismatch",
                 "badSignature", "budgetExceeded", "missingConfirmation", "forgedConfirmation",
                 "holderMismatch", "credentialExpired", "credentialRevoked",
                 "accountRedirection", "settlementNotFinal", "settlementMismatch"):
        assert code in covered, f"no scenario exercises rejection {code}"


def test_simulator_walks_credential_issuance():
    # delegation is a first-class, walked step (not just a precondition), and the
    # wallet enforces the credential's own lifecycle (wrong subject / expired / revoked).
    names = {s["name"] for s in _SCENARIOS}
    assert {"issue-delegate-authority", "issue-wrong-subject", "issue-expired-credential",
            "issue-then-revoked", "issue-ap2-intent"} <= names


def test_simulator_covers_settlement_binding():
    # the on-chain settlement-binding step is walked across all three rail profiles,
    # both binding archetypes, escrow (release + timeout-refund), and the reversal.
    names = {s["name"] for s in _SCENARIOS}
    assert {"settle-evm-direct", "settle-x402-account-binding", "settle-account-redirection",
            "settle-not-final", "settle-amount-mismatch", "settle-lightning-escrow",
            "settle-evm-escrow-timeout", "settle-reverse"} <= names


def test_settlement_messages_are_schema_conformant():
    # the settlement objects the simulator emits validate against the settlement bundle's
    # JSON Schema -- so the runtime binding and the on-the-wire format agree.
    x = _objects_by_action("settle-x402-account-binding")
    assert list(_validator(_SETTLE_SCHEMA, "PayeeAccountBinding").iter_errors(x["payee_binding"])) == []
    assert list(_validator(_SETTLE_SCHEMA, "SettlementInstruction").iter_errors(x["settle_instruct"])) == []
    assert list(_validator(_SETTLE_SCHEMA, "SettlementProof").iter_errors(x["settle_proof"])) == []
    e = _objects_by_action("settle-lightning-escrow")
    assert list(_validator(_SETTLE_SCHEMA, "EscrowLock").iter_errors(e["escrow_lock"])) == []
    assert list(_validator(_SETTLE_SCHEMA, "EscrowRelease").iter_errors(e["escrow_release"])) == []
    r = _objects_by_action("settle-evm-escrow-timeout")
    assert list(_validator(_SETTLE_SCHEMA, "EscrowRefund").iter_errors(r["escrow_refund"])) == []


def test_emitted_messages_are_schema_conformant():
    # drive a happy one-off through the builders and validate each signed message.
    world = sim.World({"name": "conformance", "policy": {"currency": "USD", "maxPerTransaction": "5.00",
                       "allowedPayees": ["payee"]}, "balances": {"agent": "100.00"},
                       "now": "2026-06-12T10:00:00Z"})
    quote = sim.build_quote(world, {"amount": "1.00"})
    world.ctx["quote"] = quote
    authz = sim.build_authorization(world, {})
    world.ctx["authz"] = authz
    execution = sim.wallet_process(world, authz)
    receipt = sim._build_receipt(world)
    # the bookkeeping-only "_payeeRole" is a private member; the schema is lenient about extras
    assert list(_pay_validator("PaymentQuote").iter_errors(quote)) == []
    assert list(_pay_validator("PaymentAuthorization").iter_errors(authz)) == []
    assert list(_pay_validator("PaymentExecution").iter_errors(execution)) == []
    assert list(_pay_validator("PaymentReceipt").iter_errors(receipt)) == []
