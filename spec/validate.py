"""AVP-Micro artifact validation harness for all four spec bundles.

Checks (exit non-zero on any failure):
  1. Turtle parse (all four ontologies, SKOS vocab, all four SHACL shape files).
  2. JSON-LD expansion of every vector (all four contexts served locally).
  3. JSON Schema validation against the relevant $def.
  4. SHACL validation against the relevant shapes file.
"""
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import rdflib
import yaml
from pyld import jsonld
from pyld.documentloader import requests as pyld_requests
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
import pyshacl

SPEC = Path(__file__).parent
AUTH = SPEC / "authority"
PAY = SPEC / "payments"
INTEROP = SPEC / "interop-sd-jwt-vc"
DISP = SPEC / "disputes"
SETTLE = SPEC / "settlement"
TRANSPORT = SPEC / "transport"
SEC_PROOF = "https://w3id.org/security#proof"
DSA_NS = "https://w3id.org/spending-authority/v1#"
AVP_NS = "https://w3id.org/avp-micro/v1#"
IOP_NS = "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#"
DISP_NS = "https://w3id.org/avp-micro/disputes/v1#"
SETTLE_NS = "https://w3id.org/avp-micro/settlement/v1#"
TXP_NS = "https://w3id.org/avp-micro/transport/v1#"

# vector file -> ($def name, schema bundle path, shapes path, namespace, dir)
AUTH_VECTORS = {
    "spending-authorization-credential.json": "SpendingAuthorizationCredential",
    "merchant-credential.json": "MerchantCredential",
    "payment-capability-credential.json": "PaymentCapabilityCredential",
    "status-list-active.json": "BitstringStatusListCredential",
    "status-list-revoked.json": "BitstringStatusListCredential",
}
PAY_VECTORS = {
    "00-payment-offer.json": "PaymentOffer",
    "12-payment-offer-compute.json": "PaymentOffer",
    "13-payment-offer-storage.json": "PaymentOffer",
    "01-payment-quote.json": "PaymentQuote",
    "02-payment-authorization.json": "PaymentAuthorization",
    "03-payment-execution.json": "PaymentExecution",
    "04-payment-receipt.json": "PaymentReceipt",
    "05-usage-session.json": "UsageSession",
    "06-session-budget-authorization.json": "SessionBudgetAuthorization",
    "07-usage-accrual.json": "UsageAccrual",
    "08-payment-execution-session.json": "PaymentExecution",
    "09-payment-receipt-session.json": "PaymentReceipt",
    "10-usage-session-extension.json": "UsageSessionExtension",
    "11-session-budget-authorization-2.json": "SessionBudgetAuthorization",
    "14b-purchase-confirmation.json": "PurchaseConfirmation",
    "18-payment-authorization-confirmed.json": "PaymentAuthorization",
}
# Bridged vectors validate against their SEMANTIC type's interop $def; the securing
# axis is the shared SecuringDescriptor/bridgeSecured mixin inside each $def.
INTEROP_VECTORS = {
    "02-imported-mandate.json": "SpendingAuthorizationCredential",
    "04-imported-from-foreign.json": "SpendingAuthorizationCredential",
    "05-coissued-mandate.json": "SpendingAuthorizationCredential",
    "07-imported-payment-authorization.json": "PaymentAuthorization",
    "08-attested-mandate.json": "SpendingAuthorizationCredential",
    "09-imported-interactive-l2.json": "SpendingAuthorizationCredential",
    "10-imported-partial-sd.json": "SpendingAuthorizationCredential",
    "12-imported-intent-mandate.json": "SpendingAuthorizationCredential",
    "14-imported-cart-quote.json": "PaymentQuote",
    "15-human-present-confirmation.json": "PurchaseConfirmation",
    "16-autonomous-no-confirmation.json": "SpendingAuthorizationCredential",
}
DISP_VECTORS = {
    "20-refund.json": "Refund",
    "21-reversal-refund.json": "Reversal",
    "22-reversal-ack.json": "ReversalAcknowledgement",
    "23-refund-partial.json": "Refund",
    "30-dispute.json": "Dispute",
    "31-dispute-evidence-payee.json": "DisputeEvidence",
    "32-dispute-evidence-payer.json": "DisputeEvidence",
    "33-dispute-resolution-payee.json": "DisputeResolution",
    "34-dispute-resolution-arbiter.json": "DisputeResolution",
    "35-reversal-dispute.json": "Reversal",
    "36-dispute-rejected.json": "Dispute",
    "37-dispute-resolution-rejected.json": "DisputeResolution",
    "38-dispute-withdrawn.json": "Dispute",
    "39-dispute-resolution-withdrawn.json": "DisputeResolution",
}
SETTLEMENT_VECTORS = {
    "40-payee-account-binding.json": "PayeeAccountBinding",
    "41-settlement-instruction-evm.json": "SettlementInstruction",
    "42-settlement-proof-evm.json": "SettlementProof",
    "43-settlement-instruction-x402.json": "SettlementInstruction",
    "44-settlement-proof-x402.json": "SettlementProof",
    "45-settlement-instruction-lightning.json": "SettlementInstruction",
    "46-escrow-lock-lightning.json": "EscrowLock",
    "47-settlement-proof-lightning.json": "SettlementProof",
    "48-escrow-release-lightning.json": "EscrowRelease",
    "49-settlement-instruction-evm-escrow.json": "SettlementInstruction",
    "50-escrow-lock-evm.json": "EscrowLock",
    "51-settlement-proof-evm-refund.json": "SettlementProof",
    "52-escrow-refund-evm.json": "EscrowRefund",
    "53-reverse-settlement-instruction.json": "SettlementInstruction",
    "54-reverse-settlement-proof.json": "SettlementProof",
    "55-payee-account-binding-agent.json": "PayeeAccountBinding",
    "56-payee-account-binding-evm.json": "PayeeAccountBinding",
    "57-processor-account-binding-card.json": "ProcessorAccountBinding",
    "58-settlement-instruction-card.json": "AttestedSettlementInstruction",
    "59-settlement-proof-card.json": "AttestedSettlementProof",
    "60-processor-account-binding-rtp.json": "ProcessorAccountBinding",
    "61-settlement-instruction-rtp.json": "AttestedSettlementInstruction",
    "62-settlement-proof-rtp.json": "AttestedSettlementProof",
    "63-processor-account-binding-paypal.json": "ProcessorAccountBinding",
    "64-settlement-instruction-paypal.json": "AttestedSettlementInstruction",
    "65-settlement-proof-paypal.json": "AttestedSettlementProof",
    "66-processor-account-binding-visa-direct.json": "ProcessorAccountBinding",
    "67-settlement-instruction-visa-direct.json": "AttestedSettlementInstruction",
    "68-settlement-proof-visa-direct.json": "AttestedSettlementProof",
}
# Signed transport objects: full expand + schema + SHACL coverage.
TRANSPORT_VECTORS = {
    "00-service-description.json": "ServiceDescription",
    "10-payment-challenge.json": "PaymentChallenge",
    "20-authorization-submission.json": "AuthorizationSubmission",
}
# Unsigned transport artifacts: JSON Schema only (no proof, not JSON-LD-expanded).
TRANSPORT_UNSIGNED_VECTORS = {
    "11-challenge-402-body.json": "Challenge402Body",
    "30-problem-details.json": "ProblemDetails",
    "40-exchange-402-flow.json": "HttpExchangeLog",
    "41-exchange-over-cap.json": "HttpExchangeLog",
    "42-exchange-quote-flow.json": "HttpExchangeLog",
    "43-exchange-streaming.json": "HttpExchangeLog",
    "44-exchange-async-settlement.json": "HttpExchangeLog",
    "45-exchange-idempotency.json": "HttpExchangeLog",
    "46-exchange-replay.json": "HttpExchangeLog",
    "47-problem-details-signed.json": "ProblemDetails",
}
# Exchange logs whose every step is cross-checked against the OpenAPI contract.
EXCHANGE_VECTORS = [
    "40-exchange-402-flow.json", "41-exchange-over-cap.json",
    "42-exchange-quote-flow.json", "43-exchange-streaming.json",
    "44-exchange-async-settlement.json", "45-exchange-idempotency.json",
    "46-exchange-replay.json",
]

failures = []


def ok(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(label)


# document loader: both AVP contexts local, everything else via network
_dsa_ctx = json.loads((AUTH / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_avp_ctx = json.loads((PAY / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_iop_ctx = json.loads((INTEROP / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_disp_ctx = json.loads((DISP / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_settle_ctx = json.loads((SETTLE / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_txp_ctx = json.loads((TRANSPORT / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_ctx_dir = SPEC / "contexts"
# Stable external W3C contexts are vendored locally so validation is offline and
# deterministic (w3.org content-negotiation via the pyld requests loader is flaky --
# it intermittently fails on multiple HTTP Link headers).
_LOCAL = {
    "https://w3id.org/spending-authority/v1": _dsa_ctx,
    "https://w3id.org/avp-micro/v1": _avp_ctx,
    "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1": _iop_ctx,
    "https://w3id.org/avp-micro/disputes/v1": _disp_ctx,
    "https://w3id.org/avp-micro/settlement/v1": _settle_ctx,
    "https://w3id.org/avp-micro/transport/v1": _txp_ctx,
    "https://www.w3.org/ns/credentials/v2":
        json.loads((_ctx_dir / "credentials-v2.jsonld").read_text(encoding="utf-8")),
    "https://w3id.org/security/data-integrity/v2":
        json.loads((_ctx_dir / "data-integrity-v2.jsonld").read_text(encoding="utf-8")),
}
_net = pyld_requests.requests_document_loader()


def loader(url, options=None):
    doc = _LOCAL.get(url.rstrip("/"))
    if doc is not None:
        return {"contextUrl": None, "documentUrl": url, "document": doc}
    return _net(url, options or {})


jsonld.set_document_loader(loader)


def section(title):
    print(f"\n=== {title} ===")


def expand_check(base, vectors, must_survive, require_proof=True):
    for name in vectors:
        inst = json.loads((base / "test-vectors" / name).read_text(encoding="utf-8"))
        try:
            expanded = jsonld.expand(inst)
            expanded_str = json.dumps(expanded)
            ok(f"{name} expands", bool(expanded))
            if require_proof:
                ok(f"{name} carries {SEC_PROOF}", SEC_PROOF in expanded_str)
            for iri, term in must_survive.get(name, []):
                ok(f"{name} keeps {term}", iri in expanded_str)
        except Exception as e:
            ok(f"{name} expands", False, str(e))


def schema_check(base, vectors, schema_file):
    bundle = json.loads((base / "schemas" / schema_file).read_text(encoding="utf-8"))
    resource = Resource(contents=bundle, specification=DRAFT202012)
    registry = Registry().with_resource(uri=bundle["$id"], resource=resource)
    for name, defname in vectors.items():
        schema = {"$ref": f'{bundle["$id"]}#/$defs/{defname}'}
        validator = Draft202012Validator(schema, registry=registry,
                                         format_checker=Draft202012Validator.FORMAT_CHECKER)
        errs = sorted(validator.iter_errors(json.loads((base / "test-vectors" / name).read_text(encoding="utf-8"))),
                      key=lambda e: e.json_path)
        ok(f"{name} matches #/$defs/{defname}", not errs,
           "; ".join(f"{e.json_path}: {e.message}" for e in errs[:4]))


def negative_schema_check(base, schema_file, cases):
    bundle = json.loads((base / "schemas" / schema_file).read_text(encoding="utf-8"))
    resource = Resource(contents=bundle, specification=DRAFT202012)
    registry = Registry().with_resource(uri=bundle["$id"], resource=resource)
    for label, vector_name, defname, mutate in cases:
        inst = json.loads((base / "test-vectors" / vector_name).read_text(encoding="utf-8"))
        mutated = mutate(deepcopy(inst))
        schema = {"$ref": f'{bundle["$id"]}#/$defs/{defname}'}
        validator = Draft202012Validator(schema, registry=registry,
                                         format_checker=Draft202012Validator.FORMAT_CHECKER)
        errs = sorted(validator.iter_errors(mutated), key=lambda e: e.json_path)
        ok(f"negative schema rejects {label}", bool(errs),
           "mutated instance unexpectedly matched schema")


def shacl_check(base, vectors, shapes_file):
    shapes_path = (base / "shapes" / shapes_file).as_posix()
    for name in vectors:
        # Parse the shapes graph fresh per instance: pyshacl (advanced=True) may mutate
        # the shapes graph during validation, so a reused graph gives non-deterministic
        # results across iterations.
        shapes_graph = rdflib.Graph().parse(shapes_path, format="turtle")
        inst = json.loads((base / "test-vectors" / name).read_text(encoding="utf-8"))
        try:
            nq = jsonld.to_rdf(inst, {"format": "application/n-quads"})
            cg = rdflib.ConjunctiveGraph()
            cg.parse(data=nq, format="nquads")
            data = rdflib.Graph()
            for triple in cg:
                data.add(triple)
            conforms, _, report = pyshacl.validate(data_graph=data, shacl_graph=shapes_graph,
                                                    inference="none", advanced=True)
            ok(f"{name} conforms to shapes", conforms,
               report.strip().splitlines()[-1] if not conforms else "")
        except Exception as e:
            ok(f"{name} conforms to shapes", False, str(e))


# Each bundle's JSON Schema is intentionally self-contained (own $id, independently
# consumable), so the primitive helper $defs are duplicated rather than $ref'd across
# files. This guard keeps that duplication honest: it fails if a shared primitive ever
# drifts functionally between bundles (the `description` doc field is ignored).
_SHARED_DEFS = ("did", "iri", "idValue", "decimal", "positiveDecimal",
                "dateTime", "contentDigest", "proof")
_SCHEMA_FILES = {
    "authority": AUTH / "schemas" / "dsa.schema.json",
    "payments": PAY / "schemas" / "avp-micro.schema.json",
    "interop": INTEROP / "schemas" / "interop.schema.json",
    "disputes": DISP / "schemas" / "disputes.schema.json",
    "settlement": SETTLE / "schemas" / "settlement.schema.json",
    "transport": TRANSPORT / "schemas" / "transport.schema.json",
}


def openapi_ref_check():
    oa = TRANSPORT / "openapi" / "avp-micro.openapi.yaml"
    try:
        doc = yaml.safe_load(oa.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        ok("OpenAPI document parses as YAML", False, str(e))
        return
    ok("OpenAPI document parses as YAML", isinstance(doc, dict))
    ok("OpenAPI version is 3.1.x", str(doc.get("openapi", "")).startswith("3.1"))
    ok("OpenAPI declares paths", bool(doc.get("paths")))

    refs = []
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref" and isinstance(v, str) and "#/$defs/" in v:
                    refs.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)
    walk(doc)
    ok("OpenAPI references bundle $defs", bool(refs))

    cache = {}
    for ref in sorted(set(refs)):
        rel, frag = ref.split("#/$defs/", 1)
        target = (oa.parent / rel).resolve()
        if target not in cache:
            cache[target] = (json.loads(target.read_text(encoding="utf-8")).get("$defs", {})
                             if target.exists() else None)
        defs = cache[target]
        ok(f"OpenAPI $ref resolves: {ref}", defs is not None and frag in defs)


def openapi_exchange_check():
    """Validate every exchange step body against the schema the OpenAPI documents for
    that path+status+content-type. Responses are fully validated; request bodies are
    validated only where the operation documents a requestBody."""
    oa = TRANSPORT / "openapi" / "avp-micro.openapi.yaml"
    doc = yaml.safe_load(oa.read_text(encoding="utf-8"))

    schema_paths = [TRANSPORT / "schemas" / "transport.schema.json",
                    PAY / "schemas" / "avp-micro.schema.json",
                    SETTLE / "schemas" / "settlement.schema.json"]
    registry = Registry()
    fileid = {}
    for p in schema_paths:
        s = json.loads(p.read_text(encoding="utf-8"))
        registry = registry.with_resource(uri=s["$id"], resource=Resource(contents=s, specification=DRAFT202012))
        fileid[p.resolve()] = s["$id"]

    def rewrite(ref):
        rel, name = ref.split("#/$defs/", 1)
        sid = fileid.get((oa.parent / rel).resolve())
        return {"$ref": f"{sid}#/$defs/{name}"} if sid else None

    def to_schema(node):
        if not isinstance(node, dict):
            return None
        if "$ref" in node:
            return rewrite(node["$ref"])
        if "oneOf" in node:
            subs = [rewrite(x["$ref"]) for x in node["oneOf"] if isinstance(x, dict) and "$ref" in x]
            return {"oneOf": subs} if subs and all(s is not None for s in subs) else None
        return None

    def match_path(concrete):
        cseg = concrete.split("/")
        for tmpl in doc.get("paths", {}):
            tseg = tmpl.split("/")
            if len(tseg) == len(cseg) and all(
                    t == c or (t.startswith("{") and t.endswith("}")) for t, c in zip(tseg, cseg)):
                return tmpl
        return None

    def validate_body(label, schema_node, body):
        sch = to_schema(schema_node)
        if sch is None:
            ok(label, False, f"could not resolve OpenAPI schema {schema_node}")
            return
        v = Draft202012Validator(sch, registry=registry,
                                 format_checker=Draft202012Validator.FORMAT_CHECKER)
        errs = sorted(v.iter_errors(body), key=lambda e: e.json_path)
        ok(label, not errs, "; ".join(f"{e.json_path}: {e.message}" for e in errs[:3]))

    for name in EXCHANGE_VECTORS:
        log = json.loads((TRANSPORT / "test-vectors" / name).read_text(encoding="utf-8"))
        for i, step in enumerate(log["steps"], 1):
            req, res = step["request"], step["response"]
            tmpl = match_path(req["path"])
            ok(f"{name} step {i}: path '{req['path']}' is documented", tmpl is not None)
            if tmpl is None:
                continue
            op = doc["paths"][tmpl].get(req["method"].lower())
            ok(f"{name} step {i}: {req['method']} {tmpl} is documented", op is not None)
            if op is None:
                continue
            resp = (op.get("responses") or {}).get(str(res["status"]))
            ok(f"{name} step {i}: {res['status']} documented on {req['method']} {tmpl}", resp is not None)
            if resp is not None and "body" in res:
                ct = res.get("headers", {}).get("Content-Type", "application/avp-micro+json")
                content = resp.get("content") or {}
                media = content.get(ct) or (next(iter(content.values()), None))
                if media and "schema" in media:
                    validate_body(f"{name} step {i}: response body conforms "
                                  f"({req['method']} {tmpl} -> {res['status']})", media["schema"], res["body"])
            if "body" in req and op.get("requestBody"):
                ct = req.get("headers", {}).get("Content-Type", "application/avp-micro+json")
                content = op["requestBody"].get("content") or {}
                media = content.get(ct) or (next(iter(content.values()), None))
                if media and "schema" in media:
                    validate_body(f"{name} step {i}: request body conforms ({req['method']} {tmpl})",
                                  media["schema"], req["body"])


def shared_defs_check():
    def _norm(d):  # functional identity: ignore the non-normative description text
        return json.dumps({k: v for k, v in d.items() if k != "description"}, sort_keys=True)
    loaded = {name: json.loads(p.read_text(encoding="utf-8")).get("$defs", {})
              for name, p in _SCHEMA_FILES.items() if p.exists()}
    for prim in _SHARED_DEFS:
        variants = {}
        for name, defs in loaded.items():
            if prim in defs:
                variants.setdefault(_norm(defs[prim]), []).append(name)
        n = sum(len(v) for v in variants.values())
        if n == 0:
            continue
        ok(f"shared $def '{prim}' consistent across {n} bundle(s)", len(variants) == 1,
           " | ".join(f"{names}" for names in variants.values()))


def main():
    section("Turtle parse")
    for ttl in [AUTH / "vocab" / "dsa.ttl", AUTH / "vocab" / "agent-service-categories.ttl",
                AUTH / "shapes" / "dsa-shapes.ttl", PAY / "vocab" / "avp.ttl",
                PAY / "vocab" / "dimensions.ttl", PAY / "vocab" / "units.ttl",
                PAY / "shapes" / "avp-shapes.ttl",
                INTEROP / "vocab" / "interop.ttl", INTEROP / "shapes" / "interop-shapes.ttl",
                DISP / "vocab" / "disputes.ttl", DISP / "vocab" / "reasons.ttl",
                DISP / "shapes" / "disputes-shapes.ttl",
                SETTLE / "vocab" / "settlement.ttl", SETTLE / "vocab" / "rails.ttl",
                SETTLE / "shapes" / "settlement-shapes.ttl",
                TRANSPORT / "vocab" / "transport.ttl", TRANSPORT / "vocab" / "errors.ttl",
                TRANSPORT / "shapes" / "transport-shapes.ttl"]:
        try:
            g = rdflib.Graph().parse(ttl.as_posix(), format="turtle")
            ok(f"{ttl.parent.parent.name}/{ttl.name} parses", True)
            print(f"        ({len(g)} triples)")
        except Exception as e:
            ok(f"{ttl.name} parses", False, str(e))

    section("JSON-LD expansion")
    expand_check(AUTH, AUTH_VECTORS, {
        "spending-authorization-credential.json": [(DSA_NS + "maxPerTransaction", "dsa:maxPerTransaction")],
    })
    expand_check(PAY, PAY_VECTORS, {
        "02-payment-authorization.json": [(AVP_NS + "amount", "avp:amount"),
                                          (AVP_NS + "quoteDigest", "avp:quoteDigest")],
        "01-payment-quote.json": [(AVP_NS + "amount", "avp:amount")],
        "05-usage-session.json": [(AVP_NS + "maxAmount", "avp:maxAmount")],
        "10-usage-session-extension.json": [(AVP_NS + "newMaxAmount", "avp:newMaxAmount")],
        "12-payment-offer-compute.json": [(AVP_NS + "components", "avp:components"),
                                          (AVP_NS + "dimension", "avp:dimension")],
        "13-payment-offer-storage.json": [(AVP_NS + "tiers", "avp:tiers"),
                                          (AVP_NS + "tierMode", "avp:tierMode")],
    })
    expand_check(INTEROP, INTEROP_VECTORS, {
        "02-imported-mandate.json": [(IOP_NS + "securing", "iop:securing"),
                                     (IOP_NS + "embedded", "iop:embedded"),
                                     (IOP_NS + "mode", "iop:mode")],
        "04-imported-from-foreign.json": [(IOP_NS + "securing", "iop:securing"),
                                          (IOP_NS + "embedded", "iop:embedded")],
        "05-coissued-mandate.json": [(IOP_NS + "embedded", "iop:embedded"),
                                     (SEC_PROOF, "proof")],
        "07-imported-payment-authorization.json": [(IOP_NS + "carrier", "iop:carrier"),
                                                   (IOP_NS + "embedded", "iop:embedded")],
        "08-attested-mandate.json": [(IOP_NS + "attestingBridge", "iop:attestingBridge"),
                                     (SEC_PROOF, "proof")],
        "09-imported-interactive-l2.json": [(IOP_NS + "importAdvisory", "iop:importAdvisory")],
        "10-imported-partial-sd.json": [(IOP_NS + "importAdvisory", "iop:importAdvisory")],
        "12-imported-intent-mandate.json": [(IOP_NS + "intentDescription", "iop:intentDescription"),
                                            (IOP_NS + "importAdvisory", "iop:importAdvisory")],
        "14-imported-cart-quote.json": [(IOP_NS + "embedded", "iop:embedded")],
        "15-human-present-confirmation.json": [(IOP_NS + "embedded", "iop:embedded")],
    }, require_proof=False)  # proof-preserving objects are unsigned projections
    expand_check(DISP, DISP_VECTORS, {
        "20-refund.json": [(DISP_NS + "reason", "disp:reason"),
                           (DISP_NS + "receiptDigest", "disp:receiptDigest")],
        "30-dispute.json": [(DISP_NS + "disputedAmount", "disp:disputedAmount"),
                            (DISP_NS + "arbiter", "disp:arbiter")],
        "34-dispute-resolution-arbiter.json": [(DISP_NS + "supersedes", "disp:supersedes"),
                                               (DISP_NS + "outcome", "disp:outcome")],
        "35-reversal-dispute.json": [(DISP_NS + "cause", "disp:cause"),
                                     (DISP_NS + "resolution", "disp:resolution")],
    })
    expand_check(SETTLE, SETTLEMENT_VECTORS, {
        "41-settlement-instruction-evm.json": [(SETTLE_NS + "amountBase", "stl:amountBase"),
                                               (SETTLE_NS + "rail", "stl:rail"),
                                               (SETTLE_NS + "mode", "stl:mode")],
        "42-settlement-proof-evm.json": [(SETTLE_NS + "finality", "stl:finality"),
                                         (SETTLE_NS + "transaction", "stl:transaction")],
        "47-settlement-proof-lightning.json": [(SETTLE_NS + "preimage", "stl:preimage")],
        "48-escrow-release-lightning.json": [(SETTLE_NS + "settlementProof", "stl:settlementProof")],
        "52-escrow-refund-evm.json": [(SETTLE_NS + "reason", "stl:reason")],
        "57-processor-account-binding-card.json": [(SETTLE_NS + "processor", "stl:processor")],
        "58-settlement-instruction-card.json": [(SETTLE_NS + "rail", "stl:rail"),
                                                (SETTLE_NS + "captureMode", "stl:captureMode")],
        "59-settlement-proof-card.json": [(SETTLE_NS + "settledAmount", "stl:settledAmount"),
                                          (SETTLE_NS + "attestation", "stl:attestation")],
        "61-settlement-instruction-rtp.json": [(SETTLE_NS + "scheme", "stl:scheme")],
        "62-settlement-proof-rtp.json": [(SETTLE_NS + "settledAmount", "stl:settledAmount")],
        "63-processor-account-binding-paypal.json": [(SETTLE_NS + "processor", "stl:processor")],
        "64-settlement-instruction-paypal.json": [(SETTLE_NS + "rail", "stl:rail")],
        "65-settlement-proof-paypal.json": [(SETTLE_NS + "attestation", "stl:attestation")],
        "66-processor-account-binding-visa-direct.json": [(SETTLE_NS + "processor", "stl:processor")],
        "67-settlement-instruction-visa-direct.json": [(SETTLE_NS + "rail", "stl:rail")],
        "68-settlement-proof-visa-direct.json": [(SETTLE_NS + "attestation", "stl:attestation")],
    })
    expand_check(TRANSPORT, TRANSPORT_VECTORS, {
        "00-service-description.json": [(TXP_NS + "acceptedSettlementRails", "txp:acceptedSettlementRails"),
                                        (TXP_NS + "offers", "txp:offers")],
        "10-payment-challenge.json": [("https://w3id.org/security#challenge", "sec:challenge"),
                                      ("https://w3id.org/avp-micro/v1#quoteDigest", "avp:quoteDigest")],
        "20-authorization-submission.json": [(TXP_NS + "authorizationDigest", "txp:authorizationDigest"),
                                             (TXP_NS + "idempotencyKey", "txp:idempotencyKey")],
    })

    section("JSON Schema validation")
    schema_check(AUTH, AUTH_VECTORS, "dsa.schema.json")
    schema_check(PAY, PAY_VECTORS, "avp-micro.schema.json")
    schema_check(INTEROP, INTEROP_VECTORS, "interop.schema.json")
    schema_check(DISP, DISP_VECTORS, "disputes.schema.json")
    schema_check(SETTLE, SETTLEMENT_VECTORS, "settlement.schema.json")
    schema_check(TRANSPORT, TRANSPORT_VECTORS, "transport.schema.json")
    schema_check(TRANSPORT, TRANSPORT_UNSIGNED_VECTORS, "transport.schema.json")
    section("Shared $def consistency (no cross-bundle drift)")
    shared_defs_check()
    section("OpenAPI contract")
    openapi_ref_check()
    openapi_exchange_check()
    negative_schema_check(AUTH, "dsa.schema.json", [
        ("DSA proof type", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["proof"].__setitem__("type", "NotDataIntegrityProof") or obj)),
        ("DSA context order", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
        ("DSA zero maxPerTransaction", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["credentialSubject"].__setitem__("maxPerTransaction", "0") or obj)),
        ("DSA zero dailyLimit", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["credentialSubject"].__setitem__("dailyLimit", "0") or obj)),
        ("DSA non-URI allowedCategory", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["credentialSubject"].__setitem__("allowedCategories", ["not a uri"]) or obj)),
    ])
    negative_schema_check(PAY, "avp-micro.schema.json", [
        ("PaymentQuote zero amount", "01-payment-quote.json", "PaymentQuote",
         lambda obj: (obj.__setitem__("amount", "0") or obj)),
        ("PaymentQuote proof type", "01-payment-quote.json", "PaymentQuote",
         lambda obj: (obj["proof"].__setitem__("type", "NotDataIntegrityProof") or obj)),
        ("PaymentQuote context order", "01-payment-quote.json", "PaymentQuote",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
        ("PaymentReceipt missing status", "04-payment-receipt.json", "PaymentReceipt",
         lambda obj: (obj.pop("status", None), obj)[1]),
        ("offer pricing missing tiers", "13-payment-offer-storage.json", "PaymentOffer",
         lambda obj: (obj["pricingModel"].pop("tiers", None), obj)[1]),
        ("offer composite empty components", "12-payment-offer-compute.json", "PaymentOffer",
         lambda obj: (obj["pricingModel"].__setitem__("components", []), obj)[1]),
        ("PurchaseConfirmation missing confirmedBy", "14b-purchase-confirmation.json", "PurchaseConfirmation",
         lambda obj: (obj.pop("confirmedBy", None), obj)[1]),
    ])
    negative_schema_check(INTEROP, "interop.schema.json", [
        ("proof on a proof-preserving object", "02-imported-mandate.json", "SpendingAuthorizationCredential",
         lambda obj: (obj.__setitem__("proof", {"type": "DataIntegrityProof"}), obj)[1]),
        ("attested without attestingBridge", "04-imported-from-foreign.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["securing"].__setitem__("mode", "attested"), obj)[1]),
        ("missing securing descriptor", "02-imported-mandate.json", "SpendingAuthorizationCredential",
         lambda obj: (obj.pop("securing", None), obj)[1]),
        ("missing embedded carrier", "02-imported-mandate.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["securing"].pop("embedded", None), obj)[1]),
        ("bad securing mode", "02-imported-mandate.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["securing"].__setitem__("mode", "frobnicate"), obj)[1]),
        ("L3 proof on a proof-preserving authorization", "07-imported-payment-authorization.json",
         "PaymentAuthorization",
         lambda obj: (obj.__setitem__("proof", {"type": "DataIntegrityProof"}), obj)[1]),
        ("L3 missing embedded presentation", "07-imported-payment-authorization.json",
         "PaymentAuthorization",
         lambda obj: (obj["securing"].pop("embedded", None), obj)[1]),
        ("cart-quote proof on proof-preserving", "14-imported-cart-quote.json", "PaymentQuote",
         lambda obj: (obj.__setitem__("proof", {"type": "DataIntegrityProof"}), obj)[1]),
        ("cart-quote missing embedded mandate", "14-imported-cart-quote.json", "PaymentQuote",
         lambda obj: (obj["securing"].pop("embedded", None), obj)[1]),
        ("confirmation missing confirmedBy", "15-human-present-confirmation.json", "PurchaseConfirmation",
         lambda obj: (obj.pop("confirmedBy", None), obj)[1]),
    ])
    negative_schema_check(DISP, "disputes.schema.json", [
        ("Refund missing reason", "20-refund.json", "Refund",
         lambda obj: (obj.pop("reason", None), obj)[1]),
        ("Refund proof type", "20-refund.json", "Refund",
         lambda obj: (obj["proof"].__setitem__("type", "NotDataIntegrityProof") or obj)),
        ("Refund context order", "20-refund.json", "Refund",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
        ("Reversal with neither refund nor resolution", "21-reversal-refund.json", "Reversal",
         lambda obj: (obj.pop("refund", None), obj.pop("refundDigest", None), obj)[2]),
        ("Dispute with no contested object", "30-dispute.json", "Dispute",
         lambda obj: (obj.pop("receipt", None), obj.pop("receiptDigest", None),
                      obj.pop("execution", None), obj.pop("executionDigest", None), obj)[4]),
        ("withdrawn resolved by payee", "39-dispute-resolution-withdrawn.json", "DisputeResolution",
         lambda obj: (obj.__setitem__("resolverRole", "payee") or obj)),
        ("arbiter resolution without supersedes", "34-dispute-resolution-arbiter.json", "DisputeResolution",
         lambda obj: (obj.pop("supersedes", None), obj.pop("supersedesDigest", None), obj)[2]),
        ("Reversal cause/branch mismatch (cause=dispute, refund branch)", "21-reversal-refund.json", "Reversal",
         lambda obj: (obj.__setitem__("cause", "dispute") or obj)),
        ("rejected with nonzero resolvedAmount", "37-dispute-resolution-rejected.json", "DisputeResolution",
         lambda obj: (obj.__setitem__("resolvedAmount", "5.00") or obj)),
        ("withdrawn with nonzero resolvedAmount", "39-dispute-resolution-withdrawn.json", "DisputeResolution",
         lambda obj: (obj.__setitem__("resolvedAmount", "5.00") or obj)),
        ("upheld with zero resolvedAmount", "34-dispute-resolution-arbiter.json", "DisputeResolution",
         lambda obj: (obj.__setitem__("resolvedAmount", "0") or obj)),
        ("DisputeEvidence sequence below 1", "31-dispute-evidence-payee.json", "DisputeEvidence",
         lambda obj: (obj.__setitem__("sequence", 0) or obj)),
    ])
    negative_schema_check(SETTLE, "settlement.schema.json", [
        ("instruction missing amountBase", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.pop("amountBase", None), obj)[1]),
        ("instruction bad mode", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.__setitem__("mode", "frobnicate") or obj)),
        ("instruction non-integer amountBase", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.__setitem__("amountBase", "10.5") or obj)),
        ("instruction context order", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
        ("proof missing finality", "42-settlement-proof-evm.json", "SettlementProof",
         lambda obj: (obj.pop("finality", None), obj)[1]),
        ("proof bad finality value", "42-settlement-proof-evm.json", "SettlementProof",
         lambda obj: (obj.__setitem__("finality", "kinda-final") or obj)),
        ("escrow refund missing settlementProof", "52-escrow-refund-evm.json", "EscrowRefund",
         lambda obj: (obj.pop("settlementProof", None), obj)[1]),
        ("binding missing subject", "40-payee-account-binding.json", "PayeeAccountBinding",
         lambda obj: (obj.pop("subject", None), obj)[1]),
    ])
    negative_schema_check(TRANSPORT, "transport.schema.json", [
        ("challenge missing quoteDigest", "10-payment-challenge.json", "PaymentChallenge",
         lambda obj: (obj.pop("quoteDigest", None), obj)[1]),
        ("challenge context order", "10-payment-challenge.json", "PaymentChallenge",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
        ("submission missing echoed challenge", "20-authorization-submission.json", "AuthorizationSubmission",
         lambda obj: (obj.pop("challenge", None), obj)[1]),
        ("submission missing idempotencyKey", "20-authorization-submission.json", "AuthorizationSubmission",
         lambda obj: (obj.pop("idempotencyKey", None), obj)[1]),
        ("problem-details type not an IRI", "30-problem-details.json", "ProblemDetails",
         lambda obj: (obj.__setitem__("type", "over-cap") or obj)),
        ("service description missing acceptedSettlementRails", "00-service-description.json", "ServiceDescription",
         lambda obj: (obj.pop("acceptedSettlementRails", None), obj)[1]),
    ])

    section("SHACL validation")
    shacl_check(AUTH, AUTH_VECTORS, "dsa-shapes.ttl")
    shacl_check(PAY, PAY_VECTORS, "avp-shapes.ttl")
    shacl_check(INTEROP, INTEROP_VECTORS, "interop-shapes.ttl")
    shacl_check(DISP, DISP_VECTORS, "disputes-shapes.ttl")
    shacl_check(SETTLE, SETTLEMENT_VECTORS, "settlement-shapes.ttl")
    shacl_check(TRANSPORT, TRANSPORT_VECTORS, "transport-shapes.ttl")

    print()
    if failures:
        print(f"FAIL: {len(failures)} check(s) failed: {failures}")
        return 1
    print("PASS: all artifact checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
