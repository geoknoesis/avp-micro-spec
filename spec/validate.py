"""AVP-Micro artifact validation harness for both peer specs.

Checks (exit non-zero on any failure):
  1. Turtle parse (both ontologies, SKOS vocab, both SHACL shape files).
  2. JSON-LD expansion of every vector (DSA + Payments contexts served locally).
  3. JSON Schema validation against the relevant $def.
  4. SHACL validation against the relevant shapes file.
"""
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import rdflib
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
SEC_PROOF = "https://w3id.org/security#proof"
DSA_NS = "https://w3id.org/spending-authority/v1#"
AVP_NS = "https://w3id.org/avp-micro/v1#"
IOP_NS = "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#"

# vector file -> ($def name, schema bundle path, shapes path, namespace, dir)
AUTH_VECTORS = {
    "spending-authorization-credential.json": "SpendingAuthorizationCredential",
    "merchant-credential.json": "MerchantCredential",
    "payment-capability-credential.json": "PaymentCapabilityCredential",
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
}
INTEROP_VECTORS = {
    "02-imported-mandate.json": "EmbeddedSdJwtVcMandate",
    "04-imported-from-foreign.json": "EmbeddedSdJwtVcMandate",
    "05-coissued-mandate.json": "EmbeddedSdJwtVcMandate",
    "07-imported-payment-authorization.json": "EmbeddedKbJwtAuthorization",
    "08-attested-mandate.json": "EmbeddedSdJwtVcMandate",
    "09-imported-interactive-l2.json": "EmbeddedSdJwtVcMandate",
    "10-imported-partial-sd.json": "EmbeddedSdJwtVcMandate",
}

failures = []


def ok(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(label)


# document loader: both AVP contexts local, everything else via network
_dsa_ctx = json.loads((AUTH / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_avp_ctx = json.loads((PAY / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_iop_ctx = json.loads((INTEROP / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_ctx_dir = SPEC / "contexts"
# Stable external W3C contexts are vendored locally so validation is offline and
# deterministic (w3.org content-negotiation via the pyld requests loader is flaky --
# it intermittently fails on multiple HTTP Link headers).
_LOCAL = {
    "https://w3id.org/spending-authority/v1": _dsa_ctx,
    "https://w3id.org/avp-micro/v1": _avp_ctx,
    "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1": _iop_ctx,
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


def main():
    section("Turtle parse")
    for ttl in [AUTH / "vocab" / "dsa.ttl", AUTH / "vocab" / "agent-service-categories.ttl",
                AUTH / "shapes" / "dsa-shapes.ttl", PAY / "vocab" / "avp.ttl",
                PAY / "vocab" / "dimensions.ttl", PAY / "vocab" / "units.ttl",
                PAY / "shapes" / "avp-shapes.ttl",
                INTEROP / "vocab" / "interop.ttl", INTEROP / "shapes" / "interop-shapes.ttl"]:
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
        "02-imported-mandate.json": [(IOP_NS + "embeddedSdJwtVc", "iop:embeddedSdJwtVc"),
                                     (IOP_NS + "bridgeMode", "iop:bridgeMode")],
        "04-imported-from-foreign.json": [(IOP_NS + "embeddedSdJwtVc", "iop:embeddedSdJwtVc")],
        "05-coissued-mandate.json": [(IOP_NS + "embeddedSdJwtVc", "iop:embeddedSdJwtVc"),
                                     (SEC_PROOF, "proof")],
        "07-imported-payment-authorization.json": [(IOP_NS + "embeddedKbJwtPresentation",
                                                    "iop:embeddedKbJwtPresentation")],
        "08-attested-mandate.json": [(IOP_NS + "attestingBridge", "iop:attestingBridge"),
                                     (SEC_PROOF, "proof")],
        "09-imported-interactive-l2.json": [(IOP_NS + "importAdvisory", "iop:importAdvisory")],
        "10-imported-partial-sd.json": [(IOP_NS + "importAdvisory", "iop:importAdvisory")],
    }, require_proof=False)  # proof-preserving objects are unsigned projections

    section("JSON Schema validation")
    schema_check(AUTH, AUTH_VECTORS, "dsa.schema.json")
    schema_check(PAY, PAY_VECTORS, "avp-micro.schema.json")
    schema_check(INTEROP, INTEROP_VECTORS, "interop.schema.json")
    negative_schema_check(AUTH, "dsa.schema.json", [
        ("DSA proof type", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj["proof"].__setitem__("type", "NotDataIntegrityProof") or obj)),
        ("DSA context order", "spending-authorization-credential.json", "SpendingAuthorizationCredential",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
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
    ])
    negative_schema_check(INTEROP, "interop.schema.json", [
        ("proof on a proof-preserving object", "02-imported-mandate.json", "EmbeddedSdJwtVcMandate",
         lambda obj: (obj.__setitem__("proof", {"type": "DataIntegrityProof"}), obj)[1]),
        ("attested without attestingBridge", "04-imported-from-foreign.json", "EmbeddedSdJwtVcMandate",
         lambda obj: (obj.__setitem__("bridgeMode", "attested"), obj)[1]),
        ("missing embeddedSdJwtVc", "02-imported-mandate.json", "EmbeddedSdJwtVcMandate",
         lambda obj: (obj.pop("embeddedSdJwtVc", None), obj)[1]),
        ("bad bridgeMode", "02-imported-mandate.json", "EmbeddedSdJwtVcMandate",
         lambda obj: (obj.__setitem__("bridgeMode", "frobnicate"), obj)[1]),
        ("L3 proof on a proof-preserving authorization", "07-imported-payment-authorization.json",
         "EmbeddedKbJwtAuthorization",
         lambda obj: (obj.__setitem__("proof", {"type": "DataIntegrityProof"}), obj)[1]),
        ("L3 missing embeddedKbJwtPresentation", "07-imported-payment-authorization.json",
         "EmbeddedKbJwtAuthorization",
         lambda obj: (obj.pop("embeddedKbJwtPresentation", None), obj)[1]),
    ])

    section("SHACL validation")
    shacl_check(AUTH, AUTH_VECTORS, "dsa-shapes.ttl")
    shacl_check(PAY, PAY_VECTORS, "avp-shapes.ttl")
    shacl_check(INTEROP, INTEROP_VECTORS, "interop-shapes.ttl")

    print()
    if failures:
        print(f"FAIL: {len(failures)} check(s) failed: {failures}")
        return 1
    print("PASS: all artifact checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
