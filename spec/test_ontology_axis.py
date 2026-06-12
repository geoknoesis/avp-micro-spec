"""Ontology assertions for the authorization capacity/instance axis (design D13-D17).

These guard the *semantics*, not the wire format: the capacity/instance subclassing,
the semantic chain relations, the strict separation of those from provenance relations,
and the intent disambiguation.
"""
from pathlib import Path

import rdflib
from rdflib import RDF, RDFS, OWL, URIRef

DSA = "https://w3id.org/spending-authority/v1#"
AVP = "https://w3id.org/avp-micro/v1#"
IOP = "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#"
PROV = "http://www.w3.org/ns/prov#"

_SPEC = Path(__file__).parent


def _g(*ttls):
    g = rdflib.Graph()
    for t in ttls:
        g.parse((_SPEC / t).as_posix(), format="turtle")
    return g


def D(name):
    return URIRef(DSA + name)


def A(name):
    return URIRef(AVP + name)


def I(name):
    return URIRef(IOP + name)


# ---- D13: capacity / instance are the two authorization kinds ----

def test_capacity_and_instance_classes_exist():
    g = _g("authority/vocab/dsa.ttl")
    for c in ("Authorization", "AuthorizationCapacity", "AuthorizationInstance"):
        assert (D(c), RDF.type, OWL.Class) in g, f"missing class dsa:{c}"
    assert (D("AuthorizationCapacity"), RDFS.subClassOf, D("Authorization")) in g
    assert (D("AuthorizationInstance"), RDFS.subClassOf, D("Authorization")) in g


def test_spending_authorization_credential_is_capacity():
    g = _g("authority/vocab/dsa.ttl")
    assert (D("SpendingAuthorizationCredential"), RDFS.subClassOf, D("AuthorizationCapacity")) in g


def test_payment_authorization_and_confirmation_are_instances():
    g = _g("authority/vocab/dsa.ttl", "payments/vocab/avp.ttl")
    for c in ("PaymentAuthorization", "PurchaseConfirmation", "SessionBudgetAuthorization"):
        assert (A(c), RDFS.subClassOf, D("AuthorizationInstance")) in g, f"avp:{c} not an instance"


# ---- D14: commitments / facts are NOT authorizations ----

def test_quote_and_execution_are_not_authorizations():
    g = _g("authority/vocab/dsa.ttl", "payments/vocab/avp.ttl")
    for c in ("PaymentQuote", "PaymentReceipt", "PaymentExecution", "PaymentOffer"):
        assert (A(c), RDFS.subClassOf, D("AuthorizationInstance")) not in g
        assert (A(c), RDFS.subClassOf, D("AuthorizationCapacity")) not in g
        assert (A(c), RDFS.subClassOf, D("Authorization")) not in g


# ---- D15: semantic chain relations exist and are NOT provenance relations ----

def test_semantic_chain_relations_exist_with_domain_range():
    g = _g("authority/vocab/dsa.ttl")
    assert (D("exercises"), RDFS.domain, D("AuthorizationInstance")) in g
    assert (D("exercises"), RDFS.range, D("AuthorizationCapacity")) in g
    assert (D("conformsTo"), RDFS.domain, D("AuthorizationInstance")) in g
    assert (D("conformsTo"), RDFS.range, D("AuthorizationCapacity")) in g
    assert (D("enables"), RDFS.domain, D("AuthorizationCapacity")) in g
    assert (D("enables"), RDFS.range, D("AuthorizationInstance")) in g
    for rel in ("exercises", "conformsTo", "enables", "mustMatch"):
        assert (D(rel), RDF.type, OWL.ObjectProperty) in g, f"missing relation dsa:{rel}"


def test_authorization_chain_never_uses_prov_derivedfrom():
    # the chain relations live in dsa: ; provenance relations MUST NOT appear in the DSA
    # ontology at all (provenance is the bridge layer's concern, not authorization).
    g = _g("authority/vocab/dsa.ttl")
    prov_terms = [URIRef(PROV + t) for t in ("wasDerivedFrom", "used", "wasGeneratedBy", "wasAttributedTo")]
    for s, p, o in g:
        assert o not in prov_terms and p not in prov_terms, f"provenance relation leaked into DSA: {p} {o}"


# ---- D15 (bridge side): provenance relations are the securing layer's ----

def test_securing_uses_provenance_relations():
    g = _g("interop-sd-jwt-vc/vocab/interop.ttl")
    # PROV is declared and the securing descriptor is tied to provenance, not authorization
    assert any(str(o).startswith(PROV) or str(p).startswith(PROV) for s, p, o in g), \
        "interop vocab should align the securing/bridge layer with PROV-O"


# ---- D16: intent disambiguation ----

def test_natural_language_intent_is_distinct_and_non_enforced():
    g = _g("interop-sd-jwt-vc/vocab/interop.ttl")
    assert (I("NaturalLanguageIntent"), RDF.type, OWL.Class) in g
    # OWL-sound: a carried string property links to the concept via seeAlso (not a class range)
    assert (I("intentDescription"), RDFS.seeAlso, I("NaturalLanguageIntent")) in g
    assert (I("intentDescription"), RDFS.range, URIRef("http://www.w3.org/2001/XMLSchema#string")) in g
