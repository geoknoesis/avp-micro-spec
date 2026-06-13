# Refunds, Reversals, Chargebacks & Dispute Lifecycles — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth peer bundle `spec/disputes/` implementing the reverse value-flow (voluntary refunds + adversarial disputes converging on a wallet-signed reversal settlement fact), with signed test vectors that pass `verify.py` and `validate.py`.

**Architecture:** A new W3C-style bundle (context / vocab / SKOS reasons / JSON Schema / SHACL shapes / signed test vectors / ReSpec prose) at namespace `https://w3id.org/avp-micro/disputes/v1#` (prefix `disp:`). Dispute objects reuse the existing Payments terms (`amount`, `currency`, `payer`, `payee`, `status`, `settlementRef`, `execution`, `timestamp`) via a 5-entry `@context`, and bind to the payment objects they concern with an IRI reference plus a JCS digest. The shared harness (`generate.py` / `verify.py` / `validate.py`) gains a disputes section; the Payments and Authority bundles are unchanged except for one additive `arbiter` DID.

**Tech Stack:** Python 3 (in `.venv`), `cryptography` (P-256), `rdflib`, `pyld`, `pyshacl`, `jsonschema`, `referencing`. JSON-LD 1.1, JSON Schema Draft 2020-12, SHACL, Turtle. The mandatory cryptosuite is `ecdsa-jcs-2022` (reused, no new crypto).

**Reference design:** `docs/superpowers/specs/2026-06-12-disputes-refunds-reversals-design.md`.

**Conventions you MUST follow (from the existing codebase):**
- Never hand-edit test vectors; `generate.py` is the source of truth and rewrites them.
- All commands run on Windows PowerShell with the venv active: `.venv\Scripts\Activate.ps1`.
- `*Digest` fields are computed over the **signed** referenced object: `ac.jcs_digest(signed_obj)`.
- `currency` in objects carries no `@type`; it expands to `dsa:currency` (so SHACL paths use `dsa:currency`). `amount`/`status`/`settlementRef`/`execution`/`payer`/`payee`/`timestamp` expand to the `avp:` namespace; `expires` expands to `sec:expiration`. New dispute members expand to `disp:`.

---

## File Structure

**Create (disputes bundle):**
- `spec/disputes/context/v1.jsonld` — JSON-LD 1.1 context, `@protected`; defines `disp:` terms only, reuses earlier contexts.
- `spec/disputes/vocab/disputes.ttl` — RDFS/OWL ontology: 6 classes + properties.
- `spec/disputes/vocab/reasons.ttl` — SKOS reason-code scheme.
- `spec/disputes/schemas/disputes.schema.json` — JSON Schema, `$defs` per object type.
- `spec/disputes/shapes/disputes-shapes.ttl` — SHACL NodeShapes per object type.
- `spec/disputes/test-vectors/*.json` — 14 signed vectors (written by `generate.py`).
- `spec/disputes/README.md` — artifact table + vector index.
- `spec/disputes/index.html` — W3C ReSpec normative prose.

**Modify (shared harness + docs):**
- `spec/generate.py` — add `arbiter` key + `DID_ARBITER`; add `arbiter` to `dids.json`; add `DISP`/`DISP_CTX`; add the disputes vector block.
- `spec/verify.py` — add `DISP` path; add the disputes B/A/S verification section.
- `spec/validate.py` — register the disputes context; add `DISPUTE_VECTORS`; add disputes to Turtle/expand/schema/SHACL passes + negatives.
- `spec/README.md` — one-line addition to the bundle list.
- `CLAUDE.md` — note the fourth bundle + namespace.

---

## Task 1: Scaffold the bundle and JSON-LD context

**Files:**
- Create: `spec/disputes/context/v1.jsonld`

- [ ] **Step 1: Create the JSON-LD context**

Create `spec/disputes/context/v1.jsonld` with exactly this content. It defines ONLY new `disp:` terms (classes, reference properties, digests, scalars); reused terms come from the earlier contexts in the 5-entry array.

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "disp": "https://w3id.org/avp-micro/disputes/v1#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "Refund": "disp:Refund",
    "Dispute": "disp:Dispute",
    "DisputeEvidence": "disp:DisputeEvidence",
    "DisputeResolution": "disp:DisputeResolution",
    "Reversal": "disp:Reversal",
    "ReversalAcknowledgement": "disp:ReversalAcknowledgement",

    "receipt": { "@id": "disp:receipt", "@type": "@id" },
    "dispute": { "@id": "disp:dispute", "@type": "@id" },
    "refund": { "@id": "disp:refund", "@type": "@id" },
    "resolution": { "@id": "disp:resolution", "@type": "@id" },
    "reversal": { "@id": "disp:reversal", "@type": "@id" },
    "supersedes": { "@id": "disp:supersedes", "@type": "@id" },
    "submittedBy": { "@id": "disp:submittedBy", "@type": "@id" },
    "arbiter": { "@id": "disp:arbiter", "@type": "@id" },
    "resolvedBy": { "@id": "disp:resolvedBy", "@type": "@id" },
    "reason": { "@id": "disp:reason", "@type": "@id" },

    "receiptDigest": { "@id": "disp:receiptDigest" },
    "executionDigest": { "@id": "disp:executionDigest" },
    "authorizationDigest": { "@id": "disp:authorizationDigest" },
    "disputeDigest": { "@id": "disp:disputeDigest" },
    "refundDigest": { "@id": "disp:refundDigest" },
    "resolutionDigest": { "@id": "disp:resolutionDigest" },
    "reversalDigest": { "@id": "disp:reversalDigest" },
    "supersedesDigest": { "@id": "disp:supersedesDigest" },

    "disputedAmount": { "@id": "disp:disputedAmount" },
    "resolvedAmount": { "@id": "disp:resolvedAmount" },
    "cause": { "@id": "disp:cause" },
    "outcome": { "@id": "disp:outcome" },
    "resolverRole": { "@id": "disp:resolverRole" },
    "role": { "@id": "disp:role" },
    "evidenceType": { "@id": "disp:evidenceType" },
    "claim": { "@id": "disp:claim" },
    "note": { "@id": "disp:note" },
    "statement": { "@id": "disp:statement" },
    "contentDigest": { "@id": "disp:contentDigest" },
    "uri": { "@id": "disp:uri", "@type": "xsd:anyURI" },
    "respondBy": { "@id": "disp:respondBy", "@type": "xsd:dateTime" },
    "receivedAt": { "@id": "disp:receivedAt", "@type": "xsd:dateTime" }
  }
}
```

- [ ] **Step 2: Verify it is valid JSON**

Run: `.venv\Scripts\python -c "import json; json.load(open('spec/disputes/context/v1.jsonld', encoding='utf-8')); print('context OK')"`
Expected: `context OK`

- [ ] **Step 3: Commit**

```bash
git add spec/disputes/context/v1.jsonld
git commit -m "feat(disputes): add JSON-LD 1.1 context for the disputes bundle"
```

---

## Task 2: Vocabulary (RDFS/OWL ontology + SKOS reason scheme)

**Files:**
- Create: `spec/disputes/vocab/disputes.ttl`
- Create: `spec/disputes/vocab/reasons.ttl`

- [ ] **Step 1: Create the ontology `spec/disputes/vocab/disputes.ttl`**

```turtle
# AVP-Micro Disputes core RDFS/OWL ontology.
#
# Declares the classes and properties whose JSON-LD term mappings are defined in
# ../context/v1.jsonld. The reverse value-flow: voluntary Refund and the adversarial
# Dispute lifecycle, converging on a wallet-signed Reversal settlement fact.
#
# Namespace: https://w3id.org/avp-micro/disputes/v1#  (prefix disp:)
@prefix disp: <https://w3id.org/avp-micro/disputes/v1#> .
@prefix avp:  <https://w3id.org/avp-micro/v1#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
@prefix dct:  <http://purl.org/dc/terms/> .

<https://w3id.org/avp-micro/disputes/v1> a owl:Ontology ;
  dct:title "AVP-Micro Disputes vocabulary"@en ;
  dct:description "Classes and properties for the AVP-Micro reverse value-flow: refunds, reversals, chargebacks, and the dispute lifecycle."@en ;
  owl:versionInfo "0.1.0" ;
  rdfs:seeAlso <https://w3id.org/avp-micro/v1> .

#################################################################
# Classes
#
# None of these are dsa:AuthorizationInstance: reverse-flow value movement does not
# consume spending authority. They are payee/payer/wallet/arbiter-signed records.
#################################################################

disp:Refund a owl:Class ;
  rdfs:label "Refund"@en ;
  rdfs:comment "A payee-signed voluntary return-of-value intent referencing a prior PaymentReceipt. A commitment, not an authorization."@en .

disp:Dispute a owl:Class ;
  rdfs:label "Dispute"@en ;
  rdfs:comment "A payer-signed case contesting a prior charge, bound to the receipt/execution/authorization it concerns. Opens the adversarial lifecycle."@en .

disp:DisputeEvidence a owl:Class ;
  rdfs:label "Dispute evidence"@en ;
  rdfs:comment "An append-only, party-signed evidence (or representment) record submitted within a dispute by the payer or the payee."@en .

disp:DisputeResolution a owl:Class ;
  rdfs:label "Dispute resolution"@en ;
  rdfs:comment "A signed decision for a dispute (upheld/rejected/partial/withdrawn), signed by the payee, the payer (withdrawal), or an arbiter (binding, on escalation)."@en .

disp:Reversal a owl:Class ;
  rdfs:label "Reversal"@en ;
  rdfs:comment "A wallet-signed settlement fact recording value actually returned to the payer, caused by a Refund or by an upheld/partial DisputeResolution."@en .

disp:ReversalAcknowledgement a owl:Class ;
  rdfs:label "Reversal acknowledgement"@en ;
  rdfs:comment "An OPTIONAL payer-signed confirmation that returned funds were received, referencing a Reversal."@en .

#################################################################
# Object properties (node references / DIDs / IRIs)
#################################################################

disp:receipt a owl:ObjectProperty ; rdfs:label "receipt"@en ;
  rdfs:comment "IRI of the referenced PaymentReceipt being refunded or disputed."@en .
disp:dispute a owl:ObjectProperty ; rdfs:label "dispute"@en ;
  rdfs:comment "IRI of the Dispute an evidence or resolution belongs to."@en .
disp:refund a owl:ObjectProperty ; rdfs:label "refund"@en ;
  rdfs:comment "IRI of the triggering Refund (when a Reversal has cause=refund)."@en .
disp:resolution a owl:ObjectProperty ; rdfs:label "resolution"@en ;
  rdfs:comment "IRI of the triggering DisputeResolution (when a Reversal has cause=dispute)."@en .
disp:reversal a owl:ObjectProperty ; rdfs:label "reversal"@en ;
  rdfs:comment "IRI of the acknowledged Reversal."@en .
disp:supersedes a owl:ObjectProperty ; rdfs:label "supersedes"@en ;
  rdfs:comment "IRI of a prior DisputeResolution overridden by an arbiter resolution on escalation."@en .
disp:submittedBy a owl:ObjectProperty ; rdfs:label "submitted by"@en ;
  rdfs:comment "DID of the party (payer or payee) that signed an evidence record."@en .
disp:arbiter a owl:ObjectProperty ; rdfs:label "arbiter"@en ;
  rdfs:comment "DID of the arbiter proposed/agreed for escalation of a dispute."@en .
disp:resolvedBy a owl:ObjectProperty ; rdfs:label "resolved by"@en ;
  rdfs:comment "DID of the party that signed a DisputeResolution (MUST control its proof)."@en .
disp:reason a owl:ObjectProperty ; rdfs:label "reason"@en ;
  rdfs:comment "IRI of a dispute/refund reason concept (a disp: SKOS concept; the scheme is extensible)."@en .

#################################################################
# Digest properties (content digests over the referenced signed object)
#################################################################

disp:receiptDigest a owl:DatatypeProperty ; rdfs:label "receipt digest"@en ; rdfs:range xsd:string .
disp:executionDigest a owl:DatatypeProperty ; rdfs:label "execution digest"@en ; rdfs:range xsd:string .
disp:authorizationDigest a owl:DatatypeProperty ; rdfs:label "authorization digest"@en ; rdfs:range xsd:string .
disp:disputeDigest a owl:DatatypeProperty ; rdfs:label "dispute digest"@en ; rdfs:range xsd:string .
disp:refundDigest a owl:DatatypeProperty ; rdfs:label "refund digest"@en ; rdfs:range xsd:string .
disp:resolutionDigest a owl:DatatypeProperty ; rdfs:label "resolution digest"@en ; rdfs:range xsd:string .
disp:reversalDigest a owl:DatatypeProperty ; rdfs:label "reversal digest"@en ; rdfs:range xsd:string .
disp:supersedesDigest a owl:DatatypeProperty ; rdfs:label "supersedes digest"@en ; rdfs:range xsd:string .
disp:contentDigest a owl:DatatypeProperty ; rdfs:label "content digest"@en ; rdfs:range xsd:string .

#################################################################
# Scalar / enumerated properties
#################################################################

disp:disputedAmount a owl:DatatypeProperty ; rdfs:label "disputed amount"@en ; rdfs:range xsd:string ;
  rdfs:comment "Strictly positive decimal (string) amount in dispute."@en .
disp:resolvedAmount a owl:DatatypeProperty ; rdfs:label "resolved amount"@en ; rdfs:range xsd:string ;
  rdfs:comment "Non-negative decimal (string) amount to be returned by a resolution; 0 for rejected/withdrawn."@en .
disp:cause a owl:DatatypeProperty ; rdfs:label "cause"@en ; rdfs:range xsd:string ;
  rdfs:comment "Either 'refund' or 'dispute' — what triggered a Reversal."@en .
disp:outcome a owl:DatatypeProperty ; rdfs:label "outcome"@en ; rdfs:range xsd:string ;
  rdfs:comment "One of 'upheld', 'rejected', 'partial', 'withdrawn'."@en .
disp:resolverRole a owl:DatatypeProperty ; rdfs:label "resolver role"@en ; rdfs:range xsd:string ;
  rdfs:comment "One of 'payer', 'payee', 'arbiter'."@en .
disp:role a owl:DatatypeProperty ; rdfs:label "role"@en ; rdfs:range xsd:string ;
  rdfs:comment "Side that submitted an evidence record: 'payer' or 'payee'."@en .
disp:evidenceType a owl:DatatypeProperty ; rdfs:label "evidence type"@en ; rdfs:range xsd:string .
disp:claim a owl:DatatypeProperty ; rdfs:label "claim"@en ; rdfs:range xsd:string .
disp:note a owl:DatatypeProperty ; rdfs:label "note"@en ; rdfs:range xsd:string .
disp:statement a owl:DatatypeProperty ; rdfs:label "statement"@en ; rdfs:range xsd:string .
disp:uri a owl:DatatypeProperty ; rdfs:label "uri"@en ; rdfs:range xsd:anyURI .
disp:respondBy a owl:DatatypeProperty ; rdfs:label "respond by"@en ; rdfs:range xsd:dateTime .
disp:receivedAt a owl:DatatypeProperty ; rdfs:label "received at"@en ; rdfs:range xsd:dateTime .
```

- [ ] **Step 2: Create the SKOS reason scheme `spec/disputes/vocab/reasons.ttl`**

```turtle
# AVP-Micro dispute/refund reason codes (native, extensible SKOS scheme).
#
# Informative skos:note / rdfs:seeAlso map concepts to external frameworks
# (card-network chargeback families, ISO 20022 returns). These mappings are
# NON-NORMATIVE. Implementers MAY mint additional concepts in their own scheme.
#
# Namespace: https://w3id.org/avp-micro/disputes/v1#  (prefix disp:)
@prefix disp: <https://w3id.org/avp-micro/disputes/v1#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

disp:DisputeReasonScheme a skos:ConceptScheme ;
  skos:prefLabel "AVP-Micro dispute/refund reason scheme"@en ;
  skos:definition "An extensible set of reason concepts for refunds and disputes."@en .

disp:not-delivered a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Service not delivered"@en ;
  skos:definition "The paid-for service or output was never provided."@en ;
  skos:note "Maps to card-network 'services not rendered'; ISO 20022 return."@en .

disp:not-as-described a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Not as described"@en ;
  skos:definition "The delivered output did not match the agreed terms."@en ;
  skos:note "Maps to card-network 'not as described / defective'."@en .

disp:unauthorized a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Unauthorized"@en ;
  skos:definition "The payer or principal did not authorize the charge."@en ;
  skos:note "Maps to card-network fraud / unauthorized family."@en .

disp:incorrect-amount a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Incorrect amount"@en ;
  skos:definition "The amount charged did not match the quote or metered usage."@en ;
  skos:note "Maps to card-network 'incorrect amount'."@en .

disp:duplicate a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Duplicate charge"@en ;
  skos:definition "The same charge was processed more than once."@en ;
  skos:note "Maps to card-network 'duplicate processing'."@en .

disp:canceled a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Canceled"@en ;
  skos:definition "The service was canceled before delivery."@en ;
  skos:note "Maps to card-network 'canceled recurring / services'."@en .

disp:quality a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Quality complaint"@en ;
  skos:definition "A subjective complaint about the quality of the delivered output."@en .

disp:goodwill a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Goodwill"@en ;
  skos:definition "A voluntary refund with no asserted fault; refund-only."@en .

disp:other a skos:Concept ; skos:inScheme disp:DisputeReasonScheme ;
  skos:prefLabel "Other"@en ;
  skos:definition "Any reason not covered by another concept; SHOULD accompany a free-text note."@en .
```

- [ ] **Step 3: Verify both Turtle files parse**

Run: `.venv\Scripts\python -c "import rdflib; [print(f.split('/')[-1], len(rdflib.Graph().parse(f, format='turtle')), 'triples') for f in ['spec/disputes/vocab/disputes.ttl','spec/disputes/vocab/reasons.ttl']]"`
Expected: two lines, e.g. `disputes.ttl 80 triples` and `reasons.ttl 40 triples` (non-zero triple counts; exact numbers may differ).

- [ ] **Step 4: Commit**

```bash
git add spec/disputes/vocab/disputes.ttl spec/disputes/vocab/reasons.ttl
git commit -m "feat(disputes): add RDFS/OWL ontology and SKOS reason scheme"
```

---

## Task 3: JSON Schema

**Files:**
- Create: `spec/disputes/schemas/disputes.schema.json`

- [ ] **Step 1: Create `spec/disputes/schemas/disputes.schema.json`**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://w3id.org/avp-micro/disputes/schemas/disputes.schema.json",
  "title": "AVP-Micro Disputes data objects",
  "description": "JSON Schema for AVP-Micro refund/reversal/dispute messages. Validate an instance against the relevant $def, e.g. #/$defs/Refund. Schemas are lenient about extra members (the @protected JSON-LD context governs semantics); they enforce required members, types, and value formats.",

  "$defs": {
    "did": { "type": "string", "pattern": "^did:[a-z0-9]+:.+" },
    "idValue": { "type": "string", "minLength": 1 },
    "iri": { "type": "string", "minLength": 1, "format": "uri" },
    "decimal": {
      "type": "string",
      "description": "Non-negative decimal amount as a string.",
      "pattern": "^(0|[1-9][0-9]*)(\\.[0-9]+)?$"
    },
    "positiveDecimal": {
      "type": "string",
      "description": "Strictly positive decimal amount as a string.",
      "pattern": "^(0\\.[0-9]*[1-9][0-9]*|[1-9][0-9]*(\\.[0-9]+)?)$"
    },
    "dateTime": { "type": "string", "format": "date-time" },
    "contentDigest": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" },
    "reasonRef": { "type": "string", "minLength": 1, "pattern": "^[A-Za-z][A-Za-z0-9+.-]*:.+" },
    "proof": {
      "type": "object",
      "required": ["type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"],
      "properties": {
        "type": { "const": "DataIntegrityProof" },
        "cryptosuite": { "const": "ecdsa-jcs-2022" },
        "created": { "$ref": "#/$defs/dateTime" },
        "verificationMethod": { "type": "string", "minLength": 1 },
        "proofPurpose": { "const": "assertionMethod" },
        "proofValue": { "type": "string", "pattern": "^z[1-9A-HJ-NP-Za-km-z]+$" }
      }
    },
    "signedContext": {
      "type": "array",
      "prefixItems": [
        { "const": "https://www.w3.org/ns/credentials/v2" },
        { "const": "https://w3id.org/security/data-integrity/v2" },
        { "const": "https://w3id.org/spending-authority/v1" },
        { "const": "https://w3id.org/avp-micro/v1" },
        { "const": "https://w3id.org/avp-micro/disputes/v1" }
      ],
      "minItems": 5,
      "maxItems": 5
    },

    "Refund": {
      "type": "object",
      "required": ["@context", "id", "type", "receipt", "receiptDigest", "payer", "payee", "amount", "currency", "reason", "timestamp", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "Refund" }, { "type": "array", "contains": { "const": "Refund" } } ] },
        "receipt": { "$ref": "#/$defs/idValue" },
        "receiptDigest": { "$ref": "#/$defs/contentDigest" },
        "execution": { "$ref": "#/$defs/idValue" },
        "executionDigest": { "$ref": "#/$defs/contentDigest" },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/positiveDecimal" },
        "currency": { "type": "string" },
        "reason": { "$ref": "#/$defs/reasonRef" },
        "note": { "type": "string" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "expires": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "Dispute": {
      "type": "object",
      "required": ["@context", "id", "type", "payer", "payee", "disputedAmount", "currency", "reason", "timestamp", "proof"],
      "anyOf": [
        { "required": ["receipt", "receiptDigest"] },
        { "required": ["execution", "executionDigest"] },
        { "required": ["authorization", "authorizationDigest"] }
      ],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "Dispute" }, { "type": "array", "contains": { "const": "Dispute" } } ] },
        "receipt": { "$ref": "#/$defs/idValue" },
        "receiptDigest": { "$ref": "#/$defs/contentDigest" },
        "execution": { "$ref": "#/$defs/idValue" },
        "executionDigest": { "$ref": "#/$defs/contentDigest" },
        "authorization": { "$ref": "#/$defs/idValue" },
        "authorizationDigest": { "$ref": "#/$defs/contentDigest" },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "disputedAmount": { "$ref": "#/$defs/positiveDecimal" },
        "currency": { "type": "string" },
        "reason": { "$ref": "#/$defs/reasonRef" },
        "claim": { "type": "string" },
        "arbiter": { "$ref": "#/$defs/did" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "respondBy": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "DisputeEvidence": {
      "type": "object",
      "required": ["@context", "id", "type", "dispute", "disputeDigest", "submittedBy", "role", "sequence", "timestamp", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "DisputeEvidence" }, { "type": "array", "contains": { "const": "DisputeEvidence" } } ] },
        "dispute": { "$ref": "#/$defs/idValue" },
        "disputeDigest": { "$ref": "#/$defs/contentDigest" },
        "submittedBy": { "$ref": "#/$defs/did" },
        "role": { "enum": ["payer", "payee"] },
        "sequence": { "type": "integer", "minimum": 0 },
        "evidenceType": { "type": "string" },
        "contentDigest": { "$ref": "#/$defs/contentDigest" },
        "uri": { "$ref": "#/$defs/iri" },
        "statement": { "type": "string" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "DisputeResolution": {
      "type": "object",
      "required": ["@context", "id", "type", "dispute", "disputeDigest", "resolvedBy", "resolverRole", "outcome", "resolvedAmount", "currency", "timestamp", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "DisputeResolution" }, { "type": "array", "contains": { "const": "DisputeResolution" } } ] },
        "dispute": { "$ref": "#/$defs/idValue" },
        "disputeDigest": { "$ref": "#/$defs/contentDigest" },
        "resolvedBy": { "$ref": "#/$defs/did" },
        "resolverRole": { "enum": ["payer", "payee", "arbiter"] },
        "outcome": { "enum": ["upheld", "rejected", "partial", "withdrawn"] },
        "resolvedAmount": { "$ref": "#/$defs/decimal" },
        "currency": { "type": "string" },
        "note": { "type": "string" },
        "supersedes": { "$ref": "#/$defs/idValue" },
        "supersedesDigest": { "$ref": "#/$defs/contentDigest" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      },
      "allOf": [
        {
          "if": { "properties": { "outcome": { "const": "withdrawn" } }, "required": ["outcome"] },
          "then": { "properties": { "resolverRole": { "const": "payer" } } }
        },
        {
          "if": { "properties": { "resolverRole": { "const": "arbiter" } }, "required": ["resolverRole"] },
          "then": { "required": ["supersedes", "supersedesDigest"] }
        }
      ]
    },

    "Reversal": {
      "type": "object",
      "required": ["@context", "id", "type", "cause", "payer", "payee", "amount", "currency", "status", "timestamp", "proof"],
      "oneOf": [
        { "required": ["refund", "refundDigest"] },
        { "required": ["resolution", "resolutionDigest"] }
      ],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "Reversal" }, { "type": "array", "contains": { "const": "Reversal" } } ] },
        "cause": { "enum": ["refund", "dispute"] },
        "refund": { "$ref": "#/$defs/idValue" },
        "refundDigest": { "$ref": "#/$defs/contentDigest" },
        "resolution": { "$ref": "#/$defs/idValue" },
        "resolutionDigest": { "$ref": "#/$defs/contentDigest" },
        "execution": { "$ref": "#/$defs/idValue" },
        "executionDigest": { "$ref": "#/$defs/contentDigest" },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/positiveDecimal" },
        "currency": { "type": "string" },
        "status": { "enum": ["pending", "completed", "partial", "failed"] },
        "settlementRef": { "type": "string" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "ReversalAcknowledgement": {
      "type": "object",
      "required": ["@context", "id", "type", "reversal", "reversalDigest", "payer", "payee", "amount", "currency", "receivedAt", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "ReversalAcknowledgement" }, { "type": "array", "contains": { "const": "ReversalAcknowledgement" } } ] },
        "reversal": { "$ref": "#/$defs/idValue" },
        "reversalDigest": { "$ref": "#/$defs/contentDigest" },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/positiveDecimal" },
        "currency": { "type": "string" },
        "receivedAt": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    }
  }
}
```

- [ ] **Step 2: Verify it is a valid Draft 2020-12 schema**

Run: `.venv\Scripts\python -c "import json; from jsonschema import Draft202012Validator as V; V.check_schema(json.load(open('spec/disputes/schemas/disputes.schema.json', encoding='utf-8'))); print('schema OK')"`
Expected: `schema OK`

- [ ] **Step 3: Commit**

```bash
git add spec/disputes/schemas/disputes.schema.json
git commit -m "feat(disputes): add JSON Schema for the six dispute object types"
```

---

## Task 4: SHACL shapes

**Files:**
- Create: `spec/disputes/shapes/disputes-shapes.ttl`

- [ ] **Step 1: Create `spec/disputes/shapes/disputes-shapes.ttl`**

Note: reused members expand to `avp:`/`dsa:`/`sec:`; new members expand to `disp:`. Helper node shapes are defined locally because `validate.py` loads only this shapes file per instance.

```turtle
# AVP-Micro Disputes SHACL shapes.
# Second validation layer alongside the JSON Schema in ../schemas/. Validates the
# RDF produced by expanding a disputes JSON-LD object. Reused members expand to the
# avp:/dsa:/sec: namespaces; new members expand to disp:.
@prefix sh:   <http://www.w3.org/ns/shacl#> .
@prefix disp: <https://w3id.org/avp-micro/disputes/v1#> .
@prefix avp:  <https://w3id.org/avp-micro/v1#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix sec:  <https://w3id.org/security#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

disp:DecimalAmount a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^(0|[1-9][0-9]*)([.][0-9]+)?$" .
disp:PositiveDecimalAmount a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^(0[.][0-9]*[1-9][0-9]*|[1-9][0-9]*([.][0-9]+)?)$" .
disp:ContentDigest a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" .

disp:RefundShape a sh:NodeShape ;
  sh:targetClass disp:Refund ;
  sh:property [ sh:path disp:receipt ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:receiptDigest ; sh:node disp:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:amount ; sh:node disp:PositiveDecimalAmount ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:reason ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

disp:DisputeShape a sh:NodeShape ;
  sh:targetClass disp:Dispute ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path disp:disputedAmount ; sh:node disp:PositiveDecimalAmount ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:reason ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] ;
  sh:or (
    [ sh:property [ sh:path disp:receipt ; sh:minCount 1 ] ]
    [ sh:property [ sh:path avp:execution ; sh:minCount 1 ] ]
    [ sh:property [ sh:path avp:authorization ; sh:minCount 1 ] ]
  ) .

disp:DisputeEvidenceShape a sh:NodeShape ;
  sh:targetClass disp:DisputeEvidence ;
  sh:property [ sh:path disp:dispute ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:disputeDigest ; sh:node disp:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:submittedBy ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:role ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:sequence ; sh:datatype xsd:integer ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

disp:DisputeResolutionShape a sh:NodeShape ;
  sh:targetClass disp:DisputeResolution ;
  sh:property [ sh:path disp:dispute ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:disputeDigest ; sh:node disp:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:resolvedBy ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:resolverRole ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:outcome ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:resolvedAmount ; sh:node disp:DecimalAmount ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

disp:ReversalShape a sh:NodeShape ;
  sh:targetClass disp:Reversal ;
  sh:property [ sh:path disp:cause ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:amount ; sh:node disp:PositiveDecimalAmount ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:status ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] ;
  sh:or (
    [ sh:property [ sh:path disp:refund ; sh:minCount 1 ] ]
    [ sh:property [ sh:path disp:resolution ; sh:minCount 1 ] ]
  ) .

disp:ReversalAcknowledgementShape a sh:NodeShape ;
  sh:targetClass disp:ReversalAcknowledgement ;
  sh:property [ sh:path disp:reversal ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:reversalDigest ; sh:node disp:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:amount ; sh:node disp:PositiveDecimalAmount ; sh:minCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path disp:receivedAt ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .
```

- [ ] **Step 2: Verify the shapes file parses**

Run: `.venv\Scripts\python -c "import rdflib; print(len(rdflib.Graph().parse('spec/disputes/shapes/disputes-shapes.ttl', format='turtle')), 'triples')"`
Expected: a non-zero triple count, e.g. `90 triples`.

- [ ] **Step 3: Commit**

```bash
git add spec/disputes/shapes/disputes-shapes.ttl
git commit -m "feat(disputes): add SHACL shapes for the six dispute object types"
```

---

## Task 5: Generator wiring (keys, dids.json, and the 14 vectors)

**Files:**
- Modify: `spec/generate.py`

The disputes block reuses in-memory signed objects already built in `main()`: `execution` (urn:avp:exec:555, 0.001), `receipt` (urn:avp:receipt:222), `session_exec` (urn:avp:exec:sess-1, 0.048), `session_receipt` (urn:avp:receipt:sess-final). All exist by the time the streaming vectors finish.

- [ ] **Step 1: Add the disputes paths and context constant**

In `spec/generate.py`, after the line `INTEROP = SPEC / "interop-sd-jwt-vc" / "test-vectors"` (line 20), add:

```python
DISP = SPEC / "disputes" / "test-vectors"
```

Then after the line `PAY_CTX = [VC2, DI, DSA, AVP]` (line 27), add:

```python
DISP_URL = "https://w3id.org/avp-micro/disputes/v1"
DISP_CTX = [VC2, DI, DSA, AVP, DISP_URL]
```

- [ ] **Step 2: Add the arbiter key**

After the line `wallet = ac.seed_key("wallet-acme")` (line 32), add:

```python
arbiter = ac.seed_key("arbiter-org")
```

After the line `DID_WALLET = ac.did_key(wallet.public_key())` (line 37), add:

```python
DID_ARBITER = ac.did_key(arbiter.public_key())
```

- [ ] **Step 3: Add the arbiter DID to `dids.json`**

In the `write(AUTH, "dids.json", {...})` call (lines 110–114), change the dict so the last entry includes the arbiter. Replace:

```python
        "principalIssuer": DID_ISSUER, "payerAgent": DID_AGENT,
        "payeeService": DID_PAYEE, "walletService": DID_WALLET,
    })
```

with:

```python
        "principalIssuer": DID_ISSUER, "payerAgent": DID_AGENT,
        "payeeService": DID_PAYEE, "walletService": DID_WALLET,
        "arbiter": DID_ARBITER,
    })
```

- [ ] **Step 4: Add the disputes vector block**

Insert the following block immediately before the line `# ---- Interop (SD-JWT-VC) bundle ----` (line 325):

```python
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

```

- [ ] **Step 5: Run the generator**

Run: `.venv\Scripts\python spec\generate.py`
Expected: `wrote ...` lines including the 14 disputes files (`disputes/20-refund.json` … `disputes/39-dispute-resolution-withdrawn.json`) and `wrote authority/dids.json`.

- [ ] **Step 6: Confirm the vectors and the arbiter DID exist**

Run: `.venv\Scripts\python -c "import json,glob; print(len(glob.glob('spec/disputes/test-vectors/*.json')), 'vectors'); print('arbiter' in json.load(open('spec/authority/test-vectors/dids.json', encoding='utf-8')))"`
Expected: `14 vectors` then `True`.

- [ ] **Step 7: Commit**

```bash
git add spec/generate.py spec/disputes/test-vectors spec/authority/test-vectors/dids.json
git commit -m "feat(disputes): generate signed refund/reversal/dispute test vectors"
```

---

## Task 6: Validator wiring (structural validation passes)

**Files:**
- Modify: `spec/validate.py`

- [ ] **Step 1: Add the disputes path and namespace**

After the line `INTEROP = SPEC / "interop-sd-jwt-vc"` (line 27), add:

```python
DISP = SPEC / "disputes"
```

After the line `IOP_NS = "https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#"` (line 31), add:

```python
DISP_NS = "https://w3id.org/avp-micro/disputes/v1#"
```

- [ ] **Step 2: Add the `DISPUTE_VECTORS` map**

After the closing brace of `INTEROP_VECTORS` (line 71), add:

```python
DISPUTE_VECTORS = {
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
```

- [ ] **Step 3: Register the disputes context in the local loader**

After the line `_iop_ctx = json.loads((INTEROP / "context" / "v1.jsonld").read_text(encoding="utf-8"))` (line 85), add:

```python
_disp_ctx = json.loads((DISP / "context" / "v1.jsonld").read_text(encoding="utf-8"))
```

Then inside the `_LOCAL = { ... }` dict, after the interop entry line `"https://w3id.org/avp-micro/interop/sd-jwt-vc/v1": _iop_ctx,` (line 93), add:

```python
    "https://w3id.org/avp-micro/disputes/v1": _disp_ctx,
```

- [ ] **Step 4: Add the disputes Turtle files to the parse list**

In the `section("Turtle parse")` loop list (lines 185–189), append the three disputes files. Change the final list entry line:

```python
                INTEROP / "vocab" / "interop.ttl", INTEROP / "shapes" / "interop-shapes.ttl"]:
```

to:

```python
                INTEROP / "vocab" / "interop.ttl", INTEROP / "shapes" / "interop-shapes.ttl",
                DISP / "vocab" / "disputes.ttl", DISP / "vocab" / "reasons.ttl",
                DISP / "shapes" / "disputes-shapes.ttl"]:
```

- [ ] **Step 5: Add the disputes JSON-LD expansion check**

Immediately after the `expand_check(INTEROP, INTEROP_VECTORS, { ... }, require_proof=False)` call closes (line 231, the line `    }, require_proof=False)  # proof-preserving objects are unsigned projections`), add:

```python
    expand_check(DISP, DISPUTE_VECTORS, {
        "20-refund.json": [(DISP_NS + "reason", "disp:reason"),
                           (DISP_NS + "receiptDigest", "disp:receiptDigest")],
        "30-dispute.json": [(DISP_NS + "disputedAmount", "disp:disputedAmount"),
                            (DISP_NS + "arbiter", "disp:arbiter")],
        "34-dispute-resolution-arbiter.json": [(DISP_NS + "supersedes", "disp:supersedes"),
                                               (DISP_NS + "outcome", "disp:outcome")],
        "35-reversal-dispute.json": [(DISP_NS + "cause", "disp:cause"),
                                     (DISP_NS + "resolution", "disp:resolution")],
    })
```

- [ ] **Step 6: Add the disputes JSON Schema check**

After the line `schema_check(INTEROP, INTEROP_VECTORS, "interop.schema.json")` (line 235), add:

```python
    schema_check(DISP, DISPUTE_VECTORS, "disputes.schema.json")
```

- [ ] **Step 7: Add disputes negative schema cases**

After the `negative_schema_check(INTEROP, "interop.schema.json", [ ... ])` call closes (line 281), add:

```python
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
    ])
```

- [ ] **Step 8: Add the disputes SHACL check**

After the line `shacl_check(INTEROP, INTEROP_VECTORS, "interop-shapes.ttl")` (line 286), add:

```python
    shacl_check(DISP, DISPUTE_VECTORS, "disputes-shapes.ttl")
```

- [ ] **Step 9: Run the validator**

Run: `.venv\Scripts\python spec\validate.py`
Expected: the run ends with `PASS: all artifact checks passed.` and the new sections show `[PASS]` lines for each `2*`/`3*` disputes vector across Turtle parse, JSON-LD expansion, JSON Schema, and SHACL, plus `[PASS] negative schema rejects ...` for the seven disputes negatives.

- [ ] **Step 10: Commit**

```bash
git add spec/validate.py
git commit -m "feat(disputes): wire the disputes bundle into validate.py (4 layers + negatives)"
```

---

## Task 7: Verifier wiring (B/A/S semantic checks)

**Files:**
- Modify: `spec/verify.py`

The disputes section reuses already-loaded forward-flow vectors (`receipt`, `execution`, `session_exec`, `session_receipt`) and the `dids` dict.

- [ ] **Step 1: Add the disputes path**

After the line `INTEROP = SPEC / "interop-sd-jwt-vc" / "test-vectors"` (line 17), add:

```python
DISP = SPEC / "disputes" / "test-vectors"
```

- [ ] **Step 2: Add the disputes verification section**

Immediately before the line `print("Negative control (tamper detection):")` (line 363), insert:

```python
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
    check("payee resolution binds dispute digest", res_payee["disputeDigest"] == ac.jcs_digest(dispute))
    check("arbiter supersedesDigest matches payee resolution",
          res_arb["supersedesDigest"] == ac.jcs_digest(res_payee))
    check("reversal(refund).refundDigest matches refund",
          rev_refund["refundDigest"] == ac.jcs_digest(refund))
    check("reversal(dispute).resolutionDigest matches arbiter resolution",
          rev_dispute["resolutionDigest"] == ac.jcs_digest(res_arb))
    check("reversal-ack.reversalDigest matches reversal",
          rev_ack["reversalDigest"] == ac.jcs_digest(rev_refund))

    # B4 + B5: party / currency consistency with the original
    check("refund parties match original receipt",
          refund["payer"] == session_receipt["payer"] and refund["payee"] == session_receipt["payee"])
    check("dispute parties match original receipt",
          dispute["payer"] == session_receipt["payer"] and dispute["payee"] == session_receipt["payee"])
    check("refund currency matches original", refund["currency"] == session_receipt["currency"])
    check("dispute currency matches original", dispute["currency"] == session_receipt["currency"])

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
    check("reversal(dispute) references upheld/partial resolution",
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

```

- [ ] **Step 3: Run the verifier**

Run: `.venv\Scripts\python spec\verify.py`
Expected: a `Refunds, reversals & dispute lifecycle:` section of `[PASS]` lines, and the run ends with `PASS: all checks passed.`

- [ ] **Step 4: Commit**

```bash
git add spec/verify.py
git commit -m "feat(disputes): add B/A/S semantic verification for the disputes bundle"
```

---

## Task 8: Documentation (README, ReSpec prose, index updates)

**Files:**
- Create: `spec/disputes/README.md`
- Create: `spec/disputes/index.html`
- Modify: `spec/README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Create `spec/disputes/README.md`**

```markdown
# AVP-Micro Disputes

The reverse value-flow for AVP-Micro: **refunds, reversals, chargebacks, and the
dispute lifecycle**. Builds on the [Payments](../payments/) and
[Delegated Spending Authority](../authority/) bundles.

Two trigger paths — a voluntary `Refund` and the adversarial
`Dispute → DisputeEvidence* → DisputeResolution` lifecycle — converge on a
wallet-signed `Reversal` settlement fact, with an optional payer-signed
`ReversalAcknowledgement`. A "chargeback" is simply a `Dispute` whose resolution is
upheld/partial, producing a `Reversal`. Resolution is bilateral with an optional
arbiter (escalation supersedes the payee's resolution). No reverse-flow object
consumes spending authority.

- **Namespace:** `https://w3id.org/avp-micro/disputes/v1#` (prefix `disp:`)
- **Context:** `https://w3id.org/avp-micro/disputes/v1` → [`context/v1.jsonld`](context/v1.jsonld)

## Artifacts

| Artifact | File |
|---|---|
| JSON-LD context | [`context/v1.jsonld`](context/v1.jsonld) |
| Ontology (RDFS/OWL) | [`vocab/disputes.ttl`](vocab/disputes.ttl) |
| Reason codes (SKOS) | [`vocab/reasons.ttl`](vocab/reasons.ttl) |
| JSON Schema | [`schemas/disputes.schema.json`](schemas/disputes.schema.json) |
| SHACL shapes | [`shapes/disputes-shapes.ttl`](shapes/disputes-shapes.ttl) |
| Prose specification | [`index.html`](index.html) |

## Test vectors

| # | File | Type |
|---|---|---|
| 20 | `20-refund.json` | Refund (partial, settled) |
| 21 | `21-reversal-refund.json` | Reversal (cause=refund) |
| 22 | `22-reversal-ack.json` | ReversalAcknowledgement |
| 23 | `23-refund-partial.json` | Refund (second partial, intent only) |
| 30 | `30-dispute.json` | Dispute |
| 31 | `31-dispute-evidence-payee.json` | DisputeEvidence (representment) |
| 32 | `32-dispute-evidence-payer.json` | DisputeEvidence (rebuttal) |
| 33 | `33-dispute-resolution-payee.json` | DisputeResolution (partial) |
| 34 | `34-dispute-resolution-arbiter.json` | DisputeResolution (upheld, supersedes 33) |
| 35 | `35-reversal-dispute.json` | Reversal (cause=dispute / chargeback) |
| 36 | `36-dispute-rejected.json` | Dispute (rejected path) |
| 37 | `37-dispute-resolution-rejected.json` | DisputeResolution (rejected) |
| 38 | `38-dispute-withdrawn.json` | Dispute (withdrawn path) |
| 39 | `39-dispute-resolution-withdrawn.json` | DisputeResolution (withdrawn) |

Regenerate and check from the repo root (see [`../README.md`](../README.md)):

```powershell
python spec/generate.py
python spec/verify.py
python spec/validate.py
```
```

- [ ] **Step 2: Create `spec/disputes/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AVP-Micro Disputes</title>
  <style>
    p.object-summary { font-style: italic; color: #333; margin-bottom: 0.5em; }
  </style>
  <script src="https://www.w3.org/Tools/respec/respec-w3c" class="remove" defer></script>
  <script class="remove">
    // @ts-check
    const respecConfig = {
      specStatus: "unofficial",
      shortName: "avp-micro-disputes",
      subtitle: "Refunds, reversals, chargebacks, and dispute lifecycles for AVP-Micro",
      editors: [
        { name: "Stephane Fellah", company: "Geoknoesis LLC", companyURL: "https://geoknoesis.com" },
      ],
      github: { repoURL: "https://github.com/geoknoesis/avp-micro", branch: "main" },
      license: "cc-by",
      lint: { "no-unused-dfns": false },
      xref: ["vc-data-model-2.0", "did-core", "INFRA"],
      localBiblio: {
        "DSA": { title: "Delegated Spending Authority", href: "../authority/",
                 publisher: "Geoknoesis LLC (editor's draft)" },
        "AVP-MICRO": { title: "AVP-Micro Payments", href: "../payments/",
                       publisher: "Geoknoesis LLC (editor's draft)" },
        "RFC8785": { title: "JSON Canonicalization Scheme (JCS)",
                     href: "https://www.rfc-editor.org/rfc/rfc8785",
                     authors: ["A. Rundgren", "B. Jordan", "S. Erdtman"],
                     date: "June 2020", status: "Informational", publisher: "IETF" },
      },
    };
  </script>
</head>
<body>
  <section id="abstract" class="informative">
    <p>
      AVP-Micro Disputes defines the <strong>reverse value-flow</strong> for
      [[AVP-MICRO]]: returning value to a payer, whether voluntarily (a
      <a>Refund</a>) or adversarially (a <a>Dispute</a> that is upheld — a
      chargeback), and the <strong>dispute lifecycle</strong> that governs the
      adversarial case. It reuses the [[AVP-MICRO]] economic terms and the
      [[DSA]] identity and securing layers; every object is secured with the
      mandatory <code>ecdsa-jcs-2022</code> cryptosuite.
    </p>
  </section>

  <section id="sotd"></section>

  <section class="informative">
    <h2>Introduction</h2>
    <p>
      "Refund", "reversal", and "chargeback" are not three parallel objects: they
      are the same reverse value-movement reached by different triggers. A
      <strong>Refund</strong> is decided voluntarily by the payee; a
      <strong>chargeback</strong> is a <a>Dispute</a> that is upheld; a
      <strong>Reversal</strong> is the wallet-signed settlement fact that actually
      moves value back, which both paths produce. This specification therefore
      models two trigger paths converging on one settlement record.
    </p>
    <p>
      State is <strong>derived from the set of signed records</strong>, not stored
      in a mutable field. Each lifecycle transition is the creation of a new signed,
      append-only object. This lets the payer, payee, and an optional arbiter each
      sign their own records independently.
    </p>
  </section>

  <section>
    <h2>Conformance</h2>
    <p>
      As well as sections marked as non-normative, all authoring guidelines,
      diagrams, examples, and notes in this specification are non-normative.
      Everything else is normative.
    </p>
    <p>
      The key words <em class="rfc2119">MUST</em>, <em class="rfc2119">MUST NOT</em>,
      <em class="rfc2119">SHOULD</em>, <em class="rfc2119">MAY</em>, and
      <em class="rfc2119">OPTIONAL</em> in this document are to be interpreted as
      described in [[RFC2119]] [[RFC8174]].
    </p>
  </section>

  <section>
    <h2>Terminology</h2>
    <dl>
      <dt><dfn>Refund</dfn></dt><dd>A payee-signed voluntary return-of-value intent.</dd>
      <dt><dfn>Dispute</dfn></dt><dd>A payer-signed case contesting a prior charge.</dd>
      <dt><dfn>DisputeEvidence</dfn></dt><dd>An append-only, party-signed evidence or representment record.</dd>
      <dt><dfn>DisputeResolution</dfn></dt><dd>A signed decision: upheld, rejected, partial, or withdrawn.</dd>
      <dt><dfn>Reversal</dfn></dt><dd>A wallet-signed settlement fact recording value returned to the payer.</dd>
      <dt><dfn>ReversalAcknowledgement</dfn></dt><dd>An OPTIONAL payer-signed confirmation of receipt.</dd>
      <dt><dfn>arbiter</dfn></dt><dd>An OPTIONAL neutral party whose signed resolution is binding on escalation.</dd>
    </dl>
  </section>

  <section>
    <h2>Namespace and JSON-LD context</h2>
    <p>
      The namespace IRI is <code>https://w3id.org/avp-micro/disputes/v1#</code>
      (prefix <code>disp:</code>). Disputes objects use a five-entry
      <code>@context</code> array, in this exact order, so that the credential,
      data-integrity, [[DSA]], [[AVP-MICRO]], and disputes terms all resolve:
    </p>
    <pre class="json">
[
  "https://www.w3.org/ns/credentials/v2",
  "https://w3id.org/security/data-integrity/v2",
  "https://w3id.org/spending-authority/v1",
  "https://w3id.org/avp-micro/v1",
  "https://w3id.org/avp-micro/disputes/v1"
]
    </pre>
    <p>
      Disputes objects <em class="rfc2119">MUST</em> reuse the [[AVP-MICRO]] terms
      <code>amount</code>, <code>currency</code>, <code>payer</code>,
      <code>payee</code>, <code>status</code>, <code>settlementRef</code>,
      <code>execution</code>, and <code>timestamp</code> rather than redefining them.
    </p>
  </section>

  <section>
    <h2>Data model</h2>
    <p>
      Every object is secured with a Data Integrity proof using the
      <code>ecdsa-jcs-2022</code> cryptosuite (see [[DSA]]). Every reference to a
      payment or dispute object <em class="rfc2119">MUST</em> include both the
      object's IRI and a <code>*Digest</code> equal to the JCS content digest of the
      referenced (signed) object, pinning it to that exact object.
    </p>

    <section>
      <h3>Refund</h3>
      <p class="object-summary">A payee-signed voluntary return-of-value intent.</p>
      <p>
        A <a>Refund</a> <em class="rfc2119">MUST</em> reference the
        <code>PaymentReceipt</code> being refunded (<code>receipt</code> +
        <code>receiptDigest</code>) and <em class="rfc2119">MUST</em> be signed by
        the <code>payee</code>. Its <code>amount</code>
        <em class="rfc2119">MUST</em> be greater than zero and
        <em class="rfc2119">MUST NOT</em> exceed the referenced charge. Multiple
        partial refunds <em class="rfc2119">MAY</em> reference the same original,
        provided the cumulative settled return does not exceed the original amount.
        The <code>reason</code> <em class="rfc2119">MUST</em> be a concept IRI (see
        <a href="#reason-codes">Reason codes</a>).
      </p>
    </section>

    <section>
      <h3>Dispute</h3>
      <p class="object-summary">A payer-signed case contesting a prior charge.</p>
      <p>
        A <a>Dispute</a> <em class="rfc2119">MUST</em> be signed by the
        <code>payer</code> and <em class="rfc2119">MUST</em> reference at least one of
        the contested objects (<code>receipt</code>, <code>execution</code>, or
        <code>authorization</code>), each with its <code>*Digest</code>. Its
        <code>disputedAmount</code> <em class="rfc2119">MUST NOT</em> exceed the
        original charge. It <em class="rfc2119">MAY</em> propose an
        <code>arbiter</code> DID for escalation and a <code>respondBy</code>
        deadline.
      </p>
    </section>

    <section>
      <h3>DisputeEvidence</h3>
      <p class="object-summary">An append-only, party-signed evidence or representment record.</p>
      <p>
        A <a>DisputeEvidence</a> record <em class="rfc2119">MUST</em> be signed by the
        party named in <code>submittedBy</code>, whose <code>role</code>
        (<code>payer</code> or <code>payee</code>) <em class="rfc2119">MUST</em>
        match. Each record carries a per-dispute <code>sequence</code> that
        <em class="rfc2119">MUST</em> be unique. The evidence artifact itself is
        out of scope; the record carries only its <code>contentDigest</code> and an
        optional <code>uri</code>.
      </p>
    </section>

    <section>
      <h3>DisputeResolution</h3>
      <p class="object-summary">A signed decision: upheld, rejected, partial, or withdrawn.</p>
      <p>
        A <a>DisputeResolution</a> carries an <code>outcome</code> and a
        <code>resolvedAmount</code> (which <em class="rfc2119">MUST NOT</em> exceed
        the <code>disputedAmount</code>, and <em class="rfc2119">MUST</em> be zero for
        <code>rejected</code> and <code>withdrawn</code>). A <code>withdrawn</code>
        resolution <em class="rfc2119">MUST</em> have <code>resolverRole</code>
        <code>payer</code>. An <code>arbiter</code> resolution
        <em class="rfc2119">MUST</em> carry <code>supersedes</code> +
        <code>supersedesDigest</code> referencing the payee resolution it overrides,
        and its signer <em class="rfc2119">MUST</em> equal the dispute's
        <code>arbiter</code>.
      </p>
    </section>

    <section>
      <h3>Reversal</h3>
      <p class="object-summary">A wallet-signed settlement fact recording value returned to the payer.</p>
      <p>
        A <a>Reversal</a> <em class="rfc2119">MUST</em> be signed by the wallet and
        <em class="rfc2119">MUST</em> reference exactly one trigger: a
        <code>refund</code> (when <code>cause</code> is <code>refund</code>) or a
        <code>resolution</code> (when <code>cause</code> is <code>dispute</code>),
        each with its digest. A dispute-caused Reversal's referenced resolution
        <em class="rfc2119">MUST</em> have outcome <code>upheld</code> or
        <code>partial</code>. The <code>amount</code> <em class="rfc2119">MUST</em>
        equal the trigger's amount (or be less when <code>status</code> is
        <code>partial</code>). When present, the original forward
        <code>execution</code> SHOULD be referenced.
      </p>
    </section>

    <section>
      <h3>ReversalAcknowledgement</h3>
      <p class="object-summary">An OPTIONAL payer-signed confirmation of receipt.</p>
      <p>
        A <a>ReversalAcknowledgement</a> <em class="rfc2119">MUST</em> be signed by
        the <code>payer</code> and reference the <code>reversal</code> (+
        <code>reversalDigest</code>) whose funds were received.
      </p>
    </section>
  </section>

  <section class="informative">
    <h2>Dispute lifecycle</h2>
    <pre>
Voluntary:   Refund (payee) -> Reversal cause=refund (wallet) -> [Ack (payer)]

Adversarial: Dispute (payer)
               -> OPENED -> [DisputeEvidence* (payer/payee)]
               -> UNDER-REVIEW -> DisputeResolution (payee)
                    rejected  -> CLOSED
                    upheld/partial -> Reversal cause=dispute (wallet) -> [Ack] -> CLOSED
                    payer escalates -> DisputeResolution (arbiter, supersedes payee) [BINDING]
                                         -> rejected -> CLOSED
                                         -> upheld/partial -> Reversal -> CLOSED
               -> WITHDRAWN (DisputeResolution role=payer, outcome=withdrawn) -> CLOSED
    </pre>
  </section>

  <section id="reason-codes">
    <h2>Reason codes</h2>
    <p>
      Reason values are concept IRIs in the extensible SKOS scheme
      <code>disp:DisputeReasonScheme</code> (see
      <a href="vocab/reasons.ttl"><code>vocab/reasons.ttl</code></a>): for example
      <code>disp:not-delivered</code>, <code>disp:not-as-described</code>,
      <code>disp:unauthorized</code>, <code>disp:incorrect-amount</code>,
      <code>disp:duplicate</code>, <code>disp:canceled</code>,
      <code>disp:quality</code>, <code>disp:goodwill</code>, and
      <code>disp:other</code>. Mappings to external frameworks (card-network
      chargeback families, ISO 20022 returns) are non-normative. Implementers
      <em class="rfc2119">MAY</em> mint additional concepts in their own scheme.
    </p>
  </section>

  <section class="informative">
    <h2>Security and Privacy</h2>
    <p>
      Reverse-flow value movement does not consume a Spending Authorization
      Credential; none of these objects are authorization instances. Integrity of a
      refund or dispute chain rests on the per-object proofs and the
      IRI-plus-digest binding to the contested payment objects. Verifiers
      <em class="rfc2119">MUST</em> reject a Reversal whose cumulative settled value
      against one original execution would exceed that original's amount.
    </p>
  </section>
</body>
</html>
```

- [ ] **Step 3: Add the disputes bundle to `spec/README.md`**

Open `spec/README.md`, find the list of the three bundles (authority / payments / interop), and add a fourth entry consistent with the existing formatting. Insert this line after the interop bundle's entry:

```markdown
- **`disputes/`** — Refunds, Reversals, Chargebacks & Dispute Lifecycles: the reverse value-flow built on Payments + DSA. Namespace `https://w3id.org/avp-micro/disputes/v1#`.
```

(If the bundles are presented as a table instead of a list, add an equivalent row matching that table's columns.)

- [ ] **Step 4: Update `CLAUDE.md`**

In `CLAUDE.md`, under "What this repo is", change "Three peer bundles live under `spec/`:" to "Four peer bundles live under `spec/`:" and add, after the interop bundle bullet:

```markdown
- **`spec/disputes/`** — Refunds, Reversals, Chargebacks & Dispute Lifecycles: the reverse value-flow (voluntary refunds + the adversarial dispute lifecycle) converging on a wallet-signed reversal. Built on Payments + DSA. Namespace `https://w3id.org/avp-micro/disputes/v1#`.
```

Then in the "Namespace / context URLs" section, after the interop context line, add:

```markdown
- Disputes context: `https://w3id.org/avp-micro/disputes/v1` → `spec/disputes/context/v1.jsonld`
```

- [ ] **Step 5: Confirm nothing regressed**

Run: `.venv\Scripts\python spec\validate.py; .venv\Scripts\python spec\verify.py`
Expected: both still end with `PASS`.

- [ ] **Step 6: Commit**

```bash
git add spec/disputes/README.md spec/disputes/index.html spec/README.md CLAUDE.md
git commit -m "docs(disputes): add README, ReSpec prose, and index/CLAUDE updates"
```

---

## Task 9: Full clean-room verification

**Files:** none (verification only)

- [ ] **Step 1: Regenerate from scratch and run both harnesses**

Run:
```powershell
.venv\Scripts\python spec\generate.py
.venv\Scripts\python spec\validate.py
.venv\Scripts\python spec\verify.py
```
Expected:
- `generate.py` prints `wrote ...` for all bundles including the 14 disputes vectors, with no traceback.
- `validate.py` ends with `PASS: all artifact checks passed.`
- `verify.py` ends with `PASS: all checks passed.`

- [ ] **Step 2: Confirm the disputes vectors are deterministic**

Run: `git status --porcelain spec/disputes/test-vectors/`
Expected: **no output** — the disputes vectors are signed with the deterministic `ecdsa-jcs-2022` cryptosuite (RFC 6979), so regeneration is byte-identical.

> **Pre-existing note (NOT a regression):** running `generate.py` also rewrites all
> `spec/interop-sd-jwt-vc/test-vectors/*.json` with fresh signatures every time —
> the interop bundle's SD-JWT envelopes use randomized ES256 (not RFC 6979), so that
> churn is inherent to the existing generator and is unrelated to this feature. The
> harnesses still PASS against the freshly-signed interop vectors. Discard that churn
> so it is not committed: `git checkout -- spec/interop-sd-jwt-vc/test-vectors/`.

- [ ] **Step 3: Discard the pre-existing interop churn and confirm a clean tree**

```bash
git checkout -- spec/interop-sd-jwt-vc/test-vectors/
git status --porcelain
```
Expected: no output. (All disputes work is already committed in Tasks 1–8; this task is verification only and should produce no new commit.)

---

## Self-Review (completed by plan author)

**1. Spec coverage** — every design section maps to a task:
- §2 bundle layout/namespace/5-entry context → Task 1 (context), Task 8 (README/CLAUDE).
- §3 object model (6 types, fields, signer, binding) → Task 3 (schema), Task 4 (shapes), Task 5 (vectors).
- §3.2 no spending-authority subclassing → Task 2 ontology comment (classes are not `dsa:AuthorizationInstance`); Task 7 needs no authority checks.
- §4 lifecycle (voluntary + adversarial, withdrawn from OPENED/UNDER-REVIEW) → Task 5 vectors (20–22 voluntary, 30–35 adversarial w/ escalation, 36–39 rejected/withdrawn), Task 8 lifecycle prose.
- §5.1 B-rules → Task 7 B1–B5 checks. §5.2 A-rules → Task 7 A1–A4. §5.3 S-rules → Task 7 S1–S5. §5.4 structural → Task 6.
- §6 reason vocabulary → Task 2 reasons.ttl; reason IRIs used in vectors (Task 5).
- §7 test vectors → Task 5 (note: refined to 14 vectors so the set is self-consistent under A2 — the design's two "against receipt 04" refunds would have collided; refunds now sit on the streaming original and disputes split across both originals).
- §8 harness wiring → Tasks 5/6/7; docs → Task 8. §9 acceptance criteria → Task 9.

**2. Placeholder scan** — no TBD/TODO; every code/edit step shows full content or an exact before/after; every run step states the expected output.

**3. Type/name consistency** — object `type` strings, `$defs` names, `DISPUTE_VECTORS` filenames, vector `id`s, and `*Digest` field names are identical across schema (Task 3), shapes (Task 4), generator (Task 5), validator (Task 6), and verifier (Task 7). Reused-term namespaces (`avp:`/`dsa:`/`sec:`) in the shapes match how the JSON-LD context maps them. The `arbiter` DID is defined in `generate.py` (Task 5), written to `dids.json` (Task 5), and read in `verify.py` (Task 7).
