# AVP-Micro Transport & Protocol Binding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sixth peer bundle, `spec/transport/`, that specifies the normative HTTP/REST wire binding (discovery + HTTP 402 challenge) for the existing AVP-Micro payment objects — as signed JSON-LD objects, an OpenAPI 3.1 contract, ReSpec prose, and signed test vectors wired into the generate/verify/validate harness.

**Architecture:** The bundle defines four new object types (`ServiceDescription`, `PaymentChallenge`, `AuthorizationSubmission`, `ProblemDetails`) plus a SKOS error-code scheme. The three signed objects use the existing `ecdsa-jcs-2022` cryptosuite and a 5-entry `@context` (`[VC2, data-integrity/v2, spending-authority/v1, avp-micro/v1, avp-micro/transport/v1]`), reusing payments/DSA terms and adding only `txp:` terms. The transport objects *wrap* existing payments objects by IRI + content digest — no other bundle is modified. Example HTTP exchanges carry byte-identical copies of the canonical signed objects.

**Tech Stack:** Python 3 (deterministic generator), JSON-LD 1.1, JSON Schema Draft 2020-12, SHACL (pyshacl), RDFS/OWL + SKOS (rdflib), OpenAPI 3.1 (YAML, validated via PyYAML), W3C ReSpec (HTML).

**Reference design:** `docs/superpowers/specs/2026-06-13-transport-protocol-binding-design.md`.

---

## Pre-flight (executor reads first)

- Work happens on branch `feat/transport-binding` (already created off `master`; the design doc is committed as `ca5b4ed`). If executing via subagents, use the **superpowers:using-git-worktrees** skill; if already isolated, stay put.
- Activate the venv before every command: the harness lives at `spec/` and uses the repo venv. All commands below use the venv python explicitly: `./.venv/Scripts/python` (Git Bash) or `.venv\Scripts\python` (PowerShell).
- **Invariants (from CLAUDE.md):** `python spec/verify.py` and `python spec/validate.py` must both report **PASS** after every change-bearing task. Never hand-edit test vectors — only `generate.py` writes them. `generate.py` is deterministic: running it twice must leave `git status` clean.
- Baseline check before starting — confirm the repo is green:
  ```bash
  ./.venv/Scripts/python spec/generate.py >/dev/null && ./.venv/Scripts/python spec/verify.py | tail -1 && ./.venv/Scripts/python spec/validate.py | tail -1
  ```
  Expected: both harnesses print `PASS: ...`.

### Reused vs. new context terms (do NOT redefine the reused ones)

The 5-entry context array means these terms already resolve from the DSA/payments/security contexts and **MUST NOT** be redefined in `transport/context/v1.jsonld` (`@protected` + the cross-bundle drift discipline):

- From payments (`avp:`): `payee`, `payer`, `quote`, `quoteDigest`, `requestHash`, `amount`, `timestamp`, `authorization`, `acceptedCredentialIssuers`, `status`.
- From DSA/security (`dsa:`/`sec:`): `currency`, `nonce`, `expires`.

New `txp:` terms this bundle adds: `challenge`, `authorizeEndpoint`, `authorizationDigest`, `idempotencyKey`, `callbackUrl`, `offers`, `endpoints`, `acceptedSettlementRails`, `supportedBundles`, plus the four class terms.

---

## File Structure

**Create (new bundle `spec/transport/`):**
- `spec/transport/context/v1.jsonld` — JSON-LD 1.1 `@protected` context; `txp:` classes + new properties.
- `spec/transport/vocab/transport.ttl` — RDFS/OWL ontology: 4 classes + new properties.
- `spec/transport/vocab/errors.ttl` — SKOS `txp:ErrorScheme` (19 error concepts).
- `spec/transport/schemas/transport.schema.json` — JSON Schema `$defs` per object + shared primitives + envelope/exchange defs.
- `spec/transport/shapes/transport-shapes.ttl` — SHACL NodeShapes for the 3 signed objects.
- `spec/transport/openapi/avp-micro.openapi.yaml` — OpenAPI 3.1 HTTP surface; bodies `$ref` the bundle schemas.
- `spec/transport/test-vectors/*.json` — written by `generate.py` (do not author by hand).
- `spec/transport/index.html` — W3C ReSpec normative prose.
- `spec/transport/README.md` — artifact table + vector index + endpoint summary.

**Modify (harness + docs):**
- `spec/generate.py` — module constants + a transport block in `main()`.
- `spec/validate.py` — context registration, `TRANSPORT_VECTORS`/unsigned map, Turtle parse, schema/SHACL/expand wiring, shared-`$def` guard, negatives, OpenAPI-ref check.
- `spec/verify.py` — transport semantic checks (proofs, signer binding, digest bindings, challenge echo, error-code resolution, exchange byte-identity).
- `requirements.txt` — add `pyyaml>=6.0` (now a direct dependency of `validate.py`).
- `spec/README.md` — add the sixth bundle.
- `CLAUDE.md` — add the sixth bundle + transport namespace.

---

## Task 1: JSON-LD context, ontology, and error scheme

**Files:**
- Create: `spec/transport/context/v1.jsonld`
- Create: `spec/transport/vocab/transport.ttl`
- Create: `spec/transport/vocab/errors.ttl`

- [ ] **Step 1: Write the JSON-LD context**

Create `spec/transport/context/v1.jsonld` with exactly this content:

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "txp": "https://w3id.org/avp-micro/transport/v1#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "ServiceDescription": "txp:ServiceDescription",
    "PaymentChallenge": "txp:PaymentChallenge",
    "AuthorizationSubmission": "txp:AuthorizationSubmission",
    "ProblemDetails": "txp:ProblemDetails",

    "offers": { "@id": "txp:offers", "@container": "@set", "@type": "@id" },
    "endpoints": { "@id": "txp:endpoints", "@type": "@json" },
    "acceptedSettlementRails": { "@id": "txp:acceptedSettlementRails", "@container": "@set", "@type": "@id" },
    "supportedBundles": { "@id": "txp:supportedBundles", "@type": "@json" },

    "challenge": { "@id": "txp:challenge" },
    "authorizeEndpoint": { "@id": "txp:authorizeEndpoint", "@type": "xsd:anyURI" },
    "authorizationDigest": { "@id": "txp:authorizationDigest" },
    "idempotencyKey": { "@id": "txp:idempotencyKey" },
    "callbackUrl": { "@id": "txp:callbackUrl", "@type": "xsd:anyURI" }
  }
}
```

Note: `payee`, `payer`, `quote`, `quoteDigest`, `requestHash`, `amount`, `timestamp`, `authorization`, `acceptedCredentialIssuers`, `currency`, `nonce`, `expires` are intentionally **absent** — they resolve from the earlier context entries and must not be redefined.

- [ ] **Step 2: Write the core ontology**

Create `spec/transport/vocab/transport.ttl` with exactly this content:

```turtle
# AVP-Micro Transport & Protocol binding RDFS/OWL ontology.
#
# Classes/properties whose JSON-LD term mappings live in ../context/v1.jsonld.
# The wire layer: a discovery document, an HTTP 402 payment challenge, the
# client's authorization submission, and an RFC 9457 problem-details body.
# Reused members (payee, payer, quote, quoteDigest, requestHash, amount,
# currency, nonce, expires, authorization, timestamp, acceptedCredentialIssuers)
# expand to avp:/dsa:/sec:; new members expand to txp:.
#
# Namespace: https://w3id.org/avp-micro/transport/v1#  (prefix txp:)
@prefix txp:  <https://w3id.org/avp-micro/transport/v1#> .
@prefix avp:  <https://w3id.org/avp-micro/v1#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
@prefix dct:  <http://purl.org/dc/terms/> .

<https://w3id.org/avp-micro/transport/v1> a owl:Ontology ;
  dct:title "AVP-Micro Transport & Protocol vocabulary"@en ;
  dct:description "Classes and properties for the normative HTTP binding of AVP-Micro: service discovery, the HTTP 402 payment challenge, the client authorization submission, and the problem-details error body."@en ;
  owl:versionInfo "0.1.0" ;
  rdfs:seeAlso <https://w3id.org/avp-micro/v1> .

#################################################################
# Classes
#################################################################

txp:ServiceDescription a owl:Class ; rdfs:label "Service description"@en ;
  rdfs:comment "A payee-signed discovery document served at /.well-known/avp-micro: endpoints, accepted issuers, accepted settlement rails, and supported bundle versions."@en .
txp:PaymentChallenge a owl:Class ; rdfs:label "Payment challenge"@en ;
  rdfs:comment "A payee-signed HTTP 402 body that wraps a PaymentQuote (by IRI + digest) and a server-chosen challenge nonce the client must echo."@en .
txp:AuthorizationSubmission a owl:Class ; rdfs:label "Authorization submission"@en ;
  rdfs:comment "A payer-agent-signed 402 retry payload that wraps a PaymentAuthorization (by IRI + digest), echoes the challenge nonce, and carries an idempotency key."@en .
txp:ProblemDetails a owl:Class ; rdfs:label "Problem details"@en ;
  rdfs:comment "An unsigned RFC 9457 problem+json error body whose type is an error-code IRI in txp:ErrorScheme."@en .

#################################################################
# Object properties (node references / DIDs / IRIs)
#################################################################

txp:offers a owl:ObjectProperty ; rdfs:label "offers"@en ;
  rdfs:comment "IRIs of the PaymentOffers advertised by the payee."@en .
txp:acceptedSettlementRails a owl:ObjectProperty ; rdfs:label "accepted settlement rails"@en ;
  rdfs:comment "IRIs of the settlement-rail SKOS concepts (see settlement rails.ttl) the payee will settle on."@en .

#################################################################
# Digest properties (content digests over the referenced signed object)
#################################################################

txp:authorizationDigest a owl:DatatypeProperty ; rdfs:label "authorization digest"@en ; rdfs:range xsd:string ;
  rdfs:comment "Content digest (e.g. sha-256:...) of the wrapped PaymentAuthorization."@en .

#################################################################
# Scalar / structured properties
#################################################################

txp:endpoints a owl:DatatypeProperty ; rdfs:label "endpoints"@en ; rdfs:range rdfs:Literal ;
  rdfs:comment "A JSON object mapping operation names (quote, authorize, execute, receipt, settlementStatus, session, accruals, close, extend) to URL templates."@en .
txp:supportedBundles a owl:DatatypeProperty ; rdfs:label "supported bundles"@en ; rdfs:range rdfs:Literal ;
  rdfs:comment "A JSON object mapping bundle context IRIs to the supported version string."@en .
txp:challenge a owl:DatatypeProperty ; rdfs:label "challenge"@en ; rdfs:range xsd:string ;
  rdfs:comment "Server-chosen anti-replay nonce; the client echoes it in the AuthorizationSubmission."@en .
txp:authorizeEndpoint a owl:DatatypeProperty ; rdfs:label "authorize endpoint"@en ; rdfs:range xsd:anyURI ;
  rdfs:comment "URL the client submits the authorization to (or the gated resource to retry)."@en .
txp:idempotencyKey a owl:DatatypeProperty ; rdfs:label "idempotency key"@en ; rdfs:range xsd:string ;
  rdfs:comment "Client-chosen idempotency key, mirrored in the Idempotency-Key header."@en .
txp:callbackUrl a owl:DatatypeProperty ; rdfs:label "callback URL"@en ; rdfs:range xsd:anyURI ;
  rdfs:comment "Optional webhook for async settlement notification."@en .
```

- [ ] **Step 3: Write the SKOS error scheme**

Create `spec/transport/vocab/errors.ttl` with exactly this content:

```turtle
# AVP-Micro Transport error-code scheme (native, extensible SKOS scheme).
#
# A ProblemDetails.type is an IRI of one of these concepts. The HTTP status
# note (skos:note) is INFORMATIVE; §4.7 of the spec gives the status mapping.
# Implementers MAY mint additional concepts in their own scheme.
#
# Namespace: https://w3id.org/avp-micro/transport/v1#  (prefix txp:)
@prefix txp:  <https://w3id.org/avp-micro/transport/v1#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .

txp:ErrorScheme a skos:ConceptScheme ;
  skos:prefLabel "AVP-Micro transport error-code scheme"@en ;
  skos:definition "An extensible set of error-code concepts used as ProblemDetails.type values."@en .

txp:amount-mismatch a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Amount mismatch"@en ;
  skos:definition "The submitted authorization amount does not equal the quoted amount."@en ;
  skos:note "HTTP 422."@en .
txp:currency-mismatch a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Currency mismatch"@en ;
  skos:definition "The submitted currency does not equal the quoted currency."@en ;
  skos:note "HTTP 422."@en .
txp:over-cap a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Over per-transaction cap"@en ;
  skos:definition "The amount exceeds the credential's maxPerTransaction."@en ;
  skos:note "HTTP 402."@en .
txp:payee-not-allowed a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Payee not allowed"@en ;
  skos:definition "The payee is not in the credential's allowedPayees."@en ;
  skos:note "HTTP 403."@en .
txp:category-not-allowed a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Category not allowed"@en ;
  skos:definition "The requested category is not in the credential's allowedCategories."@en ;
  skos:note "HTTP 403."@en .
txp:daily-limit-exceeded a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Daily limit exceeded"@en ;
  skos:definition "This charge would exceed the credential's dailyLimit."@en ;
  skos:note "HTTP 402."@en .
txp:expired a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Expired"@en ;
  skos:definition "The quote or authorization is past its expiry."@en ;
  skos:note "HTTP 422."@en .
txp:nonce-reuse a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Nonce reuse"@en ;
  skos:definition "A nonce was reused (anti-replay)."@en ;
  skos:note "HTTP 409."@en .
txp:double-spend a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Double spend"@en ;
  skos:definition "The authorization was already executed."@en ;
  skos:note "HTTP 409."@en .
txp:budget-exceeded a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Budget exceeded"@en ;
  skos:definition "A streaming accrual would exceed the session budget."@en ;
  skos:note "HTTP 402."@en .
txp:missing-confirmation a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Missing purchase confirmation"@en ;
  skos:definition "A PurchaseConfirmation is required for this charge but was absent."@en ;
  skos:note "HTTP 403."@en .
txp:forged-confirmation a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Forged confirmation"@en ;
  skos:definition "A supplied PurchaseConfirmation failed verification."@en ;
  skos:note "HTTP 422."@en .
txp:malformed-request a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Malformed request"@en ;
  skos:definition "The request body was syntactically or schematically invalid."@en ;
  skos:note "HTTP 400."@en .
txp:unauthorized a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Unauthorized"@en ;
  skos:definition "The submission signature or credential chain did not verify."@en ;
  skos:note "HTTP 401."@en .
txp:challenge-expired a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Challenge expired"@en ;
  skos:definition "The PaymentChallenge is past its expiry; request a fresh 402."@en ;
  skos:note "HTTP 422."@en .
txp:idempotency-conflict a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Idempotency conflict"@en ;
  skos:definition "The Idempotency-Key was reused with a different request body."@en ;
  skos:note "HTTP 409."@en .
txp:settlement-pending a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Settlement pending"@en ;
  skos:definition "Settlement has not reached finality; poll settlementStatus."@en ;
  skos:note "HTTP 200 + Location, or 503."@en .
txp:settlement-failed a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Settlement failed"@en ;
  skos:definition "On-chain or rail settlement failed."@en ;
  skos:note "HTTP 502."@en .
txp:credential-revoked a skos:Concept ; skos:inScheme txp:ErrorScheme ;
  skos:prefLabel "Credential revoked"@en ;
  skos:definition "A credential in the chain is revoked per its status list."@en ;
  skos:note "HTTP 403."@en .
```

- [ ] **Step 4: Verify all three parse as Turtle / load as JSON**

Run:
```bash
./.venv/Scripts/python -c "import rdflib,json; \
g=rdflib.Graph().parse('spec/transport/vocab/transport.ttl',format='turtle'); print('transport.ttl',len(g),'triples'); \
e=rdflib.Graph().parse('spec/transport/vocab/errors.ttl',format='turtle'); print('errors.ttl',len(e),'triples'); \
c=json.load(open('spec/transport/context/v1.jsonld',encoding='utf-8')); assert c['@context']['@protected'] is True; print('context terms',len(c['@context']))"
```
Expected: prints triple counts for both TTLs (non-zero) and `context terms 18`. No exceptions.

- [ ] **Step 5: Commit**

```bash
git add spec/transport/context/v1.jsonld spec/transport/vocab/transport.ttl spec/transport/vocab/errors.ttl
git commit -m "feat(transport): JSON-LD context, ontology, and SKOS error scheme"
```

---

## Task 2: JSON Schema

**Files:**
- Create: `spec/transport/schemas/transport.schema.json`

The shared primitive `$defs` (`did`, `idValue`, `dateTime`, `contentDigest`, `proof`) are copied **byte-for-byte (functionally)** from the other bundles so the cross-bundle drift guard stays green. The `signedContext` is the 5-entry array ending in the transport context URL.

- [ ] **Step 1: Write the schema**

Create `spec/transport/schemas/transport.schema.json` with exactly this content:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://w3id.org/avp-micro/transport/schemas/transport.schema.json",
  "title": "AVP-Micro Transport data objects",
  "description": "JSON Schema for AVP-Micro HTTP transport messages. Validate an instance against the relevant $def, e.g. #/$defs/PaymentChallenge. Schemas are lenient about extra members (the @protected JSON-LD context governs semantics); they enforce required members, types, and value formats.",

  "$defs": {
    "did": { "type": "string", "pattern": "^did:[a-z0-9]+:.+" },
    "idValue": { "type": "string", "minLength": 1 },
    "decimal": { "type": "string", "pattern": "^(0|[1-9][0-9]*)(\\.[0-9]+)?$" },
    "positiveDecimal": { "type": "string", "pattern": "^(0\\.[0-9]*[1-9][0-9]*|[1-9][0-9]*(\\.[0-9]+)?)$" },
    "dateTime": { "type": "string", "format": "date-time" },
    "contentDigest": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" },
    "uri": { "type": "string", "pattern": "^[a-z][a-z0-9+.-]*:.+" },
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
        { "const": "https://w3id.org/avp-micro/transport/v1" }
      ],
      "minItems": 5,
      "maxItems": 5
    },

    "ServiceDescription": {
      "type": "object",
      "required": ["@context", "id", "type", "payee", "endpoints", "acceptedSettlementRails", "supportedBundles", "timestamp", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "ServiceDescription" }, { "type": "array", "contains": { "const": "ServiceDescription" } } ] },
        "payee": { "$ref": "#/$defs/did" },
        "offers": { "type": "array", "items": { "$ref": "#/$defs/idValue" } },
        "endpoints": {
          "type": "object",
          "required": ["quote", "authorize"],
          "additionalProperties": { "type": "string", "minLength": 1 }
        },
        "acceptedCredentialIssuers": { "type": "array", "items": { "$ref": "#/$defs/did" } },
        "acceptedSettlementRails": { "type": "array", "minItems": 1, "items": { "$ref": "#/$defs/uri" } },
        "supportedBundles": { "type": "object", "minProperties": 1, "additionalProperties": { "type": "string", "minLength": 1 } },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "expires": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "PaymentChallenge": {
      "type": "object",
      "required": ["@context", "id", "type", "payee", "quote", "quoteDigest", "challenge", "authorizeEndpoint", "timestamp", "expires", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "PaymentChallenge" }, { "type": "array", "contains": { "const": "PaymentChallenge" } } ] },
        "payee": { "$ref": "#/$defs/did" },
        "quote": { "$ref": "#/$defs/idValue" },
        "quoteDigest": { "$ref": "#/$defs/contentDigest" },
        "challenge": { "type": "string", "minLength": 1 },
        "authorizeEndpoint": { "$ref": "#/$defs/uri" },
        "acceptedSettlementRails": { "type": "array", "items": { "$ref": "#/$defs/uri" } },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "expires": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "AuthorizationSubmission": {
      "type": "object",
      "required": ["@context", "id", "type", "payer", "authorization", "authorizationDigest", "challenge", "idempotencyKey", "timestamp", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "AuthorizationSubmission" }, { "type": "array", "contains": { "const": "AuthorizationSubmission" } } ] },
        "payer": { "$ref": "#/$defs/did" },
        "authorization": { "$ref": "#/$defs/idValue" },
        "authorizationDigest": { "$ref": "#/$defs/contentDigest" },
        "challenge": { "type": "string", "minLength": 1 },
        "idempotencyKey": { "type": "string", "minLength": 1 },
        "callbackUrl": { "$ref": "#/$defs/uri" },
        "timestamp": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "ProblemDetails": {
      "type": "object",
      "required": ["type", "title", "status"],
      "properties": {
        "type": { "$ref": "#/$defs/uri" },
        "title": { "type": "string", "minLength": 1 },
        "status": { "type": "integer", "minimum": 100, "maximum": 599 },
        "detail": { "type": "string" },
        "field": { "type": "string" },
        "instance": { "type": "string" }
      }
    },

    "Challenge402Body": {
      "type": "object",
      "required": ["challenge", "quote"],
      "properties": {
        "challenge": { "$ref": "#/$defs/PaymentChallenge" },
        "quote": { "type": "object" }
      }
    },

    "HttpExchangeLog": {
      "type": "object",
      "required": ["description", "steps"],
      "properties": {
        "description": { "type": "string", "minLength": 1 },
        "steps": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "required": ["request", "response"],
            "properties": {
              "request": {
                "type": "object",
                "required": ["method", "path", "headers"],
                "properties": {
                  "method": { "enum": ["GET", "POST", "PUT", "DELETE"] },
                  "path": { "type": "string", "minLength": 1 },
                  "headers": { "type": "object" },
                  "body": {}
                }
              },
              "response": {
                "type": "object",
                "required": ["status", "headers"],
                "properties": {
                  "status": { "type": "integer", "minimum": 100, "maximum": 599 },
                  "headers": { "type": "object" },
                  "body": {}
                }
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 2: Verify the schema is a valid Draft 2020-12 schema and the shared `$defs` match**

Run:
```bash
./.venv/Scripts/python -c "import json; from jsonschema import Draft202012Validator as V; \
t=json.load(open('spec/transport/schemas/transport.schema.json',encoding='utf-8')); V.check_schema(t); \
s=json.load(open('spec/settlement/schemas/settlement.schema.json',encoding='utf-8')); \
norm=lambda d:{k:v for k,v in d.items() if k!='description'}; \
[print('shared',p,norm(t['\$defs'][p])==norm(s['\$defs'][p])) for p in ('did','idValue','decimal','positiveDecimal','dateTime','contentDigest','proof')]; \
print('OK')"
```
Expected: each `shared <name> True`, then `OK`. (The `$id` differs between bundles — that is fine; the drift guard only compares the primitive `$defs`, not `$id`.)

- [ ] **Step 3: Commit**

```bash
git add spec/transport/schemas/transport.schema.json
git commit -m "feat(transport): JSON Schema for transport objects + exchange envelopes"
```

---

## Task 3: SHACL shapes

**Files:**
- Create: `spec/transport/shapes/transport-shapes.ttl`

Shapes target the three signed classes. `endpoints` and `supportedBundles` are `@json` literals and are validated by JSON Schema (Task 2) only — they are intentionally **not** constrained here, to avoid `@json`→RDF edge cases.

- [ ] **Step 1: Write the shapes**

Create `spec/transport/shapes/transport-shapes.ttl` with exactly this content:

```turtle
# AVP-Micro Transport SHACL shapes.
# Second validation layer alongside the JSON Schema in ../schemas/. Validates the
# RDF produced by expanding a transport JSON-LD object. Reused members expand to
# avp:/dsa:/sec:; new members expand to txp:. The @json members (endpoints,
# supportedBundles) are governed by the JSON Schema and are not shaped here.
@prefix sh:   <http://www.w3.org/ns/shacl#> .
@prefix txp:  <https://w3id.org/avp-micro/transport/v1#> .
@prefix avp:  <https://w3id.org/avp-micro/v1#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix sec:  <https://w3id.org/security#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

txp:ContentDigest a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" .

txp:ServiceDescriptionShape a sh:NodeShape ;
  sh:targetClass txp:ServiceDescription ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path txp:acceptedSettlementRails ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

txp:PaymentChallengeShape a sh:NodeShape ;
  sh:targetClass txp:PaymentChallenge ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:quote ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:quoteDigest ; sh:node txp:ContentDigest ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path txp:challenge ; sh:nodeKind sh:Literal ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path txp:authorizeEndpoint ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path sec:expiration ; sh:datatype xsd:dateTime ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

txp:AuthorizationSubmissionShape a sh:NodeShape ;
  sh:targetClass txp:AuthorizationSubmission ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:authorization ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path txp:authorizationDigest ; sh:node txp:ContentDigest ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path txp:challenge ; sh:nodeKind sh:Literal ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path txp:idempotencyKey ; sh:nodeKind sh:Literal ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:timestamp ; sh:datatype xsd:dateTime ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .
```

- [ ] **Step 2: Verify the shapes parse**

Run:
```bash
./.venv/Scripts/python -c "import rdflib; g=rdflib.Graph().parse('spec/transport/shapes/transport-shapes.ttl',format='turtle'); print('shapes',len(g),'triples')"
```
Expected: `shapes <N> triples` with N > 0, no exception.

- [ ] **Step 3: Commit**

```bash
git add spec/transport/shapes/transport-shapes.ttl
git commit -m "feat(transport): SHACL shapes for the signed transport objects"
```

---

## Task 4: Generate the test vectors

**Files:**
- Modify: `spec/generate.py` (module constants near line 30-34; transport block inserted before the interop block at line 769)

- [ ] **Step 1: Add module-level constants**

In `spec/generate.py`, find this block (lines 30-34):

```python
DISP_URL = "https://w3id.org/avp-micro/disputes/v1"
DISP_CTX = [VC2, DI, DSA, AVP, DISP_URL]
SETTLE_URL = "https://w3id.org/avp-micro/settlement/v1"
SETTLE_CTX = [VC2, DI, DSA, AVP, SETTLE_URL]
SETTLE = SPEC / "settlement" / "test-vectors"
```

Replace it with:

```python
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
```

- [ ] **Step 2: Insert the transport block before the interop block**

In `spec/generate.py`, find this anchor (lines 767-769):

```python
    binding_agent = ac.sign_ecdsa_jcs_2022(binding_agent, agent, "2026-03-26T09:04:00Z")
    write(SETTLE, "55-payee-account-binding-agent.json", binding_agent)

    # ---- Interop (SD-JWT-VC) bundle ----
```

Replace it with (the transport block is inserted between the two existing lines and the interop comment):

```python
    binding_agent = ac.sign_ecdsa_jcs_2022(binding_agent, agent, "2026-03-26T09:04:00Z")
    write(SETTLE, "55-payee-account-binding-agent.json", binding_agent)

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
                             "headers": {"WWW-Authenticate": "AVP-Micro",
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
                             "headers": {"Content-Type": "application/problem+json"},
                             "body": problem},
            },
        ],
    }
    write(TXP, "41-exchange-over-cap.json", over_cap)

    # ---- Interop (SD-JWT-VC) bundle ----
```

- [ ] **Step 3: Run the generator and confirm determinism**

Run:
```bash
./.venv/Scripts/python spec/generate.py | grep transport
./.venv/Scripts/python spec/generate.py >/dev/null
git status --porcelain spec/transport/test-vectors
```
Expected: the first command lists `wrote transport/00-service-description.json` … through `41-exchange-over-cap.json` (7 files). After running twice, `git status --porcelain` for the test-vectors shows only the 7 new (untracked `??`) files and **no churn** on a second run (running it a third time changes nothing).

- [ ] **Step 4: Sanity-check the digests bind the canonical objects**

Run:
```bash
./.venv/Scripts/python -c "import sys; sys.path.insert(0,'spec'); import json,avp_crypto as ac; \
ch=json.load(open('spec/transport/test-vectors/10-payment-challenge.json',encoding='utf-8')); \
q=json.load(open('spec/payments/test-vectors/01-payment-quote.json',encoding='utf-8')); \
sub=json.load(open('spec/transport/test-vectors/20-authorization-submission.json',encoding='utf-8')); \
az=json.load(open('spec/payments/test-vectors/02-payment-authorization.json',encoding='utf-8')); \
print('quoteDigest', ch['quoteDigest']==ac.jcs_digest(q)); \
print('authzDigest', sub['authorizationDigest']==ac.jcs_digest(az)); \
print('echo', sub['challenge']==ch['challenge']); \
print('proofs', ac.verify_ecdsa_jcs_2022(ch) and ac.verify_ecdsa_jcs_2022(sub))"
```
Expected: all four lines print `True`.

- [ ] **Step 5: Commit**

```bash
git add spec/generate.py spec/transport/test-vectors
git commit -m "feat(transport): deterministic generator block + signed vectors"
```

---

## Task 5: Wire validate.py (schema / JSON-LD / SHACL / drift / negatives)

**Files:**
- Modify: `spec/validate.py`

- [ ] **Step 1: Add the yaml import**

In `spec/validate.py`, find:

```python
import rdflib
from pyld import jsonld
```

Replace with:

```python
import rdflib
import yaml
from pyld import jsonld
```

- [ ] **Step 2: Add the transport bundle path + namespace**

Find:

```python
SETTLE = SPEC / "settlement"
SEC_PROOF = "https://w3id.org/security#proof"
```

Replace with:

```python
SETTLE = SPEC / "settlement"
TRANSPORT = SPEC / "transport"
SEC_PROOF = "https://w3id.org/security#proof"
```

Then find:

```python
SETTLE_NS = "https://w3id.org/avp-micro/settlement/v1#"
```

Replace with:

```python
SETTLE_NS = "https://w3id.org/avp-micro/settlement/v1#"
TXP_NS = "https://w3id.org/avp-micro/transport/v1#"
```

- [ ] **Step 3: Add the vector maps**

Find the end of the `SETTLEMENT_VECTORS` dict:

```python
    "56-payee-account-binding-evm.json": "PayeeAccountBinding",
}

failures = []
```

Replace with:

```python
    "56-payee-account-binding-evm.json": "PayeeAccountBinding",
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
}

failures = []
```

- [ ] **Step 4: Register the transport context in the local loader**

Find:

```python
_settle_ctx = json.loads((SETTLE / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_ctx_dir = SPEC / "contexts"
```

Replace with:

```python
_settle_ctx = json.loads((SETTLE / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_txp_ctx = json.loads((TRANSPORT / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_ctx_dir = SPEC / "contexts"
```

Then find:

```python
    "https://w3id.org/avp-micro/settlement/v1": _settle_ctx,
    "https://www.w3.org/ns/credentials/v2":
```

Replace with:

```python
    "https://w3id.org/avp-micro/settlement/v1": _settle_ctx,
    "https://w3id.org/avp-micro/transport/v1": _txp_ctx,
    "https://www.w3.org/ns/credentials/v2":
```

- [ ] **Step 5: Add the OpenAPI ref-check helper**

In `spec/validate.py`, find:

```python
def shared_defs_check():
```

Insert this function immediately **before** it:

```python
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


def shared_defs_check():
```

- [ ] **Step 6: Add the transport schema to the drift guard**

Find:

```python
    "settlement": SETTLE / "schemas" / "settlement.schema.json",
}
```

Replace with:

```python
    "settlement": SETTLE / "schemas" / "settlement.schema.json",
    "transport": TRANSPORT / "schemas" / "transport.schema.json",
}
```

- [ ] **Step 7: Add the Turtle parse entries**

In `main()`, find:

```python
                SETTLE / "vocab" / "settlement.ttl", SETTLE / "vocab" / "rails.ttl",
                SETTLE / "shapes" / "settlement-shapes.ttl"]:
```

Replace with:

```python
                SETTLE / "vocab" / "settlement.ttl", SETTLE / "vocab" / "rails.ttl",
                SETTLE / "shapes" / "settlement-shapes.ttl",
                TRANSPORT / "vocab" / "transport.ttl", TRANSPORT / "vocab" / "errors.ttl",
                TRANSPORT / "shapes" / "transport-shapes.ttl"]:
```

- [ ] **Step 8: Add the JSON-LD expansion checks**

Find the end of the settlement `expand_check` call:

```python
        "52-escrow-refund-evm.json": [(SETTLE_NS + "reason", "stl:reason")],
    })

    section("JSON Schema validation")
```

Replace with:

```python
        "52-escrow-refund-evm.json": [(SETTLE_NS + "reason", "stl:reason")],
    })
    expand_check(TRANSPORT, TRANSPORT_VECTORS, {
        "00-service-description.json": [(TXP_NS + "acceptedSettlementRails", "txp:acceptedSettlementRails"),
                                        (TXP_NS + "offers", "txp:offers")],
        "10-payment-challenge.json": [(TXP_NS + "challenge", "txp:challenge"),
                                      ("https://w3id.org/avp-micro/v1#quoteDigest", "avp:quoteDigest")],
        "20-authorization-submission.json": [(TXP_NS + "authorizationDigest", "txp:authorizationDigest"),
                                             (TXP_NS + "idempotencyKey", "txp:idempotencyKey")],
    })

    section("JSON Schema validation")
```

- [ ] **Step 9: Add the schema validation calls**

Find:

```python
    schema_check(SETTLE, SETTLEMENT_VECTORS, "settlement.schema.json")
    section("Shared $def consistency (no cross-bundle drift)")
    shared_defs_check()
```

Replace with:

```python
    schema_check(SETTLE, SETTLEMENT_VECTORS, "settlement.schema.json")
    schema_check(TRANSPORT, TRANSPORT_VECTORS, "transport.schema.json")
    schema_check(TRANSPORT, TRANSPORT_UNSIGNED_VECTORS, "transport.schema.json")
    section("Shared $def consistency (no cross-bundle drift)")
    shared_defs_check()
    section("OpenAPI contract")
    openapi_ref_check()
```

- [ ] **Step 10: Add the transport negative-schema cases**

Find the end of the settlement negatives block:

```python
        ("binding missing subject", "40-payee-account-binding.json", "PayeeAccountBinding",
         lambda obj: (obj.pop("subject", None), obj)[1]),
    ])

    section("SHACL validation")
```

Replace with:

```python
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
```

- [ ] **Step 11: Add the SHACL validation call**

Find:

```python
    shacl_check(SETTLE, SETTLEMENT_VECTORS, "settlement-shapes.ttl")

    print()
```

Replace with:

```python
    shacl_check(SETTLE, SETTLEMENT_VECTORS, "settlement-shapes.ttl")
    shacl_check(TRANSPORT, TRANSPORT_VECTORS, "transport-shapes.ttl")

    print()
```

- [ ] **Step 12: Run validate.py**

Run:
```bash
./.venv/Scripts/python spec/validate.py | tail -40
```
Expected: a `=== OpenAPI contract ===` section appears, all transport lines say `[PASS]`, and the last line is `PASS: all artifact checks passed.`

> Note: the OpenAPI ref-check will FAIL here because `openapi/avp-micro.openapi.yaml` does not exist yet — that file is Task 7. If `validate.py` fails **only** on the OpenAPI section, that is expected at this point; complete Task 7 before treating validate.py as green. To confirm everything *except* OpenAPI passes now, temporarily check that no non-OpenAPI line is `[FAIL]`:
> ```bash
> ./.venv/Scripts/python spec/validate.py | grep FAIL | grep -v -i openapi
> ```
> Expected: no output.

- [ ] **Step 13: Commit**

```bash
git add spec/validate.py
git commit -m "feat(transport): wire validate.py (schema, JSON-LD, SHACL, drift, negatives, OpenAPI-ref)"
```

---

## Task 6: Wire verify.py (semantic checks)

**Files:**
- Modify: `spec/verify.py`

- [ ] **Step 1: Add the transport vectors directory constant**

In `spec/verify.py`, find:

```python
SETTLE = SPEC / "settlement" / "test-vectors"
```

Replace with:

```python
SETTLE = SPEC / "settlement" / "test-vectors"
TXP = SPEC / "transport" / "test-vectors"
```

- [ ] **Step 2: Add the transport semantic-check block**

Find the end of `main()` (the negative-control section, line 714):

```python
    print("Negative control (tamper detection):")
    tampered = json.loads(json.dumps(authz))
```

Insert this block immediately **before** that `print("Negative control...")` line:

```python
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

```

- [ ] **Step 3: Run verify.py**

Run:
```bash
./.venv/Scripts/python spec/verify.py | tail -40
```
Expected: a `Transport & protocol binding:` section with all `[PASS]` lines, and the final line `PASS: all checks passed.`

- [ ] **Step 4: Commit**

```bash
git add spec/verify.py
git commit -m "feat(transport): wire verify.py (proofs, bindings, challenge echo, error-code, exchanges)"
```

---

## Task 7: OpenAPI 3.1 contract

**Files:**
- Create: `spec/transport/openapi/avp-micro.openapi.yaml`
- Modify: `requirements.txt`

- [ ] **Step 1: Write the OpenAPI document**

Create `spec/transport/openapi/avp-micro.openapi.yaml` with exactly this content:

```yaml
openapi: 3.1.0
info:
  title: AVP-Micro HTTP Transport
  version: 0.1.0
  description: >
    Normative HTTP/REST binding for AVP-Micro: service discovery plus the
    HTTP 402 "Payment Required" challenge flow. Request/response bodies are
    the signed JSON-LD objects defined by the AVP-Micro bundles; this contract
    only $refs their JSON Schemas so the two are one source of truth.
servers:
  - url: https://api.example.com/avp
    description: Example payee deployment (placeholder).
tags:
  - name: discovery
  - name: payment
  - name: streaming
  - name: settlement
paths:
  /.well-known/avp-micro:
    get:
      tags: [discovery]
      operationId: getServiceDescription
      summary: Discovery document (payee-signed ServiceDescription).
      responses:
        "200":
          description: The signed service description.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../schemas/transport.schema.json#/$defs/ServiceDescription
  /resource/{path}:
    get:
      tags: [payment]
      operationId: getGatedResource
      summary: A gated resource. First call yields 402; retry with an Authorization submission.
      parameters:
        - { name: path, in: path, required: true, schema: { type: string } }
        - name: Authorization
          in: header
          required: false
          description: "AVP-Micro <AuthorizationSubmission id>; present on the retry."
          schema: { type: string }
        - name: Idempotency-Key
          in: header
          required: false
          schema: { type: string }
      responses:
        "200":
          description: Access granted; the receipt accompanies the resource.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentReceipt
        "402":
          description: Payment required. Body is the 402 challenge envelope.
          headers:
            WWW-Authenticate:
              schema: { type: string, example: AVP-Micro }
          content:
            application/avp-micro+json:
              schema:
                $ref: ../schemas/transport.schema.json#/$defs/Challenge402Body
            application/problem+json:
              schema:
                $ref: ../schemas/transport.schema.json#/$defs/ProblemDetails
  /quote:
    post:
      tags: [payment]
      operationId: createQuote
      summary: Request a PaymentQuote for a described request (carries requestHash).
      responses:
        "200":
          description: A payee-signed quote.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentQuote
  /authorize:
    post:
      tags: [payment]
      operationId: submitAuthorization
      summary: Submit an AuthorizationSubmission; returns an execution (or problem).
      parameters:
        - name: Idempotency-Key
          in: header
          required: true
          schema: { type: string }
      requestBody:
        required: true
        content:
          application/avp-micro+json:
            schema:
              $ref: ../schemas/transport.schema.json#/$defs/AuthorizationSubmission
      responses:
        "200":
          description: The wallet-signed execution.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentExecution
        "402":
          description: Policy/budget rejection.
          content:
            application/problem+json:
              schema:
                $ref: ../schemas/transport.schema.json#/$defs/ProblemDetails
        "409":
          description: Idempotency conflict or double-spend.
          content:
            application/problem+json:
              schema:
                $ref: ../schemas/transport.schema.json#/$defs/ProblemDetails
        "422":
          description: Quote/authorization binding failure.
          content:
            application/problem+json:
              schema:
                $ref: ../schemas/transport.schema.json#/$defs/ProblemDetails
  /execute:
    post:
      tags: [payment]
      operationId: execute
      summary: Execute a previously authorized payment.
      requestBody:
        required: true
        content:
          application/avp-micro+json:
            schema:
              $ref: ../schemas/transport.schema.json#/$defs/AuthorizationSubmission
      responses:
        "200":
          description: The execution.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentExecution
  /receipt/{id}:
    get:
      tags: [payment]
      operationId: getReceipt
      summary: Retrieve a PaymentReceipt by id.
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      responses:
        "200":
          description: The payee-signed receipt.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentReceipt
  /settlement/{id}:
    get:
      tags: [settlement]
      operationId: getSettlementStatus
      summary: Poll async settlement; returns the execution, then the proof as finality advances.
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      responses:
        "200":
          description: Execution (pending) or settlement proof (final).
          content:
            application/avp-micro+json:
              schema:
                oneOf:
                  - $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentExecution
                  - $ref: ../../settlement/schemas/settlement.schema.json#/$defs/SettlementProof
  /session:
    post:
      tags: [streaming]
      operationId: openSession
      summary: Open a streaming UsageSession.
      responses:
        "200":
          description: The usage session.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/UsageSession
  /session/{id}/budget:
    post:
      tags: [streaming]
      operationId: authorizeSessionBudget
      summary: Authorize (or re-authorize) the session budget.
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          application/avp-micro+json:
            schema:
              $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/SessionBudgetAuthorization
      responses:
        "200":
          description: Budget accepted.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/UsageSession
  /session/{id}/accruals:
    get:
      tags: [streaming]
      operationId: getAccruals
      summary: List usage accruals for a session.
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      responses:
        "200":
          description: An accrual.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/UsageAccrual
  /session/{id}/extend:
    post:
      tags: [streaming]
      operationId: extendSession
      summary: Extend a session's budget or expiry.
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          application/avp-micro+json:
            schema:
              $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/UsageSessionExtension
      responses:
        "200":
          description: Extension accepted.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/UsageSession
  /session/{id}/close:
    post:
      tags: [streaming]
      operationId: closeSession
      summary: Close a session; settle the metered total and issue a receipt.
      parameters:
        - { name: id, in: path, required: true, schema: { type: string } }
      responses:
        "200":
          description: The final execution + receipt.
          content:
            application/avp-micro+json:
              schema:
                $ref: ../../payments/schemas/avp-micro.schema.json#/$defs/PaymentReceipt
```

- [ ] **Step 2: Add PyYAML as a direct dependency**

In `requirements.txt`, find:

```
referencing>=0.31.0
```

Replace with:

```
referencing>=0.31.0
pyyaml>=6.0
```

- [ ] **Step 3: Run validate.py — the OpenAPI section must now pass**

Run:
```bash
./.venv/Scripts/python spec/validate.py | sed -n '/OpenAPI contract/,/===/p'
./.venv/Scripts/python spec/validate.py | tail -1
```
Expected: every `OpenAPI $ref resolves: ...` line is `[PASS]`, `OpenAPI version is 3.1.x` is `[PASS]`, and the final line is `PASS: all artifact checks passed.`

- [ ] **Step 4: Commit**

```bash
git add spec/transport/openapi/avp-micro.openapi.yaml requirements.txt
git commit -m "feat(transport): OpenAPI 3.1 contract + pyyaml dependency"
```

---

## Task 8: Documentation (ReSpec + READMEs + CLAUDE.md)

**Files:**
- Create: `spec/transport/index.html`
- Create: `spec/transport/README.md`
- Modify: `spec/README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Write the ReSpec spec**

Create `spec/transport/index.html` with exactly this content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AVP-Micro Transport &amp; Protocol Binding</title>
  <script src="https://www.w3.org/Tools/respec/respec-w3c" class="remove" defer></script>
  <script class="remove">
    var respecConfig = {
      specStatus: "unofficial",
      editors: [{ name: "AVP-Micro Working Group" }],
      github: "https://example.com/avp-micro",
      shortName: "avp-micro-transport",
      latestVersion: "https://w3id.org/avp-micro/transport/v1",
      edDraftURI: "https://w3id.org/avp-micro/transport/v1",
      group: "unofficial"
    };
  </script>
</head>
<body>
  <section id="abstract">
    <p>
      This specification defines the normative <strong>HTTP/REST binding</strong> for
      AVP-Micro: how an agent (payer) and a service (payee) discover each other and run
      the offer &rarr; quote &rarr; authorize &rarr; execute &rarr; settle &rarr; receipt
      flow over HTTP, using an <strong>HTTP 402 "Payment Required" challenge</strong>. It
      transports the existing AVP-Micro payment objects; it defines no new economic
      semantics. It is the prerequisite that lets two independent implementations
      interoperate.
    </p>
  </section>
  <section id="sotd"></section>

  <section>
    <h2>Overview</h2>
    <p>
      AVP-Micro specifies <em>messages</em> (DSA credentials, payments, disputes,
      settlement). This bundle is the <em>wire layer</em>. It adds four object types and
      an error-code vocabulary, all in the namespace
      <code>https://w3id.org/avp-micro/transport/v1#</code> (prefix <code>txp:</code>),
      and an OpenAPI 3.1 contract for the HTTP surface.
    </p>
    <table class="simple">
      <thead><tr><th>Object</th><th>Signer</th><th>Role</th></tr></thead>
      <tbody>
        <tr><td><code>ServiceDescription</code></td><td>payee</td><td>Discovery document at <code>/.well-known/avp-micro</code>.</td></tr>
        <tr><td><code>PaymentChallenge</code></td><td>payee</td><td>Body of an HTTP 402; wraps a quote + a server challenge nonce.</td></tr>
        <tr><td><code>AuthorizationSubmission</code></td><td>payer agent</td><td>The 402 retry payload; binds the authorization to the challenge.</td></tr>
        <tr><td><code>ProblemDetails</code></td><td>unsigned</td><td>RFC 9457 error body; <code>type</code> is a <code>txp:ErrorScheme</code> IRI.</td></tr>
      </tbody>
    </table>
  </section>

  <section>
    <h2>Discovery</h2>
    <p>
      <code>GET /.well-known/avp-micro</code> returns a payee-signed
      <code>ServiceDescription</code> advertising <code>endpoints</code>,
      <code>acceptedCredentialIssuers</code>, <code>acceptedSettlementRails</code>, and
      <code>supportedBundles</code>. Clients SHOULD fetch it before transacting.
    </p>
  </section>

  <section>
    <h2>The HTTP 402 challenge flow</h2>
    <ol>
      <li>Agent requests a gated resource.</li>
      <li>Payee replies <code>402 Payment Required</code> with
        <code>WWW-Authenticate: AVP-Micro</code> and a body
        <code>{ challenge: PaymentChallenge, quote: PaymentQuote }</code>. The
        <code>PaymentChallenge</code> carries <code>quoteDigest</code> (=
        <code>jcs_digest(quote)</code>), a server <code>challenge</code> nonce, and
        <code>expires</code>.</li>
      <li>Agent verifies the quote, builds a <code>PaymentAuthorization</code> (which
        embeds the SAC verifiable presentation), and wraps it in an
        <code>AuthorizationSubmission</code> that <strong>echoes the
        <code>challenge</code></strong>, references the authorization by IRI +
        <code>authorizationDigest</code>, and carries an <code>idempotencyKey</code>.</li>
      <li>Agent retries with <code>Authorization: AVP-Micro &lt;submission&gt;</code> and
        <code>Idempotency-Key</code>.</li>
      <li>Payee verifies the quote binding, SAC policy, <strong>challenge
        freshness</strong>, and idempotency, settles, and returns <code>200</code> with
        the resource and a <code>PaymentReceipt</code> &mdash; or a <code>4xx/402</code>
        with a <code>ProblemDetails</code>.</li>
    </ol>
    <p class="note">
      The echoed <code>challenge</code> binds the submission to the verifier and request
      that issued the 402. A captured authorization cannot be replayed to a different
      verifier &mdash; closing the presentation-replay gap identified in the security
      review.
    </p>
  </section>

  <section>
    <h2>Explicit-quote, streaming, and async settlement</h2>
    <p>
      Non-gated clients MAY use <code>POST /quote</code>, <code>POST /authorize</code>,
      <code>GET /receipt/{id}</code> directly. Streaming reuses the payments session
      objects via <code>POST /session</code>, <code>/session/{id}/budget</code>,
      <code>/session/{id}/accruals</code>, <code>/session/{id}/extend</code>,
      <code>/session/{id}/close</code>. When settlement is not instant,
      <code>execute</code> returns a pending <code>PaymentExecution</code> and a
      <code>Location: /settlement/{id}</code>; polling that endpoint returns the
      execution and then the <code>SettlementProof</code> as finality advances. A
      <code>callbackUrl</code> MAY be supplied for a webhook instead of polling.
    </p>
  </section>

  <section>
    <h2>Idempotency</h2>
    <p>
      <code>Idempotency-Key</code> (mirrored in
      <code>AuthorizationSubmission.idempotencyKey</code>) makes retries safe. The payee
      MUST return the same execution/receipt for a repeated key, and MUST return
      <code>409 idempotency-conflict</code> if the key is reused with a different body.
    </p>
  </section>

  <section>
    <h2>Error model</h2>
    <p>
      Every non-success response is a <code>ProblemDetails</code> whose <code>type</code>
      is an error-code IRI in <code>txp:ErrorScheme</code> (see <code>vocab/errors.ttl</code>).
    </p>
    <table class="simple">
      <thead><tr><th>HTTP</th><th>Example codes</th></tr></thead>
      <tbody>
        <tr><td>402</td><td>(challenge), <code>over-cap</code>, <code>daily-limit-exceeded</code>, <code>budget-exceeded</code></td></tr>
        <tr><td>400</td><td><code>malformed-request</code></td></tr>
        <tr><td>401 / 403</td><td><code>unauthorized</code>, <code>payee-not-allowed</code>, <code>category-not-allowed</code>, <code>missing-confirmation</code>, <code>credential-revoked</code></td></tr>
        <tr><td>409</td><td><code>idempotency-conflict</code>, <code>double-spend</code>, <code>nonce-reuse</code></td></tr>
        <tr><td>422</td><td><code>amount-mismatch</code>, <code>currency-mismatch</code>, <code>expired</code>, <code>challenge-expired</code>, <code>forged-confirmation</code></td></tr>
        <tr><td>5xx</td><td><code>settlement-pending</code> (also 200 + Location), <code>settlement-failed</code></td></tr>
      </tbody>
    </table>
  </section>

  <section class="informative">
    <h2>Security considerations</h2>
    <ul>
      <li><strong>Challenge freshness.</strong> The payee MUST reject a submission whose
        echoed <code>challenge</code> is unknown, expired, or already consumed. This binds
        the SAC presentation to a single verifier and request.</li>
      <li><strong>Quote binding.</strong> The payee MUST verify
        <code>quoteDigest == jcs_digest(quote)</code> and that the quote's
        <code>requestHash</code> matches the attempted request.</li>
      <li><strong>Transport security.</strong> All exchanges MUST use TLS; AVP-Micro
        proofs authenticate payloads but do not replace channel encryption.</li>
    </ul>
  </section>

  <section>
    <h2>Conformance &amp; artifacts</h2>
    <p>
      The JSON-LD context, RDFS/OWL vocabulary, SKOS error scheme, JSON Schema, SHACL
      shapes, OpenAPI contract, and signed test vectors are normative companions in this
      bundle directory. The shared harness (<code>spec/generate.py</code>,
      <code>verify.py</code>, <code>validate.py</code>) generates and validates them.
    </p>
  </section>
</body>
</html>
```

- [ ] **Step 2: Write the bundle README**

Create `spec/transport/README.md` with exactly this content:

```markdown
# AVP-Micro Transport & Protocol Binding

The normative **HTTP/REST wire binding** for AVP-Micro: service discovery plus the
HTTP **402 "Payment Required"** challenge flow. It transports the existing payment
objects; it defines no new economic semantics.

- **Namespace:** `https://w3id.org/avp-micro/transport/v1#` (prefix `txp:`)
- **Context (5-entry):** `[credentials/v2, data-integrity/v2, spending-authority/v1, avp-micro/v1, avp-micro/transport/v1]`
- **Depends on:** Payments (wraps quote/authorization/execution/receipt/session objects), DSA (identity + `ecdsa-jcs-2022`), Settlement (rail IRIs, async `SettlementProof`).

## Objects

| Object | `type` / id prefix | Signer | Role |
|---|---|---|---|
| `ServiceDescription` | `ServiceDescription` / `urn:avp:txp:service:` | payee | Discovery document at `/.well-known/avp-micro`. |
| `PaymentChallenge` | `PaymentChallenge` / `urn:avp:txp:challenge:` | payee | HTTP 402 body; wraps a quote + a server challenge nonce. |
| `AuthorizationSubmission` | `AuthorizationSubmission` / `urn:avp:txp:submission:` | payer agent | 402 retry payload; binds the authorization to the challenge. |
| `ProblemDetails` | (RFC 9457) | unsigned | Error body; `type` ∈ `txp:ErrorScheme`. |

## Artifacts

| File | Purpose |
|---|---|
| `context/v1.jsonld` | JSON-LD 1.1 `@protected` context (`txp:` terms; reuses payments/DSA terms). |
| `vocab/transport.ttl` | RDFS/OWL ontology: 4 classes + new properties. |
| `vocab/errors.ttl` | SKOS `txp:ErrorScheme` (19 error concepts). |
| `schemas/transport.schema.json` | JSON Schema `$defs` per object + envelope/exchange defs. |
| `shapes/transport-shapes.ttl` | SHACL NodeShapes for the signed objects. |
| `openapi/avp-micro.openapi.yaml` | OpenAPI 3.1 HTTP surface; bodies `$ref` the bundle schemas. |
| `index.html` | W3C ReSpec normative prose. |
| `test-vectors/` | Signed objects + example HTTP exchanges (generated). |

## Test vectors

| File | `$def` / kind |
|---|---|
| `00-service-description.json` | `ServiceDescription` (payee-signed) |
| `10-payment-challenge.json` | `PaymentChallenge` (payee-signed) |
| `11-challenge-402-body.json` | `Challenge402Body` (`{challenge, quote}`) |
| `20-authorization-submission.json` | `AuthorizationSubmission` (payer-signed) |
| `30-problem-details.json` | `ProblemDetails` (over-cap, unsigned) |
| `40-exchange-402-flow.json` | `HttpExchangeLog` (happy path: 402 → 200 + receipt) |
| `41-exchange-over-cap.json` | `HttpExchangeLog` (policy rejection: 402 + ProblemDetails) |

## Endpoints

`GET /.well-known/avp-micro` · `POST /quote` · `POST /authorize` · `POST /execute` ·
`GET /receipt/{id}` · `GET /settlement/{id}` · `POST /session` ·
`POST /session/{id}/budget` · `GET /session/{id}/accruals` ·
`POST /session/{id}/extend` · `POST /session/{id}/close` · plus the `402` challenge
documented as a response on any gated path. Media type: `application/avp-micro+json`
(errors: `application/problem+json`).

## Validate

```powershell
.venv\Scripts\python spec\generate.py   # regenerate vectors
.venv\Scripts\python spec\verify.py     # crypto + bindings + challenge echo + exchanges
.venv\Scripts\python spec\validate.py   # Turtle / JSON-LD / JSON Schema / SHACL / OpenAPI-ref
```
```

- [ ] **Step 3: Add the bundle to `spec/README.md`**

Open `spec/README.md`, locate the section that lists the existing bundles (authority, payments, interop, disputes, settlement). Add a transport entry in the same style/format used for the settlement bundle. Use this wording for the new entry (adapt the surrounding markup to match the file's existing list/table style):

```markdown
- **`transport/`** — Transport & Protocol binding: the normative HTTP/REST wire binding (service discovery + HTTP 402 challenge) that carries the AVP-Micro payment objects between agent and payee. OpenAPI 3.1 + signed objects + vectors. Namespace `https://w3id.org/avp-micro/transport/v1#`.
```

If `spec/README.md` has a "namespace / context URL" list, also add:

```markdown
- Transport context: `https://w3id.org/avp-micro/transport/v1` → `spec/transport/context/v1.jsonld`
```

- [ ] **Step 4: Update `CLAUDE.md` to a sixth bundle**

In `CLAUDE.md`, find the line introducing the bundles:

```markdown
Three peer bundles live under `spec/`:
```

Replace with:

```markdown
Six peer bundles live under `spec/`:
```

Then, find the `interop-sd-jwt-vc` bullet:

```markdown
- **`spec/interop-sd-jwt-vc/`** — Bridge/binding between AVP-Micro and SD-JWT-VC credentials (Mastercard/Google Verifiable Intent, Google AP2). Namespace `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`.
```

Replace with:

```markdown
- **`spec/interop-sd-jwt-vc/`** — Bridge/binding between AVP-Micro and SD-JWT-VC credentials (Mastercard/Google Verifiable Intent, Google AP2). Namespace `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`.
- **`spec/disputes/`** — Refunds, reversals, chargebacks, and dispute lifecycles. Namespace `https://w3id.org/avp-micro/disputes/v1#`.
- **`spec/settlement/`** — On-chain settlement binding (EVM stablecoin, x402, Lightning): rail-agnostic instruction + chain-native proof + escrow lifecycle. Namespace `https://w3id.org/avp-micro/settlement/v1#`.
- **`spec/transport/`** — Transport & Protocol binding: the normative HTTP/REST wire binding (discovery + HTTP 402 challenge) carrying the payment objects between agent and payee; OpenAPI 3.1 + signed objects. Namespace `https://w3id.org/avp-micro/transport/v1#`.
```

Then, in the "Namespace / context URLs" section at the bottom of `CLAUDE.md`, find:

```markdown
- Interop context: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1` → `spec/interop-sd-jwt-vc/context/v1.jsonld`
```

Replace with:

```markdown
- Interop context: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1` → `spec/interop-sd-jwt-vc/context/v1.jsonld`
- Disputes context: `https://w3id.org/avp-micro/disputes/v1` → `spec/disputes/context/v1.jsonld`
- Settlement context: `https://w3id.org/avp-micro/settlement/v1` → `spec/settlement/context/v1.jsonld`
- Transport context: `https://w3id.org/avp-micro/transport/v1` → `spec/transport/context/v1.jsonld`
```

> Note: if the disputes/settlement bullets or context URLs are already present in `CLAUDE.md` (added by earlier work), only add the **transport** entry and skip the duplicates. Read the file first and adapt.

- [ ] **Step 5: Verify the docs don't break the harness**

Run:
```bash
./.venv/Scripts/python spec/validate.py | tail -1 && ./.venv/Scripts/python spec/verify.py | tail -1
```
Expected: both print `PASS: ...` (docs are not parsed by the harness, but this confirms nothing regressed).

- [ ] **Step 6: Commit**

```bash
git add spec/transport/index.html spec/transport/README.md spec/README.md CLAUDE.md
git commit -m "docs(transport): ReSpec spec, bundle README, sixth-bundle updates"
```

---

## Task 9: Full-suite verification + finish

**Files:** none (verification + branch completion).

- [ ] **Step 1: Regenerate and confirm determinism**

Run:
```bash
./.venv/Scripts/python spec/generate.py >/dev/null
git status --porcelain
```
Expected: no modified (`M`) tracked vectors — only the new bundle files already committed. Running `generate.py` twice in a row leaves the tree clean.

- [ ] **Step 2: Run the full harness + pytest**

Run:
```bash
./.venv/Scripts/python spec/verify.py | tail -1
./.venv/Scripts/python spec/validate.py | tail -1
./.venv/Scripts/python -m pytest spec/ -q 2>&1 | tail -5
```
Expected: `verify.py` → `PASS: all checks passed.`; `validate.py` → `PASS: all artifact checks passed.`; pytest → all tests pass (or "no tests ran" if the repo has none — either is acceptable, no failures).

- [ ] **Step 3: Confirm the other five bundles are unchanged**

Run:
```bash
git diff --stat master -- spec/authority spec/payments spec/interop-sd-jwt-vc spec/disputes spec/settlement
```
Expected: **empty** output — this bundle modifies no other bundle's artifacts (only `generate.py`/`verify.py`/`validate.py`/`requirements.txt` at the harness root changed).

- [ ] **Step 4: Finish the branch**

Use the **superpowers:finishing-a-development-branch** skill: verify tests pass (Step 2 above), then present the merge/PR options to the user and execute their choice (the user's standing preference in this repo has been to merge to `master` and push).

---

## Self-Review (completed during planning)

**Spec coverage** — every design section maps to a task:
- §2 bundle layout/namespace/deps → Task 1 (context/vocab), Task 2 (schema), Task 3 (shapes).
- §3.1–3.5 the four objects + error scheme → Task 1 (errors.ttl, context), Task 2 (`$defs`), Task 4 (vectors).
- §4 protocol flows (discovery, 402, explicit-quote, streaming, async, idempotency, errors) → Task 7 (OpenAPI paths), Task 8 (index.html prose).
- §5 OpenAPI surface → Task 7.
- §6.1 generate.py → Task 4. §6.2 validate.py (context reg, vectors, turtle, expand, schema, SHACL, drift, negatives, OpenAPI-ref) → Task 5 + 7. §6.3 verify.py (payee-signed, quoteDigest binding, submission echo, error-code resolves, exchange byte-identity) → Task 6. §6.4 docs → Task 8.
- §7 acceptance criteria → Task 9.

**Placeholder scan** — no TBD/TODO; every code/artifact step contains full content; harness edits are exact find/replace anchors.

**Type consistency** — `$def` names (`ServiceDescription`, `PaymentChallenge`, `AuthorizationSubmission`, `ProblemDetails`, `Challenge402Body`, `HttpExchangeLog`) are identical across the schema (Task 2), validate maps (Task 5), OpenAPI `$ref`s (Task 7), and vectors (Task 4). Vector filenames (`00/10/11/20/30/40/41`) match across generate (Task 4), validate maps (Task 5), and verify loads (Task 6). Property names (`challenge`, `quoteDigest`, `authorizationDigest`, `idempotencyKey`, `acceptedSettlementRails`, `endpoints`, `supportedBundles`) are consistent across context (Task 1), schema (Task 2), shapes (Task 3), generator (Task 4), and checks (Task 6). Reused terms are deliberately not redefined.

**Known sequencing note** — validate.py (Task 5) references the OpenAPI file created in Task 7, so the OpenAPI section of validate.py fails between Task 5 and Task 7. This is called out in Task 5 Step 12 with a scoped check that excludes OpenAPI. If executing strictly task-by-task with a hard "validate.py must be fully green" gate, run Task 7 immediately after Task 5 (Task 6 is independent and can follow).
```
