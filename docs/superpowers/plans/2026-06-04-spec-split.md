# AVP-Micro Spec Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the single `spec/index.html` (+ artifacts) into two peer W3C specifications — **Delegated Spending Authority (DSA)** and **AVP-Micro Payments** (which depends on DSA) — preserving every normative requirement and the green-bar test harness.

**Architecture:** Two self-contained spec bundles under `spec/authority/` and `spec/payments/`, each with its own ReSpec document, JSON-LD context, JSON Schema, SHACL shapes, and RDFS/OWL ontology. A shared harness at `spec/` root (`avp_crypto.py`, `generate.py`, `verify.py`, `validate.py`) generates the cryptographically-linked test vectors into both bundles and validates both. DSA owns the `https://w3id.org/spending-authority/v1#` namespace and all standing/identity/trust/credential terms plus shared primitives (`currency`, content-digest form, decimal-amount format); Payments keeps `https://w3id.org/avp-micro/v1#` and uses a 4-entry `@context` so the shared terms and embedded DSA credential resolve.

**Tech stack:** W3C ReSpec (HTML), JSON-LD 1.1, JSON Schema draft 2020-12, SHACL (Turtle), RDFS/OWL, Python 3.11 (`cryptography`, `rdflib`, `pyld`, `jsonschema`, `pyshacl`) in the existing `.venv`.

**Source of truth for relocated content:** The design doc `docs/superpowers/specs/2026-06-04-spec-split-design.md` §3.1 holds the authoritative section→spec mapping. Prose is relocated **verbatim** unless a step says otherwise; the only text changes are namespace/`@context` statements and cross-references, which are given in full below.

**Ground rule:** No normative requirement changes. After the harness tasks, `python spec/verify.py` and `python spec/validate.py` MUST both end with `PASS`. That green bar is the regression test for this entire plan.

---

## Reference: current → new file moves

| Current | New |
|---------|-----|
| `spec/test-vectors/avp_crypto.py` | `spec/avp_crypto.py` |
| `spec/test-vectors/generate.py` | `spec/generate.py` (rewritten) |
| `spec/test-vectors/verify.py` | `spec/verify.py` (rewritten) |
| `spec/validate.py` | `spec/validate.py` (rewritten in place) |
| `spec/context/v1.jsonld` | split → `spec/authority/context/v1.jsonld` + `spec/payments/context/v1.jsonld` |
| `spec/schemas/avp-micro.schema.json` | split → `spec/authority/schemas/dsa.schema.json` + `spec/payments/schemas/avp-micro.schema.json` |
| `spec/shapes/avp-shapes.ttl` | split → `spec/authority/shapes/dsa-shapes.ttl` + `spec/payments/shapes/avp-shapes.ttl` |
| `spec/vocab/avp.ttl` | split → `spec/authority/vocab/dsa.ttl` + `spec/payments/vocab/avp.ttl` |
| `spec/vocab/agent-service-categories.ttl` (+ `generate_agent_service_skos.py`) | `spec/authority/vocab/` |
| `spec/index.html` | split → `spec/authority/index.html` + `spec/payments/index.html` |
| `spec/test-vectors/*.json` | split → `spec/authority/test-vectors/` + `spec/payments/test-vectors/` |
| `spec/README.md` | rewritten (top-level) + new `spec/authority/README.md` + `spec/payments/README.md` |

**Namespaces:**
- DSA: `https://w3id.org/spending-authority/v1#` (prefix `dsa:`), context served at `https://w3id.org/spending-authority/v1`.
- Payments: `https://w3id.org/avp-micro/v1#` (prefix `avp:`), context served at `https://w3id.org/avp-micro/v1`.

**`@context` arrays (verbatim):**
- DSA objects: `["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/data-integrity/v2","https://w3id.org/spending-authority/v1"]`
- Payments objects: `["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/data-integrity/v2","https://w3id.org/spending-authority/v1","https://w3id.org/avp-micro/v1"]`

---

## Task 1: Scaffold directories

**Files:**
- Create dirs: `spec/authority/{context,schemas,shapes,vocab,test-vectors}`, `spec/payments/{context,schemas,shapes,vocab,test-vectors}`

- [ ] **Step 1: Create the directory tree**

```bash
cd /c/Users/steph/work/avp-micro
mkdir -p spec/authority/context spec/authority/schemas spec/authority/shapes spec/authority/vocab spec/authority/test-vectors
mkdir -p spec/payments/context spec/payments/schemas spec/payments/shapes spec/payments/vocab spec/payments/test-vectors
```

- [ ] **Step 2: Verify**

Run: `ls -d spec/authority/* spec/payments/*`
Expected: 10 directories listed, no errors.

- [ ] **Step 3: Commit** (directories are empty; commit happens with Task 2's first file — skip standalone commit).

---

## Task 2: Authority JSON-LD context

**Files:**
- Create: `spec/authority/context/v1.jsonld`

DSA owns the standing-credential, trust, identity, and **shared-primitive** terms (`currency`, monetary fields, `asset`/`assetScale`, `account`, categories, trust terms). It does **not** define payment-message terms.

- [ ] **Step 1: Write the DSA context**

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "dsa": "https://w3id.org/spending-authority/v1#",
    "cat": "https://w3id.org/avp-micro/cat#",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "SpendingAuthorizationCredential": "dsa:SpendingAuthorizationCredential",
    "PaymentCapabilityCredential": "dsa:PaymentCapabilityCredential",
    "MerchantCredential": "dsa:MerchantCredential",
    "TrustedIssuer": "dsa:TrustedIssuer",
    "IssuerScope": "dsa:IssuerScope",

    "currency": { "@id": "dsa:currency" },
    "asset": { "@id": "dsa:asset" },
    "assetScale": { "@id": "dsa:assetScale", "@type": "xsd:integer" },
    "expires": { "@id": "sec:expiration", "@type": "xsd:dateTime" },
    "nonce": "sec:nonce",

    "maxPerTransaction": { "@id": "dsa:maxPerTransaction" },
    "maxDailyTotal": { "@id": "dsa:maxDailyTotal" },
    "dailyLimit": { "@id": "dsa:dailyLimit" },
    "limitTimezone": { "@id": "dsa:limitTimezone" },
    "allowedPayees": { "@id": "dsa:allowedPayees", "@container": "@set", "@type": "@id" },
    "allowedServiceTypes": { "@id": "dsa:allowedServiceTypes", "@container": "@set", "@type": "@id" },
    "allowedMerchantCategories": { "@id": "dsa:allowedServiceTypes", "@container": "@set", "@type": "@id" },
    "requiresApprovalAbove": { "@id": "dsa:requiresApprovalAbove" },

    "trustedIssuers": { "@id": "dsa:trustedIssuers", "@container": "@set" },
    "issuerScope": { "@id": "dsa:issuerScope" },

    "account": { "@id": "dsa:account" },
    "merchantName": { "@id": "dsa:merchantName" },
    "companyName": { "@id": "dsa:companyName" },
    "categories": { "@id": "dsa:categories", "@container": "@set", "@type": "@id" }
  }
}
```

- [ ] **Step 2: Validate JSON**

Run: `.venv/Scripts/python.exe -c "import json; json.load(open('spec/authority/context/v1.jsonld')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add spec/authority/context/v1.jsonld
git commit -m "feat(spec): add Delegated Spending Authority JSON-LD context"
```

---

## Task 3: Payments JSON-LD context

**Files:**
- Create: `spec/payments/context/v1.jsonld`

Payments defines **only** payment-message terms. It MUST NOT redefine any term in the DSA context (`currency`, `nonce`, `expires`, category terms, etc.); payment objects include the DSA context via the 4-entry array so those resolve.

- [ ] **Step 1: Write the payments context**

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "avp": "https://w3id.org/avp-micro/v1#",
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "PaymentOffer": "avp:PaymentOffer",
    "PaymentQuote": "avp:PaymentQuote",
    "PaymentAuthorization": "avp:PaymentAuthorization",
    "PaymentExecution": "avp:PaymentExecution",
    "PaymentReceipt": "avp:PaymentReceipt",
    "UsageSession": "avp:UsageSession",
    "UsageAccrual": "avp:UsageAccrual",
    "SessionBudgetAuthorization": "avp:SessionBudgetAuthorization",
    "UsageSessionExtension": "avp:UsageSessionExtension",

    "payee": { "@id": "avp:payee", "@type": "@id" },
    "payer": { "@id": "avp:payer", "@type": "@id" },
    "wallet": { "@id": "avp:wallet", "@type": "@id" },
    "pricingModel": { "@id": "avp:pricingModel" },
    "unit": { "@id": "avp:unit" },
    "acceptedSettlementMethods": { "@id": "avp:acceptedSettlementMethods", "@container": "@set" },
    "acceptedCredentialIssuers": { "@id": "avp:acceptedCredentialIssuers", "@container": "@set", "@type": "@id" },
    "quoteEndpoint": { "@id": "avp:quoteEndpoint", "@type": "xsd:anyURI" },
    "offerValidity": { "@id": "avp:offerValidity", "@type": "xsd:dateTime" },

    "serviceRequestHash": { "@id": "avp:serviceRequestHash" },
    "quoteDigest": { "@id": "avp:quoteDigest" },
    "sessionDigest": { "@id": "avp:sessionDigest" },
    "amount": { "@id": "avp:amount" },
    "settlementMethod": { "@id": "avp:settlementMethod" },
    "settlementTarget": { "@id": "avp:settlementTarget" },

    "quote": { "@id": "avp:quote", "@type": "@id" },
    "timestamp": { "@id": "avp:timestamp", "@type": "xsd:dateTime" },
    "vp": { "@id": "avp:vp" },

    "authorization": { "@id": "avp:authorization", "@type": "@id" },
    "sessionBudgetAuthorization": { "@id": "avp:sessionBudgetAuthorization", "@type": "@id" },
    "status": { "@id": "avp:status" },
    "settlementRef": { "@id": "avp:settlementRef" },

    "execution": { "@id": "avp:execution", "@type": "@id" },
    "serviceOutputHash": { "@id": "avp:serviceOutputHash" },
    "fulfilledAt": { "@id": "avp:fulfilledAt", "@type": "xsd:dateTime" },

    "maxAmount": { "@id": "avp:maxAmount" },
    "newMaxAmount": { "@id": "avp:newMaxAmount" },
    "newExpires": { "@id": "avp:newExpires", "@type": "xsd:dateTime" },
    "startingBalance": { "@id": "avp:startingBalance" },
    "session": { "@id": "avp:session", "@type": "@id" },
    "meterReading": { "@id": "avp:meterReading" },
    "meterType": { "@id": "avp:meterType" },
    "meterUnit": { "@id": "avp:meterUnit" },
    "amountAccrued": { "@id": "avp:amountAccrued" },
    "accrualKind": { "@id": "avp:accrualKind" },
    "sequence": { "@id": "avp:sequence", "@type": "xsd:integer" },
    "settlementMode": { "@id": "avp:settlementMode" },

    "usageSession": { "@id": "avp:usageSession", "@type": "@id" },
    "committedAmount": { "@id": "avp:committedAmount" },
    "totalMeterReading": { "@id": "avp:totalMeterReading" }
  }
}
```

- [ ] **Step 2: Validate JSON**

Run: `.venv/Scripts/python.exe -c "import json; json.load(open('spec/payments/context/v1.jsonld')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add spec/payments/context/v1.jsonld
git commit -m "feat(spec): add AVP-Micro Payments JSON-LD context (payment terms only)"
```

---

## Task 4: Authority JSON Schema

**Files:**
- Create: `spec/authority/schemas/dsa.schema.json`

Self-contained: includes shared low-level `$defs` plus the credential and trust object defs. `signedContext` is the **3-entry** DSA array.

- [ ] **Step 1: Write the schema**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://w3id.org/spending-authority/schemas/dsa.schema.json",
  "title": "Delegated Spending Authority data objects",
  "description": "JSON Schema for the SpendingAuthorizationCredential, PaymentCapabilityCredential, MerchantCredential, and trust-configuration structures. Validate an instance against the relevant $def, e.g. #/$defs/SpendingAuthorizationCredential.",
  "$defs": {
    "did": { "type": "string", "pattern": "^did:[a-z0-9]+:.+" },
    "iri": { "type": "string", "minLength": 1, "format": "uri" },
    "idValue": { "type": "string", "minLength": 1 },
    "decimal": {
      "type": "string",
      "description": "Non-negative decimal amount as a string.",
      "pattern": "^(0|[1-9][0-9]*)(\\.[0-9]+)?$"
    },
    "dateTime": { "type": "string", "format": "date-time" },
    "contentDigest": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" },
    "categoryList": { "type": "array", "items": { "$ref": "#/$defs/iri" } },
    "didList": { "type": "array", "items": { "$ref": "#/$defs/did" } },
    "proof": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "type": { "type": "string" },
        "cryptosuite": { "type": "string" },
        "created": { "$ref": "#/$defs/dateTime" },
        "verificationMethod": { "type": "string" },
        "proofPurpose": { "type": "string" },
        "proofValue": { "type": "string" }
      }
    },
    "signedContext": {
      "type": "array",
      "allOf": [
        { "contains": { "const": "https://www.w3.org/ns/credentials/v2" } },
        { "contains": { "const": "https://w3id.org/security/data-integrity/v2" } },
        { "contains": { "const": "https://w3id.org/spending-authority/v1" } }
      ]
    },

    "IssuerScope": {
      "type": "object",
      "description": "Bounds on what a trusted issuer may authorize. All members optional; the more restrictive of scope and credential applies.",
      "properties": {
        "currency": { "type": "string" },
        "maxPerTransaction": { "$ref": "#/$defs/decimal" },
        "maxDailyTotal": { "$ref": "#/$defs/decimal" },
        "allowedServiceTypes": { "$ref": "#/$defs/categoryList" }
      }
    },
    "TrustedIssuer": {
      "type": "object",
      "description": "A trust-configuration entry. Not a signed wire message; part of a wallet's local trust policy.",
      "required": ["issuer"],
      "properties": {
        "issuer": { "$ref": "#/$defs/did" },
        "issuerScope": { "$ref": "#/$defs/IssuerScope" },
        "validFrom": { "$ref": "#/$defs/dateTime" },
        "validUntil": { "$ref": "#/$defs/dateTime" }
      }
    },

    "SpendingAuthorizationCredential": {
      "type": "object",
      "required": ["@context", "type", "issuer", "credentialSubject", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "type": "array", "allOf": [ { "contains": { "const": "VerifiableCredential" } }, { "contains": { "const": "SpendingAuthorizationCredential" } } ] },
        "issuer": { "oneOf": [ { "$ref": "#/$defs/did" }, { "type": "object", "required": ["id"], "properties": { "id": { "$ref": "#/$defs/did" } } } ] },
        "validFrom": { "$ref": "#/$defs/dateTime" },
        "validUntil": { "$ref": "#/$defs/dateTime" },
        "credentialStatus": { "type": ["object", "array"] },
        "credentialSubject": {
          "type": "object",
          "required": ["id"],
          "properties": {
            "id": { "$ref": "#/$defs/did" },
            "currency": { "type": "string" },
            "maxPerTransaction": { "$ref": "#/$defs/decimal" },
            "dailyLimit": { "$ref": "#/$defs/decimal" },
            "limitTimezone": { "type": "string" },
            "requiresApprovalAbove": { "$ref": "#/$defs/decimal" },
            "allowedPayees": { "$ref": "#/$defs/didList" },
            "allowedServiceTypes": { "$ref": "#/$defs/categoryList" }
          }
        },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },
    "PaymentCapabilityCredential": {
      "type": "object",
      "required": ["@context", "type", "issuer", "credentialSubject", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "type": "array", "allOf": [ { "contains": { "const": "VerifiableCredential" } }, { "contains": { "const": "PaymentCapabilityCredential" } } ] },
        "issuer": { "oneOf": [ { "$ref": "#/$defs/did" }, { "type": "object", "required": ["id"], "properties": { "id": { "$ref": "#/$defs/did" } } } ] },
        "credentialSubject": {
          "type": "object",
          "required": ["id"],
          "properties": {
            "id": { "$ref": "#/$defs/did" },
            "account": { "type": "string" },
            "currency": { "type": "string" },
            "asset": { "type": "string" },
            "assetScale": { "type": "integer", "minimum": 0 },
            "expires": { "$ref": "#/$defs/dateTime" }
          }
        },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },
    "MerchantCredential": {
      "type": "object",
      "required": ["@context", "type", "issuer", "credentialSubject", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "type": "array", "allOf": [ { "contains": { "const": "VerifiableCredential" } }, { "contains": { "const": "MerchantCredential" } } ] },
        "issuer": { "oneOf": [ { "$ref": "#/$defs/did" }, { "type": "object", "required": ["id"], "properties": { "id": { "$ref": "#/$defs/did" } } } ] },
        "credentialSubject": {
          "type": "object",
          "required": ["id"],
          "properties": {
            "id": { "$ref": "#/$defs/did" },
            "merchantName": { "type": "string" },
            "companyName": { "type": "string" },
            "categories": { "$ref": "#/$defs/categoryList" }
          }
        },
        "proof": { "$ref": "#/$defs/proof" }
      }
    }
  }
}
```

- [ ] **Step 2: Validate JSON**

Run: `.venv/Scripts/python.exe -c "import json; json.load(open('spec/authority/schemas/dsa.schema.json')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add spec/authority/schemas/dsa.schema.json
git commit -m "feat(spec): add DSA JSON Schema (credentials + trust config)"
```

---

## Task 5: Payments JSON Schema

**Files:**
- Create: `spec/payments/schemas/avp-micro.schema.json`

Take the **current** `spec/schemas/avp-micro.schema.json` and remove the credential and trust defs that moved to DSA (`SpendingAuthorizationCredential`, `PaymentCapabilityCredential`, `MerchantCredential`, `TrustedIssuer`, `IssuerScope`). Keep all payment message defs and the shared low-level `$defs`. Change `signedContext` to the **4-entry** array.

- [ ] **Step 1: Create the file** by copying the current schema, then applying the two edits below.

```bash
cp spec/schemas/avp-micro.schema.json spec/payments/schemas/avp-micro.schema.json
```

- [ ] **Step 2: Update `$id` and `signedContext`** in `spec/payments/schemas/avp-micro.schema.json`

Set `$id` to `"https://w3id.org/avp-micro/schemas/avp-micro.schema.json"` (unchanged if already so) and replace the `signedContext` def with the 4-entry form:

```json
    "signedContext": {
      "type": "array",
      "allOf": [
        { "contains": { "const": "https://www.w3.org/ns/credentials/v2" } },
        { "contains": { "const": "https://w3id.org/security/data-integrity/v2" } },
        { "contains": { "const": "https://w3id.org/spending-authority/v1" } },
        { "contains": { "const": "https://w3id.org/avp-micro/v1" } }
      ]
    },
```

- [ ] **Step 3: Delete the moved defs.** Remove the `$defs` blocks `SpendingAuthorizationCredential`, `PaymentCapabilityCredential`, `MerchantCredential`, `IssuerScope`, and `TrustedIssuer` from the payments schema (they now live only in `dsa.schema.json`). Keep `PaymentOffer`, `PaymentQuote`, `PaymentAuthorization`, `PaymentExecution`, `PaymentReceipt`, `UsageSession`, `UsageAccrual`, `SessionBudgetAuthorization`, `UsageSessionExtension`, and all shared low-level defs (`did`, `iri`, `idValue`, `decimal`, `dateTime`, `contentDigest`, `categoryList`, `didList`, `proof`, `signedContext`, `verifiablePresentation`).

- [ ] **Step 4: Validate JSON + confirm defs removed**

Run:
```bash
.venv/Scripts/python.exe -c "import json; d=json.load(open('spec/payments/schemas/avp-micro.schema.json')); defs=d['\$defs']; assert 'SpendingAuthorizationCredential' not in defs and 'TrustedIssuer' not in defs and 'IssuerScope' not in defs; assert 'PaymentAuthorization' in defs and 'UsageSessionExtension' in defs; assert d['\$defs']['signedContext']['allOf'][2]['contains']['const']=='https://w3id.org/spending-authority/v1'; print('ok')"
```
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add spec/payments/schemas/avp-micro.schema.json
git commit -m "feat(spec): add Payments JSON Schema (4-entry context, credential defs moved to DSA)"
```

---

## Task 6: Authority SHACL shapes

**Files:**
- Create: `spec/authority/shapes/dsa-shapes.ttl`

DSA owns the shared primitive node shapes (`DecimalAmount`, `ContentDigest`) and the credential shape.

- [ ] **Step 1: Write the shapes** (prefix `dsa:`)

```turtle
# Delegated Spending Authority SHACL shapes.
@prefix sh:   <http://www.w3.org/ns/shacl#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix sec:  <https://w3id.org/security#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

dsa:DecimalAmount
  a sh:NodeShape ;
  sh:nodeKind sh:Literal ;
  sh:pattern "^(0|[1-9][0-9]*)([.][0-9]+)?$" .

dsa:ContentDigest
  a sh:NodeShape ;
  sh:nodeKind sh:Literal ;
  sh:pattern "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" .

dsa:SpendingAuthorizationCredentialShape
  a sh:NodeShape ;
  sh:targetClass dsa:SpendingAuthorizationCredential ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .
```

- [ ] **Step 2: Validate Turtle parses**

Run: `.venv/Scripts/python.exe -c "import rdflib; print(len(rdflib.Graph().parse('spec/authority/shapes/dsa-shapes.ttl', format='turtle')), 'triples')"`
Expected: a triple count, no exception.

- [ ] **Step 3: Commit**

```bash
git add spec/authority/shapes/dsa-shapes.ttl
git commit -m "feat(spec): add DSA SHACL shapes"
```

---

## Task 7: Payments SHACL shapes

**Files:**
- Create: `spec/payments/shapes/avp-shapes.ttl`

Take the **current** `spec/shapes/avp-shapes.ttl` verbatim and remove only the `avp:SpendingAuthorizationCredentialShape` block (moved to DSA as `dsa:SpendingAuthorizationCredentialShape`). Keep `DecimalAmount` and `ContentDigest` (payment objects need them) and all payment shapes including `UsageSessionExtensionShape`.

- [ ] **Step 1: Copy then edit**

```bash
cp spec/shapes/avp-shapes.ttl spec/payments/shapes/avp-shapes.ttl
```

- [ ] **Step 2: Remove the SAC shape block** from `spec/payments/shapes/avp-shapes.ttl`:

```turtle
avp:SpendingAuthorizationCredentialShape
  a sh:NodeShape ;
  sh:targetClass avp:SpendingAuthorizationCredential ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .
```

- [ ] **Step 3: Validate Turtle parses + SAC shape gone**

Run:
```bash
.venv/Scripts/python.exe -c "import rdflib; g=rdflib.Graph().parse('spec/payments/shapes/avp-shapes.ttl', format='turtle'); s=g.serialize(format='turtle'); assert 'SpendingAuthorizationCredentialShape' not in s; assert 'UsageSessionExtensionShape' in s; print(len(g), 'triples, SAC shape removed')"
```
Expected: triple count + confirmation.

- [ ] **Step 4: Commit**

```bash
git add spec/payments/shapes/avp-shapes.ttl
git commit -m "feat(spec): add Payments SHACL shapes (SAC shape moved to DSA)"
```

---

## Task 8: Authority ontology + SKOS vocabulary

**Files:**
- Create: `spec/authority/vocab/dsa.ttl`
- Move: `spec/vocab/agent-service-categories.ttl` → `spec/authority/vocab/agent-service-categories.ttl`
- Move: `spec/vocab/generate_agent_service_skos.py` → `spec/authority/vocab/generate_agent_service_skos.py`

- [ ] **Step 1: Move the SKOS vocabulary and its generator**

```bash
git mv spec/vocab/agent-service-categories.ttl spec/authority/vocab/agent-service-categories.ttl
git mv spec/vocab/generate_agent_service_skos.py spec/authority/vocab/generate_agent_service_skos.py
```

- [ ] **Step 2: Write `spec/authority/vocab/dsa.ttl`** declaring the authority classes/properties. Use the current `spec/vocab/avp.ttl` as the template; keep only the authority classes (`SpendingAuthorizationCredential`, `PaymentCapabilityCredential`, `MerchantCredential`, `TrustedIssuer`, `IssuerScope`) and the properties they own (`currency`, `maxPerTransaction`, `dailyLimit`, `maxDailyTotal`, `limitTimezone`, `allowedPayees`, `allowedServiceTypes`, `requiresApprovalAbove`, `account`, `asset`, `assetScale`, `merchantName`, `companyName`, `categories`, `trustedIssuers`, `issuerScope`). Change the namespace prefix to `dsa:` / `https://w3id.org/spending-authority/v1#` and the `owl:Ontology` IRI to `https://w3id.org/spending-authority/v1`. Ontology header:

```turtle
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
@prefix dct:  <http://purl.org/dc/terms/> .

<https://w3id.org/spending-authority/v1> a owl:Ontology ;
  dct:title "Delegated Spending Authority core vocabulary"@en ;
  dct:description "Classes and properties for delegated spending authority: credentials, trust configuration, and identity."@en ;
  owl:versionInfo "0.1.0" .
```

Then the class/property declarations (copy the matching entries from current `spec/vocab/avp.ttl`, switching the `avp:` prefix to `dsa:`). Example for the SAC class and a property:

```turtle
dsa:SpendingAuthorizationCredential a owl:Class ;
  rdfs:label "Spending authorization credential"@en ;
  rdfs:comment "A verifiable credential issued by a principal that constrains how a payer agent may spend."@en .

dsa:currency a owl:DatatypeProperty ; rdfs:label "currency"@en ; rdfs:range xsd:string .
dsa:maxPerTransaction a owl:DatatypeProperty ; rdfs:label "max per transaction"@en ; rdfs:range xsd:string .
dsa:issuerScope a owl:ObjectProperty ; rdfs:label "issuer scope"@en ;
  rdfs:domain dsa:TrustedIssuer ; rdfs:range dsa:IssuerScope .
```

(Include every authority class/property listed above with label/comment and ranges as in the current `avp.ttl`.)

- [ ] **Step 3: Validate both Turtle files parse**

Run:
```bash
.venv/Scripts/python.exe -c "import rdflib; [rdflib.Graph().parse(f, format='turtle') for f in ['spec/authority/vocab/dsa.ttl','spec/authority/vocab/agent-service-categories.ttl']]; print('ok')"
```
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add -A spec/authority/vocab/ spec/vocab/
git commit -m "feat(spec): add DSA ontology; move SKOS service categories to authority/"
```

---

## Task 9: Payments ontology

**Files:**
- Create: `spec/payments/vocab/avp.ttl`

Take the **current** `spec/vocab/avp.ttl` and remove the authority classes/properties moved to DSA (those listed in Task 8 Step 2). Keep payment classes (`PaymentOffer`, `PaymentQuote`, `PaymentAuthorization`, `PaymentExecution`, `PaymentReceipt`, `UsageSession`, `UsageAccrual`, `SessionBudgetAuthorization`, `UsageSessionExtension`) and payment properties (`payer`, `payee`, `wallet`, `amount`, `settlementMethod`, `settlementTarget`, `settlementMode`, `settlementRef`, `status`, `serviceRequestHash`, `serviceOutputHash`, `quote`, `quoteDigest`, `sessionDigest`, `timestamp`, `fulfilledAt`, `offerValidity`, `maxAmount`, `newMaxAmount`, `newExpires`, `startingBalance`, `committedAmount`, `amountAccrued`, `accrualKind`, `sequence`, `meterReading`, `meterType`, `meterUnit`, `totalMeterReading`, `unit`, `quoteEndpoint`, `acceptedSettlementMethods`, `acceptedCredentialIssuers`, `authorization`, `sessionBudgetAuthorization`, `execution`, `session`, `usageSession`, `pricingModel`, `vp`).

- [ ] **Step 1: Copy then prune**

```bash
cp spec/vocab/avp.ttl spec/payments/vocab/avp.ttl
```
Edit `spec/payments/vocab/avp.ttl`: keep the `avp:` namespace; remove the authority classes/properties (Task 8 Step 2 list) and update the ontology title to "AVP-Micro Payments core vocabulary". Add `rdfs:seeAlso <https://w3id.org/spending-authority/v1> .` to the `owl:Ontology` node.

- [ ] **Step 2: Validate parses + authority terms gone**

Run:
```bash
.venv/Scripts/python.exe -c "import rdflib; g=rdflib.Graph().parse('spec/payments/vocab/avp.ttl', format='turtle'); s=g.serialize(); assert 'SpendingAuthorizationCredential' not in s and 'TrustedIssuer' not in s; assert 'PaymentAuthorization' in s and 'UsageSessionExtension' in s; print('ok')"
```
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add spec/payments/vocab/avp.ttl
git commit -m "feat(spec): add Payments ontology (authority classes moved to DSA)"
```

---

## Task 10: Move the shared crypto module

**Files:**
- Move: `spec/test-vectors/avp_crypto.py` → `spec/avp_crypto.py`

The crypto primitives are unchanged.

- [ ] **Step 1: Move**

```bash
git mv spec/test-vectors/avp_crypto.py spec/avp_crypto.py
rm -rf spec/test-vectors/__pycache__
```

- [ ] **Step 2: Import smoke test**

Run: `cd spec && ../.venv/Scripts/python.exe -c "import avp_crypto; print('import ok')"; cd ..`
Expected: `import ok`

- [ ] **Step 3: Commit**

```bash
git add -A spec/avp_crypto.py spec/test-vectors/
git commit -m "refactor(spec): move shared crypto module to spec/ root"
```

---

## Task 11: Rewrite the shared generator

**Files:**
- Create: `spec/generate.py` (replaces `spec/test-vectors/generate.py`)

Writes DSA objects (3-entry context) into `authority/test-vectors/` and payment objects (4-entry context) into `payments/test-vectors/`. The payment authorization embeds the DSA SAC.

- [ ] **Step 1: Write `spec/generate.py`**

```python
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

SPEC = Path(__file__).parent
AUTH = SPEC / "authority" / "test-vectors"
PAY = SPEC / "payments" / "test-vectors"

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
        "credentialSubject": {
            "id": DID_AGENT,
            "currency": "USD",
            "maxPerTransaction": "0.05",
            "dailyLimit": "5.00",
            "allowedPayees": [DID_PAYEE],
        },
    }
    spendauth = ac.sign_eddsa_jcs_2022(spendauth, issuer, "2026-03-25T20:00:01Z")
    write(AUTH, "spending-authorization-credential.json", spendauth)

    merchant = {
        "@context": DSA_CTX,
        "id": "urn:dsa:vc:merchant:001",
        "type": ["VerifiableCredential", "MerchantCredential"],
        "issuer": DID_ISSUER,
        "credentialSubject": {"id": DID_PAYEE, "merchantName": "Tool API Inc.",
                               "categories": ["cat:ChatCompletionApi"]},
    }
    merchant = ac.sign_eddsa_jcs_2022(merchant, issuer, "2026-03-25T20:00:02Z")
    write(AUTH, "merchant-credential.json", merchant)

    capability = {
        "@context": DSA_CTX,
        "id": "urn:dsa:vc:capability:001",
        "type": ["VerifiableCredential", "PaymentCapabilityCredential"],
        "issuer": DID_WALLET,
        "credentialSubject": {"id": DID_AGENT, "account": "https://wallet.example.com/alice",
                               "currency": "USD"},
    }
    capability = ac.sign_eddsa_jcs_2022(capability, wallet, "2026-03-25T20:00:03Z")
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

    quote = {
        "@context": PAY_CTX, "id": "urn:avp:quote:789", "type": "PaymentQuote",
        "payer": DID_AGENT, "payee": DID_PAYEE, "serviceRequestHash": srh,
        "amount": amount, "currency": currency, "settlementMethod": settlement_method,
        "settlementTarget": settlement_target, "expires": "2026-03-25T21:35:00Z",
    }
    quote = ac.sign_eddsa_jcs_2022(quote, payee, "2026-03-25T21:30:00Z")
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
    authz = ac.sign_eddsa_jcs_2022(authz, agent, "2026-03-25T21:30:02Z")
    write(PAY, "02-payment-authorization.json", authz)

    execution = {
        "@context": PAY_CTX, "id": "urn:avp:exec:555", "type": "PaymentExecution",
        "authorization": "urn:avp:authz:999", "amount": amount, "currency": currency,
        "status": "completed", "settlementRef": "internal-ledger://txn/abc123",
        "timestamp": "2026-03-25T21:30:03Z",
    }
    execution = ac.sign_eddsa_jcs_2022(execution, wallet, "2026-03-25T21:30:03Z")
    write(PAY, "03-payment-execution.json", execution)

    service_output = {"summary": "...", "tokens": 211}
    receipt = {
        "@context": PAY_CTX, "id": "urn:avp:receipt:222", "type": "PaymentReceipt",
        "quote": "urn:avp:quote:789", "execution": "urn:avp:exec:555",
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": amount, "currency": currency,
        "serviceOutputHash": ac.content_digest(ac.jcs(service_output)),
        "fulfilledAt": "2026-03-25T21:30:05Z",
    }
    receipt = ac.sign_eddsa_jcs_2022(receipt, payee, "2026-03-25T21:30:05Z")
    write(PAY, "04-payment-receipt.json", receipt)

    # Streaming chain
    session = {
        "@context": PAY_CTX, "id": "urn:avp:session:001", "type": "UsageSession",
        "payer": DID_AGENT, "payee": DID_PAYEE, "currency": currency,
        "pricingModel": {"type": "PerUnit", "amount": "0.001", "unit": "datapoint"},
        "maxAmount": "0.50", "meterType": "sensorSamples", "meterUnit": "datapoint",
        "settlementMethod": settlement_method, "settlementTarget": settlement_target,
        "settlementMode": "deferred", "timestamp": "2026-03-25T21:40:00Z",
        "expires": "2026-03-25T22:00:00Z",
    }
    session = ac.sign_eddsa_jcs_2022(session, payee, "2026-03-25T21:40:00Z")
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
    session_budget = ac.sign_eddsa_jcs_2022(session_budget, agent, "2026-03-25T21:40:05Z")
    write(PAY, "06-session-budget-authorization.json", session_budget)

    accrual = {
        "@context": PAY_CTX, "id": "urn:avp:usage:123", "type": "UsageAccrual",
        "session": "urn:avp:session:001", "accrualKind": "cumulative",
        "meterReading": "48", "amountAccrued": "0.048", "currency": currency,
        "sequence": 3, "timestamp": "2026-03-25T21:45:00Z",
    }
    accrual = ac.sign_eddsa_jcs_2022(accrual, payee, "2026-03-25T21:45:00Z")
    write(PAY, "07-usage-accrual.json", accrual)

    session_exec = {
        "@context": PAY_CTX, "id": "urn:avp:exec:sess-1", "type": "PaymentExecution",
        "sessionBudgetAuthorization": "urn:avp:session-auth:aa", "amount": "0.048",
        "currency": currency, "status": "completed",
        "settlementRef": "internal-ledger://txn/sess-001", "timestamp": "2026-03-25T21:58:30Z",
    }
    session_exec = ac.sign_eddsa_jcs_2022(session_exec, wallet, "2026-03-25T21:58:30Z")
    write(PAY, "08-payment-execution-session.json", session_exec)

    session_receipt = {
        "@context": PAY_CTX, "id": "urn:avp:receipt:sess-final", "type": "PaymentReceipt",
        "usageSession": "urn:avp:session:001", "execution": "urn:avp:exec:sess-1",
        "payer": DID_AGENT, "payee": DID_PAYEE, "amount": "0.048", "currency": currency,
        "totalMeterReading": "48", "fulfilledAt": "2026-03-25T21:58:00Z",
    }
    session_receipt = ac.sign_eddsa_jcs_2022(session_receipt, payee, "2026-03-25T21:58:00Z")
    write(PAY, "09-payment-receipt-session.json", session_receipt)

    extension = {
        "@context": PAY_CTX, "id": "urn:avp:session-ext:e1", "type": "UsageSessionExtension",
        "usageSession": "urn:avp:session:001", "sessionDigest": ac.jcs_digest(session),
        "newMaxAmount": "1.00", "newExpires": "2026-03-25T22:30:00Z",
        "timestamp": "2026-03-25T21:59:00Z",
    }
    extension = ac.sign_eddsa_jcs_2022(extension, payee, "2026-03-25T21:59:00Z")
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
    session_budget2 = ac.sign_eddsa_jcs_2022(session_budget2, agent, "2026-03-25T21:59:05Z")
    write(PAY, "11-session-budget-authorization-2.json", session_budget2)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Remove the old generator**

```bash
git rm spec/test-vectors/generate.py
```

- [ ] **Step 3: Run the generator**

Run: `cd spec && ../.venv/Scripts/python.exe generate.py; cd ..`
Expected: 17 `wrote ...` lines (6 authority files incl. dids/trusted-issuers, 11 payment files), no errors.

- [ ] **Step 4: Commit**

```bash
git add -A spec/generate.py spec/test-vectors/ spec/authority/test-vectors/ spec/payments/test-vectors/
git commit -m "feat(spec): shared generator emits both DSA and Payments vectors"
```

---

## Task 12: Rewrite the shared verifier

**Files:**
- Create: `spec/verify.py` (replaces `spec/test-vectors/verify.py`)

Loads the SAC from `authority/test-vectors/` and the payment chain from `payments/test-vectors/`. Logic is the current `verify.py` with updated paths and filenames (one-off vectors renumbered `01`–`04`, streaming `05`–`11`).

- [ ] **Step 1: Write `spec/verify.py`**

```python
"""Reference verifier for the AVP-Micro split test vectors (both bundles)."""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path
import json

import avp_crypto as ac

SPEC = Path(__file__).parent
AUTH = SPEC / "authority" / "test-vectors"
PAY = SPEC / "payments" / "test-vectors"
_failed = []


def load(base: Path, name: str) -> dict:
    return json.loads((base / name).read_text(encoding="utf-8"))


def check(label: str, ok: bool) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        _failed.append(label)


def controller(obj):
    return obj["proof"]["verificationMethod"].split("#", 1)[0]


def main() -> int:
    dids = load(AUTH, "dids.json")
    agent, payee = dids["payerAgent"], dids["payeeService"]
    issuer, wallet = dids["principalIssuer"], dids["walletService"]

    spendauth = load(AUTH, "spending-authorization-credential.json")
    quote = load(PAY, "01-payment-quote.json")
    authz = load(PAY, "02-payment-authorization.json")
    execution = load(PAY, "03-payment-execution.json")
    receipt = load(PAY, "04-payment-receipt.json")

    print("Proof verification (eddsa-jcs-2022):")
    for label, obj in [("credential", spendauth), ("quote", quote), ("authorization", authz),
                       ("execution", execution), ("receipt", receipt)]:
        check(f"{label} proof", ac.verify_eddsa_jcs_2022(obj))

    print("Verification-method binding:")
    check("credential signed by issuer", controller(spendauth) == issuer)
    check("quote signed by payee", controller(quote) == payee)
    check("authorization signed by payer", controller(authz) == agent)
    check("execution signed by wallet", controller(execution) == wallet)
    check("receipt signed by payee", controller(receipt) == payee)

    print("Quote binding & economic-term equality:")
    check("authz.payer == quote.payer", authz["payer"] == quote["payer"])
    check("authz.payee == quote.payee", authz["payee"] == quote["payee"])
    check("quoteDigest matches resolved quote", authz["quoteDigest"] == ac.jcs_digest(quote))
    for term in ("amount", "currency", "settlementMethod", "settlementTarget"):
        check(f"authz.{term} == quote.{term}", authz[term] == quote[term])
    check("serviceRequestHash byte-equal", authz["serviceRequestHash"] == quote["serviceRequestHash"])

    print("Credential / policy:")
    subj = spendauth["credentialSubject"]
    check("credentialSubject.id == payer", subj["id"] == authz["payer"])
    check("authz.payer controls the auth proof", controller(authz) == subj["id"])
    check("amount <= maxPerTransaction", Decimal(authz["amount"]) <= Decimal(subj["maxPerTransaction"]))
    check("payee in allowedPayees", authz["payee"] in subj.get("allowedPayees", []))
    check("currency matches credential", authz["currency"] == subj.get("currency"))

    print("Execution & receipt linkage:")
    check("execution.authorization == authz.id", execution.get("authorization") == authz["id"])
    check("execution.amount == authz.amount", execution["amount"] == authz["amount"])
    check("execution.status completed", execution["status"] == "completed")
    check("execution signer == authz.wallet (execution binding)", controller(execution) == authz.get("wallet"))
    check("receipt.quote == quote.id", receipt.get("quote") == quote["id"])
    check("receipt.execution == execution.id", receipt.get("execution") == execution["id"])
    check("receipt.amount == authz.amount", receipt["amount"] == authz["amount"])

    print("Streaming / session metering:")
    session = load(PAY, "05-usage-session.json")
    session_budget = load(PAY, "06-session-budget-authorization.json")
    accrual = load(PAY, "07-usage-accrual.json")
    session_exec = load(PAY, "08-payment-execution-session.json")
    session_receipt = load(PAY, "09-payment-receipt-session.json")
    for label, obj in [("session", session), ("session-budget", session_budget),
                       ("accrual", accrual), ("session execution", session_exec),
                       ("session receipt", session_receipt)]:
        check(f"{label} proof", ac.verify_eddsa_jcs_2022(obj))
    check("session signed by payee", controller(session) == payee)
    check("session-budget signed by payer", controller(session_budget) == agent)
    check("accrual signed by payee", controller(accrual) == payee)
    check("session execution signed by wallet", controller(session_exec) == wallet)
    check("session receipt signed by payee", controller(session_receipt) == payee)
    check("sessionDigest matches resolved session", session_budget["sessionDigest"] == ac.jcs_digest(session))
    check("budget.usageSession == session.id", session_budget["usageSession"] == session["id"])
    check("budget payer/payee match session",
          session_budget["payer"] == session["payer"] and session_budget["payee"] == session["payee"])
    check("committedAmount <= session.maxAmount",
          Decimal(session_budget["committedAmount"]) <= Decimal(session["maxAmount"]))
    check("accrual.session == session.id", accrual["session"] == session["id"])
    check("accrual currency matches session", accrual["currency"] == session["currency"])
    check("accrual <= maxAmount", Decimal(accrual["amountAccrued"]) <= Decimal(session["maxAmount"]))
    pm = session["pricingModel"]
    if pm.get("type") == "PerUnit" and "meterReading" in accrual:
        check("accrual consistent with PerUnit pricing",
              Decimal(accrual["amountAccrued"]) == Decimal(pm["amount"]) * Decimal(accrual["meterReading"]))
    check("session exec references budget auth",
          session_exec.get("sessionBudgetAuthorization") == session_budget["id"])
    check("session exec signer == budget.wallet (execution binding)",
          controller(session_exec) == session_budget.get("wallet"))
    check("session exec amount <= committedAmount",
          Decimal(session_exec["amount"]) <= Decimal(session_budget["committedAmount"]))
    check("session receipt references session", session_receipt.get("usageSession") == session["id"])
    check("session receipt amount == execution amount", session_receipt["amount"] == session_exec["amount"])

    print("Session extension & re-authorization:")
    extension = load(PAY, "10-usage-session-extension.json")
    session_budget2 = load(PAY, "11-session-budget-authorization-2.json")
    check("extension proof", ac.verify_eddsa_jcs_2022(extension))
    check("re-auth budget proof", ac.verify_eddsa_jcs_2022(session_budget2))
    check("extension signed by payee", controller(extension) == payee)
    check("re-auth budget signed by payer", controller(session_budget2) == agent)
    check("extension references session", extension["usageSession"] == session["id"])
    check("extension sessionDigest matches session", extension["sessionDigest"] == ac.jcs_digest(session))
    check("newMaxAmount > original maxAmount", Decimal(extension["newMaxAmount"]) > Decimal(session["maxAmount"]))
    check("newExpires later than original expires", extension["newExpires"] > session["expires"])
    check("re-auth committedAmount <= newMaxAmount",
          Decimal(session_budget2["committedAmount"]) <= Decimal(extension["newMaxAmount"]))
    check("re-auth references same session", session_budget2["usageSession"] == session["id"])

    print("Negative control (tamper detection):")
    tampered = json.loads(json.dumps(authz))
    tampered["amount"] = "0.05"
    check("tampered amount breaks the payer signature", not ac.verify_eddsa_jcs_2022(tampered))

    print()
    if _failed:
        print(f"FAIL: {len(_failed)} check(s) failed: {_failed}")
        return 1
    print("PASS: all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Remove old verifier; run new one**

```bash
git rm spec/test-vectors/verify.py
cd spec && ../.venv/Scripts/python.exe verify.py | tail -3; cd ..
```
Expected: ends with `PASS: all checks passed.`

- [ ] **Step 3: Commit**

```bash
git add -A spec/verify.py spec/test-vectors/
git commit -m "feat(spec): shared reference verifier over both bundles"
```

---

## Task 13: Rewrite the shared validator

**Files:**
- Modify: `spec/validate.py`

Serve **two** local contexts; validate both ontologies + SKOS + both SHACL files; run JSON-LD/Schema/SHACL across both vector dirs.

- [ ] **Step 1: Replace `spec/validate.py`**

```python
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
SEC_PROOF = "https://w3id.org/security#proof"
DSA_NS = "https://w3id.org/spending-authority/v1#"
AVP_NS = "https://w3id.org/avp-micro/v1#"

# vector file -> ($def name, schema bundle path, shapes path, namespace, dir)
AUTH_VECTORS = {
    "spending-authorization-credential.json": "SpendingAuthorizationCredential",
    "merchant-credential.json": "MerchantCredential",
    "payment-capability-credential.json": "PaymentCapabilityCredential",
}
PAY_VECTORS = {
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

failures = []


def ok(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(label)


# document loader: both AVP contexts local, everything else via network
_dsa_ctx = json.loads((AUTH / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_avp_ctx = json.loads((PAY / "context" / "v1.jsonld").read_text(encoding="utf-8"))
_net = pyld_requests.requests_document_loader()


def loader(url, options=None):
    u = url.rstrip("/")
    if u == "https://w3id.org/spending-authority/v1":
        return {"contextUrl": None, "documentUrl": url, "document": _dsa_ctx}
    if u == "https://w3id.org/avp-micro/v1":
        return {"contextUrl": None, "documentUrl": url, "document": _avp_ctx}
    return _net(url, options or {})


jsonld.set_document_loader(loader)


def section(title):
    print(f"\n=== {title} ===")


def expand_check(base, vectors, must_survive):
    for name in vectors:
        inst = json.loads((base / "test-vectors" / name).read_text(encoding="utf-8"))
        try:
            expanded = jsonld.expand(inst)
            node = expanded[0]
            ok(f"{name} expands", bool(expanded))
            ok(f"{name} carries {SEC_PROOF}", SEC_PROOF in json.dumps(expanded))
            for iri, term in must_survive.get(name, []):
                ok(f"{name} keeps {term}", iri in node)
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


def shacl_check(base, vectors, shapes_file):
    shapes_graph = rdflib.Graph().parse((base / "shapes" / shapes_file).as_posix(), format="turtle")
    for name in vectors:
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
                PAY / "shapes" / "avp-shapes.ttl"]:
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
    })

    section("JSON Schema validation")
    schema_check(AUTH, AUTH_VECTORS, "dsa.schema.json")
    schema_check(PAY, PAY_VECTORS, "avp-micro.schema.json")

    section("SHACL validation")
    shacl_check(AUTH, AUTH_VECTORS, "dsa-shapes.ttl")
    shacl_check(PAY, PAY_VECTORS, "avp-shapes.ttl")

    print()
    if failures:
        print(f"FAIL: {len(failures)} check(s) failed: {failures}")
        return 1
    print("PASS: all artifact checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Commit**

```bash
git add spec/validate.py
git commit -m "feat(spec): shared validator covers both DSA and Payments bundles"
```

---

## Task 14: Green-bar gate (regression test for the whole split)

**Files:** none (verification only)

- [ ] **Step 1: Regenerate, verify, validate**

Run:
```bash
cd spec && ../.venv/Scripts/python.exe generate.py >/dev/null && ../.venv/Scripts/python.exe verify.py | tail -1; cd ..
.venv/Scripts/python.exe spec/validate.py | tail -1
```
Expected:
```
PASS: all checks passed.
PASS: all artifact checks passed.
```

- [ ] **Step 2: If any check FAILs**, read the failing label, fix the corresponding artifact (context term, schema def, or shape), and re-run. Do not proceed until both report PASS.

- [ ] **Step 3: Commit regenerated vectors**

```bash
git add spec/authority/test-vectors/ spec/payments/test-vectors/
git commit -m "test(spec): regenerate vectors; both harnesses green after split"
```

---

## Task 15: Delegated Spending Authority document

**Files:**
- Create: `spec/authority/index.html`

Build the DSA ReSpec document from the authority sections of the current `spec/index.html` (design doc §3.1 list).

- [ ] **Step 1: Write the ReSpec config head.** Create `spec/authority/index.html` with this `<head>` config (adapt `localBiblio` from current spec; keep VC/DI/DID-KEY/SKOS/RFC entries used by authority sections):

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Delegated Spending Authority</title>
  <script src="https://www.w3.org/Tools/respec/respec-w3c" class="remove" defer></script>
  <script class="remove">
    const respecConfig = {
      specStatus: "unofficial",
      shortName: "spending-authority",
      subtitle: "Delegated, verifiable spending authority for autonomous agents using DIDs and Verifiable Credentials",
      editors: [{ name: "Stephane Fellah", company: "Geoknoesis LLC", companyURL: "https://geoknoesis.com" }],
      github: { repoURL: "https://github.com/geoknoesis/avp-micro", branch: "main" },
      license: "cc-by",
      lint: { "no-unused-dfns": false },
      xref: ["vc-data-model-2.0", "did-core", "INFRA"],
      localBiblio: { /* copy VC-DATA-INTEGRITY, VC-DI-EDDSA, BITSTRING-STATUS-LIST,
        DID-KEY, SKOS, RFC8785, RFC7515, JSON-LD11, SECURITY-PRIVACY-QUESTIONNAIRE
        entries verbatim from the current spec/index.html */ }
    };
  </script>
</head>
<body>
```

- [ ] **Step 2: Add DSA front matter** — abstract, SOTD, introduction written for the authority layer. Abstract (new text):

```html
  <section id="abstract">
    <p>
      <dfn>Delegated Spending Authority</dfn> (DSA) defines how a
      <a>principal</a> delegates bounded spending authority to an autonomous
      <a>payer agent</a> using <a data-cite="did-core#dfn-decentralized-identifiers">decentralized identifiers</a>
      and <a data-cite="vc-data-model-2.0#dfn-verifiable-credentials">verifiable credentials</a>,
      and how a relying party establishes trust in the issuers of those
      credentials. It defines the identity, securing, credential, and trust
      vocabulary that the [[AVP-MICRO]] payments layer (and other delegated-spend
      systems) build upon. Settlement and payment-message flow are out of scope.
    </p>
  </section>
```

Copy the SOTD and introduction from the current spec, trimming payment-specific sentences (keep the CG/CCG host, IPR/CLA, dependency-maturity paragraphs).

- [ ] **Step 3: Relocate the authority sections verbatim** from current `spec/index.html` into the DSA body, in this order: Conformance; Terminology (Principal, payer agent, Securing mechanism, content digest, monetary amount format, currency); Namespace & JSON-LD context (rewrite to reference `spec/authority/context/v1.jsonld` and the `dsa:`/`spending-authority` namespace, and the `vocab/dsa.ttl` ontology + `vocab/agent-service-categories.ttl` SKOS); DID requirements; Securing mechanisms (+ key-binding, did-state-binding); content-digest form definition; Credential types (SpendingAuthorizationCredential, PaymentCapabilityCredential, MerchantCredential, Category matching); `dailyLimit` claim + day-boundary definition; Trust establishment (+ trust-vocabulary); Security/Privacy/i18n/Accessibility (authority subset); Examples (SAC + MerchantCredential fragments); Conformance classes (issuer/principal, credential verifier, trust evaluator); Security & Privacy self-review (authority subset); Acknowledgements.

In the relocated Namespace section, set the `@context` array statement to the **3-entry** DSA array and keep the `@protected`/no-`@vocab` security note.

- [ ] **Step 4: Structural check**

Run:
```bash
echo "section:" $(grep -o '<section' spec/authority/index.html | wc -l)/$(grep -o '</section>' spec/authority/index.html | wc -l) "| pre:" $(grep -o '<pre' spec/authority/index.html | wc -l)/$(grep -o '</pre>' spec/authority/index.html | wc -l)
```
Expected: open/close counts equal.

- [ ] **Step 5: Commit**

```bash
git add spec/authority/index.html
git commit -m "feat(spec): add Delegated Spending Authority ReSpec document"
```

---

## Task 16: AVP-Micro Payments document

**Files:**
- Create: `spec/payments/index.html`

- [ ] **Step 1: ReSpec config head** with a `[[DSA]]` bibliography entry pointing to the DSA document:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AVP-Micro Payments</title>
  <script src="https://www.w3.org/Tools/respec/respec-w3c" class="remove" defer></script>
  <script class="remove">
    const respecConfig = {
      specStatus: "unofficial",
      shortName: "avp-micro",
      subtitle: "A transport-agnostic micropayment layer for autonomous agents, built on Delegated Spending Authority",
      editors: [{ name: "Stephane Fellah", company: "Geoknoesis LLC", companyURL: "https://geoknoesis.com" }],
      github: { repoURL: "https://github.com/geoknoesis/avp-micro", branch: "main" },
      license: "cc-by",
      lint: { "no-unused-dfns": false },
      xref: ["vc-data-model-2.0", "did-core", "INFRA"],
      localBiblio: {
        "DSA": {
          title: "Delegated Spending Authority",
          href: "https://w3id.org/spending-authority/",
          publisher: "Geoknoesis LLC (editor's draft)"
        }
        /* plus OPEN-PAYMENTS, RFC9421, RFC9449, RFC8785, RFC7515, GNAP, SD-JWT-VC,
           VC-DATA-INTEGRITY, VC-DI-EDDSA, BITSTRING-STATUS-LIST, JSON-LD11,
           SECURITY-PRIVACY-QUESTIONNAIRE — copy verbatim from current spec */
      }
    };
  </script>
</head>
<body>
```

- [ ] **Step 2: Payments front matter** — abstract/SOTD/introduction stating the DSA dependency. Abstract (new text):

```html
  <section id="abstract">
    <p>
      <dfn>AVP-Micro Payments</dfn> defines a transport-agnostic layer for
      programmatic micropayments by autonomous agents: signed quotes,
      authorizations, executions, and receipts, plus a streaming/session-metering
      mode. Payer identity, the spending-authority credential, securing
      mechanisms, and issuer trust are defined by [[DSA]]; this specification
      composes them with per-transaction economic terms. Value transfer
      (settlement) is intentionally out of scope as a normative rail.
    </p>
  </section>
```

- [ ] **Step 3: Relocate the payment sections verbatim** in order: Conformance; Terminology (payee service, wallet service, settlement rail, payment quote, economic terms — with Securing mechanism / content digest / amount format **cited from [[DSA]]**); Namespace & JSON-LD context (rewrite for the `avp:` context and the **4-entry** `@context` array, noting the included DSA context); Request binding (serviceRequestHash, quoteDigest, default canonicalization); Securing (short section referencing [[DSA]] §securing; defines execution-binding); Messages (PaymentOffer, PaymentQuote, PaymentAuthorization, PaymentExecution, PaymentReceipt); Streaming (UsageSession, UsageAccrual, SessionBudgetAuthorization, UsageSessionExtension, amount-format reference, lifecycle/settlement/integrity); Workflows; Wallet verification (one-off, session-budget, streaming accrual, daily-limit aggregation enforcement — referencing [[DSA]] for the SAC claim semantics); Integrity/replay; Error model; Disputes; Extensions; Audit; Security/Privacy (payments subset); Examples; Conformance classes (payer agent, wallet, payee, verifier); Security & Privacy self-review (payments subset); Acknowledgements.

Anywhere the relocated text references a DSA concept (SpendingAuthorizationCredential, securing mechanisms, key-binding, did-state-binding, trust, content-digest form, MerchantCredential, category-matching), replace the in-document `<a href="#...">` with a `[[DSA]]`-qualified cross-reference (e.g., "see [[DSA]] Securing mechanisms").

- [ ] **Step 4: Structural check**

Run:
```bash
echo "section:" $(grep -o '<section' spec/payments/index.html | wc -l)/$(grep -o '</section>' spec/payments/index.html | wc -l) "| pre:" $(grep -o '<pre' spec/payments/index.html | wc -l)/$(grep -o '</pre>' spec/payments/index.html | wc -l)
echo "4-entry context present:" $(grep -c 'spending-authority/v1' spec/payments/index.html)
```
Expected: balanced tags; `spending-authority/v1` appears (in the context arrays and examples).

- [ ] **Step 5: Commit**

```bash
git add spec/payments/index.html
git commit -m "feat(spec): add AVP-Micro Payments ReSpec document (depends on DSA)"
```

---

## Task 17: READMEs

**Files:**
- Modify: `spec/README.md` (top-level)
- Create: `spec/authority/README.md`, `spec/payments/README.md`

- [ ] **Step 1: Rewrite `spec/README.md`** to describe the two peer specs, their relationship, the shared harness, and the validate/generate/verify commands. Include this artifact map:

```markdown
# AVP-Micro specifications

Two peer specifications:

- **[Delegated Spending Authority](authority/)** (`authority/`) — identity, the
  SpendingAuthorizationCredential, securing mechanisms, and the trust framework.
  Namespace `https://w3id.org/spending-authority/v1#`.
- **[AVP-Micro Payments](payments/)** (`payments/`) — quotes, authorizations,
  executions, receipts, and streaming, built on Delegated Spending Authority.
  Namespace `https://w3id.org/avp-micro/v1#`.

## Validate everything

```bash
pip install cryptography rdflib pyld jsonschema pyshacl requests referencing
python spec/generate.py    # (re)build the signed vectors for both bundles
python spec/verify.py      # verify proofs + bindings + policy across the chain
python spec/validate.py    # Turtle / JSON-LD / JSON Schema / SHACL for both bundles
```

All checks must report `PASS`.
```

- [ ] **Step 2: Write `spec/authority/README.md`** and `spec/payments/README.md` — each lists that bundle's artifacts (index.html, context/v1.jsonld, schema, shapes, ontology, test-vectors) and its canonical namespace URL, mirroring the relevant rows from the current `spec/README.md`. The authority README notes its test-vectors are consumed (embedded) by the payments chain.

- [ ] **Step 3: Commit**

```bash
git add spec/README.md spec/authority/README.md spec/payments/README.md
git commit -m "docs(spec): top-level + per-spec READMEs for the split"
```

---

## Task 18: Remove superseded files and final verification

**Files:**
- Delete: `spec/index.html`, `spec/context/`, `spec/schemas/`, `spec/shapes/`, `spec/vocab/avp.ttl`, `spec/test-vectors/` (now empty of scripts), `spec/validate.py` is kept (rewritten in place).

- [ ] **Step 1: Remove superseded originals**

```bash
git rm spec/index.html
git rm -r spec/context spec/schemas spec/shapes
git rm spec/vocab/avp.ttl
git rm -r spec/test-vectors
rmdir spec/vocab 2>/dev/null || true
```

- [ ] **Step 2: Confirm no references to removed paths remain in harness**

Run:
```bash
grep -rnE "test-vectors/(avp_crypto|generate|verify)|schemas/avp-micro\.schema|shapes/avp-shapes|context/v1\.jsonld" spec/*.py
```
Expected: no matches (all harness paths now point into `authority/` and `payments/`).

- [ ] **Step 3: Full green-bar re-run**

Run:
```bash
cd spec && ../.venv/Scripts/python.exe generate.py >/dev/null && ../.venv/Scripts/python.exe verify.py | tail -1; cd ..
.venv/Scripts/python.exe spec/validate.py | tail -1
```
Expected:
```
PASS: all checks passed.
PASS: all artifact checks passed.
```

- [ ] **Step 4: Confirm tree**

Run: `ls spec/ spec/authority/ spec/payments/`
Expected: `spec/` has `authority/ payments/ avp_crypto.py generate.py verify.py validate.py README.md`; each spec dir has `index.html context/ schemas/ shapes/ vocab/ test-vectors/ README.md`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(spec): remove superseded single-spec files; split complete"
```

---

## Self-review notes (completed by plan author)

- **Spec coverage:** Every design-doc §3.1 authority section maps to Task 15; every payment section to Task 16; context split → Tasks 2–3; schema → 4–5; SHACL → 6–7; ontology+SKOS → 8–9; harness → 10–13; vectors/green-bar → 11, 14, 18; READMEs → 17. The `currency`-in-DSA decision is realized in Task 2; the 4-entry payments `@context` in Tasks 3, 5, 11, 16.
- **Type/name consistency:** Vector filenames are consistent between `generate.py` (Task 11), `verify.py` (Task 12), and `validate.py` (Task 13): authority uses named files; payments uses `01`–`11`. Namespace strings (`https://w3id.org/spending-authority/v1`, `https://w3id.org/avp-micro/v1`) are identical across context, schema `signedContext`, generator `@context`, and validator loader.
- **No placeholders:** Harness code, contexts, and schemas are complete. Prose-relocation tasks (8/9 ontology pruning, 15/16 document bodies) reference the current files as the verbatim source per the design doc — these are moves, not new content, so the existing text is the literal input; the *changed* text (abstracts, `@context` arrays, cross-references) is given in full.
- **Verification:** The green-bar gate (Task 14, re-run in Task 18) is the regression test proving no normative/behavioral change.
