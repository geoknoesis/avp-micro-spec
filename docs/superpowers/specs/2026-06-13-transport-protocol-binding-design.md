# Design: AVP-Micro Transport & Protocol Binding

**Date:** 2026-06-13
**Status:** Approved design — ready for implementation planning
**Bundle:** `spec/transport/` (new peer bundle)
**Namespace:** `https://w3id.org/avp-micro/transport/v1#` (prefix `txp:`)

## 1. Summary

AVP-Micro today specifies *messages* (DSA credentials, payments, disputes, settlement)
and calls itself "transport-agnostic," but defines no normative way for two parties to
exchange those messages over a network. This bundle is the **wire/protocol layer**: it
pins how an agent and a payee actually discover each other and run the
offer→quote→authorize→execute→settle→receipt flow over **HTTP**, using an **HTTP 402
"Payment Required" challenge**. It is the prerequisite that lets two independent
implementations interoperate.

This is the first of several "operational" bundles (the others — wallet conformance,
operational revocation, key rotation, trust registry — are deferred to their own
design→plan→build cycles). It was selected first because it is the load-bearing
prerequisite and because discovery, the error model, and protocol-level idempotency
naturally live in it.

### Scope decisions (settled during brainstorming)

1. **First operational spec:** Transport & Protocol binding.
2. **Substrate:** one normative **HTTP/REST binding** built around an **HTTP 402
   challenge**, web-native and aligned with the existing `x402` settlement rail; the
   flow is described abstractly enough to map onto other substrates (MCP/A2A) later.
3. **Deliverable shape:** new transport objects defined as **signed/structured JSON-LD**
   (context/vocab/schema/shapes + signed test vectors, wired into the existing
   generate/verify/validate harness) **plus** an **OpenAPI 3.1** document for the HTTP
   surface, **plus** ReSpec prose for the flow state machine and error registry.

### Non-goals

- No new economic semantics. This bundle only transports the *existing* payment objects;
  it does not redefine quotes/authorizations/executions/receipts/sessions.
- No modification to the payments, disputes, settlement, or authority bundles. The
  challenge-freshness binding is added here (in `AuthorizationSubmission`), not by adding
  a field to the payments `PaymentAuthorization`.
- Not a second substrate. Only the HTTP binding is normative in v1; MCP/A2A bindings are
  future work.
- No new settlement-status object — async settlement polling reuses the existing
  `PaymentExecution` / `SettlementProof` (a `GET` returns them as finality advances).

## 2. Bundle layout, namespace & dependencies

```
spec/transport/
  context/v1.jsonld              # JSON-LD 1.1, @protected; txp: terms + reuse
  vocab/transport.ttl            # RDFS/OWL ontology: classes + properties
  vocab/errors.ttl               # SKOS error-code scheme (txp:ErrorScheme)
  schemas/transport.schema.json  # JSON Schema $defs per object type
  shapes/transport-shapes.ttl    # SHACL NodeShapes
  openapi/avp-micro.openapi.yaml # OpenAPI 3.1 HTTP surface
  test-vectors/*.json            # signed objects + example HTTP exchanges
  README.md
  index.html                     # W3C ReSpec normative prose
```

- **Namespace:** `https://w3id.org/avp-micro/transport/v1#` (prefix `txp:`), a sub-path
  of `avp-micro`, mirroring how the other extension bundles nest.
- **Context (5-entry):** `[VC2, data-integrity/v2, spending-authority/v1, avp-micro/v1,
  avp-micro/transport/v1]`. The transport objects reuse the payments terms
  (`payee`, `payer`, `quote`, `quoteDigest`, `requestHash`, `amount`, `currency`,
  `nonce`, `expires`, `authorization`, `execution`, `timestamp`) and add only new `txp:`
  terms. Reused terms MUST NOT be redefined (matches the `@protected` discipline and the
  cross-bundle `$def` drift guard already in `validate.py`).
- **Dependencies:** builds on **Payments** (wraps `PaymentQuote`, `PaymentAuthorization`,
  `PaymentExecution`, `PaymentReceipt`, the streaming objects) and **DSA** (identity via
  `did:key`, the mandatory `ecdsa-jcs-2022` cryptosuite). Signed transport objects use
  the existing `DataIntegrityProof` / `ecdsa-jcs-2022` envelope; no new crypto.

## 3. Data model — new objects

Four object types plus an error-code vocabulary. Signed objects use `ecdsa-jcs-2022`.

| Object | `type` / id prefix | Signer | Role |
|---|---|---|---|
| **ServiceDescription** | `ServiceDescription` / `urn:avp:txp:service:` | payee | Discovery document at `/.well-known/avp-micro`. |
| **PaymentChallenge** | `PaymentChallenge` / `urn:avp:txp:challenge:` | payee | Body of an HTTP 402; wraps a quote + a server challenge nonce. |
| **AuthorizationSubmission** | `AuthorizationSubmission` / `urn:avp:txp:submission:` | payer agent | The client's 402 retry payload; binds the authorization to the challenge. |
| **ProblemDetails** | `ProblemDetails` / (no id required) | unsigned | RFC 9457-style error body. |

### 3.1 ServiceDescription (payee-signed)

- `payee` (DID).
- `offers` — array of `PaymentOffer` (or IRIs) advertised.
- `endpoints` — object: `quote`, `authorize`, `execute`, `receipt`, `settlementStatus`,
  and the streaming endpoints (`session`, `accruals`, `close`, `extend`) as absolute or
  relative URLs.
- `acceptedCredentialIssuers` — array of issuer DIDs.
- `acceptedSettlementRails` — array of rail identifiers (e.g. `stl:rail-evm-stablecoin`,
  `stl:rail-x402`, `stl:rail-lightning`).
- `supportedBundles` — map of bundle namespace → version supported (payments, disputes,
  settlement, transport).
- `timestamp`; optional `expires`; `proof`.

### 3.2 PaymentChallenge (payee-signed)

The 402 response body is an envelope `{ challenge: PaymentChallenge, quote: PaymentQuote }`
— the signed `PaymentChallenge` plus the referenced `PaymentQuote` delivered together, so
the client has the quote content and can verify the challenge's digest binding without a
second round-trip.

- `quote` (IRI) + `quoteDigest` — the `PaymentQuote` the payee is offering for the gated
  request; `quoteDigest` MUST equal `jcs_digest(quote)`, and the quote's `requestHash`
  MUST equal the content digest of the attempted request.
- `challenge` — a server-chosen nonce (freshness / anti-replay; the client echoes it).
- `authorizeEndpoint` — URL to submit the authorization to (or the resource to retry).
- `acceptedSettlementRails` — rails the payee will settle on for this charge.
- `payee` (DID); `timestamp`; `expires`; `proof`.

### 3.3 AuthorizationSubmission (payer-agent-signed)

- `authorization` (IRI) + `authorizationDigest` — the `PaymentAuthorization` being
  submitted (which itself binds the quote + embeds the SAC VP).
- `challenge` — the value echoed from the `PaymentChallenge` (binds this submission to
  *this* verifier + request + 402; defeats VP/authorization replay to a different
  verifier — the gap flagged in the security review).
- `idempotencyKey` — the client's idempotency key for this submission.
- optional `callbackUrl` — webhook for async settlement notification.
- `payer` (DID); `timestamp`; `proof`.

### 3.4 ProblemDetails (unsigned)

RFC 9457 "problem+json" shape:
- `type` — an error-code IRI in `txp:ErrorScheme` (REQUIRED).
- `title`, `status` (HTTP status int), `detail` (human text), optional `field` (the
  offending member), optional `instance`.

### 3.5 Error-code SKOS scheme (`vocab/errors.ttl`, `txp:ErrorScheme`)

Concepts (each `skos:Concept` with `prefLabel` + `definition` + an informative HTTP
status note). Reuses the rejection-reason names already used by the simulator and adds
transport-native ones:

`amount-mismatch`, `currency-mismatch`, `over-cap`, `payee-not-allowed`,
`category-not-allowed`, `daily-limit-exceeded`, `expired`, `nonce-reuse`,
`double-spend`, `budget-exceeded`, `missing-confirmation`, `forged-confirmation`,
`malformed-request`, `unauthorized`, `challenge-expired`, `idempotency-conflict`,
`settlement-pending`, `settlement-failed`, `credential-revoked`.

## 4. Protocol flows

### 4.1 Discovery

`GET /.well-known/avp-micro` → `200` `ServiceDescription` (payee-signed). The agent
learns endpoints, accepted issuers, and rails before transacting.

### 4.2 Core 402-challenge flow

```
1. Agent → GET/POST <resource>
2. Payee → 402 Payment Required
        WWW-Authenticate: AVP-Micro
        body: PaymentChallenge { quote (bound to requestHash of the attempt),
                                 challenge, authorizeEndpoint, expires }
3. Agent verifies the quote; builds a PaymentAuthorization (embeds the SAC VP);
   wraps it in an AuthorizationSubmission { authorization(+digest), challenge(echoed),
                                            idempotencyKey }
4. Agent → retry <resource>
        Authorization: AVP-Micro <submission>
        Idempotency-Key: <key>
5. Payee verifies (quote binding, SAC policy, challenge freshness, nonce/idempotency),
   settles, → 200 + resource; PaymentReceipt (+ PaymentExecution) in the body/headers
   or → 402 / 4xx with a ProblemDetails
```

The echoed `challenge` binds the submission to the verifier + request that issued it; a
captured authorization cannot be replayed to a different verifier.

### 4.3 Explicit-quote (programmatic, non-gated) flow

`POST /quote` (carrying `requestHash`) → `PaymentQuote`; `POST /authorize`
(`AuthorizationSubmission`) → `PaymentExecution` / `PaymentReceipt`; `GET /receipt/{id}`.

### 4.4 Streaming flow

`POST /session` → `UsageSession`; `POST /session/{id}/budget`
(`SessionBudgetAuthorization`) → opens; `GET /session/{id}/accruals` → `UsageAccrual`s;
`POST /session/{id}/extend` (`UsageSessionExtension`); `POST /session/{id}/close` →
`PaymentExecution` + `PaymentReceipt`.

### 4.5 Async settlement

When settlement is not instant, `execute` returns `PaymentExecution{status: pending}`
plus a `Location: /settlement/{id}`. `GET /settlement/{id}` returns the execution and
then the `SettlementProof` as finality advances (`pending → final`); the
`PaymentReceipt` is issued once final. An `AuthorizationSubmission.callbackUrl` MAY be
supplied for a webhook instead of polling.

### 4.6 Idempotency

`Idempotency-Key` (header, mirrored in `AuthorizationSubmission.idempotencyKey`) on
`authorize`/`execute` and the 402 retry. The payee MUST return the same
execution/receipt for a repeated key, and MUST return `409` `idempotency-conflict` if
the key is reused with a different body. This makes retries safe over flaky networks and
prevents accidental double-charge.

### 4.7 Error model

Every non-success response is a `ProblemDetails` whose `type` is an error-code IRI from
`txp:ErrorScheme`, with this HTTP status mapping:

| HTTP | Meaning | Example codes |
|---|---|---|
| 402 | payment required / insufficient | (challenge), `over-cap`, `daily-limit-exceeded`, `budget-exceeded` |
| 400 | malformed | `malformed-request` |
| 401 / 403 | auth / policy | `unauthorized`, `payee-not-allowed`, `category-not-allowed`, `missing-confirmation`, `credential-revoked` |
| 409 | idempotency | `idempotency-conflict`, `double-spend`, `nonce-reuse` |
| 422 | binding failure | `amount-mismatch`, `currency-mismatch`, `expired`, `challenge-expired`, `forged-confirmation` |
| 5xx | settlement / server | `settlement-pending` (also 200+Location), `settlement-failed` |

## 5. HTTP surface (OpenAPI 3.1)

`openapi/avp-micro.openapi.yaml` is the machine-readable contract:

- **Endpoints:** `GET /.well-known/avp-micro`; `POST /quote`; `POST /authorize`;
  `POST /execute`; `GET /receipt/{id}`; `GET /settlement/{id}`; `POST /session`,
  `/session/{id}/budget`, `/session/{id}/accruals`, `/session/{id}/close`,
  `/session/{id}/extend`; and the 402 challenge documented as a response on any gated
  path.
- **Media type:** `application/avp-micro+json` (JSON-LD bodies).
- **Headers:** `WWW-Authenticate: AVP-Micro` (402), `Authorization: AVP-Micro <submission>`,
  `Idempotency-Key`, `Location` (async settlement).
- **Status codes:** as in §4.7.
- Request/response bodies `$ref` the bundle JSON Schemas (transport objects) and the
  payments/settlement schemas (the wrapped objects) so OpenAPI and JSON Schema are one
  source of truth.

## 6. Harness wiring

### 6.1 `generate.py`

A transport block producing signed vectors and example exchanges:
- `ServiceDescription` (payee-signed).
- `PaymentChallenge` wrapping the existing quote (`01-payment-quote.json`), bound to its
  `requestHash`, with a `challenge` nonce.
- `AuthorizationSubmission` wrapping the existing authorization (`02`), echoing the
  challenge, with an `idempotencyKey`.
- `ProblemDetails` example (e.g. an `over-cap` 402).
- **Example HTTP exchanges**: request+response envelope JSON (method, path, status,
  headers, body) for (a) the full 402 flow and (b) an error case, whose bodies are the
  above signed objects.

### 6.2 `validate.py`

- Register the transport context in the local document loader `_LOCAL`.
- Add `TRANSPORT_VECTORS` (filename → `$def`).
- Turtle parse (`transport.ttl`, `errors.ttl`, `transport-shapes.ttl`); JSON-LD
  expansion; JSON Schema; SHACL — for the transport vectors.
- The shared-`$def` drift guard now also covers the transport schema.
- Negative-schema cases: challenge missing `quoteDigest`; submission missing the echoed
  `challenge`; `ProblemDetails.type` not an IRI; bad context order.
- An OpenAPI-consistency check: every request/response `$ref` in the OpenAPI doc resolves
  to an existing `$def` in the bundle schemas.

### 6.3 `verify.py`

- `ServiceDescription` and `PaymentChallenge` proofs verify and are signed by the payee.
- `PaymentChallenge.quoteDigest == jcs_digest(quote)` and the challenge's quote
  `requestHash` matches the gated request.
- `AuthorizationSubmission` signed by the payer, references authorization `02` by IRI +
  digest, and **echoes the challenge nonce** from the `PaymentChallenge` (freshness).
- `ProblemDetails.type` resolves to a concept in `txp:ErrorScheme`.
- The example-exchange bodies are byte-identical to the canonical signed objects they
  embed.

### 6.4 Docs

- `spec/transport/index.html` (ReSpec): the flow state machine, the 402 sequence
  (SVG), the error registry, idempotency, and a Security section covering the
  challenge-freshness rule.
- `spec/transport/README.md` — artifact table + vector index + endpoint summary.
- `spec/README.md` and `CLAUDE.md` updated to a sixth bundle + the transport namespace.

## 7. Acceptance criteria

- `python spec/generate.py` regenerates all vectors including transport, deterministically.
- `python spec/verify.py` reports **PASS** with the transport semantic checks active.
- `python spec/validate.py` reports **PASS** (Turtle / JSON-LD / JSON Schema / SHACL /
  drift-guard / OpenAPI-ref check) for the transport bundle, fully offline.
- The OpenAPI document is valid OpenAPI 3.1 and all body `$ref`s resolve to bundle
  `$defs`.
- The payments / disputes / settlement / authority bundles are unchanged.
