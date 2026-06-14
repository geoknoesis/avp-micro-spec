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

The `challenge` field reuses the Data Integrity `sec:challenge` term (an anti-replay
challenge nonce); the client echoes it in the `AuthorizationSubmission`.

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
