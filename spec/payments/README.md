# AVP-Micro Payments

This bundle defines the payment-message layer: signed quotes, authorizations,
executions, receipts, and a streaming/session-metering mode for autonomous
agents. Payer identity, the `SpendingAuthorizationCredential`, securing
mechanisms, and the issuer-trust framework are defined by
[Delegated Spending Authority](../authority/) (DSA); this specification composes
them with per-transaction economic terms.

## Artifacts

| Artifact | Path | Status |
|----------|------|--------|
| Specification (W3C ReSpec) | [`index.html`](index.html) | normative |
| JSON-LD 1.1 context | [`context/v1.jsonld`](context/v1.jsonld) | normative |
| JSON Schema (payment messages) | [`schemas/avp-micro.schema.json`](schemas/avp-micro.schema.json) | conformance aid |
| SHACL shapes | [`shapes/avp-shapes.ttl`](shapes/avp-shapes.ttl) | conformance aid |
| RDFS/OWL ontology | [`vocab/avp.ttl`](vocab/avp.ttl) | conformance aid |
| Metering dimensions (SKOS) | [`vocab/dimensions.ttl`](vocab/dimensions.ttl) | conformance aid |
| Composite unit registry (QUDT-anchored) | [`vocab/units.ttl`](vocab/units.ttl) | conformance aid |
| Signed test vectors | [`test-vectors/`](test-vectors/) | informative fixtures |

## Canonical URLs (registration pending)

The context and vocabulary are authored for these `w3id.org` URLs; registering
the redirects is a prerequisite for cross-implementation interoperability that
depends on network dereferencing. Until registration is complete, validation uses
local context files by explicit configuration:

- Context: `https://w3id.org/avp-micro/v1` → `context/v1.jsonld`
- Vocabulary namespace: `https://w3id.org/avp-micro/v1#`

Signed payment objects use the **4-entry** context array so that the embedded
DSA credential and shared terms (`currency`, `nonce`, `expires`, category IRIs)
resolve correctly:

```json
["https://www.w3.org/ns/credentials/v2",
 "https://w3id.org/security/data-integrity/v2",
 "https://w3id.org/spending-authority/v1",
 "https://w3id.org/avp-micro/v1"]
```

The DSA context (`https://w3id.org/spending-authority/v1`) is the third entry
because payment objects embed a `SpendingAuthorizationCredential` inside a
Verifiable Presentation, and that credential uses DSA-defined terms. The DSA
context is served locally by the shared validation harness.

## Test vectors

`test-vectors/` contains a discovery offer (`00`), the one-off flow (`01`–`04`),
the streaming flow (`05`–`11`), and a bare service-request. Rich-pricing offers
(`12`–`13`) and `pricing-conformance.json` exercise the pricing-model vocabulary.

| File | Type |
|------|------|
| `service-request.json` | Example service request (input to `serviceRequestHash`) |
| `00-payment-offer.json` | `PaymentOffer` (payee advertisement; discovery entrypoint) |
| `12-payment-offer-compute.json` | `PaymentOffer` (multi-dimensional: requests + GB-second, with allowances) |
| `13-payment-offer-storage.json` | `PaymentOffer` (tiered graduated GB-month storage) |
| `pricing-conformance.json` | Pricing-evaluation fixtures `(pricingModel, usage) → amount` (unsigned) |
| `01-payment-quote.json` | `PaymentQuote` |
| `02-payment-authorization.json` | `PaymentAuthorization` (embeds DSA `SpendingAuthorizationCredential`) |
| `03-payment-execution.json` | `PaymentExecution` |
| `04-payment-receipt.json` | `PaymentReceipt` |
| `05-usage-session.json` | `UsageSession` |
| `06-session-budget-authorization.json` | `SessionBudgetAuthorization` (embeds DSA credential) |
| `07-usage-accrual.json` | `UsageAccrual` |
| `08-payment-execution-session.json` | `PaymentExecution` (session settlement) |
| `09-payment-receipt-session.json` | `PaymentReceipt` (session) |
| `10-usage-session-extension.json` | `UsageSessionExtension` |
| `11-session-budget-authorization-2.json` | `SessionBudgetAuthorization` (re-authorization after extension) |

## Dependency on DSA

This specification **normatively depends** on the
[Delegated Spending Authority](../authority/) specification. Implementations
MUST also implement the DSA securing mechanism, key-binding, DID requirements,
and trust-establishment rules defined there.
