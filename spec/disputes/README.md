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

| Artifact | File | Status |
|---|---|---|
| JSON-LD context | [`context/v1.jsonld`](context/v1.jsonld) | normative |
| Prose specification | [`index.html`](index.html) | normative |
| JSON Schema | [`schemas/disputes.schema.json`](schemas/disputes.schema.json) | conformance aid |
| SHACL shapes | [`shapes/disputes-shapes.ttl`](shapes/disputes-shapes.ttl) | conformance aid |
| Ontology (RDFS/OWL) | [`vocab/disputes.ttl`](vocab/disputes.ttl) | conformance aid |
| Reason codes (SKOS) | [`vocab/reasons.ttl`](vocab/reasons.ttl) | conformance aid |
| Test vectors | [`test-vectors/`](test-vectors/) | informative |

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
