# AVP-Micro On-Chain Settlement Binding

On-chain settlement binding for AVP-Micro: defines the **money-moving step** that
the [Payments](../payments/) specification deliberately scopes out. Builds on the
[Payments](../payments/) and [Delegated Spending Authority](../authority/) bundles
by reference, modifying neither. Three normative rail profiles &mdash; EVM stablecoin
(USDC on an L2), Coinbase x402, and Bitcoin Lightning &mdash; share a rail-agnostic
core of signed objects (`SettlementInstruction`, `SettlementProof`,
`PayeeAccountBinding`) with an optional escrow lifecycle (`EscrowLock`,
`EscrowRelease`, `EscrowRefund`). DID&harr;account binding prevents payment
redirection. On-chain irreversibility is handled by compensating-transfer reversals
that reference [[AVP-DISPUTES]] `Reversal` objects. Every object is secured with the
mandatory `ecdsa-jcs-2022` cryptosuite.

- **Namespace:** `https://w3id.org/avp-micro/settlement/v1#` (prefix `stl:`)
- **Context:** `https://w3id.org/avp-micro/settlement/v1` &rarr; [`context/v1.jsonld`](context/v1.jsonld)

## Artifacts

| Artifact | File |
|---|---|
| JSON-LD context | [`context/v1.jsonld`](context/v1.jsonld) |
| Core ontology (RDFS/OWL) | [`vocab/settlement.ttl`](vocab/settlement.ttl) |
| Rail registry (SKOS) | [`vocab/rails.ttl`](vocab/rails.ttl) |
| JSON Schema | [`schemas/settlement.schema.json`](schemas/settlement.schema.json) |
| SHACL shapes | [`shapes/settlement-shapes.ttl`](shapes/settlement-shapes.ttl) |
| Prose specification | [`index.html`](index.html) |

## Test vectors

| # | File | Type | Rail |
|---|---|---|---|
| 40 | `40-payee-account-binding.json` | PayeeAccountBinding | — |
| 41 | `41-settlement-instruction-evm.json` | SettlementInstruction | EVM stablecoin |
| 42 | `42-settlement-proof-evm.json` | SettlementProof | EVM stablecoin |
| 43 | `43-settlement-instruction-x402.json` | SettlementInstruction | x402 |
| 44 | `44-settlement-proof-x402.json` | SettlementProof | x402 |
| 45 | `45-settlement-instruction-lightning.json` | SettlementInstruction | Lightning |
| 46 | `46-escrow-lock-lightning.json` | EscrowLock | Lightning |
| 47 | `47-settlement-proof-lightning.json` | SettlementProof | Lightning |
| 48 | `48-escrow-release-lightning.json` | EscrowRelease | Lightning |
| 49 | `49-settlement-instruction-evm-escrow.json` | SettlementInstruction (escrow) | EVM stablecoin |
| 50 | `50-escrow-lock-evm.json` | EscrowLock | EVM stablecoin |
| 51 | `51-settlement-proof-evm-refund.json` | SettlementProof (refund path) | EVM stablecoin |
| 52 | `52-escrow-refund-evm.json` | EscrowRefund | EVM stablecoin |
| 53 | `53-reverse-settlement-instruction.json` | SettlementInstruction (reverse) | EVM stablecoin |
| 54 | `54-reverse-settlement-proof.json` | SettlementProof (reverse) | EVM stablecoin |
| 55 | `55-payee-account-binding-agent.json` | PayeeAccountBinding | — |

Regenerate and check from the repo root (see [`../README.md`](../README.md)):

```powershell
python spec/generate.py
python spec/verify.py
python spec/validate.py
```
