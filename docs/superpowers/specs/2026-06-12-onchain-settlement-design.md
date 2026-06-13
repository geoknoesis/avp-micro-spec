# Design: AVP-Micro on-chain settlement binding (EVM stablecoin / x402 / Lightning)

**Date:** 2026-06-12
**Status:** Design — proposed, no implementation committed
**Depends on:** [`spec/payments/`](../../../spec/payments/) (per-transaction terms, `settlementMethod`/`settlementTarget`/`settlementRef`), [`spec/authority/`](../../../spec/authority/) (DSA credential, `ecdsa-jcs-2022` securing), [`spec/disputes/`](../../../spec/disputes/) (the `Reversal` settlement fact)
**Bundles:** ships as a **new fifth peer bundle** `spec/settlement/`; rides on top of Payments **by reference** (does not mutate Payments objects or their signed vectors)
**Scope:** spec-level + harness. The bundle stays **100% mock/offline** — `generate.py` uses deterministic chain fixtures and never broadcasts; no live-chain code ships.

## 1. Goal

AVP-Micro is the trust/authorization layer and deliberately scopes *value movement* out (`CLAUDE.md`: "settlement is the only money-touching step and is the one part the spec scopes out"). This bundle defines **how a public blockchain plugs into the existing settlement seam** as the rail that actually moves value, without AVP-Micro itself touching funds.

The seam already exists in three places, so this is a binding, not a rewrite:

- `settlementMethod` + `settlementTarget` on `PaymentQuote` / `PaymentAuthorization` (today `"sim-ledger"` / `"sim:payee"`).
- `settlementRef` on `PaymentExecution` (today `"internal-ledger://txn/abc123"`).
- `SettlementRail.settle(payer, payee, amount, key) -> (ref, settled)` in `sim.py`, whose docstring already says *"a deployment swaps in a real rail or testnet adapter exposing the same settle() interface."*

Concretely: a **rail-agnostic settlement-binding core** plus three normative **rail profiles** — EVM stablecoin (USDC on an L2), Coinbase **x402**, and Bitcoin **Lightning**.

## 2. The two hard differences from the in-memory ledger

On-chain settlement breaks two assumptions the synchronous `SimulatedLedger` makes. Every design choice below flows from these:

| | In-memory `settle()` | On-chain reality | Consequence |
|---|---|---|---|
| **Finality** | instantaneous, total | asynchronous, probabilistic (reorgs) | cannot emit `fulfilled` on broadcast; need a finality state machine + per-rail confirmation threshold |
| **Reversibility** | a second `settle()` undoes it | irreversible; no clawback | a `Reversal` must be a **new compensating transfer**, not an undo |

These are why finality tracking is **mandatory core** (every rail needs it) while escrow is an **optional profile** (rails lean different ways — §5).

## 3. Bundle layout

```
spec/settlement/
  context/v1.jsonld          # JSON-LD 1.1 context, term mapping
  vocab/settlement.ttl       # RDFS/OWL: SettlementInstruction, SettlementProof, EscrowLock/Release/Refund, PayeeAccountBinding
  vocab/rails.ttl            # SKOS rail registry (evm-stablecoin, x402, lightning) + finality terms
  schemas/settlement.schema.json
  shapes/settlement-shapes.ttl
  index.html                 # ReSpec prose, core + 3 profile sections
  README.md
  test-vectors/              # numbered 40+ (payments 01–18, disputes 20–39)
```

- **Namespace:** `https://w3id.org/avp-micro/settlement/v1#` (prefix `stl:`)
- **Context URL:** `https://w3id.org/avp-micro/settlement/v1` → `spec/settlement/context/v1.jsonld` (registration pending, served locally by the harness)
- Signed settlement objects use the same 4-entry context array as Payments, appending the settlement context as a 5th entry so DSA/Payments terms still resolve.

## 4. Core objects (rail-agnostic)

All are wallet-signed with `ecdsa-jcs-2022` (P-256), the AVP-Micro MTI suite — **not** a chain-native signature. The chain signature lives inside the referenced transaction; the AVP object *attests to* it.

### 4.1 `SettlementInstruction`
References a `PaymentAuthorization` by `id`; declares the concrete rail + recipient.

| Field | Meaning |
|---|---|
| `authorization` | ref to `urn:avp:authz:…` |
| `rail` | SKOS code: `stl:rail/evm-stablecoin` \| `stl:rail/x402` \| `stl:rail/lightning` |
| `chain` | **CAIP-2** chain id (`eip155:8453`, LN network id) |
| `payeeAccount` | **CAIP-10** account, or Lightning destination (BOLT11 / LNURL / node pubkey) |
| `asset` | **CAIP-19** asset id (e.g. `eip155:8453/erc20:0x833…` USDC); native where applicable |
| `amount` / `currency` | decimal — **MUST equal** the referenced authorization |
| `amountBase` | integer base units (minor units / sats / msat) as a string |
| `rate` | OPTIONAL agreed conversion when `currency` ≠ settlement asset (§6) |
| `confirmationThreshold` | required confirmations / finality policy for this instruction |
| `mode` | `direct` \| `escrow` |
| `expires`, `nonce`, `proof` | freshness + wallet signature |

### 4.2 `SettlementProof`
The chain-native attestation that settlement occurred. **`PaymentExecution.settlementRef` resolves to this object's `id`.**

| Field | Meaning |
|---|---|
| `instruction` / `execution` | refs binding proof ↔ instruction ↔ payment |
| `chain` | CAIP-2 |
| `transaction` | chain-native ref: tx hash (EVM/BTC); Lightning `payment_hash` **+ `preimage`** |
| `settledAmountBase` / `asset` | what actually moved |
| `blockHeight` / `blockHash` / `confirmations` | inclusion evidence (omitted for LN) |
| `finality` | `pending` \| `probabilistic` \| `final` |
| `observedAt`, `proof` | observation time + signer |

### 4.3 Escrow objects (optional profile)
- **`EscrowLock`** — `instruction` ref, `lockRef` (contract address + escrowId, or LN hold-invoice `payment_hash`), `lockedAmountBase`, `timeout`, `proof`.
- **`EscrowRelease`** — release to payee on delivery; carries the settling `SettlementProof`.
- **`EscrowRefund`** — refund to payer on timeout/dispute; carries the settling `SettlementProof`. Maps to a disputes `Reversal` (§7).

### 4.4 `PayeeAccountBinding` (§5 below)
Binds a `payeeAccount` to the payee DID.

## 5. The DID ↔ on-chain-account binding (security-critical)

Payments identifies parties by **DID**; chains use **accounts**. Without a verifiable link, a man-in-the-middle could swap `payeeAccount` and redirect funds while the authorization still verifies. So `payeeAccount` **MUST** be bound to the payee DID by one of:

- **(a) `did:pkh`** — the payee DID *is* the CAIP-10 account (`did:pkh:eip155:8453:0x…`). Binding is identity; nothing extra to verify.
- **(b) `PayeeAccountBinding`** — a payee/issuer-signed credential asserting the payee DID controls the CAIP-10 account, referenced by the instruction. Used when the payee keeps a `did:key`/`did:web` identity distinct from its settlement account.

`verify.py` enforces that every `SettlementInstruction.payeeAccount` is covered by (a) or (b).

## 6. Amount precision & FX (real-world hazard)

Quotes are decimal (`"0.001"` USD); chains settle **integer base units of a specific asset**. The core mandates:

- `amountBase` = `amount × 10^decimals`, computed **exactly**; if the value is not representable in base units the instruction is **rejected** (no silent rounding).
- `asset` (CAIP-19) pins which token's decimals apply (USDC = 6, ETH = 18, BTC = 8, LN = msat).
- When quote `currency` ≠ settlement asset (BTC, or a de-pegged stablecoin), an explicit `rate` records the agreed conversion and **both** the decimal and base figures are retained. A 1:1 USD↔USDC assumption is allowed only when `rate` is absent and asset is a USD stablecoin.

`verify.py` asserts the `amountBase == amount × 10^decimals` (and rate, when present) invariant on every vector.

## 7. Flows

**Direct (USDC/Base; x402):**
quote → authorization *(unchanged Payments objects)* → wallet signs `SettlementInstruction` (`mode=direct`) → broadcasts ERC-20 `transfer` (or x402 `X-PAYMENT`) → watcher emits `SettlementProof`, `finality` advancing `pending → probabilistic → final` as `confirmations` reach `confirmationThreshold` → `PaymentExecution.status` flips `pending → completed` **only at `final`** → payee signs `PaymentReceipt fulfilled`.

**Escrow (trustless / Lightning-native):**
instruction `mode=escrow` → `EscrowLock` (EVM escrow contract, or LN hold-invoice) → payee delivers service → `EscrowRelease` + `SettlementProof` (LN: revealing the preimage *is* the proof) → receipt. Timeout → `EscrowRefund` → payer.

## 8. Reversal / disputes alignment

On-chain is irreversible, so a disputes-bundle **`Reversal` is realized as a new compensating transfer** (payee → payer): a `SettlementInstruction` with the parties swapped, producing a reverse `SettlementProof`. The existing `Reversal.settlementRef` simply points at that proof. **The disputes bundle is not modified** — same by-reference discipline as the Payments coupling.

## 9. The three profiles (normative sub-sections)

| | EVM stablecoin | x402 | Lightning |
|---|---|---|---|
| `chain` (CAIP-2) | `eip155:*` | `eip155:*` (under HTTP 402) | LN network id |
| `payeeAccount` | CAIP-10 `0x…` | 402 `accepts` → CAIP-10 | BOLT11 invoice / LNURL / node id |
| `asset` / base unit | ERC-20 USDC / minor units | USDC / minor units | native / **millisatoshi** |
| `SettlementProof.transaction` | tx hash + confirmations | facilitator settle response (tx hash) | `payment_hash` + `preimage` |
| finality | block depth / `finalized` tag | same | preimage revealed (single-shot `final`) |
| escrow | reference escrow contract (lock/release/refund — interface sketched, informative) | opt-in | **hold-invoice (native)** |
| notes | broadest tooling; default reference profile | maps AVP quote ↔ HTTP 402 challenge; pay-then-serve | sats not USD → `rate` mandatory; sub-cent micro fit |

## 10. Harness integration

- **`generate.py`** — deterministic signed vectors (existing `seed_key` P-256, deterministic like the non-interop bundles) for each profile: a `SettlementInstruction` + `SettlementProof` per rail, an `EscrowLock`/`EscrowRelease` pair, an `EscrowRefund`/on-chain `Reversal`, and a `PayeeAccountBinding`. **Chain data (tx hashes, block heights, preimages) are deterministic fixtures; `generate.py` never contacts a chain.**
- **`verify.py`** — verify `ecdsa-jcs-2022` proofs on every settlement object; assert `amountBase == amount × 10^decimals` (+ `rate`), the finality rule **per rail** (confirmation-based rails: `confirmations ≥ confirmationThreshold ⇒ finality=final`; Lightning: a revealed `preimage` matching `payment_hash` ⇒ `finality=final`), the `payeeAccount`↔DID binding (§5), and `instruction.amount == authorization.amount`.
- **`validate.py`** — Turtle parse, JSON-LD expansion (local context), JSON Schema, and SHACL for the new bundle; vendor a CAIP context locally if expansion needs one. Stays fully offline.
- **`sim.py`** — three new `SettlementRail` adapters (`EvmStablecoinRail`, `X402Rail`, `LightningRail`) implementing the **same `settle()` seam**, plus a deterministic "block clock" that advances `confirmations` so the `pending → final` state machine and escrow lock/release/refund are exercised behaviourally. New `sim-scenarios.json` cases: one per rail (direct), one escrow, one on-chain reversal. **Adapters are mock — no real money — staying true to "settlement is stubbed."**

**Explicitly out of scope (this pass):** any live-chain / testnet broadcast. No env-gated testnet adapter ships; the bundle is 100% mock/offline so `verify.py` / `validate.py` / `sim.py` stay deterministic and network-free.

## 11. Identifiers decision (resolved)

Adopt the **Chain Agnostic Standards** — **CAIP-2** (chain), **CAIP-10** (account), **CAIP-19** (asset), and **`did:pkh`** for account-as-DID — rather than AVP-specific identifiers. This keeps the binding rail-neutral and interoperable with the wider ecosystem the README already name-checks (Polygon/Solana/Base, x402, Lightning, Interledger).

## 12. Vector numbering & docs

- Test vectors numbered **40+** (offers `00`, payments `01–18`, disputes `20–39`).
- Update `spec/README.md` and `CLAUDE.md` from "four bundles" → "five"; add the settlement bundle paragraph, the namespace, and the context URL to the canonical-URL lists.

## 13. Open questions (for spec-review pass)

- Exact `confirmationThreshold` encoding: integer confirmations vs. a named finality tag (`safe`/`finalized`) vs. either-of. Likely allow both, profile-specified.
- Whether `PayeeAccountBinding` is its own VC type or a thin claim inside the DSA credential. Leaning standalone, to keep DSA untouched.
- x402: pin to a specific facilitator response shape, or stay facilitator-neutral and only require a tx-hash-bearing `SettlementProof`. Leaning neutral.
