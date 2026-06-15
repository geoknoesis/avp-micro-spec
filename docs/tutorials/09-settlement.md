# Tutorial 09 — Settlement & the Rails

> **Series:** [AVP-Micro Tutorials](README.md) · **Previous:** [08 — The HTTP 402 Transport Binding](08-http-402-transport.md) · **Next:** 10 — Interop: SD-JWT-VC & AP2
>
> **You'll learn:** how an authorized payment is bound to an actual rail and proven settled —
> the rail-agnostic instruction/proof core, the two finality models (publicly-verifiable vs.
> attested), escrow, anti-redirection, and the full rail matrix from blockchains to Visa Direct.

---

## 1. The separation that makes this possible

Recall Tutorial 01: authorization and settlement are *deliberately decoupled*. AVP-Micro keeps
the actual money-movement **out of the core** — it's the one regulated, money-touching step the
spec scopes out — and instead defines a thin, rail-agnostic binding:

- a **`SettlementInstruction`** (wallet-signed): "settle *this authorization* on *this rail*, to
  *this account*, for *this amount*," and
- a **`SettlementProof`**: evidence that settlement reached **finality**.

Because the authorization side never names a rail, the *same* payment can settle anywhere. The
rail vocabulary is an **extensible SKOS scheme** (`stl:RailScheme`) — implementers can mint new
rails without touching the core.

## 2. Two finality models

The deep distinction (Tutorial 01's punchline) is **who attests that settlement happened**:

| | **On-chain rails** | **Closed-processor rails** |
|---|---|---|
| Examples | EVM stablecoin, Coinbase x402, Lightning | Card (Stripe/Adyen), bank RTP/Zum, PayPal, Visa Direct / Mastercard Send |
| Proof | `SettlementProof` | `AttestedSettlementProof` |
| Finality | **Publicly verifiable** — confirmations / Lightning preimage | **Attested** — a signed processor statement |
| Amounts | base units (wei, sats, msat) | decimal fiat |
| Accounts | CAIP-10 (`did:pkh`) | processor/bank account refs |
| Trust root | the chain itself | a named `did:web` processor |

`finality` is a typed value — `pending`, `probabilistic`, or `final` — and a wallet must not
treat a payment as done until the rail's rule is met.

## 3. On-chain settlement

For public chains, the `SettlementInstruction` carries CAIP identifiers (CAIP-2 chain, CAIP-10
account, CAIP-19 asset), an integer `amountBase`, and a `confirmationThreshold`. The
`SettlementProof` carries the chain `transaction`, `confirmations`/`blockHeight`, and
`finality`:

- **EVM stablecoin** — an ERC-20 transfer; final by confirmation depth.
- **x402** — Coinbase's HTTP-402 stablecoin flow; the facilitator's on-chain transfer is the proof.
- **Lightning** — finality is the **preimage** reveal (`sha256(preimage) == payment_hash`);
  escrow is native via hold-invoices.

**Account binding (anti-redirection):** a `PayeeAccountBinding` ties the payee's DID to its
on-chain account, so the wallet refuses to settle to an account the payee doesn't control
(`accountRedirection`). The `settlement.py` helpers do exact decimal→base-unit conversion
(rejecting non-representable values), CAIP/`did:pkh` parsing, and the finality predicate.

**Escrow lifecycle:** for held funds there's `EscrowLock` → `EscrowRelease` (on delivery) or
`EscrowRefund` (on timeout/dispute), each binding a final `SettlementProof`. A lock is resolved
*exactly once* — never both released and refunded.

## 4. Closed-processor settlement (attested finality)

Most of the world's money moves inside private processors whose ledgers you can't read. There,
finality can't be publicly verified, so the proof **embeds an attestation**:

- **`AttestedSettlementInstruction`** — fiat decimal `amount` (no chain/asset/base units),
  references a **`ProcessorAccountBinding`**, and carries rail-specifics (`captureMode` for card
  auth/capture, `scheme` for bank rails).
- **`AttestedSettlementProof`** — embeds an `attestation` with a `mode`
  (`payee-attested` or `processor-attested`), the **`processor`** as a `did:web` trust root
  (e.g. `did:web:visa.com`), a processor `reference`, and a terminal `status`. Finality is
  `final` when that status is terminal (card *captured*, bank *settled*, OCT *approved*).

The same anti-redirection rule applies: the `ProcessorAccountBinding` ties the payee DID to the
receiving account, on the same rail, or the wallet refuses (`accountRedirection`).

## 5. The full rail matrix

Every rail below ships as a signed, verifiable example vector and a conformance requirement:

| Family | Rails | Mode | Terminal status |
|--------|-------|------|-----------------|
| On-chain | `rail-evm-stablecoin`, `rail-x402`, `rail-lightning` | direct / escrow | `final` (confirmations / preimage) |
| Card via processor | `rail-card-stripe`, `rail-card-adyen` | escrow (auth/capture) | `captured` |
| Bank (instant) | `rail-bank-rtp`, `rail-bank-zum` | direct push | `settled` |
| Wallet | `rail-paypal` | direct (immediate capture) | `completed` |
| Push-to-card | `rail-visa-direct`, `rail-mc-send` | direct (OCT/MoneySend) | `approved` |

Adding another processor (the pattern from the build) is: mint a `rail-*` concept, name its
`did:web` processor, bind the account, add a vector — the authorization layer is untouched.

## 6. Reversal on the rail

The reverse value-flow (Tutorial 11) terminates here: an on-chain **reverse settlement** is a
compensating transfer with payer/payee swapped, with its own instruction and proof — so a
chargeback or refund is itself a verifiable settlement.

## 7. Recap

- Settlement is a thin, rail-agnostic **instruction + proof**; the money-touching step is out of
  the core, which is *why* any rail works under one authorization.
- Two finality models: **publicly-verifiable** on-chain proofs vs. **attested** closed-processor
  proofs (signed by the payee or a named `did:web` processor).
- **Account binding** stops redirection; **escrow** brackets held funds; the rail matrix spans
  chains, cards, bank, wallet, and push-to-card.

## Glossary

- **SettlementInstruction / SettlementProof** — wallet-signed "settle this on that rail" / proof of finality.
- **AttestedSettlement\*** — the closed-processor analogues, carrying a processor attestation.
- **Finality** — `pending` / `probabilistic` / `final`; the rail's irreversibility point.
- **PayeeAccountBinding / ProcessorAccountBinding** — DID↔account bindings that prevent redirection.
- **Escrow (Lock/Release/Refund)** — hold funds, then release on delivery or refund on timeout.
- **CAIP-2/10/19** — chain / account / asset identifiers for on-chain rails.

## Try it

```powershell
.venv\Scripts\python spec\conformance.py | findstr /C:"WCP-CHN" /C:"WCP-PSP"
ls spec\settlement\test-vectors            # SettlementProof (on-chain) vs AttestedSettlementProof (processor)
```

`WCP-CHN` lines certify the on-chain rails and `WCP-PSP` the closed-processor ones — including
the anti-redirection refusal — all from real signed proofs.

---

**Next:** Tutorial 10 — *Interop: SD-JWT-VC & AP2.*
