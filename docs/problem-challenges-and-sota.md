# Problem, Challenges, and State of the Art

This document describes the problem **AVP-Micro** (Agent Verifiable Micropayments) is meant to address, the practical challenges that block today’s systems from solving it, and the current state of the art in standards and products. It complements the normative specifications under [`spec/`](../spec/) — [Delegated Spending Authority](../spec/authority/index.html) and [AVP-Micro Payments](../spec/payments/index.html) — and the narrative draft [`avp-micro.md`](../avp-micro.md).

---

## 1. The problem in detail

### 1.1 The shift to autonomous economic actors

Software is increasingly able to act on its own: call APIs, chain tools, purchase data or compute, and negotiate access in real time. These **autonomous agents** are not human end users. They do not have passports, credit histories, or patience for billing portals. Yet they participate in the same economy as people and businesses: they need to **pay for marginal resources** (tokens, rows, minutes, inference calls) at a pace and granularity humans never needed.

That creates a **machine-native payments** requirement: high frequency, small amounts, programmatic authorization, and minimal friction—without giving every agent unlimited access to a real bank account or corporate card.

### 1.2 Three questions every serious deployment must answer

Any architecture for agent payments must answer, in a **verifiable** way:

1. **Who is paying (or acting)?**  
   Not just “which API key,” but an identity that can be recognized across services and audits, bound to cryptographic keys.

2. **Under what authority?**  
   The agent should spend **only** within rules a principal (person or organization) has set: per-transaction caps, daily limits, allowed counterparties, categories of service, time windows, and revocation.

3. **Did value move, and what was delivered?**  
   Settlement (money or ledger movement) is distinct from authorization. After payment, there should be a **clear link** between agreed terms, execution, and delivery—supporting reconciliation and dispute handling.

Traditional stacks often collapse these questions into a single vendor account or opaque bearer token. That is fragile for agents at scale.

### 1.3 Why “just use cards / OAuth / API keys” is insufficient

- **Cards and bank rails** were designed for human consent patterns, chargeback regimes, and fee structures that punish true **micropayments** (fractions of a cent to a few cents per action).
- **OAuth2 and API keys** express **access** to an API, not necessarily **spending policy** under a principal’s mandate. Delegation is often coarse, revocable only inside one IdP, and not naturally **portable** across independent merchants.
- **Platform wallets** solve flow for one ecosystem but reinforce **lock-in**: each marketplace defines its own notion of identity, limits, and audit logs.

Agents that operate **across organizations** need a layer that works **above** any single rail or merchant stack.

### 1.4 The architectural insight AVP-Micro uses

**Separate trust from settlement.**

- **Trust layer:** portable identifiers (DIDs), machine-verifiable delegation (VCs), and signed messages that bind quotes and authorizations to specific requests.
- **Settlement layer:** whatever moves value—Open Payments/ILP, Lightning, stablecoin transfers, card rails, internal ledgers—chosen per deployment.

If this separation is explicit, the same authorization semantics can be reused when the underlying rail changes, and multiple rails can coexist behind one wallet policy engine.

---

## 2. Current challenges

### 2.1 Economic and product challenges

| Challenge | Why it matters |
|-----------|----------------|
| **Unit economics** | Per-transaction fees on cards and some chains dominate when the payment itself is tiny. Micropayment designs must combine **batching**, **streaming/session budgets**, or **low-fee rails** with realistic pricing models. |
| **Liquidity and onboarding** | Agents need funded instruments or delegated access without a human in the loop every time. Custody, compliance, and KYC boundaries vary by jurisdiction. |
| **Merchant integration cost** | Each new payment method historically required bespoke integration. Agent commerce needs **repeatable** integration patterns. |

### 2.2 Technical challenges

| Challenge | Why it matters |
|-----------|----------------|
| **Latency vs. security** | Strong cryptography and verification add latency. High-frequency agents need **caching**, **session-based authorization**, and **clear trust boundaries** between “check once” and “pay many times.” |
| **Replay and binding** | Quotes and authorizations must be bound to **specific requests** (hashes, nonces, short expiry) so old approvals cannot be replayed against new charges. |
| **Metering honesty** | In streaming or usage-based models, the payee often **meters** consumption. Without signed accruals and session budgets, disputes over “what was used” are hard to resolve. |
| **Revocation and status** | Spending rights change. Credentials can be revoked; sessions can be closed. Systems need **status mechanisms** and wallet behavior that matches real operations. |

### 2.3 Trust and interoperability challenges

| Challenge | Why it matters |
|-----------|----------------|
| **Fragmented identity** | Without portable identity, every platform becomes its own root of trust for “which agent may spend.” |
| **Opaque delegation** | If delegation is only “this bearer token is valid,” verifiers cannot enforce **fine-grained policy** or produce **auditable evidence** for compliance. |
| **Cross-domain verification** | A merchant or wallet should verify authority **without** a pre-existing bilateral integration with the principal’s IT—ideally using **open formats** and **standard verification** steps. |

### 2.4 Operational and regulatory challenges

| Challenge | Why it matters |
|-----------|----------------|
| **Audit trails** | Enterprises need to show **who authorized what** and **which service was paid**—aligned with existing expectations for procurement and financial controls. |
| **Privacy** | Payment metadata correlates agents, principals, and behavior. Designs should support **minimal disclosure** and, where appropriate, selective disclosure or rotation of identifiers. |
| **Liability allocation** | Principals, wallet operators, and merchants need clarity on who bears loss when keys leak, credentials are mis-issued, or settlement fails after authorization. Standards help; contracts still matter. |

### 2.5 Failure modes when the problem is ignored

- **Overspending** or paying unintended counterparties (no enforceable policy).
- **Fraud** (malicious payees, confused deputy, replayed authorizations).
- **Poor dispute resolution** (no cryptographic binding between payment and delivered output).
- **Vendor lock-in** (agent cannot move to another wallet or rail without re-onboarding every merchant).

---

## 3. State of the art (SOTA)

This section surveys **directionally relevant** standards and initiatives. It is not an exhaustive product catalog; it frames **what exists** and **what gap remains** for AVP-Micro-style trust layers.

### 3.1 Account-to-account and open banking style APIs

**Open Payments** (Interledger ecosystem) standardizes HTTP-oriented flows around payment pointers, quotes, incoming/outgoing payments, and related resource semantics. It is **rail- and currency-agnostic** in intent and fits programmable, account-based settlement.

**GNAP** (Grant Negotiation and Authorization Protocol) generalizes **delegated authorization** to resources (including payment-related grants). It improves on older OAuth patterns for some use cases but is not, by itself, a universal **spending mandate** format verifiable by arbitrary third-party merchants.

**Relevance:** Strong for **moving money** and **API-shaped** integration; **policy expressiveness** and **portable merchant-verifiable mandates** are still often layered separately.

### 3.2 Streaming and web monetization

**Web Monetization** (Interledger-oriented) enables **streaming-style** payments to creators and similar recipients, often tied to browser or agent-like consumption patterns.

**Relevance:** Validates demand for **continuous micro-flows**; trust and identity semantics are not the same as a full **VC-backed spending authorization** model for arbitrary B2B APIs.

### 3.3 HTTP 402 and “pay in band” protocols

**HTTP 402 Payment Required** has re-emerged as a carrier for payment challenges.

- **Lightning (e.g. L402-style flows):** invoice + macaroon or similar constructs for **fast** Lightning settlement; strong for Bitcoin/LN ecosystems.
- **Coinbase x402 and similar:** HTTP 402 with **stablecoin** or token transfer semantics, aiming for **low-friction** agent round-trips.
- **Stripe Machine Payments Protocol (MPP):** HTTP 402 with structured payment challenges, **multiple rails** (e.g. cards, Lightning, stablecoins), and concepts like **one-shot** vs **session** intents.

**Relevance:** These advances **standardize how to ask for payment over HTTP** and **how to complete a charge** on specific rails. They do not, by themselves, replace a **cross-ecosystem** representation of **who the payer agent is** and **what spending rules** a principal has issued—especially when the verifier is not the same organization as the wallet issuer.

### 3.4 Request integrity and sender binding

- **RFC 9421 (HTTP Message Signatures):** end-to-end request integrity and authentication building blocks.
- **RFC 9449 (OAuth DPoP):** proof-of-possession for OAuth tokens bound to client keys.

**Relevance:** Essential **plumbing** for non-repudiation and replay resistance when AVP-Micro messages are carried over HTTP-based APIs.

### 3.5 Decentralized identifiers and verifiable credentials

**W3C Decentralized Identifiers (DIDs)** provide **globally resolvable**, cryptographically grounded identifiers without mandating a single central registry.

**W3C Verifiable Credentials (VCs)** provide a **standard data model** for tamper-evident claims (including who issued them and about whom), with presentations verifiable by third parties.

**Industry direction:** Major agent-commerce and delegated-payment narratives (e.g. initiatives in large tech and consortia) increasingly reference **DIDs/VCs** or adjacent identity layers for **mandates** and **machine-verifiable policy**.

**Relevance:** AVP-Micro intentionally **composes** these standards rather than inventing a parallel identity stack.

### 3.6 Synthesis: what SOTA covers vs. what is still missing

| Layer | Largely addressed by SOTA | Still underspecified for cross-vendor agent commerce |
|--------|---------------------------|------------------------------------------------------|
| **Settlement** | Open Payments, LN, stablecoin flows, MPP-style HTTP 402 | Choosing one rail is not enough; principals need **policy** that survives rail changes |
| **HTTP challenge patterns** | x402, MPP, L402 | Same **authorization semantics** across rails and merchants |
| **Signing / replay protection** | HTTP Message Signatures, DPoP | Binding **quotes**, **sessions**, and **accruals** into one auditable story |
| **Portable identity & mandates** | DID / VC standards (general purpose) | **Payment-specific profiles** (spending caps, payee allowlists, session budgets) as **normative** interop artifacts |

AVP-Micro targets that last row: a **concrete**, **composable** trust and authorization layer that sits **above** settlement and **beside** HTTP payment challenge protocols.

---

## 4. How this document relates to AVP-Micro

- **Problem:** machine-native micropayments need **portable identity**, **verifiable delegation**, and **auditable** linkage between authorization, settlement, and delivery.
- **Challenges:** economics, latency, metering, revocation, fragmentation, compliance.
- **SOTA:** strong movement on **rails** and **HTTP payment challenges**; mature **DID/VC** foundations; **gap** in widely shared **credential and message profiles** for agent spending at scale.

The AVP-Micro specification defines those profiles and messages (offers, quotes, authorizations, executions, receipts, sessions, accruals) so implementations can interoperate while plugging in **any** settlement technology.

---

## 5. References (informative)

| Topic | Pointer |
|--------|---------|
| W3C Verifiable Credentials Data Model | <https://www.w3.org/TR/vc-data-model/> |
| W3C Decentralized Identifiers | <https://www.w3.org/TR/did-core/> |
| Open Payments | <https://openpayments.guide/> |
| HTTP Message Signatures (RFC 9421) | <https://www.rfc-editor.org/rfc/rfc9421> |
| OAuth DPoP (RFC 9449) | <https://www.rfc-editor.org/rfc/rfc9449> |
| GNAP | IETF work on Grant Negotiation and Authorization Protocol |

---

*Document maintained as part of the AVP-Micro work. Author: Stephane Fellah, Geoknoesis LLC.*
