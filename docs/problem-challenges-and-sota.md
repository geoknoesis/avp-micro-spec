# Problem, Challenges, and State of the Art

This document describes the problem **AVP-Micro** (Agent Verifiable Micropayments) is meant to address, the practical challenges that block today’s systems from solving it, and the current state of the art in standards and products. It complements the four normative specification bundles under [`spec/`](../spec/):

- **[Delegated Spending Authority (DSA)](../spec/authority/index.html)** — identity, the `SpendingAuthorizationCredential`, securing mechanisms, and the issuer trust framework.
- **[AVP-Micro Payments](../spec/payments/index.html)** — signed quotes, authorizations, executions, receipts, and streaming/session metering, built on DSA.
- **[AVP-Micro ⇄ SD-JWT-VC interop](../spec/interop-sd-jwt-vc/index.html)** — the bridge that carries spending authority across the SD-JWT-VC stack used by Mastercard/Google **Verifiable Intent** and Google **AP2**.
- **[AVP-Micro Disputes](../spec/disputes/index.html)** — the reverse value-flow: refunds, reversals, chargebacks, and the dispute lifecycle, built on Payments + DSA.

A shared conformance harness and signed test vectors exercise all four, and a protocol simulator enforces the runtime behaviour (single-use consumption, replay rejection, caps, budgets, request binding) that static vectors cannot.

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

| Challenge | Why it matters | How AVP-Micro addresses it |
|-----------|----------------|----------------------------|
| **Unit economics** | Per-transaction fees on cards and some chains dominate when the payment itself is tiny. Micropayment designs must combine **batching**, **streaming/session budgets**, or **low-fee rails** with realistic pricing models. | **Payments** defines a streaming/session-metering mode with signed accruals and session budgets, plus a pricing-model vocabulary (flat, per-call, tiered, composite). Because settlement is left to any rail, low-fee rails plug in without changing the authorization semantics. |
| **Liquidity and onboarding** | Agents need funded instruments or delegated access without a human in the loop every time. Custody, compliance, and KYC boundaries vary by jurisdiction. | **DSA** lets a principal delegate *bounded* authority once — caps, payee allowlists, categories, time windows — so the agent transacts repeatedly with no human in the loop. Custody/KYC stay in the settlement layer (out of scope by design), keeping the trust layer jurisdiction-neutral. |
| **Merchant integration cost** | Each new payment method historically required bespoke integration. Agent commerce needs **repeatable** integration patterns. | One credential grammar and one signed-message set serve every rail; a payee verifies a DID-anchored credential with no bilateral integration. The **interop** bridge maps the same authority into the SD-JWT-VC stack, so a merchant already on Verifiable Intent / AP2 integrates once. |

### 2.2 Technical challenges

| Challenge | Why it matters | How AVP-Micro addresses it |
|-----------|----------------|----------------------------|
| **Latency vs. security** | Strong cryptography and verification add latency. High-frequency agents need **caching**, **session-based authorization**, and **clear trust boundaries** between “check once” and “pay many times.” | The **DSA** credential is the "check once" trust anchor; **Payments** binds each charge with a lightweight per-request proof ("pay many"). The streaming/session mode amortizes verification across a session rather than re-establishing trust per call. |
| **Replay and binding** | Quotes and authorizations must be bound to **specific requests** (hashes, nonces, short expiry) so old approvals cannot be replayed against new charges. | **Payments** binds every payment to a `requestHash` and `quoteDigest`, with nonces and short `expires`. The **simulator** enforces single-use consumption and rejects replayed authorizations and stale quotes at runtime — behaviour the static vectors don't exercise. |
| **Metering honesty** | In streaming or usage-based models, the payee often **meters** consumption. Without signed accruals and session budgets, disputes over “what was used” are hard to resolve. | **Payments** defines signed accruals and session budgets over a metering-dimension SKOS scheme, so each increment is attributable. When a metered total is still contested, the **Disputes** bundle provides the reverse-flow and an auditable lifecycle to resolve it. |
| **Revocation and status** | Spending rights change. Credentials can be revoked; sessions can be closed. Systems need **status mechanisms** and wallet behavior that matches real operations. | **DSA** carries credential status via `BitstringStatusList`; the **simulator** exercises wallet behaviour for revoked credentials and closed sessions, so revocation is a tested operation, not just a field. |

### 2.3 Trust and interoperability challenges

| Challenge | Why it matters | How AVP-Micro addresses it |
|-----------|----------------|----------------------------|
| **Fragmented identity** | Without portable identity, every platform becomes its own root of trust for “which agent may spend.” | **DSA** identifies every party by **DID** and proves authority by verifying an issuer-signed VC against that DID — no per-platform account is the root of trust. The same credential is recognizable across independent merchants. |
| **Opaque delegation** | If delegation is only “this bearer token is valid,” verifiers cannot enforce **fine-grained policy** or produce **auditable evidence** for compliance. | The `SpendingAuthorizationCredential` carries **explicit, machine-verifiable policy** — caps, payee allowlists, service categories, time windows — so verifiers enforce fine-grained limits and retain the signed credential as audit evidence rather than a bare bearer token. |
| **Cross-domain verification** | A merchant or wallet should verify authority **without** a pre-existing bilateral integration with the principal’s IT—ideally using **open formats** and **standard verification** steps. | Verification is a standard W3C check: resolve the issuer DID, verify the `ecdsa-jcs-2022` proof, evaluate the policy — no bilateral integration required. The **interop** bundle extends this *across ecosystems*, transcoding the same authority to/from SD-JWT-VC (Verifiable Intent / AP2) so it verifies on either stack. |

### 2.4 Operational and regulatory challenges

| Challenge | Why it matters | How AVP-Micro addresses it |
|-----------|----------------|----------------------------|
| **Audit trails** | Enterprises need to show **who authorized what** and **which service was paid**—aligned with existing expectations for procurement and financial controls. | Every message is a signed object binding authorization → execution → receipt; the **Disputes** bundle continues the same append-only signed chain through refunds, reversals, and chargebacks. "Who authorized what, what was delivered, and what was returned" is reconstructable from signatures alone. |
| **Privacy** | Payment metadata correlates agents, principals, and behavior. Designs should support **minimal disclosure** and, where appropriate, selective disclosure or rotation of identifiers. | AVP-Micro objects carry only payment-adjacent terms, and DIDs can be rotated. When authority is bridged to the SD-JWT-VC stack, the **interop** profile preserves that stack's **selective disclosure**, so a verifier sees only the claims it needs. |
| **Liability allocation** | Principals, wallet operators, and merchants need clarity on who bears loss when keys leak, credentials are mis-issued, or settlement fails after authorization. Standards help; contracts still matter. | The **DSA** trust framework names the issuer/wallet/verifier roles and the evidence each produces; signed, attributable records make fault traceable (mis-issuance, replayed authorization, contested delivery). Loss allocation still rests on contracts — the spec supplies the evidence, not the legal terms. |

### 2.5 Failure modes when the problem is ignored

Each failure mode maps to a mechanism in the bundles that prevents it:

- **Overspending** or paying unintended counterparties (no enforceable policy). → **DSA** caps, payee allowlists, categories, and time windows, enforced by the wallet policy engine and exercised by the **simulator**.
- **Fraud** (malicious payees, confused deputy, replayed authorizations). → **Payments** request binding (`requestHash`/`quoteDigest`), nonces and short expiry, and DID-anchored verification of the issuer; replay and stale-quote rejection are enforced at runtime.
- **Poor dispute resolution** (no cryptographic binding between payment and delivered output). → the **Disputes** bundle binds payment, delivery (receipt), and a wallet-signed **reversal** into one signed chain, with an explicit dispute lifecycle and an optional arbiter.
- **Vendor lock-in** (agent cannot move to another wallet or rail without re-onboarding every merchant). → a portable, rail-neutral credential grammar plus the **interop** bridge across competing ecosystems (Verifiable Intent / AP2).

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

### 3.6 Agent-payment authorization protocols (the direct competitors)

Since 2024 a wave of **agentic-commerce** and **agent-payment** protocols has emerged. Most operate at a *different layer* than AVP-Micro — they orchestrate checkout or move money — and only a few compete head-on with AVP-Micro's actual job: a portable, merchant-verifiable **spending mandate**. Sorting them by layer makes the overlap precise.

**Same layer — signed authorization mandates (direct competitors)**

- **AP2 — Agent Payments Protocol** (Google, with 60+ partners). Defines **Intent**, **Cart**, and **Payment** mandates, each a **W3C Verifiable Credential** signed by the user's wallet or the agent's key. This is the closest analog to AVP-Micro's DSA + `SpendingAuthorizationCredential`, and AVP-Micro already treats it as an **interop target** rather than a pure rival: the [interop bundle](../spec/interop-sd-jwt-vc/index.html) transcodes the same authority to and from the SD-JWT-VC carrier AP2 uses. AP2 is rapidly becoming the de-facto payment-authorization layer that the orchestration protocols below compose onto.
- **Skyfire — KYA / KYAPay** ("Know Your Agent"). Issues signed JWTs carrying verified agent identity — who built it, which human authorized it, what it may do, and how it can pay — with OAuth2/OIDC compatibility over a stablecoin rail. As of late 2025 it is the identity layer for **Experian's Know-Your-Agent** framework. It targets the same job-to-be-done as DSA, but encodes the mandate as a KYA JWT rather than a W3C VC carrying an `ecdsa-jcs-2022` proof.

**Adjacent — commerce / checkout orchestration (compose onto a payment-auth layer)**

- **ACP — Agentic Commerce Protocol** (OpenAI + Stripe; Apache 2.0). Optimized for conversational "chat-to-buy" in ChatGPT. It **bundles** checkout and payment via a Stripe **Shared Payment Token** rather than a signed credential — so it competes on *how intent is authorized*, but with a delegated-token model instead of a verifiable mandate.
- **UCP — Universal Commerce Protocol** (Google + Shopify; launched at NRF in Jan 2026 with 20+ retailers, incl. Etsy, Wayfair, Target, Walmart, Klarna). A surface-agnostic standard for the full shopping journey. It deliberately **separates** checkout from payment and plugs into **AP2** for authorization (plus MCP for tool access and A2A for cross-agent delegation) — making it a *consumer* of the mandate layer AVP-Micro occupies, not a rival to it.

**Network-specific implementations (commercial, on card rails)**

- **Mastercard Agent Pay** (announced Apr 2025) — verified agents transact via **Agentic Tokens**.
- **Visa Intelligent Commerce / Trusted Agent Protocol (TAP)** — agent-authorized payments on Visa rails.

These are productized implementations layered on card networks rather than open trust-layer specifications; they compete commercially but not as open, third-party-verifiable mandate formats.

**Settlement rails.** x402 (Coinbase), L402/Lightning, and Stripe's MPP are covered in [§3.3](#33-http-402-and-pay-in-band-protocols); they sit *below* the authorization layer and are complementary (AP2 itself ships an x402 settlement extension). AVP-Micro scopes settlement out by design, so these are bridge targets, not competitors.

**How AVP-Micro is positioned**

| Protocol | Primary layer | Authorization model | Relationship to AVP-Micro |
|----------|---------------|---------------------|---------------------------|
| **AVP-Micro** | Trust + delegated authorization | W3C VC mandate (`SpendingAuthorizationCredential`), `ecdsa-jcs-2022`, settlement-agnostic | — |
| **AP2** | Trust + authorization | W3C VC mandates (Intent / Cart / Payment) | Closest analog; **interop target** via the SD-JWT-VC bridge |
| **Skyfire KYA / KYAPay** | Identity + authorization + rail | Signed KYA JWT, OAuth2/OIDC | Direct competitor at the mandate layer; candidate bridge target |
| **ACP** | Commerce orchestration + payment | Stripe Shared Payment Token | Competes on intent authorization; token model, not a VC |
| **UCP** | Commerce orchestration | Delegates to AP2 | Composes *onto* the mandate layer; not a rival |
| **Mastercard Agent Pay** | Card-rail implementation | Agentic Tokens | Commercial competitor at the rails layer |
| **Visa Intelligent Commerce / TAP** | Card-rail implementation | Network-specific | Commercial competitor at the rails layer |
| **x402 / L402 / MPP** | Settlement (HTTP 402) | Rail-specific challenge | Complementary; bridge / settlement target |

Two observations follow. First, there is **no single dominant *open* standard for the delegated-authorization layer specifically** — AP2 is the front-runner and is consolidating the field (UCP composes onto it; the card networks implement beneath it). Second, AVP-Micro's defensible niche is exactly what the orchestration-first protocols under-specify: **micropayment and streaming semantics** (signed accruals, session budgets, single-use consumption, replay rejection, caps and budgets) enforced at runtime, plus a **mandatory-to-implement cryptosuite** rather than "some verifiable credential." The interop bundle is the strategic hedge — AVP-Micro need not *displace* AP2 to be useful; it rides AP2's carrier while adding the micro-/streaming-payment and dispute machinery AP2 leaves open. Skyfire KYA and the ACP Shared Payment Token are natural next bridge/mapping targets for the same reason.

### 3.7 Synthesis: what SOTA covers vs. what is still missing

| Layer | Largely addressed by SOTA | Still underspecified for cross-vendor agent commerce |
|--------|---------------------------|------------------------------------------------------|
| **Settlement** | Open Payments, LN, stablecoin flows, MPP-style HTTP 402 | Choosing one rail is not enough; principals need **policy** that survives rail changes |
| **HTTP challenge patterns** | x402, MPP, L402 | Same **authorization semantics** across rails and merchants |
| **Signing / replay protection** | HTTP Message Signatures, DPoP | Binding **quotes**, **sessions**, and **accruals** into one auditable story |
| **Portable identity & mandates** | DID / VC standards (general purpose) | **Payment-specific profiles** (spending caps, payee allowlists, session budgets) as **normative** interop artifacts |
| **Cross-ecosystem mandates** | SD-JWT-VC stacks (Verifiable Intent, AP2) and DID/VC stacks each internally coherent | A **normative bridge** so one agent's authority verifies on *either* stack without re-issuance |
| **Refunds & disputes** | Card chargeback regimes; rail-specific reversals | A **cross-vendor, cryptographically-bound reverse value-flow** (refund/reversal/chargeback) tied to the original authorization and receipt |

AVP-Micro targets that last row: a **concrete**, **composable** trust and authorization layer that sits **above** settlement and **beside** HTTP payment challenge protocols.

---

## 4. How this document relates to AVP-Micro

- **Problem:** machine-native micropayments need **portable identity**, **verifiable delegation**, and **auditable** linkage between authorization, settlement, and delivery.
- **Challenges:** economics, latency, metering, revocation, fragmentation, compliance, and dispute resolution.
- **SOTA:** strong movement on **rails** and **HTTP payment challenges**; mature **DID/VC** foundations; **gap** in widely shared **credential and message profiles** for agent spending at scale.

The AVP-Micro bundles fill that gap, end to end:

- **Delegated Spending Authority** defines the portable identity and the `SpendingAuthorizationCredential` (caps, allowlists, categories, windows, revocation) — the *who* and *under what authority*.
- **AVP-Micro Payments** defines the forward value-flow messages (quotes, authorizations, executions, receipts, sessions, accruals) bound to specific requests — the *did value move, and what was delivered*.
- **AVP-Micro Disputes** defines the reverse value-flow (refunds, reversals, chargebacks, dispute lifecycle) — closing the loop when delivery is contested or value must be returned.
- **AVP-Micro ⇄ SD-JWT-VC interop** carries the same authority across the SD-JWT-VC ecosystems (Verifiable Intent / AP2), so the trust layer is not captive to one credential stack.

All four plug in **any** settlement technology, and a conformance harness with signed test vectors and a protocol simulator demonstrates the guarantees rather than merely asserting them.

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
| SD-JWT and SD-JWT VC (selective disclosure) | <https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc.html> |
| Google Agent Payments Protocol (AP2) | <https://github.com/google-agentic-commerce/AP2> |
| Agentic Commerce Protocol (ACP, OpenAI + Stripe) | <https://github.com/agentic-commerce-protocol/agentic-commerce-protocol> |
| Universal Commerce Protocol (UCP, Google + Shopify) | <https://github.com/universal-commerce-protocol/ucp> |
| Skyfire KYAPay / Know Your Agent | <https://skyfire.xyz/> |
| Coinbase x402 (HTTP 402 stablecoin payments) | <https://www.x402.org/> |
| Mastercard Agent Pay | <https://www.mastercard.com/news/press/2025/april/mastercard-unveils-agent-pay/> |
| Visa Intelligent Commerce | <https://corporate.visa.com/en/products/intelligent-commerce.html> |
| BitstringStatusList (credential status) | <https://www.w3.org/TR/vc-bitstring-status-list/> |

---

*Document maintained as part of the AVP-Micro work. Author: Stephane Fellah, Geoknoesis LLC.*
