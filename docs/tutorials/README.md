# AVP-Micro Tutorials

A guided path from "what is a payment?" to "I can build and certify a wallet on this stack."
Each tutorial is self-contained, builds on the previous one, and links to the exact spec
artifacts, test vectors, and runnable code it describes.

## Who this is for

- **Engineers** integrating agent payments (building a wallet, a payee/service, or a rail).
- **Architects** evaluating the trust and settlement model.
- **Curious readers** who want to understand how money moves — for AI agents and in general.

No prior payments knowledge is assumed. Cryptography is introduced from first principles.

> **Read them on the website:** <https://geoknoesis.github.io/avp-micro-spec/tutorials/> — the
> same Markdown rendered with the site's styling, navigation, and Mermaid diagrams. (These
> `.md` files are the source; the site reader loads them directly.)

## The path

| # | Tutorial | You'll learn |
|---|----------|--------------|
| **01** | [Introduction to Digital Payments](01-introduction-to-digital-payments.md) | What a payment really is; authorize vs clear vs settle; the rail families; finality and risk. **(start here)** |
| 02 | [Why AI-Agent Payments Are Different](02-why-agent-payments-are-different.md) | Delegation, autonomy, micro-amounts, and the trust gaps cards/wallets weren't built for. |
| 03 | [The AVP-Micro Stack at a Glance](03-the-stack-at-a-glance.md) | The six bundles and how a single payment flows through all of them. |
| 04 | [Identity & Cryptography](04-identity-and-cryptography.md) | DIDs, `did:key`, JCS canonicalization, `ecdsa-jcs-2022`, Data Integrity proofs — by hand. |
| 05 | [Delegated Spending Authority](05-delegated-spending-authority.md) | The mandate: `SpendingAuthorizationCredential`, caps, allow-lists, and the trust framework. |
| 06 | [The Payment Lifecycle](06-the-payment-lifecycle.md) | quote → authorize → execute → receipt, and the bindings that make it safe. |
| 07 | [Streaming & Metered Payments](07-streaming-and-metered-payments.md) | Sessions, budgets, accruals, and pay-per-token. |
| 08 | [The HTTP 402 Transport Binding](08-http-402-transport.md) | Discovery, the 402 challenge, idempotency, signed errors, anti-replay. |
| 09 | [Settlement](09-settlement.md) | On-chain rails (EVM/x402/Lightning) and closed-processor rails (cards, bank, PayPal, Visa Direct / Mastercard Send); attestation and finality. |
| 10 | [Interop](10-interop.md) | Bridging SD-JWT-VC and Google AP2 IntentMandates into AVP-Micro. |
| 11 | [Refunds, Reversals & Disputes](11-refunds-reversals-disputes.md) | The reverse value-flow and the adversarial dispute lifecycle. |
| 12 | [Revocation & Status](12-revocation-and-status.md) | Bitstring Status Lists, freshness, and revoke-mid-flight. |
| 13 | [Conformance](13-conformance.md) | The Wallet Conformance Profile and certifying your own wallet. |
| 14 | [Hands-on](14-hands-on.md) | Run the simulator and the live `server.py`, and write a `WalletAdapter`. |

## How to use them

- Read **01–03** for the mental model. Read **04–06** to understand the core protocol.
- Skip to the bundle you're integrating (07–12) once you have the core.
- **13–14** are for implementers proving conformance.
- Every claim links to a spec section, a signed test vector, or runnable code, so you can
  verify it yourself with `python spec/verify.py` / `validate.py` / `conformance.py`.

> Status: **all 14 tutorials are written.** The series is complete; corrections and additions welcome.
