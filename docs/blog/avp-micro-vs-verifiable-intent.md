# Two Ways to Prove an Agent May Spend: AVP-Micro vs. Verifiable Intent

*Both specs answer the same question — "who authorized this agent, and within what limits?" — and they answer it with almost opposite machinery. Here's how they line up.*

---

In the space of a single quarter in 2026, the question of how an autonomous agent proves it's allowed to spend money stopped being theoretical. Two serious specifications now answer it. They were written by very different rooms — one a standards-first project built on W3C primitives, the other a partnership between the world's second-largest card network and the company that ships the world's most-used agent runtime — and that difference shows up in almost every design choice.

This post puts them side by side:

- **AVP-Micro** — two peer specifications (Delegated Spending Authority + AVP-Micro Payments), built on W3C Verifiable Credentials, DIDs, and JSON-LD Data Integrity proofs. Rail-agnostic, vendor-neutral, submission-candidate.
- **Verifiable Intent (VI)** — the open-source trust layer (Mastercard + Google, March 2026) underneath Mastercard's *Agent Pay for Machines* network. Built on SD-JWT VC and JOSE. Aligned with Google's Agent Payments Protocol (AP2).

They are not the same kind of thing, they don't share a wire format, and yet they're solving the same problem. Both of those facts matter.

## The thing they agree on

Strip away the encodings and the two specs describe the *same shape*: a **cryptographically verifiable chain of delegated authority**, running from a principal who owns the money, through a human or organizational authorization, down to the agent that actually transacts — such that any party in the chain can verify the agent stayed within bounds, after the fact, without phoning home to the issuer.

VI expresses that chain as three layers:

1. **L1** — an issuer-signed credential binding the user's identity and key.
2. **L2** — a user-signed token expressing purchase intent ("I approve this").
3. **L3** — an agent-signed token (autonomous mode) proving the agent acted inside that intent.

AVP-Micro expresses essentially the same idea as an issuer-signed `SpendingAuthorizationCredential` (the principal's mandate to the agent), which the agent then embeds inside a signed `PaymentAuthorization` when it accepts a merchant's quote.

In both, the load-bearing insight is identical: **intent and authority become cryptographic primitives**, not database rows. That convergence is the real headline. Two independent teams, starting from opposite tooling traditions, agreed that agent payments need a portable, tamper-evident proof of "who said this agent could spend."

## The thing they disagree on: the entire stack

Here's where they diverge — and it's not a detail, it's the whole substrate.

| | **AVP-Micro** | **Verifiable Intent / AP2** |
|---|---|---|
| Credential format | W3C VC Data Model 2.0, JSON-LD | SD-JWT VC (IETF), three-layer `KB-SD-JWT` chain |
| Proof / signing | Data Integrity, `eddsa-jcs-2022` (Ed25519) | `ES256` (ECDSA P-256), JOSE, `sd_hash` layer binding |
| Credential typing | JSON-LD `@context` + `type` | `vct` claim (SD-JWT-VC profile) |
| Identity | DIDs (`did:key` mandatory-to-implement) | `iss` / `sub` URIs, opaque `kid` — **no DIDs** |
| Selective disclosure | Whole-credential proof (no native SD) | **Native** (`_sd` digests) |
| Semantic layer | RDF / OWL ontology, SHACL shapes | None — JSON claims |
| Trust anchor | Any issuer, verified via DID | Issuer = financial institution / payment network |
| Scope | Identity **+** full payment flow (quote → auth → execute → receipt, plus streaming) | Authorization/intent attestation; settlement handled by the surrounding network |
| Governance | Open W3C standards, no operator | Open-source (Apache-2.0), Mastercard/Google-led |

This is the old fault line in the credentials world, surfacing in a new place: **JSON-LD + Data Integrity** versus **JOSE + SD-JWT**. AVP-Micro sits squarely in the first camp; VI and AP2 in the second. The well-funded corner of agentic commerce has, for now, planted its flag on the JOSE side.

The practical consequence is blunt: **a `SpendingAuthorizationCredential` cannot be verified by an SD-JWT-VC verifier, and a VI L1/L2/L3 chain cannot be verified by an `eddsa-jcs-2022` verifier.** They share a concept and nothing else on the wire. Interop between them requires a bridge — a translator that maps policy semantics across and reconciles two different identity models — not a shared library.

## Where each one is genuinely stronger

It would be easy, and wrong, to declare a winner. They optimize for different things.

**Verifiable Intent plays to ubiquity and disclosure.** SD-JWT VC rides on JOSE — the same `ES256`/JWT machinery already in every payment SDK, every FIDO deployment, every OAuth stack. There's no JSON-LD processor, no RDF canonicalization, no context-resolution step. And selective disclosure is *native*: a holder can reveal "spending cap = $5/day" while withholding the user's identity, by construction. Sitting under Mastercard's network, VI also inherits something AVP-Micro deliberately doesn't provide — **guaranteed settlement, tokenization, and fraud controls** — plus thirty-odd launch partners and a distribution channel most standards never get. If your world is cards, FIs, and the existing payments rail, VI meets you exactly where you already are.

**AVP-Micro plays to neutrality and semantics.** Its trust anchor is a DID, not a financial institution. *Any* issuer can grant authority and *any* verifier can check it, with no privileged operator in the middle — which is precisely the property you want when the whole point is to transact across organizations that haven't pre-integrated. Because credentials are JSON-LD with an OWL ontology and SHACL shapes, the spending semantics — caps, allowed payees, time windows, pricing models — are *machine-checkable and self-describing*, not just claims two parties agreed to interpret the same way. And critically, AVP-Micro specifies the **full payment lifecycle**, not just the authorization: signed offers and quotes bound to a request hash, the authorization, rail-agnostic settlement, signed receipts, and a streaming/session mode for metered usage. VI attests *intent*; AVP-Micro attests intent **and** carries the payment.

> **Sidebar: "Open" is doing two different jobs here**
>
> Both specs call themselves open, and both are — but in different senses. VI is *open-source*: an Apache-2.0 spec and reference implementation you can read, fork, and run, governed by Mastercard and Google. AVP-Micro is *open-standard*: it composes only ratified, vendor-neutral W3C and IETF building blocks, with no operator in the trust path at all. The first gives you transparency and a reference to build against. The second gives you independence from any single operator's network. Which kind of "open" you need depends on whether your concern is *inspectability* or *neutrality*.

## So which should you reach for?

The honest answer is that the choice tracks your *trust model*, not your feature checklist.

Reach for **Verifiable Intent / AP2** when you're building inside the card-and-FI world, want native selective disclosure and ubiquitous JOSE tooling, and value being on the rail Mastercard and Google are actively scaling — settlement guarantees included. You're accepting an issuer-anchored trust model (your authority is rooted in an FI / network) in exchange for reach and batteries-included settlement.

Reach for **AVP-Micro** when you need authority that's portable *across* networks and organizations with no privileged operator, want the spending policy itself to be machine-verifiable and auditable from the artifacts alone, and need the full signed lifecycle — quote, authorization, settlement, receipt, streaming — rather than just an intent attestation. You're accepting JSON-LD's heavier tooling and the minority encoding in exchange for genuine vendor-neutrality and richer semantics.

And there's a third stance worth naming, because it may be the most realistic: **use both.** AVP-Micro was designed as a rail-agnostic trust layer that sits *above* settlement networks. Nothing stops Mastercard's Agent Pay for Machines from being one of the rails underneath an AVP-Micro authorization — the way Lightning or Interledger already are. That requires a bridge between the two credential stacks (the encodings won't round-trip on their own), but the *semantics* — caps, allowed payees, expiry, revocation — map cleanly. In a world that's clearly going to have more than one agent-payment network, the open question isn't "which spec wins," it's "what's the neutral grammar that lets an agent's authority travel across all of them."

That last question is the one AVP-Micro was built to answer. Verifiable Intent answers a narrower, nearer-term one — and answers it with real distribution behind it. Both are right about the same thing: the money was never the hard part. Proving who's allowed to move it is.

---

*AVP-Micro is published as two peer specifications — Delegated Spending Authority and AVP-Micro Payments — with JSON-LD contexts, JSON Schemas, SHACL shapes, an ontology, and signed test vectors. A companion design note (`docs/superpowers/specs/2026-06-11-interop-sdjwt-vc-verifiable-intent-design.md`) works through what a concrete AVP-Micro ⇄ SD-JWT-VC bridge would take.*
