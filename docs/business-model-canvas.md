# Business Model Canvas: AVP-Micro–Centric Venture

This document applies the [Business Model Canvas](https://www.strategyzer.com/canvas/business-model-canvas) (Osterwalder & Pigneur) to a venture whose **core differentiator** is implementing and operating services defined by **AVP-Micro** (Agent Verifiable Micropayments)—portable DID/VC trust and authorization **above** settlement rails.

It is a **strategic template**: numbers, segments, and priorities should be validated with customers and investors. The aim is a **scalable, high-margin** model where the specification drives **defensible interoperability**, not commodity payment processing alone.

### V1 product definition (three things only)

| # | Core product | What it is |
|---|----------------|------------|
| **1** | **Authorization engine** | VC-based spend limits and policy (evaluate Spending Authorization and related constraints; decide allow/deny for a proposed payment or session budget). |
| **2** | **Verification API** | For **merchants / payees**: cryptographically verify that a request (e.g. presentation + signed authorization) satisfies policy and authenticity before they rely on it. |
| **3** | **Receipt + audit chain** | Immutable-style **proof of what happened**: linked artifacts (e.g. quote, authorization, execution pointer, receipt) so enterprises can reconcile and audit without building the ledger themselves. |

**Explicitly not in v1** (later phases):

- **Full wallet ecosystem** (custody, multi-account UX, end-user apps as your product).
- **Multi-rail optimization** (routing, price comparison, or owning settlement across rails—customers or partners move money; you do not optimize rails in v1).
- **Certification network** (badges, trust registries, paid MerchantCredential marketplaces at scale).

Everything else in this canvas should be read **through** that v1 lens unless labeled as a later expansion.

---

## 1. Customer segments

| Segment | Why they pay | Fit with AVP-Micro |
|---------|----------------|-------------------|
| **Enterprises deploying AI agents** | Governed spend + proof for internal audit | Authorization engine + audit chain |
| **API / data marketplaces (merchants)** | Trust agent-originated payment intents | Verification API + receipts |
| **Fintechs & wallet builders** | Policy and verify without building VC stack | Embed authorization engine + call Verification API |
| **Regulated industries** (finance, health-adjacent, procurement) | Evidence trails | Receipt + audit chain as first-class export |
| **Identity / trust vendors** | Mandated spend next to identity | Issue VCs; integrate your **Verification API** |

**Beachhead (recommended):** one vertical where **verification + audit** close the sale (e.g. B2B APIs or corporate agent procurement)—not where you must own the wallet or every rail first.

---

## 2. Value propositions

| For the customer | What you deliver (mapped to the spec) |
|------------------|----------------------------------------|
| **Let AI agents safely buy APIs and services with enforceable spending limits and audit trails—without you building billing, trust, or compliance systems.** | **v1:** the three products above—**authorization engine**, **Verification API**, **receipt + audit chain**—mapped to AVP-Micro message types. **Settlement** is the customer’s or a partner’s problem in v1; you do not ship a full wallet or rail optimization. |
| **Lower integration tax** | Standard AVP-Micro artifacts (quotes, authorizations, receipts; sessions/accruals when you enable streaming) |
| **Faster time-to-market** | Hosted engine + APIs + SDKs—not a from-scratch trust stack |

**Elevator pitch:** *Let AI agents safely buy APIs and services with enforceable spending limits and audit trails—without you building billing, trust, or compliance systems.*

---

## 3. Channels

| Channel | Role |
|---------|------|
| **Direct enterprise sales** | High ACV: audit + policy integration |
| **Developer platform** | Docs, sandboxes, SDKs for verify + receipt logging |
| **Partners** | Agent frameworks, DID/VC vendors, **PSPs only as settlement hooks** (you are not building multi-rail product in v1) |
| **Open specification** | Thought leadership; reference **the three v1 products** |
| **Marketplaces** | Merchant adoption of Verification API (**certification badges later**) |

---

## 4. Customer relationships

| Model | Tactic |
|-------|--------|
| **Self-serve + paid tiers** | Free tier for dev/test; paid for production **verification + audit** volume |
| **Co-pilot onboarding** | First merchant verify path + first enterprise audit export |
| **Enterprise success** | SLAs, VPC, custom issuer allowlists for the **authorization engine** |
| **Community** | Public spec feedback, sample integrations (**conformance/cert program later**) |

**Retention driver:** switching cost = **deployed policies, issuer integrations, and historical audit logs**—not just API keys.

---

## 5. Revenue streams (lucrative by design)

Combine **recurring** and **usage-based** revenue; avoid pure interchange-only dependency.

| Stream | Mechanics | Why it scales |
|--------|-----------|----------------|
| **SaaS platform fee** | Per month per org / per environment (engine + audit retention) | Predictable ARR |
| **Verification API usage** | Per verify call / per authenticated request | Scales with merchant traffic |
| **Authorization engine usage** | Per policy evaluation (or bundled with verify) | Scales with agent spend attempts |
| **Audit chain storage / export** | Retention tiers, SIEM/GRC export | Enterprise upsell |
| **Enterprise licenses** | VPC for engine + verify + audit | Large deals, services attach |
| **Professional services** | Integration, security review, issuer templates | Early cash; later productize |
| **Later (not v1):** take rate on flow | Only if you become a regulated settlement actor | Defer |
| **Later (not v1):** certification / trust network fees | Badges, registries | Defer |

**Margin focus in v1:** policy evaluation, verification, and audit APIs are **high gross margin**. **Do not** anchor the business on interchange or rail arbitrage in v1.

---

## 6. Key resources

| Resource | Notes |
|----------|--------|
| **Team** | Identity (DID/VC), API security, audit/logging, minimal payments domain for message semantics |
| **IP & brand** | AVP-Micro spec authorship + **reference implementation of the three v1 products** |
| **Infrastructure** | HA Verification API, authorization engine, append-only / WORM-friendly audit store |
| **Trust relationships** | Enterprise security / GRC; PSPs as **partners** not as your v1 product surface |
| **Data (careful)** | Aggregated **non-PII** metrics on success rates and latency—not raw spend PII unless contracted |

---

## 7. Key activities

| Activity | Purpose |
|----------|---------|
| **Authorization engine** | VC-based spend limits, policy evaluation, session budget rules as spec allows |
| **Verification API** | Merchant-facing verify endpoints, clear error model, docs |
| **Receipt + audit chain** | Ingest, link, store, query, export signed artifacts |
| **SDKs** | Thin clients for verify + audit (agents/merchants) |
| **Issuer templates** | Samples for SpendingAuthorization issuance (customers or partners run issuers) |
| **Security & compliance** | Threat models, SOC2 path for **your** SaaS (not “we are the bank”) |
| **Sales & solutions** | Repeatable **verify + audit** playbooks |

**Deferred activities:** full wallet product, rail routing/optimization, certification marketplace, large interop consortia as a dependency.

---

## 8. Key partners

| Partner type | Value exchange |
|--------------|----------------|
| **PSPs / rails (optional hooks)** | They settle funds; you pass through **execution references** into the audit chain without owning rails in v1 |
| **DID methods & VC platforms** | Issuance upstream; your engine **consumes** VPs |
| **Cloud & AI vendors** | Recommend **Verification API + audit** SDKs—not “our wallet” |
| **Auditors & GRC tools** | Native export of **receipt + audit chain** |
| **Standards bodies (optional)** | Credibility for spec; **no dependency** on running a cert network in v1 |

**v1 posture:** one rail or one PSP integration in **examples** is fine; **multi-rail optimization is not the product**.

---

## 9. Cost structure

| Cost bucket | Strategy |
|-------------|----------|
| **R&D** | Front-loaded; amortize via platform reuse |
| **Infra** | Start multi-tenant; isolate enterprise tenants at scale |
| **Compliance & legal** | Lighter in v1 if you **avoid** holding funds; still budget for audit, privacy, and contracts |
| **Sales** | Enterprise motion is expensive—balance with PLG for developers |
| **Partner rev-share** | Trade margin for distribution where needed |

---

## 10. One-page canvas summary

```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ KEY PARTNERS    │ KEY ACTIVITIES  │ VALUE PROP      │ CUSTOMER         │
│ DID/VC, PSPs*   │ Auth engine     │ Safe agent buys │ Enterprises w/  │
│ Cloud/AI        │ Verify API      │ Limits + audit  │ agents, APIs,    │
│ GRC tools       │ Receipt/audit   │ No DIY billing/ │ marketplaces     │
│ *settlement     │ SDKs, templates │ trust stack     │ Wallet builders  │
├─────────────────┤                 │                 ├─────────────────┤
│ KEY RESOURCES   │                 │                 │ CHANNELS        │
│ Team, spec IP   │                 │                 │ Direct, devplat, │
│ Verify+audit    │                 │                 │ partners, OSS    │
├─────────────────┴─────────────────┤                 ├─────────────────┤
│ COST STRUCTURE                   │                 │ REVENUE         │
│ R&D, infra, compliance, sales    │                 │ SaaS + API use  │
│                                  │                 │ Enterprise + svc│
│                                  │                 │ (no bps v1)     │
└──────────────────────────────────┴─────────────────┴─────────────────┘
```

---

## 11. What makes this model “lucrative” (realistically)

1. **Composite pricing in v1:** SaaS + verification usage + audit retention + enterprise VPC—**no need** for interchange to be profitable.
2. **Sticky switching costs:** Issuer allowlists, policy rules, and **audit history** embed deeply in ops and compliance.
3. **Spec-led moat (v1):** First credible **three-product** reference (engine + verify + audit) tied to AVP-Micro **messages** beats ad hoc internal builds.
4. **Expansion (explicitly later):** Full **wallet ecosystem**, **multi-rail optimization**, **certification / trust networks**, take-rate models, and richer interop programs—**after** v1 revenue and repeatability.

---

## 12. Risks to name in pitch decks

| Risk | Mitigation |
|------|------------|
| Spec adoption lag | Ship **working** products; spec follows practice |
| Regulatory classification | Counsel early; partner with licensed entities for settlement |
| Commoditization | Own **policy depth**, **audit analytics**, and merchant **verification** UX (**certification network later**) |
| Big tech fast-follow | Move fast on vertical depth and partner exclusives in one segment |

---

*Strategic draft aligned with AVP-Micro. Author: Stephane Fellah, Geoknoesis LLC.*
