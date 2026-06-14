# Design: Transport flow-coverage + OpenAPI conformance

**Date:** 2026-06-13
**Status:** Approved design — ready for implementation planning
**Bundles touched:** `spec/transport/` (new vectors + harness), and the `avp-micro-sim-demo` Streamlit app (new tabs).
**Builds on:** the transport bundle (`docs/superpowers/specs/2026-06-13-transport-protocol-binding-design.md`).

## 1. Summary

The transport bundle's OpenAPI documents **12 operations**, but only **two flows** ship
as signed example exchanges (the 402 core happy-path `40` and the over-cap error `41`).
This increment closes that gap: it adds signed example exchanges for the remaining
documented flows (explicit-quote, streaming, async settlement, idempotency), makes the
OpenAPI contract and the example exchanges **provably consistent** via a new validation
check, and surfaces the new flows as tabs in the Streamlit demo.

No new economic objects and no edits to the other five bundles: every exchange body is an
**existing committed vector** read from disk and embedded (the same pattern `40/41` use).

### Scope (settled during brainstorming)

1. **Spec + demo.** Spec-side vectors + harness, *and* the unlocked tabs in the demo.
2. **Full body validation** for the OpenAPI↔exchange cross-check: each exchange body is
   validated against the schema the OpenAPI documents for that path+status+content-type.

### Non-goals

- No new payments/settlement/disputes/authority objects; no edits to those bundles.
- No live client/server. Exchanges remain static signed fixtures (a "try it" server is a
  separate, larger effort).
- No new transport object types. Only new `HttpExchangeLog` vectors + harness + demo.

## 2. New exchange vectors (`generate.py`)

Four new `HttpExchangeLog` vectors. Bodies are reloaded from disk so they are byte-identical
to the canonical vectors (mirrors the `40/41` block).

| Vector | Flow | Steps — `METHOD path → status body(← vector)` |
|---|---|---|
| `42-exchange-quote-flow.json` | Explicit / programmatic | `POST /quote → 200 PaymentQuote`(01) · `POST /authorize`(submission 20)+Idempotency-Key `→ 200 PaymentExecution`(03) · `GET /receipt/{id} → 200 PaymentReceipt`(04) |
| `43-exchange-streaming.json` | Streaming session | `POST /session → 200 UsageSession`(05) · `POST /session/{id}/budget`(SessionBudgetAuthorization 06) `→ 200 UsageSession`(05) · `GET /session/{id}/accruals → 200 UsageAccrual`(07) · `POST /session/{id}/close → 200 PaymentReceipt`(09) |
| `44-exchange-async-settlement.json` | Async settlement | `POST /authorize`(20) `→ 200 PaymentExecution`(03) + `Location: /settlement/{id}` · `GET /settlement/{id} → 200 PaymentExecution`(03) *(still settling)* · `GET /settlement/{id} → 200 SettlementProof`(42, `finality:final`) |
| `45-exchange-idempotency.json` | Idempotency | `POST /authorize`(Idempotency-Key K, submission 20) `→ 200 PaymentExecution`(03) · same K + same body `→ 200 PaymentExecution`(03) *(safe replay)* · same K + a **different** signed submission `→ 409 ProblemDetails{idempotency-conflict}` |

Notes:
- **`42` `POST /quote` carries no request body.** The OpenAPI's `/quote` documents no
  `requestBody`, so the exchange step omits one (the request descriptor is illustrative
  headers). This keeps the request side consistent with the contract.
- **`44` async is modelled as `execution → (poll: still executing) → final proof`.** There
  is no non-final `SettlementProof` vector in the settlement bundle (all are
  `finality:final`), so the first `GET /settlement/{id}` returns the `PaymentExecution`
  (the wallet has executed; chain finality not yet proven) and the second returns the
  final `SettlementProof`. Both bodies validate under the documented
  `oneOf[PaymentExecution, SettlementProof]`. A dedicated `pending`/`probabilistic` proof
  vector would let this show a true `pending→final` proof transition — noted as future work,
  not built here. The execution(03) and proof(42) are not cryptographically bound to each
  other (they come from different object chains); this exchange illustrates the HTTP shape,
  and `verify.py` asserts only body-type and `finality`, not an exec↔proof binding.
- **`45` conflict step.** The "different" submission is built inline in `generate.py` and
  **re-signed with the agent key** (new id `urn:avp:txp:submission:def457`, a changed
  `callbackUrl`) so it is a genuinely distinct, schema-valid, signed `AuthorizationSubmission`.
  The `409` body is an inline `ProblemDetails` with
  `type: …transport/v1#idempotency-conflict`. Neither needs a separate top-level vector.

These four vectors are added to `validate.py`'s `TRANSPORT_UNSIGNED_VECTORS`
(`HttpExchangeLog` schema check) alongside `40/41`.

## 3. OpenAPI↔exchange cross-validation (`validate.py`)

A new `openapi_exchange_check()` run in the `=== OpenAPI contract ===` section, after the
existing `openapi_ref_check()`.

Algorithm:
1. Load the OpenAPI doc once. Build a registry of the referenced bundle schemas
   (transport, payments, settlement) keyed by their `$id`, so any `#/$defs/Name` ref
   resolves cross-file with `referencing` + `Draft202012Validator`.
2. For each exchange log (`40`–`45`), for each step:
   - **Path match:** map the concrete request path to a templated OpenAPI path by
     segment-wise comparison — equal segment count, each segment equal literally or the
     OpenAPI segment is a `{param}` placeholder (`/session/abc/accruals` →
     `/session/{id}/accruals`). Then select the operation by HTTP method.
   - **Response:** look up `responses[str(status)]`; pick the `content` entry by the
     response's `Content-Type` header; resolve its `schema` (`$ref`, or `oneOf` of `$ref`s);
     **validate the response body** against the resolved schema(s) — for `oneOf`, the body
     must validate against at least one branch.
   - **Request:** only when the operation documents a `requestBody`, resolve its schema
     for the request `Content-Type` and validate the request body. Steps whose request
     carries a body for an operation that documents none (the GET-with-illustrative-body
     402 retry in `40/41`) are **skipped, not failed** — responses are the contract surface
     that is fully enforced.
   - Emit one `ok(...)` per validated body, plus an `ok(...)` that the
     (method, templated-path, status) is documented at all.

This guarantees the OpenAPI and the example exchanges cannot drift: an example whose
body no documented operation/response/schema covers fails the harness.

## 4. `verify.py`

Extend the transport section to mirror the `40/41` discipline for `42`–`45`:
- **byte-identity:** each embedded body equals its canonical on-disk vector (quote 01,
  execution 03, receipt 04, session 05, budget-auth 06, accrual 07, session-receipt 09,
  settlement proof 42).
- **flow bindings:** `42` receipt step's `receipt.execution == execution.id`;
  `43` close step returns the session receipt; `44` final poll's `SettlementProof.finality
  == "final"` and the first two `/settlement/{id}` bodies are the execution; `45` the two
  successful `/authorize` steps return the *same* execution under the *same*
  `Idempotency-Key`, and the conflict step's body is a `ProblemDetails` whose `type`
  resolves to `idempotency-conflict` in `txp:ErrorScheme`.

## 5. Demo (`avp-micro-sim-demo/app.py`)

The `_render_exchange` renderer is already generic. Add four tabs to the Transport view so
the order reads as the protocol's surface:

`💳 402 happy path · 🧾 explicit quote · 📡 streaming · ⏳ async settle · 🔁 idempotency · ⛔ over-cap · 🛰️ discovery`

Each new tab is `_render_exchange(_txp("4x-…"))`. Add a few annotation cases so the bindings
read well:
- `SessionBudgetAuthorization` request → "commits the session budget cap".
- `UsageAccrual` response → "incremental metered usage".
- `SettlementProof` response → finality badge (`pending`/`probabilistic`/`final`).
- `ProblemDetails{idempotency-conflict}` → the existing `TXP_WHY` mapping already covers it;
  ensure a `409` status colour.
- a small caption on `44` explaining `Location:` + polling.

Demo work happens on a branch in `avp-micro-sim-demo`; the demo reads the spec repo live, so
the spec increment must be present on the spec checkout for the new tabs to populate.

## 6. Acceptance criteria

- `python spec/generate.py` regenerates all vectors including `42`–`45`, deterministically.
- `python spec/verify.py` reports **PASS** with the new exchange bindings active.
- `python spec/validate.py` reports **PASS**, including the new `openapi_exchange_check()`
  (every `40`–`45` response body validates against the OpenAPI-documented schema).
- pytest green; the other five bundles are byte-unchanged.
- The Streamlit app imports + headless-renders all seven Transport tabs without error, and
  the new flows appear in the Conformance-vectors list.
