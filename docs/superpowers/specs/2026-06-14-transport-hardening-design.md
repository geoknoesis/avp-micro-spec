# Design: Transport hardening — anti-replay profile + signed errors

**Date:** 2026-06-14
**Status:** Approved (part of the "do all" program, increment #1)
**Bundle:** `spec/transport/` (extend) + the Streamlit demo.

## 1. Summary

Two gaps from the perfection analysis:
- **A3 — normative anti-replay / freshness.** The bundle *describes* challenge freshness in
  prose but pins no rules: nonce single-use, a consumed-nonce store, expiry handling,
  clock-skew tolerance, and `WWW-Authenticate` parameters. This increment adds the normative
  rules and demonstrates them with a **replay-blocked** example exchange.
- **A4 — authenticated errors.** `ProblemDetails` is unsigned, so a `402`/error can be
  spoofed. Since `ecdsa-jcs-2022` signs the **JCS canonicalization of the JSON** (no RDF /
  `@context` required), a signed error is simply the problem JSON plus a `proof`. This
  increment makes `ProblemDetails.proof` an **optional** member and ships a signed example.

No new object types; no edits to the other five bundles.

## 2. A3 — anti-replay / freshness

### Normative rules (`index.html`, new "Challenge lifecycle & anti-replay" section)
- The `challenge` nonce is **single-use** and bound to the (verifier, request) that issued
  the `402`. The verifier **MUST** persist consumed nonces until the challenge's `expires`
  and reject a re-presented nonce with **`409 nonce-reuse`**.
- The verifier **MUST** reject a challenge/submission whose `expires` is in the past with
  **`422 challenge-expired`**.
- **Clock skew:** verifiers **SHOULD** allow a small leeway (RECOMMENDED ≤ 60 s) when
  comparing `timestamp`/`expires`.
- **`WWW-Authenticate` parameters (RFC 7235):** the `402` carries
  `AVP-Micro challenge="<nonce>"`; a failed retry carries
  `AVP-Micro error="<error-code>"` where `<error-code>` is the local name of a
  `txp:ErrorScheme` concept.

### Vectors
- **Enrich existing 402 headers** (regenerate, bodies unchanged): `40` step-1 `402` →
  `WWW-Authenticate: AVP-Micro challenge="<nonce>"`; `41` step-1 `402` →
  `WWW-Authenticate: AVP-Micro error="over-cap"`. (verify.py checks bodies/status, not the
  header string, so this is safe.)
- **New `46-exchange-replay.json`** — replay blocked:
  1. `GET /resource/premium` (Authorization: AVP-Micro `<submission>`, Idempotency-Key) →
     `200 PaymentReceipt` (nonce consumed).
  2. same submission re-presented → `409 ProblemDetails{nonce-reuse}` (signed — see A4),
     `WWW-Authenticate: AVP-Micro error="nonce-reuse"`.
- **OpenAPI:** add a `409` response (`ProblemDetails`) to `GET /resource/{path}` so the
  replay step cross-validates.

## 3. A4 — signed error envelope

### Schema
Extend the `ProblemDetails` `$def` with an **optional** `proof` (`$ref #/$defs/proof`).
The unsigned form stays valid (only `type`/`title`/`status` required). No `@context` is
introduced — `ecdsa-jcs-2022` is JCS-based.

### Vectors
- **New `47-problem-details-signed.json`** — a payee-signed `ProblemDetails` (e.g.
  `challenge-expired`), `proof` over its JCS canonicalization.
- The `46` replay `409` body is a **signed** `nonce-reuse` `ProblemDetails` (so a flow shows
  authenticated rejection). Both reuse the payee key.

### Harness
- `validate.py`: `47` added to `TRANSPORT_UNSIGNED_VECTORS` (schema-checked as
  `ProblemDetails`; the optional `proof` is allowed). `46` added to
  `TRANSPORT_UNSIGNED_VECTORS` + `EXCHANGE_VECTORS` (HttpExchangeLog + cross-check). The
  cross-check validates the `409` body against the new `/resource/{path}` `409`
  `ProblemDetails` schema (the extra `proof` is permitted — `ProblemDetails` has no
  `additionalProperties:false`).
- `verify.py`: `47`'s proof verifies and is signed by the payee; the `46` replay `409` body
  is a signed `nonce-reuse` `ProblemDetails` whose proof verifies and `type` resolves in
  `txp:ErrorScheme`; the replay re-presents the *same* submission as step 1.

### OpenAPI
Document that error responses **MAY** be signed (an optional `proof`), referencing the
extended `ProblemDetails` `$def` (already referenced — the optional member needs no path
change beyond the new `409` on `/resource/{path}`).

## 4. Demo

Add a **🚫 replay** tab (`46`) to the Transport view. The existing `_body_expander` already
detects a `proof` with `cryptosuite: ecdsa-jcs-2022` and shows "✅ signed proof verifies", so
signed errors annotate automatically. Add a `nonce-reuse` caption (already in `TXP_WHY`).

## 5. Acceptance

- `generate.py` deterministic; `verify.py`/`validate.py` PASS (incl. the cross-check over
  `40`–`47`); pytest green; other five bundles byte-unchanged.
- A negative control confirms a tampered signed-error proof fails.
- The demo headless-renders the new tab.
