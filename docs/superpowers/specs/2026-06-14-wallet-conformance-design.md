# Design: Wallet Conformance Profile

**Date:** 2026-06-14
**Status:** Approved (program increment #3)
**Adds:** `spec/conformance/` (catalog + docs), `spec/conformance.py` (runner),
`spec/test_conformance.py`; plus a "Wallet conformance" view in the demo.

## 1. Summary

The suite has a behavioural reference engine (`sim.py`) that replays 45 declarative
scenarios and asserts each behaves as declared — but there is no **named, normative
conformance profile** an implementer can run against *their own* wallet to certify it. This
increment adds:
- a machine-readable **requirements catalog** (`conformance/profile.json`) mapping every
  normative wallet behaviour to a stable requirement id, a category, a conformance level,
  a plain statement, the exercising scenario, and the decisive outcome;
- a **runner** (`conformance.py`) that exercises a wallet through a pluggable
  `WalletAdapter` and prints a PASS/FAIL conformance report (non-zero exit on any failure);
- a **reference adapter** that drives `sim.py` and is certified 100% conformant;
- a guard test ensuring the catalog stays complete and consistent as the suite grows.

## 2. Requirements catalog (`conformance/profile.json`)

`{ "version", "requirements": [ {id, category, level, statement, scenario, decisive} ] }`.
One requirement per reference scenario (45), grouped into ten categories:

| Prefix | Category | Examples |
|---|---|---|
| `WCP-ISS` | Issuance & delegated authority | accept well-formed; reject holder-mismatch / expired / revoked; accept AP2 intent |
| `WCP-LIM` | Spending limits | accept compliant; reject over-cap / payee / category / daily-limit / expired; daily reset |
| `WCP-BND` | Binding & integrity | reject replay / quote-tamper / amount / currency / bad-signature |
| `WCP-SET` | Settlement outcomes | insufficient-funds → failed; partial settlement |
| `WCP-HMP` | Human-present approval | confirmed; missing; forged |
| `WCP-STR` | Streaming / metering | happy; budget-exceeded; extend; token-usage; metered |
| `WCP-AP2` | AP2 bridge | imported happy; imported over-cap; imported human-present; missing |
| `WCP-DIS` | Refunds / reversals / disputes | refund full/partial; over-refund; chargeback; rejected; withdrawn |
| `WCP-CHN` | On-chain settlement | evm/x402/lightning; account-redirection; not-final; amount-mismatch; escrow-timeout; reverse |

`decisive` mirrors the scenario's decisive step `expect` (e.g. `{"reject":"overCap"}`,
`{"status":"completed","settled":"1.00"}`, or `"ok"`) — used in the report and cross-checked
against the live scenario by the guard test.

## 3. Runner (`conformance.py`)

- `class CaseResult(passed: bool, decisive, error)`.
- `WalletAdapter` (Protocol): `run_case(scenario_name: str) -> CaseResult`. The contract:
  drive the wallet implementation through the named scenario's signed inputs and report
  whether every step behaved as the scenario declares.
- `ReferenceAdapter`: wraps `sim.run_traced` — `passed = result["ok"]`, `decisive` = the
  last step's outcome.
- `run_profile(adapter=None, profile_path=None) -> int`: loads the catalog, runs each
  requirement through the adapter, prints per-category `[PASS]/[FAIL]` lines + an
  `N/M requirements satisfied` summary; returns non-zero on any failure.
- `__main__` runs `run_profile()` (reference adapter) — the suite's executable certification.

To certify a third-party wallet: implement a `WalletAdapter` that drives it and pass it to
`run_profile`. Documented in `conformance/README.md`.

## 4. Guard test (`test_conformance.py`)

- the reference adapter satisfies **100%** of the profile (`run_profile() == 0`);
- every `requirement.scenario` exists in `sim-scenarios.json`;
- **completeness:** every reference scenario is covered by exactly one requirement (no
  orphan scenarios, no duplicate coverage) — so the catalog can't silently fall behind;
- requirement ids are unique and well-formed (`WCP-[A-Z]{3}-\d{3}`);
- **consistency:** each `requirement.decisive` equals the scenario's decisive step `expect`.

## 5. Docs (`conformance/README.md`)

What conformance means, how to run (`python spec/conformance.py`), the category overview,
and a worked `WalletAdapter` skeleton for certifying an external wallet.

## 6. Demo

A new **"✅ Wallet conformance"** sidebar view that runs the profile against the bundled
reference engine and renders the report grouped by category with a satisfied/total metric.
`conformance.py` is vendored into the demo `engine/` (like `sim.py`); the catalog is read
live from `SPEC_DIR/conformance/profile.json` so it stays current with the spec.

## 7. Acceptance

- `python spec/conformance.py` prints `PASS: wallet is conformant …` (exit 0).
- `test_conformance.py` green (100% + completeness + consistency); full pytest green;
  `verify.py`/`validate.py` unaffected and still PASS.
- The demo headless-renders the conformance view (all categories PASS).
