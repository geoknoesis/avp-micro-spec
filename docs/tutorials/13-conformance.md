# Tutorial 13 — Conformance

> **Series:** [AVP-Micro Tutorials](README.md) · **Previous:** [12 — Revocation & Status](12-revocation-and-status.md) · **Next:** 14 — Hands-on
>
> **You'll learn:** how "the wallet enforces the rules" becomes a *demonstrated, certifiable*
> fact — the Wallet Conformance Profile, the pluggable runner, and how to certify your own
> implementation.

---

## 1. Specs need teeth

A specification that only *describes* correct behaviour is a wish. AVP-Micro's safety claims —
caps enforced, replays refused, redirection blocked — only matter if an implementation can be
**tested** against them and a third party can **certify** the result. That's the Wallet
Conformance Profile (WCP).

It has three parts:

1. a machine-readable **catalogue** of required behaviours (`conformance/profile.json`),
2. a **runner** that exercises a wallet and reports pass/fail (`conformance.py`), and
3. a **guard test** that keeps the catalogue honest (`test_conformance.py`).

## 2. The requirements catalogue

`profile.json` lists every normative behaviour as a stable requirement:

```json
{ "id": "WCP-LIM-002", "category": "Spending limits", "level": "MUST",
  "statement": "Refuse an authorization whose amount exceeds maxPerTransaction.",
  "scenario": "over-per-transaction-cap", "decisive": { "reject": "overCap" } }
```

Each requirement names:

- a **stable id** (`WCP-<CAT>-<NNN>`) you can cite in docs and audits,
- a **category** and **conformance level** (MUST),
- a plain-language **statement**,
- the **scenario** that exercises it, and
- the **decisive outcome** expected (accept with a settlement status, or reject with a code).

The categories span the whole stack — issuance, spending limits, binding & integrity,
settlement outcomes, human-present, streaming, AP2 bridge, refunds/disputes, on-chain
settlement, and closed-processor settlement (`WCP-ISS / LIM / BND / SET / HMP / STR / AP2 / DIS /
CHN / PSP`). Crucially, conformance is mostly about **correct refusals**: a wallet is safe
because it says *no* to the right things.

## 3. The runner and the adapter seam

`conformance.py` runs the catalogue against a **`WalletAdapter`** — the seam that lets *any*
implementation be tested:

```python
class WalletAdapter:
    def run_case(self, scenario_name: str) -> CaseResult: ...
```

`run_case` drives the implementation through a named scenario's signed inputs and reports whether
**every step behaved as the scenario declares**. The bundled **`ReferenceAdapter`** drives the
reference engine (`sim.py`) and is the suite's self-certification:

```
=== Spending limits ===
  [PASS] WCP-LIM-002 (MUST) Refuse an authorization whose amount exceeds maxPerTransaction.
  …
54/54 requirements satisfied.
PASS: wallet is conformant with the AVP-Micro Wallet Conformance Profile.
```

The runner exits non-zero on any failure, so it drops straight into CI.

## 4. Certifying *your* wallet

To certify a third-party wallet, implement a `WalletAdapter` that drives it and hand it to the
runner:

```python
import conformance as conf, sim

class MyWalletAdapter(conf.WalletAdapter):
    def __init__(self):
        self._scenarios = {s["name"]: s for s in sim.load_scenarios()}
    def run_case(self, name):
        sc = self._scenarios.get(name)
        if sc is None:
            return conf.CaseResult(False, error=f"unknown scenario '{name}'")
        passed, decisive = my_wallet_drive(sc)   # ← your integration: feed steps to YOUR wallet
        return conf.CaseResult(passed, decisive=decisive)

raise SystemExit(conf.run_profile(MyWalletAdapter()))
```

A scenario **passes** when your wallet **accepts** the steps the scenario declares valid and
**refuses, with the declared error code**, the steps it declares invalid. The catalogue's
`decisive` field documents the expected terminal behaviour for each requirement.

## 5. Keeping the catalogue honest

A conformance suite is worthless if it silently falls behind the spec. `test_conformance.py`
enforces:

- the reference engine satisfies **100%** of the profile;
- every requirement references a real scenario, and **every scenario is covered by exactly one
  requirement** (no orphan behaviours, no double-counting);
- requirement ids are unique and well-formed; and
- each requirement's `decisive` outcome **matches the live scenario** (no drift).

So when a new behaviour is added (as when the settlement rails grew), the catalogue *must* grow
with it or the test fails — which is exactly how it should be.

## 6. Recap

- The **Wallet Conformance Profile** turns the spec's safety claims into a catalogue of
  testable, citable requirements (`WCP-…`), most of them *correct refusals*.
- A pluggable **`WalletAdapter`** lets any implementation be certified; the **`ReferenceAdapter`**
  proves the reference engine is 100% conformant.
- A **guard test** keeps the catalogue complete and consistent with the live scenarios.

## Glossary

- **WCP** — Wallet Conformance Profile.
- **Requirement** — one catalogued behaviour with an id, statement, scenario, and decisive outcome.
- **WalletAdapter** — the interface an implementation provides to be certified.
- **ReferenceAdapter** — adapter driving the bundled reference engine (`sim.py`).
- **Decisive outcome** — the terminal accept/reject (with code) a requirement expects.

## Try it

```powershell
.venv\Scripts\python spec\conformance.py     # certify the reference engine (exit 0 on PASS)
.venv\Scripts\python -m pytest spec\test_conformance.py -q   # the completeness/consistency guard
```

The first prints the full per-category report; the second proves the catalogue still matches
every scenario in the suite.

---

**Next:** Tutorial 14 — *Hands-on.*
