# AVP-Micro Wallet Conformance Profile

A normative, machine-readable catalog of the behaviours an **AVP-Micro wallet** MUST
exhibit — and an executable runner that certifies an implementation against it.

- **Catalog:** [`profile.json`](profile.json) — 54 requirements (`WCP-…`) in ten categories,
  each mapping a behaviour to the scenario that exercises it and the decisive outcome.
- **Runner:** [`../conformance.py`](../conformance.py).

## Run it

```powershell
.venv\Scripts\python spec\conformance.py
```

Prints a per-category `[PASS]/[FAIL]` report and a `N/54 requirements satisfied` summary;
exits non-zero on any failure. With no adapter it certifies the bundled reference engine
(`sim.py`), which is expected to satisfy 100%.

## Categories

| Prefix | Category |
|---|---|
| `WCP-ISS` | Issuance & delegated authority |
| `WCP-LIM` | Spending limits |
| `WCP-BND` | Binding & integrity |
| `WCP-SET` | Settlement outcomes |
| `WCP-HMP` | Human-present approval |
| `WCP-STR` | Streaming & metering |
| `WCP-AP2` | AP2 bridge |
| `WCP-DIS` | Refunds, reversals & disputes |
| `WCP-CHN` | On-chain settlement |
| `WCP-PSP` | Closed-processor settlement |

## Certifying your own wallet

Implement a `WalletAdapter` that drives **your** implementation through a named scenario's
signed inputs (from [`../sim-scenarios.json`](../sim-scenarios.json)) and reports whether
every step behaved as the scenario declares:

```python
import conformance as conf, sim

class MyWalletAdapter(conf.WalletAdapter):
    def __init__(self):
        self._scenarios = {s["name"]: s for s in sim.load_scenarios()}

    def run_case(self, scenario_name):
        sc = self._scenarios.get(scenario_name)
        if sc is None:
            return conf.CaseResult(False, error=f"unknown scenario '{scenario_name}'")
        try:
            # 1. build/sign the scenario's inputs (or replay the bundled signed vectors)
            # 2. feed each step to YOUR wallet; collect its verdict per step
            # 3. compare each verdict to the step's declared `expect`
            passed, decisive = my_wallet_drive(sc)   # <- your integration
            return conf.CaseResult(passed, decisive=decisive)
        except Exception as e:                        # noqa: BLE001
            return conf.CaseResult(False, error=str(e))

raise SystemExit(conf.run_profile(MyWalletAdapter()))
```

A scenario "passes" when the wallet **accepts** every step the scenario declares `ok`/a
settlement status for, and **refuses with the declared error code** every step the scenario
declares a `reject` for. The catalog's `decisive` field documents the terminal expectation
for each requirement.

## Conformance level

A wallet is **conformant** when it satisfies every `MUST` requirement in `profile.json`.
The catalog is kept complete and consistent with the reference scenarios by
[`../test_conformance.py`](../test_conformance.py) (every scenario is covered by exactly one
requirement; each requirement's `decisive` matches the live scenario).
