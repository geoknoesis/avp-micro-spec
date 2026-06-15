"""AVP-Micro Wallet Conformance Profile runner.

Runs the normative conformance catalog (``conformance/profile.json``) against a wallet
implementation via a pluggable :class:`WalletAdapter` and prints a PASS/FAIL report.

The bundled :class:`ReferenceAdapter` drives the reference engine (``sim.py``) and is the
suite's executable self-certification. To certify your own wallet, implement
``WalletAdapter.run_case`` (see ``conformance/README.md``) and pass an instance to
:func:`run_profile`.

    python spec/conformance.py        # certify the reference engine (exit 0 on PASS)
"""
from __future__ import annotations

import json
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import sim  # noqa: E402  (reference engine)

SPEC = Path(__file__).parent
DEFAULT_PROFILE = SPEC / "conformance" / "profile.json"


class CaseResult:
    """Outcome of running one conformance case against a wallet.

    ``passed``   -- did every step behave as the scenario declares?
    ``decisive`` -- the decisive (final) step outcome, for the report.
    ``error``    -- harness-level problem (e.g. unknown scenario); None if the case ran.
    """

    def __init__(self, passed: bool, decisive=None, error: str | None = None):
        self.passed = passed
        self.decisive = decisive
        self.error = error


class WalletAdapter:
    """Interface a wallet implementation provides to be certified.

    ``run_case(scenario_name)`` MUST drive the implementation through the named scenario's
    signed inputs (from ``sim-scenarios.json``) and return a :class:`CaseResult` reporting
    whether every step behaved as the scenario declares.
    """

    def run_case(self, scenario_name: str) -> CaseResult:  # pragma: no cover - interface
        raise NotImplementedError


class ReferenceAdapter(WalletAdapter):
    """Drives the bundled reference engine (``sim.py``)."""

    def __init__(self):
        self._scenarios = {s["name"]: s for s in sim.load_scenarios()}

    def run_case(self, scenario_name: str) -> CaseResult:
        sc = self._scenarios.get(scenario_name)
        if sc is None:
            return CaseResult(False, error=f"unknown scenario '{scenario_name}'")
        res = sim.run_traced(sc)
        decisive = None
        for rec in res["trace"]:
            decisive = rec["outcome"]
        return CaseResult(bool(res["ok"]), decisive=decisive)


def _amt(x) -> str:
    """Canonical decimal rendering so numerically-equal amounts ('0' vs '0.00',
    '1' vs '1.00') compare equal; 'f' format avoids scientific notation."""
    return format(Decimal(str(x)).normalize(), "f")


def _decisive_str(o) -> str:
    """Render a decisive outcome as a short string. Handles both the catalog form
    ("ok" | {"reject": code} | {"status","settled"}) and the engine's observed form
    ({"outcome": "ok"|"reject", "code"|"status"|"settled": ...}). Settled amounts are
    normalized so a numeric match isn't defeated by trailing-zero formatting."""
    if o is None or o == "ok":
        return "ok"
    if isinstance(o, dict):
        if "reject" in o:
            return f"reject:{o['reject']}"
        if o.get("outcome") == "reject":
            return f"reject:{o.get('code')}"
        if "status" in o:
            s = o["status"]
            return f"{s} {_amt(o['settled'])}" if o.get("settled") is not None else s
    return "ok"


def load_profile(profile_path: Path | str | None = None) -> dict:
    return json.loads(Path(profile_path or DEFAULT_PROFILE).read_text(encoding="utf-8"))


def evaluate(adapter: WalletAdapter | None = None, profile_path=None) -> dict:
    """Run every requirement; return a structured report (no printing, never raises)."""
    adapter = adapter or ReferenceAdapter()
    profile = load_profile(profile_path)
    rows = []
    for req in profile["requirements"]:
        cr = adapter.run_case(req["scenario"])
        expected = _decisive_str(req.get("decisive"))
        observed = _decisive_str(cr.decisive)
        rows.append({
            "id": req["id"], "category": req["category"], "level": req["level"],
            "statement": req["statement"], "scenario": req["scenario"],
            "expected": expected,
            "observed": observed,
            # a requirement is satisfied only when the wallet's OBSERVED decisive outcome
            # matches the catalog's normative one -- not merely that the adapter self-reported
            # every step met its own expectation.
            "passed": bool(cr.passed) and cr.error is None and observed == expected,
            "error": cr.error,
        })
    satisfied = sum(1 for r in rows if r["passed"])
    return {"name": profile.get("name"), "version": profile.get("version"),
            "rows": rows, "satisfied": satisfied, "total": len(rows)}


def run_profile(adapter: WalletAdapter | None = None, profile_path=None) -> int:
    """Run the profile and print a PASS/FAIL report; return non-zero on any failure."""
    report = evaluate(adapter, profile_path)
    cat = None
    for r in report["rows"]:
        if r["category"] != cat:
            cat = r["category"]
            print(f"\n=== {cat} ===")
        mark = "PASS" if r["passed"] else "FAIL"
        line = f"  [{mark}] {r['id']} ({r['level']}) {r['statement']}"
        if not r["passed"]:
            line += f"  -- expected {r['expected']}, observed {r['observed']}"
            if r["error"]:
                line += f" ({r['error']})"
        print(line)
    failed = [r["id"] for r in report["rows"] if not r["passed"]]
    print(f"\n{report['satisfied']}/{report['total']} requirements satisfied.")
    if failed:
        print(f"FAIL: {len(failed)} requirement(s) not satisfied: {failed}")
        return 1
    print("PASS: wallet is conformant with the AVP-Micro Wallet Conformance Profile.")
    return 0


if __name__ == "__main__":
    sys.exit(run_profile())
