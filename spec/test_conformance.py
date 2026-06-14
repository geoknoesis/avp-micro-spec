"""Guard tests for the Wallet Conformance Profile (spec/conformance.py)."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import conformance as conf  # noqa: E402
import sim  # noqa: E402

_PROFILE = conf.load_profile()
_REQS = _PROFILE["requirements"]
_SCENARIOS = {s["name"]: s for s in sim.load_scenarios()}


def _decisive_expect(sc):
    dec = "ok"
    for step in sc["steps"]:
        if "expect" in step:
            dec = step["expect"]
    return dec


def test_reference_engine_is_fully_conformant():
    assert conf.run_profile() == 0


def test_every_requirement_scenario_exists():
    missing = [r["id"] for r in _REQS if r["scenario"] not in _SCENARIOS]
    assert not missing, f"requirements reference unknown scenarios: {missing}"


def test_every_scenario_is_covered_exactly_once():
    covered = [r["scenario"] for r in _REQS]
    orphans = sorted(set(_SCENARIOS) - set(covered))
    dupes = sorted({s for s in covered if covered.count(s) > 1})
    assert not orphans, f"scenarios with no conformance requirement: {orphans}"
    assert not dupes, f"scenarios mapped by more than one requirement: {dupes}"


def test_requirement_ids_unique_and_well_formed():
    ids = [r["id"] for r in _REQS]
    assert len(ids) == len(set(ids)), "duplicate requirement ids"
    bad = [i for i in ids if not re.fullmatch(r"WCP-[A-Z0-9]{3}-\d{3}", i)]
    assert not bad, f"malformed requirement ids: {bad}"


def test_decisive_matches_live_scenario():
    drift = []
    for r in _REQS:
        sc = _SCENARIOS[r["scenario"]]
        if r.get("decisive") != _decisive_expect(sc):
            drift.append(r["id"])
    assert not drift, f"requirement.decisive out of sync with the scenario: {drift}"


def test_levels_are_valid():
    assert all(r["level"] in ("MUST", "SHOULD", "MAY") for r in _REQS)
