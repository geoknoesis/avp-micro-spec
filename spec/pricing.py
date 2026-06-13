"""Reference evaluator for the AVP-Micro pricing vocabulary.

Pure, dependency-free (stdlib `decimal` only). `evaluate(model, usage)` returns the
total charge for a usage vector, quantized to 1e-8 with ROUND_HALF_UP — matching the
running app's money rule. `usage` maps a dimension IRI (string) to a quantity, plus
optional `"calls"` (PerCall) and `"periods"` (CommitmentRate).
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP

QUANTUM = Decimal("0.00000001")


class PricingError(ValueError):
    """Raised when a pricing model is internally inconsistent."""


def quantize(value: Decimal) -> Decimal:
    return value.quantize(QUANTUM, rounding=ROUND_HALF_UP)


def _components(model: dict) -> list:
    if model.get("type") == "CompositePricing":
        return model["components"]
    return [model]


def _nonneg(value, label: str) -> Decimal:
    """Coerce a usage quantity to Decimal, rejecting negatives (a negative quantity
    would yield a negative — credit — charge, which is never valid usage)."""
    q = Decimal(str(value))
    if q < 0:
        raise PricingError(f"negative usage quantity for {label}: {q}")
    return q


def _qty(usage: dict, dimension: str) -> Decimal:
    return _nonneg(usage.get(dimension, 0), dimension)


def _tier_charge(component: dict, qty: Decimal) -> Decimal:
    tiers = component["tiers"]
    if not tiers:
        raise PricingError("TieredRate has no tiers")
    mode = component.get("tierMode", "graduated")
    if mode == "volume":
        for tier in tiers:
            if "upTo" not in tier or qty <= Decimal(tier["upTo"]):
                return Decimal(tier["amount"]) * qty
        return Decimal(tiers[-1]["amount"]) * qty
    # graduated
    total = Decimal(0)
    lower = Decimal(0)
    for tier in tiers:
        rate = Decimal(tier["amount"])
        if "upTo" in tier:
            upper = Decimal(tier["upTo"])
            band = min(qty, upper) - lower
            if band > 0:
                total += band * rate
            lower = upper
            if qty <= upper:
                return total
        else:
            band = qty - lower
            if band > 0:
                total += band * rate
            return total
    # Every tier was bounded and the usage exceeds the highest ceiling: the model
    # cannot price the excess. A graduated TieredRate MUST end with an open-ended tier.
    raise PricingError(
        "graduated TieredRate must end with an open-ended tier (no upTo); "
        f"usage {qty} exceeds the highest tier ceiling {lower}")


def _component_charge(component: dict, usage: dict) -> Decimal:
    ctype = component["type"]
    if ctype == "Allowance":
        return Decimal(0)
    if ctype == "PerCall":
        return Decimal(component["amount"]) * _nonneg(usage.get("calls", 1), "calls")
    if ctype == "CommitmentRate":
        charge = Decimal(component.get("upfront", "0"))
        recurring = component.get("recurring")
        if recurring:
            charge += Decimal(recurring["amount"]) * _nonneg(usage.get("periods", 1), "periods")
        return charge
    qty = _qty(usage, component["dimension"])
    if ctype == "PerUnit":
        return Decimal(component["amount"]) * qty
    if ctype == "TieredRate":
        return _tier_charge(component, qty)
    raise PricingError(f"unknown component type: {ctype}")


def _apply_allowances(components: list, usage: dict) -> dict:
    adjusted = dict(usage)
    for component in components:
        if component["type"] == "Allowance":
            dim = component["dimension"]
            remaining = _qty(adjusted, dim) - Decimal(component["freeQuantity"])
            adjusted[dim] = remaining if remaining > 0 else Decimal(0)
    return adjusted


def assert_single_currency(model: dict) -> None:
    """Raise PricingError unless all currency fields in the model are identical."""
    seen = {c for c in (
        [model.get("currency")] + [comp.get("currency") for comp in _components(model)]
    ) if c is not None}
    if len(seen) > 1:
        raise PricingError(f"mixed currencies in model: {sorted(seen)}")


def evaluate(model: dict, usage: dict) -> Decimal:
    components = _components(model)
    adjusted = _apply_allowances(components, usage)
    total = sum((_component_charge(c, adjusted) for c in components), Decimal(0))
    return quantize(total)
