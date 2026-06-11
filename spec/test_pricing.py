"""Unit tests for the AVP-Micro reference pricing evaluator."""
from decimal import Decimal

import pytest

import pricing


def test_percall_single_invocation():
    model = {"type": "PerCall", "amount": "0.001", "currency": "USD"}
    assert pricing.evaluate(model, {}) == Decimal("0.00100000")


def test_percall_multiple_calls():
    model = {"type": "PerCall", "amount": "0.001", "currency": "USD"}
    assert pricing.evaluate(model, {"calls": 5}) == Decimal("0.00500000")


def test_perunit_linear():
    model = {"type": "PerUnit", "dimension": "dim:Requests",
             "unit": "qudtu:NUM", "amount": "0.0000002", "currency": "USD"}
    assert pricing.evaluate(model, {"dim:Requests": 1000000}) == Decimal("0.20000000")


def test_tiered_graduated():
    # 0-100 @ 0.10, 100-200 @ 0.05, 200+ @ 0.01; usage 250
    # = 100*0.10 + 100*0.05 + 50*0.01 = 10 + 5 + 0.5 = 15.5
    model = {"type": "TieredRate", "dimension": "dim:StorageDuration",
             "unit": "aunit:GigaByteMonth", "tierMode": "graduated",
             "tiers": [{"upTo": "100", "amount": "0.10"},
                       {"upTo": "200", "amount": "0.05"},
                       {"amount": "0.01"}], "currency": "USD"}
    assert pricing.evaluate(model, {"dim:StorageDuration": 250}) == Decimal("15.50000000")


def test_tiered_volume():
    # whole usage priced at the landed tier; usage 250 lands in 200+ @ 0.01 => 2.5
    model = {"type": "TieredRate", "dimension": "dim:StorageDuration",
             "unit": "aunit:GigaByteMonth", "tierMode": "volume",
             "tiers": [{"upTo": "100", "amount": "0.10"},
                       {"upTo": "200", "amount": "0.05"},
                       {"amount": "0.01"}], "currency": "USD"}
    assert pricing.evaluate(model, {"dim:StorageDuration": 250}) == Decimal("2.50000000")


def test_allowance_reduces_dimension_before_charge():
    model = {"type": "CompositePricing", "currency": "USD", "components": [
        {"type": "Allowance", "dimension": "dim:Requests",
         "unit": "qudtu:NUM", "freeQuantity": "1000000"},
        {"type": "PerUnit", "dimension": "dim:Requests",
         "unit": "qudtu:NUM", "amount": "0.0000002"},
    ]}
    # 1,500,000 - 1,000,000 free = 500,000 * 0.0000002 = 0.10
    assert pricing.evaluate(model, {"dim:Requests": 1500000}) == Decimal("0.10000000")


def test_allowance_floors_at_zero():
    model = {"type": "CompositePricing", "currency": "USD", "components": [
        {"type": "Allowance", "dimension": "dim:Requests",
         "unit": "qudtu:NUM", "freeQuantity": "1000000"},
        {"type": "PerUnit", "dimension": "dim:Requests",
         "unit": "qudtu:NUM", "amount": "0.0000002"},
    ]}
    assert pricing.evaluate(model, {"dim:Requests": 500000}) == Decimal("0.00000000")


def test_composite_lambda_like():
    model = {"type": "CompositePricing", "currency": "USD", "components": [
        {"type": "PerUnit", "dimension": "dim:Requests",
         "unit": "qudtu:NUM", "amount": "0.0000002"},
        {"type": "PerUnit", "dimension": "dim:ComputeMemoryTime",
         "unit": "aunit:GigaByteSecond", "amount": "0.0000166667"},
    ]}
    usage = {"dim:Requests": 3000000, "dim:ComputeMemoryTime": 600000}
    # 3,000,000*0.0000002 + 600,000*0.0000166667 = 0.6 + 10.00002 = 10.60002
    assert pricing.evaluate(model, usage) == Decimal("10.60002000")


def test_commitment_upfront_plus_recurring():
    model = {"type": "CommitmentRate", "dimension": "dim:ComputeTime",
             "unit": "qudtu:HR", "upfront": "100.00",
             "recurring": {"amount": "0.05", "period": "qudtu:HR"},
             "currency": "USD"}
    # upfront 100 + 720 periods * 0.05 = 100 + 36 = 136
    assert pricing.evaluate(model, {"periods": 720}) == Decimal("136.00000000")


def test_currency_mismatch_rejected():
    model = {"type": "CompositePricing", "currency": "USD", "components": [
        {"type": "PerUnit", "dimension": "dim:Requests", "unit": "qudtu:NUM",
         "amount": "0.0000002", "currency": "EUR"},
    ]}
    with pytest.raises(pricing.PricingError):
        pricing.assert_single_currency(model)


def test_assert_single_currency_component_mismatch_without_top_currency():
    model = {"type": "CompositePricing", "components": [
        {"type": "PerUnit", "dimension": "dim:Requests", "unit": "qudtu:NUM",
         "amount": "0.0000002", "currency": "USD"},
        {"type": "PerUnit", "dimension": "dim:Requests", "unit": "qudtu:NUM",
         "amount": "0.0000003", "currency": "EUR"},
    ]}
    with pytest.raises(pricing.PricingError):
        pricing.assert_single_currency(model)


def test_assert_single_currency_uniform_ok():
    model = {"type": "CompositePricing", "currency": "USD", "components": [
        {"type": "PerUnit", "dimension": "dim:Requests", "unit": "qudtu:NUM", "amount": "0.0000002"},
    ]}
    pricing.assert_single_currency(model)  # must not raise


def test_tiered_empty_tiers_raises():
    model = {"type": "TieredRate", "dimension": "dim:StorageDuration",
             "unit": "aunit:GigaByteMonth", "tierMode": "graduated", "tiers": []}
    with pytest.raises(pricing.PricingError):
        pricing.evaluate(model, {"dim:StorageDuration": 10})


def test_tiered_graduated_exact_boundary():
    # qty exactly at the first tier ceiling: 100 units all priced at tier-1 rate.
    model = {"type": "TieredRate", "dimension": "dim:StorageDuration",
             "unit": "aunit:GigaByteMonth", "tierMode": "graduated",
             "tiers": [{"upTo": "100", "amount": "0.10"},
                       {"upTo": "200", "amount": "0.05"},
                       {"amount": "0.01"}]}
    assert pricing.evaluate(model, {"dim:StorageDuration": 100}) == Decimal("10.00000000")


def test_storage_graduated_closed_form():
    storage = {"type": "TieredRate", "dimension": "dim:StorageDuration",
               "unit": "aunit:GigaByteMonth", "tierMode": "graduated",
               "tiers": [{"upTo": "51200", "amount": "0.023"},
                         {"upTo": "512000", "amount": "0.022"},
                         {"amount": "0.021"}]}
    # 51200*0.023 + 460800*0.022 + 88000*0.021 = 1177.6 + 10137.6 + 1848 = 13163.2
    assert pricing.evaluate(storage, {"dim:StorageDuration": "600000"}) == Decimal("13163.20000000")


def test_compute_allowance_closed_form():
    compute = {"type": "CompositePricing", "currency": "USD", "components": [
        {"type": "Allowance", "dimension": "dim:Requests", "unit": "qudtu:NUM", "freeQuantity": "1000000"},
        {"type": "PerUnit", "dimension": "dim:Requests", "unit": "qudtu:NUM", "amount": "0.0000002"},
        {"type": "PerUnit", "dimension": "dim:ComputeMemoryTime", "unit": "aunit:GigaByteSecond", "amount": "0.0000166667"}]}
    # (3,000,000-1,000,000)*0.0000002 + 600,000*0.0000166667 = 0.4 + 10.00002 = 10.40002
    assert pricing.evaluate(compute, {"dim:Requests": "3000000", "dim:ComputeMemoryTime": "600000"}) == Decimal("10.40002000")
