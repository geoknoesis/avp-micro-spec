"""Unit tests for the AP2 mandate-model bridge translators (spec/interop.py)."""
import json

import avp_crypto as ac
import interop
import sdjwt


# ---- M4: canonical cart -> serviceRequestHash ----

def _cart():
    return {
        "merchant": "did:web:merchant.example",
        "currency": "USD",
        "items": [
            {"sku": "SKU-2", "qty": 1, "price": "12.00"},
            {"sku": "SKU-1", "qty": 3, "price": "4.00"},
        ],
        "total": {"amount": "24.00", "currency": "USD"},
        "cartExpiry": "2026-06-12T12:00:00Z",
    }


def test_canonical_cart_is_order_independent():
    a = _cart()
    b = json.loads(json.dumps(a))
    b["items"] = list(reversed(b["items"]))  # same items, different order
    assert interop.canonical_cart(a) == interop.canonical_cart(b)


def test_cart_service_request_hash_is_content_digest():
    h = interop.cart_service_request_hash(_cart())
    assert h.startswith("sha-256:")
    assert h == ac.content_digest(interop.canonical_cart(_cart()))
