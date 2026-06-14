"""Tests for the Bitstring Status List codec (spec/status.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import status as stx  # noqa: E402


def test_roundtrip_sets_and_reads_bits():
    enc = stx.encode_status_list({0, 7, 8, 94567})
    assert stx.is_revoked(enc, 0)
    assert stx.is_revoked(enc, 7)
    assert stx.is_revoked(enc, 8)
    assert stx.is_revoked(enc, 94567)
    assert not stx.is_revoked(enc, 1)
    assert not stx.is_revoked(enc, 94566)


def test_empty_list_has_no_revocations():
    enc = stx.encode_status_list(set())
    assert not stx.is_revoked(enc, 0)
    assert not stx.is_revoked(enc, 94567)


def test_encoding_is_deterministic():
    assert stx.encode_status_list({94567}) == stx.encode_status_list({94567})
    assert stx.encode_status_list(set()) == stx.encode_status_list(set())


def test_minimum_length_is_16kb():
    raw = stx.decode_status_list(stx.encode_status_list(set()))
    assert len(raw) >= 16384  # 131072 bits


def test_multibase_u_prefix():
    enc = stx.encode_status_list({1})
    assert enc.startswith("u")
    assert "=" not in enc  # no base64 padding


def test_out_of_range_index_rejected():
    enc = stx.encode_status_list(set())
    try:
        stx.is_revoked(enc, 131072)  # one past the end
    except ValueError:
        return
    raise AssertionError("expected ValueError for out-of-range index")
