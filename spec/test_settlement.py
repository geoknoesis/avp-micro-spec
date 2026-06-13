import hashlib

import pytest

import settlement as st


def test_to_base_units_exact_usdc():
    assert st.to_base_units("0.001", 6) == "1000"
    assert st.to_base_units("1", 6) == "1000000"


def test_to_base_units_rejects_non_representable():
    with pytest.raises(st.SettlementError):
        st.to_base_units("0.0000001", 6)  # 7th decimal: not representable in 6-dp USDC


def test_usd_to_msat_exact():
    # 0.001 USD at 100000 USD/BTC = 1e-8 BTC = 1 sat = 1000 msat
    assert st.usd_to_msat("0.001", "100000") == "1000"


def test_usd_to_msat_rejects_non_integer():
    with pytest.raises(st.SettlementError):
        st.usd_to_msat("0.0010000001", "100000")


def test_decimals_for_asset():
    assert st.decimals_for_asset("eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") == 6


def test_did_pkh_account_roundtrip():
    chain, account = st.did_pkh_account("did:pkh:eip155:8453:0xabc")
    assert chain == "eip155:8453"
    assert account == "eip155:8453:0xabc"


def test_account_binding_ok_did_pkh():
    instr = {"payee": "did:pkh:eip155:8453:0xabc",
             "payeeAccount": "eip155:8453:0xabc", "chain": "eip155:8453"}
    assert st.account_binding_ok(instr, None) is True
    bad = dict(instr, payeeAccount="eip155:8453:0xDEAD")
    assert st.account_binding_ok(bad, None) is False


def test_account_binding_ok_binding_object():
    instr = {"payee": "did:key:zPayee", "payeeAccount": "eip155:8453:0xabc",
             "chain": "eip155:8453"}
    binding = {"subject": "did:key:zPayee", "account": "eip155:8453:0xabc",
               "chain": "eip155:8453"}
    assert st.account_binding_ok(instr, binding) is True
    assert st.account_binding_ok(instr, dict(binding, subject="did:key:zEvil")) is False
    assert st.account_binding_ok(instr, None) is False  # did:key requires a binding


def test_finality_ok_confirmation_based():
    proof = {"confirmations": 12, "finality": "final"}
    assert st.finality_ok(proof, threshold=12) is True
    assert st.finality_ok({"confirmations": 3, "finality": "final"}, threshold=12) is False
    assert st.finality_ok({"confirmations": 12, "finality": "pending"}, threshold=12) is False


def test_finality_ok_lightning_preimage():
    preimage = st.fake_preimage("demo")
    payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    proof = {"transaction": payment_hash, "preimage": preimage, "finality": "final"}
    assert st.finality_ok(proof, threshold=0) is True
    bad = dict(proof, preimage=st.fake_preimage("other"))
    assert st.finality_ok(bad, threshold=0) is False


def test_fake_tx_is_deterministic():
    assert st.fake_tx("a") == st.fake_tx("a")
    assert st.fake_tx("a") != st.fake_tx("b")
    assert st.fake_tx("a").startswith("0x") and len(st.fake_tx("a")) == 66


def test_parse_caip10_malformed_raises_settlement_error():
    with pytest.raises(st.SettlementError):
        st.parse_caip10("eip155:8453")  # missing address segment


def test_decimals_for_asset_unknown_raises():
    with pytest.raises(st.SettlementError):
        st.decimals_for_asset("eip155:1/erc20:0xUnknown")


def test_finality_ok_absent_confirmations_is_not_final():
    assert st.finality_ok({"finality": "final"}, threshold=0) is False
