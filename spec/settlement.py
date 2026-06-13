"""Reference helpers for the AVP-Micro on-chain settlement binding.

Pure, dependency-light functions (no sim/generate coupling) shared by generate.py,
verify.py, and sim.py:

  * exact decimal -> integer base-unit conversion (rejects non-representable values)
  * USD -> millisatoshi conversion for the Lightning profile (explicit FX rate)
  * CAIP-2/10/19 + did:pkh parsing and the DID<->account binding rule
  * the finality predicate (confirmation-threshold rails AND Lightning preimage)
  * deterministic chain fixtures (tx hashes, payment hashes, preimages)

TEST FIXTURES ONLY -- chain references are derived deterministically from labels;
this module never contacts a chain.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal


class SettlementError(ValueError):
    """A settlement-binding constraint violation (e.g. non-representable amount)."""


MSAT_PER_BTC = 10 ** 11  # 1 BTC = 1e8 sat = 1e11 msat

# Per-asset minor-unit decimals for the test fixtures (CAIP-19 -> decimals).
_ASSET_DECIMALS = {
    "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913": 6,  # Base USDC
}

# Rail registry: default confirmation threshold + the asset used by each profile.
RAILS = {
    "evm-stablecoin": {"threshold": 12,
                       "asset": "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
    "x402":           {"threshold": 12,
                       "asset": "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
    "lightning":      {"threshold": 0,
                       "asset": "bip122:000000000019d6689c085ae165831e93/slip44:0"},
}


def decimals_for_asset(asset: str) -> int:
    if asset not in _ASSET_DECIMALS:
        raise SettlementError(f"unknown asset decimals: {asset}")
    return _ASSET_DECIMALS[asset]


def to_base_units(amount: str, decimals: int) -> str:
    """Exact decimal -> integer base units. Raises if not representable."""
    scaled = Decimal(amount).scaleb(decimals)
    if scaled != scaled.to_integral_value():
        raise SettlementError(f"{amount} not representable in {decimals} base-unit decimals")
    return str(int(scaled))


def usd_to_msat(amount_usd: str, rate_usd_per_btc: str) -> str:
    """Exact USD -> msat at an agreed USD/BTC rate. Raises if not an integer msat."""
    msat = Decimal(amount_usd) / Decimal(rate_usd_per_btc) * MSAT_PER_BTC
    if msat != msat.to_integral_value():
        raise SettlementError(f"{amount_usd} USD @ {rate_usd_per_btc} is not an integer msat")
    return str(int(msat))


def parse_caip10(account: str) -> tuple[str, str]:
    """CAIP-10 'namespace:reference:address' -> (chain_id 'namespace:reference', address)."""
    ns, ref, addr = account.split(":", 2)
    return f"{ns}:{ref}", addr


def did_pkh_account(did: str) -> tuple[str, str]:
    """did:pkh:NS:REF:ADDR -> (chain_id, CAIP-10 account)."""
    if not did.startswith("did:pkh:"):
        raise SettlementError(f"not a did:pkh: {did}")
    ns, ref, addr = did[len("did:pkh:"):].split(":", 2)
    return f"{ns}:{ref}", f"{ns}:{ref}:{addr}"


def account_binding_ok(instruction: dict, binding: dict | None) -> bool:
    """Is the instruction's payeeAccount bound to its payee DID?

    (a) payee is a did:pkh whose account == payeeAccount on the same chain, OR
    (b) a PayeeAccountBinding asserts the payee controls payeeAccount on that chain.
    The caller is responsible for verifying the binding's signature/signer separately.
    """
    payee = instruction["payee"]
    account = instruction["payeeAccount"]
    chain = instruction["chain"]
    if payee.startswith("did:pkh:"):
        bchain, baccount = did_pkh_account(payee)
        return bchain == chain and baccount == account
    if binding is None:
        return False
    return (binding.get("subject") == payee and binding.get("account") == account
            and binding.get("chain") == chain)


def finality_ok(proof: dict, threshold: int) -> bool:
    """Finality predicate. Lightning (preimage present): sha256(preimage)==payment_hash
    and finality=='final'. Confirmation rails: confirmations>=threshold and finality=='final'."""
    if proof.get("finality") != "final":
        return False
    if "preimage" in proof:
        digest = hashlib.sha256(bytes.fromhex(proof["preimage"])).hexdigest()
        return digest == proof.get("transaction")
    return int(proof.get("confirmations", -1)) >= threshold


# ---- deterministic chain fixtures (never a real chain) ----------------------

def fake_tx(label: str) -> str:
    return "0x" + hashlib.sha256(("avp-settle-tx:" + label).encode()).hexdigest()


def fake_preimage(label: str) -> str:
    return hashlib.sha256(("avp-ln-preimage:" + label).encode()).hexdigest()


def fake_payment_hash(label: str) -> str:
    return hashlib.sha256(bytes.fromhex(fake_preimage(label))).hexdigest()


def fake_address(label: str) -> str:
    """A 20-byte hex fixture address (NOT keccak-derived; fixtures only)."""
    return "0x" + hashlib.sha256(("avp-settle-addr:" + label).encode()).hexdigest()[:40]
