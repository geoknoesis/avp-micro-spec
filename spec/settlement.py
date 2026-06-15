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
# threshold = confirmation depth for finality (Base mainnet fixture default: 12).
RAILS = {
    "evm-stablecoin": {"threshold": 12,
                       "asset": "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
    "x402":           {"threshold": 12,
                       "asset": "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"},
    "lightning":      {"threshold": 0,
                       "asset": "bip122:000000000019d6689c085ae165831e93/slip44:0"},
}


# Wire rail identifier -> minimum confirmation depth a verifier MUST require for
# finality. A self-set instruction threshold below this floor is a finality downgrade.
_RAIL_THRESHOLD_FLOOR = {
    "stl:rail-evm-stablecoin": 12,
    "stl:rail-x402": 12,
    "stl:rail-lightning": 0,
}


def rail_threshold_floor(rail: str) -> int:
    """Minimum confirmation threshold a verifier MUST enforce for a rail (anti-downgrade)."""
    return _RAIL_THRESHOLD_FLOOR.get(rail, 12)  # conservative default for unknown rails


def decimals_for_asset(asset: str) -> int:
    # CAIP-19 chain namespace/reference are case-insensitive; normalize before lookup.
    if asset in _ASSET_DECIMALS:
        return _ASSET_DECIMALS[asset]
    low = {k.lower(): v for k, v in _ASSET_DECIMALS.items()}
    if asset.lower() in low:
        return low[asset.lower()]
    raise SettlementError(f"unknown asset decimals: {asset}")


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
    try:
        ns, ref, addr = account.split(":", 2)
    except ValueError:
        raise SettlementError(f"invalid CAIP-10 account: {account!r}")
    if not (ns and ref and addr) or any(c.isspace() for c in account):
        raise SettlementError(f"malformed CAIP-10 account: {account!r}")
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


def finality_ok(proof: dict, threshold: int, *, rail: str | None = None) -> bool:
    """Finality predicate. Lightning: sha256(preimage)==payment_hash and finality=='final'.
    Confirmation rails: confirmations>=threshold and finality=='final'.

    When `rail` is supplied (verifiers SHOULD always supply it), the finality METHOD is
    selected by the rail, not merely by the presence of a `preimage`: a `preimage` on a
    confirmation rail is rejected (it must not let a 0-confirmation proof masquerade as
    final), and a confirmation rail still requires confirmations>=threshold.
    """
    if proof.get("finality") != "final":
        return False
    is_lightning = rail is not None and rail.endswith("lightning")
    if rail is not None and not is_lightning and "preimage" in proof:
        return False  # SECURITY: a preimage is not a finality signal on a confirmation rail
    if is_lightning or (rail is None and "preimage" in proof):
        if "preimage" not in proof:
            return False
        digest = hashlib.sha256(bytes.fromhex(proof["preimage"])).hexdigest()
        return digest == proof.get("transaction")
    return int(proof.get("confirmations", -1)) >= threshold  # -1 sentinel: absent == never confirmed


# ---- attested (closed-processor) rails: card via Stripe + bank/RTP ----------
# These rails settle inside a private processor, so finality is NOT publicly
# verifiable: the proof embeds a processor attestation and is signed by the payee
# (payee-attested) or carries a processor signature (processor-attested).

_ATTESTED_RAILS = {"stl:rail-card-stripe", "stl:rail-bank-rtp", "stl:rail-paypal",
                   "stl:rail-visa-direct"}
# Statuses that count as final per rail family (card capture / bank settlement /
# PayPal capture COMPLETED / Visa Direct OCT approved).
_ATTESTED_FINAL_STATUS = {"succeeded", "captured", "settled", "completed", "approved"}
_ATTESTED_MODES = {"payee-attested", "processor-attested"}


def is_attested_rail(rail: str) -> bool:
    """True for closed-processor rails whose finality is attested, not on-chain."""
    return rail in _ATTESTED_RAILS


def attested_finality_ok(proof: dict) -> bool:
    """Finality predicate for an AttestedSettlementProof.

    final  <=>  proof.finality == 'final'  AND  the embedded attestation is well-formed:
    a recognized mode, a resolvable did:web processor (the named trust root), a non-empty
    processor reference, and a terminal status (captured/succeeded/settled).
    """
    if proof.get("finality") != "final":
        return False
    att = proof.get("attestation") or {}
    if att.get("mode") not in _ATTESTED_MODES:
        return False
    if not str(att.get("processor", "")).startswith("did:web:"):
        return False
    if not att.get("reference"):
        return False
    return att.get("status") in _ATTESTED_FINAL_STATUS


def attested_binding_ok(instruction: dict, binding: dict | None) -> bool:
    """Anti-redirection for attested rails: the instruction must settle to an account a
    ProcessorAccountBinding ties to the instruction's payee, on the same rail, and the
    instruction must reference that binding. (Caller verifies the binding's signature and
    that binding.subject == the authorized payee separately.)
    """
    if binding is None:
        return False
    return (binding.get("subject") == instruction.get("payee")
            and instruction.get("payeeAccountBinding") == binding.get("id")
            and binding.get("rail") == instruction.get("rail")
            and bool(binding.get("account")))


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
