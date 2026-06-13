# On-chain Settlement Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fifth peer bundle `spec/settlement/` that binds AVP-Micro payments to public-blockchain settlement rails (EVM stablecoin, Coinbase x402, Bitcoin Lightning) via a rail-agnostic core, riding on Payments **by reference** with zero Payments-vector churn.

**Architecture:** New signed object types (`SettlementInstruction`, `SettlementProof`, `PayeeAccountBinding`, `EscrowLock`, `EscrowRelease`, `EscrowRefund`) that reference existing `PaymentAuthorization`/`PaymentExecution` by id and carry CAIP-2/10/19 identifiers, integer base-unit amounts, a finality state machine, and a DID↔account binding. A new pure-helper module `spec/settlement.py` (modelled on `pricing.py`/`interop.py`) holds base-unit/finality/binding logic; `generate.py`/`verify.py`/`validate.py`/`sim.py` gain a settlement section. The simulator gets three mock `SettlementRail` adapters subclassing the existing `SimulatedLedger` (play balances only — never broadcasts).

**Tech Stack:** Python 3 + `cryptography` (P-256 `ecdsa-jcs-2022`), `rdflib`/`pyld`/`jsonschema`/`pyshacl` (offline validation), JSON-LD 1.1, JSON Schema 2020-12, SHACL, W3C ReSpec. Reference identifiers per Chain Agnostic Standards (CAIP-2/10/19, `did:pkh`).

**Source spec:** [`docs/superpowers/specs/2026-06-12-onchain-settlement-design.md`](../specs/2026-06-12-onchain-settlement-design.md)

**Conventions locked for all fixtures (use verbatim):**
- Settlement context URL: `https://w3id.org/avp-micro/settlement/v1`; namespace `https://w3id.org/avp-micro/settlement/v1#`; prefix `stl:`.
- 5-entry signed `@context`: `["https://www.w3.org/ns/credentials/v2","https://w3id.org/security/data-integrity/v2","https://w3id.org/spending-authority/v1","https://w3id.org/avp-micro/v1","https://w3id.org/avp-micro/settlement/v1"]`.
- Reused terms (`amount`, `currency`, `payer`, `payee`, `status`, `timestamp`, `settlementRef`, `execution`, `authorization`, `nonce`, `expires`) resolve via the AVP/DSA contexts already in the array — **do not** redefine them in the settlement context. New terms are minted under `stl:`.
- All settlement objects are signed with `ac.sign_ecdsa_jcs_2022`. Signers: `PayeeAccountBinding` → **payee**; every other settlement object → **wallet** (the same key that signs `PaymentExecution`).
- Test assets: Base USDC `eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` (6 decimals); Lightning native `bip122:000000000019d6689c085ae165831e93/slip44:0` (msat base units). Chains: EVM `eip155:8453`; Lightning network id `bip122:000000000019d6689c085ae165831e93`.
- Vectors are numbered **40+** (offers `00`, payments `01–18`, disputes `20–39`).
- Run the full gate after every Task that touches vectors: `python spec/generate.py && python spec/verify.py && python spec/validate.py && python spec/sim.py` — all four must print `PASS`.

---

## Task 1: Reference helper module `spec/settlement.py` (base units, finality, CAIP, binding)

**Files:**
- Create: `spec/settlement.py`
- Test: `spec/test_settlement.py`

- [ ] **Step 1: Write the failing unit tests**

Create `spec/test_settlement.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd spec && python -m pytest test_settlement.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'settlement'`.

- [ ] **Step 3: Implement `spec/settlement.py`**

```python
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd spec && python -m pytest test_settlement.py -q`
Expected: PASS (11 passed).

- [ ] **Step 5: Commit**

```bash
git add spec/settlement.py spec/test_settlement.py
git commit -m "feat(settlement): reference helpers for base units, finality, CAIP binding"
```

---

## Task 2: Bundle scaffold — JSON-LD context + RDFS/OWL vocab + rails SKOS

**Files:**
- Create: `spec/settlement/context/v1.jsonld`
- Create: `spec/settlement/vocab/settlement.ttl`
- Create: `spec/settlement/vocab/rails.ttl`
- Test (manual): `python -c "import rdflib; rdflib.Graph().parse('spec/settlement/vocab/settlement.ttl', format='turtle'); rdflib.Graph().parse('spec/settlement/vocab/rails.ttl', format='turtle'); print('OK')"`

- [ ] **Step 1: Write `spec/settlement/context/v1.jsonld`**

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "stl": "https://w3id.org/avp-micro/settlement/v1#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",

    "SettlementInstruction": "stl:SettlementInstruction",
    "SettlementProof": "stl:SettlementProof",
    "PayeeAccountBinding": "stl:PayeeAccountBinding",
    "EscrowLock": "stl:EscrowLock",
    "EscrowRelease": "stl:EscrowRelease",
    "EscrowRefund": "stl:EscrowRefund",

    "authorizationDigest": { "@id": "stl:authorizationDigest" },
    "rail": { "@id": "stl:rail", "@type": "@id" },
    "chain": { "@id": "stl:chain" },
    "payeeAccount": { "@id": "stl:payeeAccount" },
    "asset": { "@id": "stl:asset" },
    "amountBase": { "@id": "stl:amountBase" },
    "rate": { "@id": "stl:rate" },
    "confirmationThreshold": { "@id": "stl:confirmationThreshold" },
    "mode": { "@id": "stl:mode" },
    "payeeAccountBinding": { "@id": "stl:payeeAccountBinding", "@type": "@id" },

    "instruction": { "@id": "stl:instruction", "@type": "@id" },
    "instructionDigest": { "@id": "stl:instructionDigest" },
    "transaction": { "@id": "stl:transaction" },
    "preimage": { "@id": "stl:preimage" },
    "settledAmountBase": { "@id": "stl:settledAmountBase" },
    "blockHeight": { "@id": "stl:blockHeight" },
    "confirmations": { "@id": "stl:confirmations" },
    "finality": { "@id": "stl:finality" },
    "observedAt": { "@id": "stl:observedAt", "@type": "xsd:dateTime" },

    "subject": { "@id": "stl:subject", "@type": "@id" },
    "account": { "@id": "stl:account" },

    "lock": { "@id": "stl:lock", "@type": "@id" },
    "lockDigest": { "@id": "stl:lockDigest" },
    "lockRef": { "@id": "stl:lockRef" },
    "lockedAmountBase": { "@id": "stl:lockedAmountBase" },
    "timeout": { "@id": "stl:timeout", "@type": "xsd:dateTime" },
    "settlementProof": { "@id": "stl:settlementProof", "@type": "@id" },
    "settlementProofDigest": { "@id": "stl:settlementProofDigest" },
    "reason": { "@id": "stl:reason" }
  }
}
```

- [ ] **Step 2: Write `spec/settlement/vocab/settlement.ttl`**

```turtle
# AVP-Micro Settlement core RDFS/OWL ontology.
#
# Classes/properties whose JSON-LD term mappings live in ../context/v1.jsonld.
# The on-chain settlement binding: rail-agnostic instruction + chain-native proof,
# an optional escrow lifecycle, and a payee account<->DID binding. Reused members
# (amount, currency, payer, payee, status, timestamp, settlementRef, execution,
# authorization) expand to avp:/dsa:/sec:; new members expand to stl:.
#
# Namespace: https://w3id.org/avp-micro/settlement/v1#  (prefix stl:)
@prefix stl:  <https://w3id.org/avp-micro/settlement/v1#> .
@prefix avp:  <https://w3id.org/avp-micro/v1#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
@prefix dct:  <http://purl.org/dc/terms/> .

<https://w3id.org/avp-micro/settlement/v1> a owl:Ontology ;
  dct:title "AVP-Micro Settlement vocabulary"@en ;
  dct:description "Classes and properties for binding AVP-Micro payments to public-blockchain settlement rails (EVM stablecoin, x402, Lightning)."@en ;
  owl:versionInfo "0.1.0" ;
  rdfs:seeAlso <https://w3id.org/avp-micro/v1> .

#################################################################
# Classes
#################################################################

stl:SettlementInstruction a owl:Class ; rdfs:label "Settlement instruction"@en ;
  rdfs:comment "A wallet-signed instruction binding a PaymentAuthorization to a concrete rail, recipient account, asset, and base-unit amount."@en .
stl:SettlementProof a owl:Class ; rdfs:label "Settlement proof"@en ;
  rdfs:comment "A chain-native attestation that settlement occurred (transaction reference + finality)."@en .
stl:PayeeAccountBinding a owl:Class ; rdfs:label "Payee account binding"@en ;
  rdfs:comment "A payee-signed assertion that a DID controls an on-chain account (CAIP-10) on a chain (CAIP-2)."@en .
stl:EscrowLock a owl:Class ; rdfs:label "Escrow lock"@en ;
  rdfs:comment "A wallet-signed record that funds were locked (escrow contract or Lightning hold-invoice) pending delivery."@en .
stl:EscrowRelease a owl:Class ; rdfs:label "Escrow release"@en ;
  rdfs:comment "A wallet-signed record releasing a prior EscrowLock to the payee, carrying the settling SettlementProof."@en .
stl:EscrowRefund a owl:Class ; rdfs:label "Escrow refund"@en ;
  rdfs:comment "A wallet-signed record refunding a prior EscrowLock to the payer (timeout/dispute), carrying the settling SettlementProof."@en .

#################################################################
# Object properties (node references / DIDs / IRIs)
#################################################################

stl:rail a owl:ObjectProperty ; rdfs:label "rail"@en ;
  rdfs:comment "IRI of the settlement-rail concept (a stl: SKOS concept; see rails.ttl)."@en .
stl:instruction a owl:ObjectProperty ; rdfs:label "instruction"@en ;
  rdfs:comment "IRI of the SettlementInstruction a proof/lock concerns."@en .
stl:payeeAccountBinding a owl:ObjectProperty ; rdfs:label "payee account binding"@en ;
  rdfs:comment "IRI of the PayeeAccountBinding that authorizes payeeAccount (when payee is not a did:pkh)."@en .
stl:subject a owl:ObjectProperty ; rdfs:label "subject"@en ;
  rdfs:comment "DID whose control of an account a PayeeAccountBinding asserts."@en .
stl:lock a owl:ObjectProperty ; rdfs:label "lock"@en ;
  rdfs:comment "IRI of the EscrowLock a release/refund concerns."@en .
stl:settlementProof a owl:ObjectProperty ; rdfs:label "settlement proof"@en ;
  rdfs:comment "IRI of the SettlementProof recording the on-chain transaction for a release/refund."@en .

#################################################################
# Digest properties (content digests over the referenced signed object)
#################################################################

stl:authorizationDigest a owl:DatatypeProperty ; rdfs:label "authorization digest"@en ; rdfs:range xsd:string .
stl:instructionDigest a owl:DatatypeProperty ; rdfs:label "instruction digest"@en ; rdfs:range xsd:string .
stl:lockDigest a owl:DatatypeProperty ; rdfs:label "lock digest"@en ; rdfs:range xsd:string .
stl:settlementProofDigest a owl:DatatypeProperty ; rdfs:label "settlement proof digest"@en ; rdfs:range xsd:string .

#################################################################
# Scalar / enumerated properties
#################################################################

stl:chain a owl:DatatypeProperty ; rdfs:label "chain"@en ; rdfs:range xsd:string ;
  rdfs:comment "CAIP-2 chain id (e.g. eip155:8453)."@en .
stl:payeeAccount a owl:DatatypeProperty ; rdfs:label "payee account"@en ; rdfs:range xsd:string ;
  rdfs:comment "CAIP-10 account or Lightning destination (BOLT11/LNURL/node id)."@en .
stl:account a owl:DatatypeProperty ; rdfs:label "account"@en ; rdfs:range xsd:string .
stl:asset a owl:DatatypeProperty ; rdfs:label "asset"@en ; rdfs:range xsd:string ;
  rdfs:comment "CAIP-19 asset id."@en .
stl:amountBase a owl:DatatypeProperty ; rdfs:label "amount (base units)"@en ; rdfs:range xsd:string ;
  rdfs:comment "Integer minor units / sats / msat as a string."@en .
stl:settledAmountBase a owl:DatatypeProperty ; rdfs:label "settled amount (base units)"@en ; rdfs:range xsd:string .
stl:lockedAmountBase a owl:DatatypeProperty ; rdfs:label "locked amount (base units)"@en ; rdfs:range xsd:string .
stl:rate a owl:DatatypeProperty ; rdfs:label "rate"@en ; rdfs:range xsd:string ;
  rdfs:comment "Agreed conversion when the quote currency differs from the settlement asset (e.g. USD per BTC)."@en .
stl:confirmationThreshold a owl:DatatypeProperty ; rdfs:label "confirmation threshold"@en ; rdfs:range xsd:integer .
stl:confirmations a owl:DatatypeProperty ; rdfs:label "confirmations"@en ; rdfs:range xsd:integer .
stl:blockHeight a owl:DatatypeProperty ; rdfs:label "block height"@en ; rdfs:range xsd:integer .
stl:mode a owl:DatatypeProperty ; rdfs:label "mode"@en ; rdfs:range xsd:string ;
  rdfs:comment "One of 'direct' or 'escrow'."@en .
stl:finality a owl:DatatypeProperty ; rdfs:label "finality"@en ; rdfs:range xsd:string ;
  rdfs:comment "One of 'pending', 'probabilistic', 'final'."@en .
stl:transaction a owl:DatatypeProperty ; rdfs:label "transaction"@en ; rdfs:range xsd:string ;
  rdfs:comment "Chain-native transaction reference: tx hash, or Lightning payment_hash."@en .
stl:preimage a owl:DatatypeProperty ; rdfs:label "preimage"@en ; rdfs:range xsd:string ;
  rdfs:comment "Lightning payment preimage; sha256(preimage)==transaction proves payment."@en .
stl:lockRef a owl:DatatypeProperty ; rdfs:label "lock reference"@en ; rdfs:range xsd:string ;
  rdfs:comment "Escrow handle: contract address + escrow id, or a Lightning hold-invoice payment_hash."@en .
stl:reason a owl:DatatypeProperty ; rdfs:label "reason"@en ; rdfs:range xsd:string ;
  rdfs:comment "Why an EscrowRefund occurred (e.g. 'timeout')."@en .
stl:observedAt a owl:DatatypeProperty ; rdfs:label "observed at"@en ; rdfs:range xsd:dateTime .
stl:timeout a owl:DatatypeProperty ; rdfs:label "timeout"@en ; rdfs:range xsd:dateTime .
```

- [ ] **Step 3: Write `spec/settlement/vocab/rails.ttl`**

```turtle
# AVP-Micro settlement-rail registry (extensible SKOS scheme) + finality terms.
# Informative skos:note maps each rail to its real-world substrate. NON-NORMATIVE
# mappings; implementers MAY mint additional rail concepts in their own scheme.
#
# Namespace: https://w3id.org/avp-micro/settlement/v1#  (prefix stl:)
@prefix stl:  <https://w3id.org/avp-micro/settlement/v1#> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .

stl:RailScheme a skos:ConceptScheme ;
  skos:prefLabel "AVP-Micro settlement-rail scheme"@en ;
  skos:definition "An extensible set of settlement-rail concepts for on-chain binding."@en .

stl:rail-evm-stablecoin a skos:Concept ; skos:inScheme stl:RailScheme ;
  skos:prefLabel "EVM stablecoin"@en ;
  skos:definition "ERC-20 stablecoin transfer on an EVM chain (CAIP-2 eip155:*)."@en ;
  skos:note "Reference: USDC on Base. Finality by confirmation depth."@en .

stl:rail-x402 a skos:Concept ; skos:inScheme stl:RailScheme ;
  skos:prefLabel "Coinbase x402"@en ;
  skos:definition "HTTP 402 + stablecoin settlement for agent/API micropayments."@en ;
  skos:note "Pay-then-serve; settlement proof is the facilitator's on-chain transfer."@en .

stl:rail-lightning a skos:Concept ; skos:inScheme stl:RailScheme ;
  skos:prefLabel "Bitcoin Lightning"@en ;
  skos:definition "Lightning Network payment; amounts in millisatoshi."@en ;
  skos:note "Finality is preimage reveal; escrow is native via hold-invoices."@en .
```

> NOTE: the SKOS concept IRIs are `stl:rail-evm-stablecoin` etc. The `rail` value in vectors uses these exact IRIs in compact form `"stl:rail-evm-stablecoin"`. (JSON-LD will expand them via the `stl` prefix in the context.)

- [ ] **Step 4: Verify all three parse**

Run:
```bash
cd spec && python -c "import rdflib; rdflib.Graph().parse('settlement/vocab/settlement.ttl', format='turtle'); rdflib.Graph().parse('settlement/vocab/rails.ttl', format='turtle'); import json; json.load(open('settlement/context/v1.jsonld')); print('OK')"
```
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add spec/settlement/context/v1.jsonld spec/settlement/vocab/settlement.ttl spec/settlement/vocab/rails.ttl
git commit -m "feat(settlement): JSON-LD context, core ontology, rails SKOS scheme"
```

---

## Task 3: JSON Schema for the six settlement object types

**Files:**
- Create: `spec/settlement/schemas/settlement.schema.json`

- [ ] **Step 1: Write the schema**

Create `spec/settlement/schemas/settlement.schema.json`. The `$defs` for `did`, `idValue`, `decimal`, `positiveDecimal`, `dateTime`, `contentDigest`, `proof` are copied verbatim from `spec/disputes/schemas/disputes.schema.json` (lines 8–35). Add `baseUnits` and the 5-entry `signedContext`, then the six object `$defs`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://w3id.org/avp-micro/settlement/schemas/settlement.schema.json",
  "title": "AVP-Micro Settlement data objects",
  "description": "JSON Schema for AVP-Micro on-chain settlement-binding messages. Validate an instance against the relevant $def, e.g. #/$defs/SettlementInstruction. Schemas are lenient about extra members (the @protected JSON-LD context governs semantics); they enforce required members, types, and value formats.",

  "$defs": {
    "did": { "type": "string", "pattern": "^did:[a-z0-9]+:.+" },
    "idValue": { "type": "string", "minLength": 1 },
    "decimal": { "type": "string", "pattern": "^(0|[1-9][0-9]*)(\\.[0-9]+)?$" },
    "positiveDecimal": { "type": "string", "pattern": "^(0\\.[0-9]*[1-9][0-9]*|[1-9][0-9]*(\\.[0-9]+)?)$" },
    "baseUnits": { "type": "string", "pattern": "^(0|[1-9][0-9]*)$" },
    "dateTime": { "type": "string", "format": "date-time" },
    "contentDigest": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" },
    "caip2": { "type": "string", "pattern": "^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$" },
    "proof": {
      "type": "object",
      "required": ["type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue"],
      "properties": {
        "type": { "const": "DataIntegrityProof" },
        "cryptosuite": { "const": "ecdsa-jcs-2022" },
        "created": { "$ref": "#/$defs/dateTime" },
        "verificationMethod": { "type": "string", "minLength": 1 },
        "proofPurpose": { "const": "assertionMethod" },
        "proofValue": { "type": "string", "pattern": "^z[1-9A-HJ-NP-Za-km-z]+$" }
      }
    },
    "signedContext": {
      "type": "array",
      "prefixItems": [
        { "const": "https://www.w3.org/ns/credentials/v2" },
        { "const": "https://w3id.org/security/data-integrity/v2" },
        { "const": "https://w3id.org/spending-authority/v1" },
        { "const": "https://w3id.org/avp-micro/v1" },
        { "const": "https://w3id.org/avp-micro/settlement/v1" }
      ],
      "minItems": 5,
      "maxItems": 5
    },

    "PayeeAccountBinding": {
      "type": "object",
      "required": ["@context", "id", "type", "subject", "account", "chain", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "PayeeAccountBinding" }, { "type": "array", "contains": { "const": "PayeeAccountBinding" } } ] },
        "subject": { "$ref": "#/$defs/did" },
        "account": { "type": "string", "minLength": 1 },
        "chain": { "$ref": "#/$defs/caip2" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "SettlementInstruction": {
      "type": "object",
      "required": ["@context", "id", "type", "authorization", "authorizationDigest", "rail", "chain", "payeeAccount", "asset", "payer", "payee", "amount", "currency", "amountBase", "confirmationThreshold", "mode", "nonce", "expires", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "SettlementInstruction" }, { "type": "array", "contains": { "const": "SettlementInstruction" } } ] },
        "authorization": { "$ref": "#/$defs/idValue" },
        "authorizationDigest": { "$ref": "#/$defs/contentDigest" },
        "rail": { "type": "string", "minLength": 1 },
        "chain": { "$ref": "#/$defs/caip2" },
        "payeeAccount": { "type": "string", "minLength": 1 },
        "asset": { "type": "string", "minLength": 1 },
        "payer": { "$ref": "#/$defs/did" },
        "payee": { "$ref": "#/$defs/did" },
        "amount": { "$ref": "#/$defs/positiveDecimal" },
        "currency": { "type": "string" },
        "amountBase": { "$ref": "#/$defs/baseUnits" },
        "rate": { "$ref": "#/$defs/positiveDecimal" },
        "confirmationThreshold": { "type": "integer", "minimum": 0 },
        "mode": { "enum": ["direct", "escrow"] },
        "payeeAccountBinding": { "$ref": "#/$defs/idValue" },
        "nonce": { "type": "string", "minLength": 1 },
        "expires": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "SettlementProof": {
      "type": "object",
      "required": ["@context", "id", "type", "instruction", "instructionDigest", "chain", "transaction", "settledAmountBase", "asset", "finality", "observedAt", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "SettlementProof" }, { "type": "array", "contains": { "const": "SettlementProof" } } ] },
        "instruction": { "$ref": "#/$defs/idValue" },
        "instructionDigest": { "$ref": "#/$defs/contentDigest" },
        "execution": { "$ref": "#/$defs/idValue" },
        "chain": { "$ref": "#/$defs/caip2" },
        "transaction": { "type": "string", "minLength": 1 },
        "preimage": { "type": "string", "minLength": 1 },
        "settledAmountBase": { "$ref": "#/$defs/baseUnits" },
        "asset": { "type": "string", "minLength": 1 },
        "blockHeight": { "type": "integer", "minimum": 0 },
        "confirmations": { "type": "integer", "minimum": 0 },
        "finality": { "enum": ["pending", "probabilistic", "final"] },
        "observedAt": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "EscrowLock": {
      "type": "object",
      "required": ["@context", "id", "type", "instruction", "instructionDigest", "lockRef", "lockedAmountBase", "asset", "timeout", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "EscrowLock" }, { "type": "array", "contains": { "const": "EscrowLock" } } ] },
        "instruction": { "$ref": "#/$defs/idValue" },
        "instructionDigest": { "$ref": "#/$defs/contentDigest" },
        "lockRef": { "type": "string", "minLength": 1 },
        "lockedAmountBase": { "$ref": "#/$defs/baseUnits" },
        "asset": { "type": "string", "minLength": 1 },
        "timeout": { "$ref": "#/$defs/dateTime" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "EscrowRelease": {
      "type": "object",
      "required": ["@context", "id", "type", "lock", "lockDigest", "settlementProof", "settlementProofDigest", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "EscrowRelease" }, { "type": "array", "contains": { "const": "EscrowRelease" } } ] },
        "lock": { "$ref": "#/$defs/idValue" },
        "lockDigest": { "$ref": "#/$defs/contentDigest" },
        "settlementProof": { "$ref": "#/$defs/idValue" },
        "settlementProofDigest": { "$ref": "#/$defs/contentDigest" },
        "proof": { "$ref": "#/$defs/proof" }
      }
    },

    "EscrowRefund": {
      "type": "object",
      "required": ["@context", "id", "type", "lock", "lockDigest", "settlementProof", "settlementProofDigest", "reason", "proof"],
      "properties": {
        "@context": { "$ref": "#/$defs/signedContext" },
        "id": { "$ref": "#/$defs/idValue" },
        "type": { "oneOf": [ { "const": "EscrowRefund" }, { "type": "array", "contains": { "const": "EscrowRefund" } } ] },
        "lock": { "$ref": "#/$defs/idValue" },
        "lockDigest": { "$ref": "#/$defs/contentDigest" },
        "settlementProof": { "$ref": "#/$defs/idValue" },
        "settlementProofDigest": { "$ref": "#/$defs/contentDigest" },
        "reason": { "type": "string", "minLength": 1 },
        "proof": { "$ref": "#/$defs/proof" }
      }
    }
  }
}
```

- [ ] **Step 2: Verify the schema is well-formed**

Run:
```bash
cd spec && python -c "from jsonschema import Draft202012Validator; import json; Draft202012Validator.check_schema(json.load(open('settlement/schemas/settlement.schema.json'))); print('schema OK')"
```
Expected: `schema OK`.

- [ ] **Step 3: Commit**

```bash
git add spec/settlement/schemas/settlement.schema.json
git commit -m "feat(settlement): JSON Schema for the six settlement object types"
```

---

## Task 4: SHACL shapes for the settlement objects

**Files:**
- Create: `spec/settlement/shapes/settlement-shapes.ttl`

- [ ] **Step 1: Write the shapes**

```turtle
# AVP-Micro Settlement SHACL shapes.
# Second validation layer alongside the JSON Schema in ../schemas/. Validates the
# RDF produced by expanding a settlement JSON-LD object. Reused members expand to
# avp:/dsa:/sec:; new members expand to stl:.
@prefix sh:   <http://www.w3.org/ns/shacl#> .
@prefix stl:  <https://w3id.org/avp-micro/settlement/v1#> .
@prefix avp:  <https://w3id.org/avp-micro/v1#> .
@prefix dsa:  <https://w3id.org/spending-authority/v1#> .
@prefix sec:  <https://w3id.org/security#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .

stl:PositiveDecimalAmount a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^(0[.][0-9]*[1-9][0-9]*|[1-9][0-9]*([.][0-9]+)?)$" .
stl:BaseUnits a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^(0|[1-9][0-9]*)$" .
stl:ContentDigest a sh:NodeShape ; sh:nodeKind sh:Literal ;
  sh:pattern "^[a-z0-9][a-z0-9-]*:[A-Za-z0-9_-]+$" .

stl:PayeeAccountBindingShape a sh:NodeShape ;
  sh:targetClass stl:PayeeAccountBinding ;
  sh:property [ sh:path stl:subject ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path stl:account ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:chain ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

stl:SettlementInstructionShape a sh:NodeShape ;
  sh:targetClass stl:SettlementInstruction ;
  sh:property [ sh:path avp:authorization ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:authorizationDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:rail ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:chain ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:payeeAccount ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:asset ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path avp:payer ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:payee ; sh:nodeKind sh:IRI ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path avp:amount ; sh:node stl:PositiveDecimalAmount ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path dsa:currency ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:amountBase ; sh:node stl:BaseUnits ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path stl:confirmationThreshold ; sh:datatype xsd:integer ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:mode ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path dsa:nonce ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path dsa:expires ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

stl:SettlementProofShape a sh:NodeShape ;
  sh:targetClass stl:SettlementProof ;
  sh:property [ sh:path stl:instruction ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:instructionDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:chain ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:transaction ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:settledAmountBase ; sh:node stl:BaseUnits ; sh:minCount 1 ; sh:maxCount 1 ] ;
  sh:property [ sh:path stl:asset ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:finality ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:observedAt ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

stl:EscrowLockShape a sh:NodeShape ;
  sh:targetClass stl:EscrowLock ;
  sh:property [ sh:path stl:instruction ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:instructionDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:lockRef ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:lockedAmountBase ; sh:node stl:BaseUnits ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:asset ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:timeout ; sh:datatype xsd:dateTime ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

stl:EscrowReleaseShape a sh:NodeShape ;
  sh:targetClass stl:EscrowRelease ;
  sh:property [ sh:path stl:lock ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:lockDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:settlementProof ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:settlementProofDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .

stl:EscrowRefundShape a sh:NodeShape ;
  sh:targetClass stl:EscrowRefund ;
  sh:property [ sh:path stl:lock ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:lockDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:settlementProof ; sh:nodeKind sh:IRI ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:settlementProofDigest ; sh:node stl:ContentDigest ; sh:minCount 1 ] ;
  sh:property [ sh:path stl:reason ; sh:nodeKind sh:Literal ; sh:minCount 1 ] ;
  sh:property [ sh:path sec:proof ; sh:minCount 1 ] .
```

- [ ] **Step 2: Verify the shapes parse**

Run: `cd spec && python -c "import rdflib; print(len(rdflib.Graph().parse('settlement/shapes/settlement-shapes.ttl', format='turtle')), 'triples')"`
Expected: a positive triple count, no exception.

- [ ] **Step 3: Commit**

```bash
git add spec/settlement/shapes/settlement-shapes.ttl
git commit -m "feat(settlement): SHACL shapes for settlement objects"
```

---

## Task 5: Generate signed vectors — EVM stablecoin profile (direct)

**Files:**
- Modify: `spec/generate.py` (add a settlement section after the disputes block, before the interop block at line ~508)

This task adds the shared settlement constants + the EVM direct-mode vectors. Later tasks append x402, Lightning, escrow, and reversal vectors to the same section.

- [ ] **Step 1: Add the settlement import and constants**

In `spec/generate.py`, add to the imports (near line 13–15):

```python
import settlement as st
```

And after the context constants (near line 30, after `DISP_CTX = ...`):

```python
SETTLE_URL = "https://w3id.org/avp-micro/settlement/v1"
SETTLE_CTX = [VC2, DI, DSA, AVP, SETTLE_URL]
SETTLE = SPEC / "settlement" / "test-vectors"
```

- [ ] **Step 2: Add the EVM section at the end of `main()`**

Insert immediately before the `# ---- Interop (SD-JWT-VC) bundle ----` comment (line ~508). This block reuses the already-built `authz` (urn:avp:authz:999, amount "0.001") and `execution` (urn:avp:exec:555) and the `wallet`/`payee` keys/DIDs:

```python
    # ---- Settlement bundle (on-chain settlement binding) ----
    # Rides on Payments by reference: a SettlementInstruction binds the existing
    # PaymentAuthorization (urn:avp:authz:999, 0.001 USD) to a concrete rail; a
    # SettlementProof carries the chain-native transaction + finality. Chain data
    # (tx hashes, heights, preimages) are DETERMINISTIC FIXTURES -- nothing is broadcast.
    authz_digest = ac.jcs_digest(authz)
    usdc = st.RAILS["evm-stablecoin"]["asset"]
    evm_threshold = st.RAILS["evm-stablecoin"]["threshold"]

    # EVM payee identified by did:pkh (binding archetype (a): the DID *is* the account).
    evm_addr = st.fake_address("payee-evm")
    evm_account = "eip155:8453:" + evm_addr
    evm_payee_did = "did:pkh:eip155:8453:" + evm_addr

    # 41: EVM stablecoin SettlementInstruction (direct), did:pkh payee.
    instr_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:evm", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-evm-stablecoin", "chain": "eip155:8453",
        "payeeAccount": evm_account, "asset": usdc,
        "payer": DID_AGENT, "payee": evm_payee_did,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": evm_threshold, "mode": "direct",
        "nonce": "settle-evm-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_evm = ac.sign_ecdsa_jcs_2022(instr_evm, wallet, "2026-03-25T21:30:10Z")
    write(SETTLE, "41-settlement-instruction-evm.json", instr_evm)

    # 42: EVM SettlementProof (final at >= threshold confirmations).
    proof_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:evm", "type": "SettlementProof",
        "instruction": instr_evm["id"], "instructionDigest": ac.jcs_digest(instr_evm),
        "execution": execution["id"], "chain": "eip155:8453",
        "transaction": st.fake_tx("evm-direct"),
        "settledAmountBase": instr_evm["amountBase"], "asset": usdc,
        "blockHeight": 19000000, "confirmations": evm_threshold, "finality": "final",
        "observedAt": "2026-03-25T21:33:00Z",
    }
    proof_evm = ac.sign_ecdsa_jcs_2022(proof_evm, wallet, "2026-03-25T21:33:00Z")
    write(SETTLE, "42-settlement-proof-evm.json", proof_evm)
```

- [ ] **Step 3: Run generate and confirm the two files appear**

Run: `cd spec && python generate.py`
Expected: output includes `wrote test-vectors/41-settlement-instruction-evm.json` and `...42-settlement-proof-evm.json` (the `write` helper prints `base.name`, which is `test-vectors`).

- [ ] **Step 4: Sanity-check the generated proof verifies**

Run:
```bash
cd spec && python -c "import json, avp_crypto as ac; print(ac.verify_ecdsa_jcs_2022(json.load(open('settlement/test-vectors/41-settlement-instruction-evm.json'))), ac.verify_ecdsa_jcs_2022(json.load(open('settlement/test-vectors/42-settlement-proof-evm.json'))))"
```
Expected: `True True`.

- [ ] **Step 5: Commit**

```bash
git add spec/generate.py spec/settlement/test-vectors/41-settlement-instruction-evm.json spec/settlement/test-vectors/42-settlement-proof-evm.json
git commit -m "feat(settlement): generate EVM stablecoin direct-mode vectors"
```

---

## Task 6: Generate vectors — x402 profile + PayeeAccountBinding (direct, binding archetype b)

**Files:**
- Modify: `spec/generate.py` (append to the settlement section)

- [ ] **Step 1: Append the x402 + binding block**

After the EVM block in the settlement section:

```python
    # x402 uses a did:key payee (the existing DID_PAYEE) + a PayeeAccountBinding
    # (binding archetype (b)): the payee signs that it controls a CAIP-10 account.
    x402_addr = st.fake_address("payee-x402")
    x402_account = "eip155:8453:" + x402_addr

    # 40: PayeeAccountBinding (payee-signed).
    binding = {
        "@context": SETTLE_CTX, "id": "urn:avp:payee-binding:x402", "type": "PayeeAccountBinding",
        "subject": DID_PAYEE, "account": x402_account, "chain": "eip155:8453",
    }
    binding = ac.sign_ecdsa_jcs_2022(binding, payee, "2026-03-25T21:29:30Z")
    write(SETTLE, "40-payee-account-binding.json", binding)

    # 43: x402 SettlementInstruction (direct) referencing the binding.
    instr_x402 = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:x402", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-x402", "chain": "eip155:8453",
        "payeeAccount": x402_account, "asset": usdc,
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": st.RAILS["x402"]["threshold"], "mode": "direct",
        "payeeAccountBinding": binding["id"],
        "nonce": "settle-x402-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_x402 = ac.sign_ecdsa_jcs_2022(instr_x402, wallet, "2026-03-25T21:30:11Z")
    write(SETTLE, "43-settlement-instruction-x402.json", instr_x402)

    # 44: x402 SettlementProof (final).
    proof_x402 = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:x402", "type": "SettlementProof",
        "instruction": instr_x402["id"], "instructionDigest": ac.jcs_digest(instr_x402),
        "execution": execution["id"], "chain": "eip155:8453",
        "transaction": st.fake_tx("x402-direct"),
        "settledAmountBase": instr_x402["amountBase"], "asset": usdc,
        "blockHeight": 19000005, "confirmations": st.RAILS["x402"]["threshold"], "finality": "final",
        "observedAt": "2026-03-25T21:33:30Z",
    }
    proof_x402 = ac.sign_ecdsa_jcs_2022(proof_x402, wallet, "2026-03-25T21:33:30Z")
    write(SETTLE, "44-settlement-proof-x402.json", proof_x402)
```

- [ ] **Step 2: Run generate and verify the three files appear and verify**

Run:
```bash
cd spec && python generate.py >/dev/null && python -c "import json, avp_crypto as ac, settlement as st; b=json.load(open('settlement/test-vectors/40-payee-account-binding.json')); i=json.load(open('settlement/test-vectors/43-settlement-instruction-x402.json')); print(ac.verify_ecdsa_jcs_2022(b), ac.verify_ecdsa_jcs_2022(i), st.account_binding_ok(i, b))"
```
Expected: `True True True`.

- [ ] **Step 3: Commit**

```bash
git add spec/generate.py spec/settlement/test-vectors/40-payee-account-binding.json spec/settlement/test-vectors/43-settlement-instruction-x402.json spec/settlement/test-vectors/44-settlement-proof-x402.json
git commit -m "feat(settlement): generate x402 vectors + payee account binding"
```

---

## Task 7: Generate vectors — Lightning profile (escrow: instruction → lock → release → proof)

**Files:**
- Modify: `spec/generate.py` (append to the settlement section)

- [ ] **Step 1: Append the Lightning escrow block**

```python
    # Lightning: USD quote settled in msat at an agreed USD/BTC rate; escrow is the
    # native hold-invoice. payee is the did:key DID_PAYEE bound to a node pubkey.
    ln_asset = st.RAILS["lightning"]["asset"]
    ln_chain = "bip122:000000000019d6689c085ae165831e93"
    ln_rate = "100000"  # USD per BTC (fixture)
    ln_base = st.usd_to_msat(amount, ln_rate)  # 0.001 USD @ 100000 -> 1000 msat
    ln_node = "02" + st.fake_address("payee-ln-node")[2:]  # 33-byte-ish pubkey fixture
    ln_invoice = "lnbc10n1p" + st.fake_preimage("ln-invoice")[:40]
    ln_payment_hash = st.fake_payment_hash("ln-hold")
    ln_preimage = st.fake_preimage("ln-hold")

    # 45: Lightning SettlementInstruction (escrow / hold-invoice).
    instr_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:ln", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-lightning", "chain": ln_chain,
        "payeeAccount": ln_invoice, "asset": ln_asset,
        "payer": DID_AGENT, "payee": DID_PAYEE,
        "amount": amount, "currency": currency, "amountBase": ln_base, "rate": ln_rate,
        "confirmationThreshold": st.RAILS["lightning"]["threshold"], "mode": "escrow",
        "nonce": "settle-ln-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_ln = ac.sign_ecdsa_jcs_2022(instr_ln, wallet, "2026-03-25T21:30:12Z")
    write(SETTLE, "45-settlement-instruction-lightning.json", instr_ln)

    # 46: EscrowLock (hold-invoice held).
    lock_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-lock:ln", "type": "EscrowLock",
        "instruction": instr_ln["id"], "instructionDigest": ac.jcs_digest(instr_ln),
        "lockRef": "ln-hold:" + ln_payment_hash, "lockedAmountBase": ln_base, "asset": ln_asset,
        "timeout": "2026-03-25T22:30:00Z",
    }
    lock_ln = ac.sign_ecdsa_jcs_2022(lock_ln, wallet, "2026-03-25T21:30:40Z")
    write(SETTLE, "46-escrow-lock-lightning.json", lock_ln)

    # 47: Lightning SettlementProof (preimage reveal == finality; no confirmations).
    proof_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:ln", "type": "SettlementProof",
        "instruction": instr_ln["id"], "instructionDigest": ac.jcs_digest(instr_ln),
        "execution": execution["id"], "chain": ln_chain,
        "transaction": ln_payment_hash, "preimage": ln_preimage,
        "settledAmountBase": ln_base, "asset": ln_asset, "finality": "final",
        "observedAt": "2026-03-25T21:34:00Z",
    }
    proof_ln = ac.sign_ecdsa_jcs_2022(proof_ln, wallet, "2026-03-25T21:34:00Z")
    write(SETTLE, "47-settlement-proof-lightning.json", proof_ln)

    # 48: EscrowRelease (settles the hold-invoice to the payee, carrying the proof).
    release_ln = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-release:ln", "type": "EscrowRelease",
        "lock": lock_ln["id"], "lockDigest": ac.jcs_digest(lock_ln),
        "settlementProof": proof_ln["id"], "settlementProofDigest": ac.jcs_digest(proof_ln),
    }
    release_ln = ac.sign_ecdsa_jcs_2022(release_ln, wallet, "2026-03-25T21:34:10Z")
    write(SETTLE, "48-escrow-release-lightning.json", release_ln)
```

- [ ] **Step 2: Run generate and verify the LN finality predicate**

Run:
```bash
cd spec && python generate.py >/dev/null && python -c "import json, settlement as st; p=json.load(open('settlement/test-vectors/47-settlement-proof-lightning.json')); print(st.finality_ok(p, 0))"
```
Expected: `True`.

- [ ] **Step 3: Commit**

```bash
git add spec/generate.py spec/settlement/test-vectors/45-settlement-instruction-lightning.json spec/settlement/test-vectors/46-escrow-lock-lightning.json spec/settlement/test-vectors/47-settlement-proof-lightning.json spec/settlement/test-vectors/48-escrow-release-lightning.json
git commit -m "feat(settlement): generate Lightning escrow vectors (lock/release/proof)"
```

---

## Task 8: Generate vectors — EVM escrow refund path + on-chain reversal

**Files:**
- Modify: `spec/generate.py` (append to the settlement section)

- [ ] **Step 1: Append the EVM-escrow-refund + reversal block**

```python
    # EVM escrow with a TIMEOUT -> refund to the payer (the EscrowRefund path).
    # 49: EVM escrow SettlementInstruction.
    instr_evm_esc = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:evm-escrow", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-evm-stablecoin", "chain": "eip155:8453",
        "payeeAccount": evm_account, "asset": usdc,
        "payer": DID_AGENT, "payee": evm_payee_did,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": evm_threshold, "mode": "escrow",
        "nonce": "settle-evm-esc-1", "expires": "2026-03-25T22:00:00Z",
    }
    instr_evm_esc = ac.sign_ecdsa_jcs_2022(instr_evm_esc, wallet, "2026-03-25T21:30:13Z")
    write(SETTLE, "49-settlement-instruction-evm-escrow.json", instr_evm_esc)

    # 50: EscrowLock (escrow contract holds the funds).
    lock_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-lock:evm", "type": "EscrowLock",
        "instruction": instr_evm_esc["id"], "instructionDigest": ac.jcs_digest(instr_evm_esc),
        "lockRef": st.fake_address("escrow-contract") + ":42", "lockedAmountBase": instr_evm_esc["amountBase"],
        "asset": usdc, "timeout": "2026-03-25T21:45:00Z",
    }
    lock_evm = ac.sign_ecdsa_jcs_2022(lock_evm, wallet, "2026-03-25T21:31:00Z")
    write(SETTLE, "50-escrow-lock-evm.json", lock_evm)

    # 51: SettlementProof for the refund transaction (funds returned to payer; final).
    proof_evm_refund = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:evm-refund", "type": "SettlementProof",
        "instruction": instr_evm_esc["id"], "instructionDigest": ac.jcs_digest(instr_evm_esc),
        "chain": "eip155:8453", "transaction": st.fake_tx("evm-refund"),
        "settledAmountBase": instr_evm_esc["amountBase"], "asset": usdc,
        "blockHeight": 19000100, "confirmations": evm_threshold, "finality": "final",
        "observedAt": "2026-03-25T21:46:00Z",
    }
    proof_evm_refund = ac.sign_ecdsa_jcs_2022(proof_evm_refund, wallet, "2026-03-25T21:46:00Z")
    write(SETTLE, "51-settlement-proof-evm-refund.json", proof_evm_refund)

    # 52: EscrowRefund (timeout -> refund to payer), carrying the refund proof.
    refund_evm = {
        "@context": SETTLE_CTX, "id": "urn:avp:escrow-refund:evm", "type": "EscrowRefund",
        "lock": lock_evm["id"], "lockDigest": ac.jcs_digest(lock_evm),
        "settlementProof": proof_evm_refund["id"], "settlementProofDigest": ac.jcs_digest(proof_evm_refund),
        "reason": "timeout",
    }
    refund_evm = ac.sign_ecdsa_jcs_2022(refund_evm, wallet, "2026-03-25T21:46:10Z")
    write(SETTLE, "52-escrow-refund-evm.json", refund_evm)

    # On-chain REVERSAL = a compensating transfer (payer<->payee swapped). A disputes
    # Reversal's settlementRef would point at proof 54. Here we generate the swapped
    # instruction + proof; the disputes bundle is NOT modified.
    # 53: reverse SettlementInstruction (payee now pays the agent back).
    instr_rev = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-instr:reverse", "type": "SettlementInstruction",
        "authorization": authz["id"], "authorizationDigest": authz_digest,
        "rail": "stl:rail-evm-stablecoin", "chain": "eip155:8453",
        "payeeAccount": "eip155:8453:" + st.fake_address("agent-evm"), "asset": usdc,
        "payer": evm_payee_did, "payee": DID_AGENT,
        "amount": amount, "currency": currency,
        "amountBase": st.to_base_units(amount, st.decimals_for_asset(usdc)),
        "confirmationThreshold": evm_threshold, "mode": "direct",
        "nonce": "settle-reverse-1", "expires": "2026-03-26T10:00:00Z",
    }
    instr_rev = ac.sign_ecdsa_jcs_2022(instr_rev, wallet, "2026-03-26T09:05:00Z")
    write(SETTLE, "53-reverse-settlement-instruction.json", instr_rev)

    # 54: reverse SettlementProof.
    proof_rev = {
        "@context": SETTLE_CTX, "id": "urn:avp:settle-proof:reverse", "type": "SettlementProof",
        "instruction": instr_rev["id"], "instructionDigest": ac.jcs_digest(instr_rev),
        "chain": "eip155:8453", "transaction": st.fake_tx("evm-reverse"),
        "settledAmountBase": instr_rev["amountBase"], "asset": usdc,
        "blockHeight": 19000200, "confirmations": evm_threshold, "finality": "final",
        "observedAt": "2026-03-26T09:08:00Z",
    }
    proof_rev = ac.sign_ecdsa_jcs_2022(proof_rev, wallet, "2026-03-26T09:08:00Z")
    write(SETTLE, "54-reverse-settlement-proof.json", proof_rev)
```

- [ ] **Step 2: Run generate; confirm all 15 settlement vectors exist**

Run: `cd spec && python generate.py >/dev/null && ls settlement/test-vectors | wc -l`
Expected: `15`.

- [ ] **Step 3: Commit**

```bash
git add spec/generate.py spec/settlement/test-vectors/49-settlement-instruction-evm-escrow.json spec/settlement/test-vectors/50-escrow-lock-evm.json spec/settlement/test-vectors/51-settlement-proof-evm-refund.json spec/settlement/test-vectors/52-escrow-refund-evm.json spec/settlement/test-vectors/53-reverse-settlement-instruction.json spec/settlement/test-vectors/54-reverse-settlement-proof.json
git commit -m "feat(settlement): generate EVM escrow-refund and on-chain reversal vectors"
```

---

## Task 9: Cryptographic + binding verification in `verify.py`

**Files:**
- Modify: `spec/verify.py`

- [ ] **Step 1: Add the settlement import and path**

In `spec/verify.py`, add `import settlement as st` to the imports (near line 12) and `SETTLE = SPEC / "settlement" / "test-vectors"` after `DISP = ...` (line 18).

- [ ] **Step 2: Add the settlement section before the "Negative control" block**

Insert before `print("Negative control (tamper detection):")` (line ~499):

```python
    print("On-chain settlement binding:")
    binding = load(SETTLE, "40-payee-account-binding.json")
    instr_evm = load(SETTLE, "41-settlement-instruction-evm.json")
    proof_evm = load(SETTLE, "42-settlement-proof-evm.json")
    instr_x402 = load(SETTLE, "43-settlement-instruction-x402.json")
    proof_x402 = load(SETTLE, "44-settlement-proof-x402.json")
    instr_ln = load(SETTLE, "45-settlement-instruction-lightning.json")
    lock_ln = load(SETTLE, "46-escrow-lock-lightning.json")
    proof_ln = load(SETTLE, "47-settlement-proof-lightning.json")
    release_ln = load(SETTLE, "48-escrow-release-lightning.json")
    instr_evm_esc = load(SETTLE, "49-settlement-instruction-evm-escrow.json")
    lock_evm = load(SETTLE, "50-escrow-lock-evm.json")
    proof_evm_refund = load(SETTLE, "51-settlement-proof-evm-refund.json")
    refund_evm = load(SETTLE, "52-escrow-refund-evm.json")
    instr_rev = load(SETTLE, "53-reverse-settlement-instruction.json")
    proof_rev = load(SETTLE, "54-reverse-settlement-proof.json")

    settle_objs = [("40 binding", binding), ("41 instr(evm)", instr_evm),
                   ("42 proof(evm)", proof_evm), ("43 instr(x402)", instr_x402),
                   ("44 proof(x402)", proof_x402), ("45 instr(ln)", instr_ln),
                   ("46 lock(ln)", lock_ln), ("47 proof(ln)", proof_ln),
                   ("48 release(ln)", release_ln), ("49 instr(evm-esc)", instr_evm_esc),
                   ("50 lock(evm)", lock_evm), ("51 proof(evm-refund)", proof_evm_refund),
                   ("52 refund(evm)", refund_evm), ("53 instr(reverse)", instr_rev),
                   ("54 proof(reverse)", proof_rev)]
    for label, obj in settle_objs:
        check(f"{label} proof", ac.verify_ecdsa_jcs_2022(obj))

    # signer binding: payee signs the account binding; wallet signs everything else.
    check("payee-account binding signed by its subject (payee)",
          controller(binding) == binding["subject"] == payee)
    for label, obj in settle_objs:
        if obj is binding:
            continue
        check(f"{label} signed by wallet", controller(obj) == wallet)

    # instruction <-> authorization economic binding
    for label, instr in [("evm", instr_evm), ("x402", instr_x402), ("ln", instr_ln),
                         ("evm-esc", instr_evm_esc)]:
        check(f"instr({label}).authorization == authz.id", instr["authorization"] == authz["id"])
        check(f"instr({label}).authorizationDigest matches authz",
              instr["authorizationDigest"] == ac.jcs_digest(authz))
        check(f"instr({label}).amount == authz.amount", instr["amount"] == authz["amount"])
        check(f"instr({label}).currency == authz.currency", instr["currency"] == authz["currency"])

    # base-unit invariant: stablecoin rails == amount x 10^decimals; Lightning via rate.
    for label, instr in [("evm", instr_evm), ("x402", instr_x402), ("evm-esc", instr_evm_esc)]:
        check(f"instr({label}).amountBase == amount x 10^decimals",
              instr["amountBase"] == st.to_base_units(instr["amount"], st.decimals_for_asset(instr["asset"])))
    check("instr(ln).amountBase == usd_to_msat(amount, rate)",
          instr_ln["amountBase"] == st.usd_to_msat(instr_ln["amount"], instr_ln["rate"]))

    # DID <-> account binding (archetype a for EVM did:pkh; archetype b for x402)
    check("instr(evm) payeeAccount bound via did:pkh", st.account_binding_ok(instr_evm, None))
    check("instr(x402) payeeAccount bound via PayeeAccountBinding",
          st.account_binding_ok(instr_x402, binding))
    check("instr(x402) references the binding it relies on",
          instr_x402.get("payeeAccountBinding") == binding["id"])

    # finality: confirmation rails reach threshold; Lightning via preimage==payment_hash
    for label, proof, thr in [("evm", proof_evm, instr_evm["confirmationThreshold"]),
                             ("x402", proof_x402, instr_x402["confirmationThreshold"]),
                             ("evm-refund", proof_evm_refund, instr_evm_esc["confirmationThreshold"]),
                             ("reverse", proof_rev, instr_rev["confirmationThreshold"])]:
        check(f"proof({label}) final at threshold", st.finality_ok(proof, thr))
    check("proof(ln) final via preimage reveal", st.finality_ok(proof_ln, 0))

    # proof <-> instruction binding + settled == instructed amount
    for label, instr, proof in [("evm", instr_evm, proof_evm), ("x402", instr_x402, proof_x402),
                               ("ln", instr_ln, proof_ln)]:
        check(f"proof({label}).instruction == instr.id", proof["instruction"] == instr["id"])
        check(f"proof({label}).instructionDigest matches instr",
              proof["instructionDigest"] == ac.jcs_digest(instr))
        check(f"proof({label}).settledAmountBase == instr.amountBase",
              proof["settledAmountBase"] == instr["amountBase"])

    # escrow linkage: release/refund bind their lock + a final settlement proof
    check("ln release binds its lock", release_ln["lockDigest"] == ac.jcs_digest(lock_ln))
    check("ln release binds the LN settlement proof",
          release_ln["settlementProofDigest"] == ac.jcs_digest(proof_ln))
    check("ln lock references the escrow instruction", lock_ln["instruction"] == instr_ln["id"])
    check("evm refund binds its lock", refund_evm["lockDigest"] == ac.jcs_digest(lock_evm))
    check("evm refund binds the refund proof",
          refund_evm["settlementProofDigest"] == ac.jcs_digest(proof_evm_refund))
    check("evm refund reason is timeout", refund_evm["reason"] == "timeout")

    # on-chain reversal: a compensating transfer with payer/payee swapped vs the original
    check("reverse instruction swaps payer/payee vs the original payment",
          instr_rev["payer"] == instr_evm["payee"] and instr_rev["payee"] == instr_evm["payer"])
    check("reverse proof settles the reverse instruction amount",
          proof_rev["settledAmountBase"] == instr_rev["amountBase"])
```

- [ ] **Step 3: Run verify**

Run: `cd spec && python verify.py`
Expected: ends with `PASS: all checks passed.` (exit 0). If a `KeyError`/`FAIL` appears, the offending check name is printed — fix the corresponding vector field in `generate.py`, re-run `generate.py`, then `verify.py`.

- [ ] **Step 4: Commit**

```bash
git add spec/verify.py
git commit -m "test(settlement): verify proofs, base-unit invariant, binding, finality, escrow, reversal"
```

---

## Task 10: Register the bundle in `validate.py` (expansion / schema / SHACL / negatives)

**Files:**
- Modify: `spec/validate.py`

- [ ] **Step 1: Add path, namespace, and the SETTLEMENT_VECTORS map**

In `spec/validate.py`: add `SETTLE = SPEC / "settlement"` after `DISP = ...` (line 28), `SETTLE_NS = "https://w3id.org/avp-micro/settlement/v1#"` after `DISP_NS = ...` (line 33), and after the `DISP_VECTORS` dict (line 89):

```python
SETTLEMENT_VECTORS = {
    "40-payee-account-binding.json": "PayeeAccountBinding",
    "41-settlement-instruction-evm.json": "SettlementInstruction",
    "42-settlement-proof-evm.json": "SettlementProof",
    "43-settlement-instruction-x402.json": "SettlementInstruction",
    "44-settlement-proof-x402.json": "SettlementProof",
    "45-settlement-instruction-lightning.json": "SettlementInstruction",
    "46-escrow-lock-lightning.json": "EscrowLock",
    "47-settlement-proof-lightning.json": "SettlementProof",
    "48-escrow-release-lightning.json": "EscrowRelease",
    "49-settlement-instruction-evm-escrow.json": "SettlementInstruction",
    "50-escrow-lock-evm.json": "EscrowLock",
    "51-settlement-proof-evm-refund.json": "SettlementProof",
    "52-escrow-refund-evm.json": "EscrowRefund",
    "53-reverse-settlement-instruction.json": "SettlementInstruction",
    "54-reverse-settlement-proof.json": "SettlementProof",
}
```

- [ ] **Step 2: Register the local context in the document loader**

In the `_LOCAL` dict (line ~109), add after the disputes entry:

```python
    "https://w3id.org/avp-micro/settlement/v1":
        json.loads((SETTLE / "context" / "v1.jsonld").read_text(encoding="utf-8")),
```

And add the context read near the other `_disp_ctx = ...` lines (line ~104):

```python
_settle_ctx = json.loads((SETTLE / "context" / "v1.jsonld").read_text(encoding="utf-8"))
```

Then change the `_LOCAL` settlement entry to use `_settle_ctx` (replace the inline `json.loads(...)` with `_settle_ctx` for consistency with the others).

- [ ] **Step 3: Add Turtle parse, expansion, schema, and SHACL calls**

In `main()`:

Add to the Turtle-parse loop list (line ~205, after the DISP entries):
```python
                SETTLE / "vocab" / "settlement.ttl", SETTLE / "vocab" / "rails.ttl",
                SETTLE / "shapes" / "settlement-shapes.ttl",
```

Add an expansion check after the `expand_check(DISP, ...)` call (line ~262):
```python
    expand_check(SETTLE, SETTLEMENT_VECTORS, {
        "41-settlement-instruction-evm.json": [(SETTLE_NS + "amountBase", "stl:amountBase"),
                                               (SETTLE_NS + "rail", "stl:rail"),
                                               (SETTLE_NS + "mode", "stl:mode")],
        "42-settlement-proof-evm.json": [(SETTLE_NS + "finality", "stl:finality"),
                                         (SETTLE_NS + "transaction", "stl:transaction")],
        "47-settlement-proof-lightning.json": [(SETTLE_NS + "preimage", "stl:preimage")],
        "48-escrow-release-lightning.json": [(SETTLE_NS + "settlementProof", "stl:settlementProof")],
        "52-escrow-refund-evm.json": [(SETTLE_NS + "reason", "stl:reason")],
    })
```

Add the schema and SHACL calls (after the DISP equivalents at lines ~268 and ~337):
```python
    schema_check(SETTLE, SETTLEMENT_VECTORS, "settlement.schema.json")
```
```python
    shacl_check(SETTLE, SETTLEMENT_VECTORS, "settlement-shapes.ttl")
```

- [ ] **Step 4: Add negative schema cases**

After the `negative_schema_check(DISP, ...)` call (line ~331):
```python
    negative_schema_check(SETTLE, "settlement.schema.json", [
        ("instruction missing amountBase", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.pop("amountBase", None), obj)[1]),
        ("instruction bad mode", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.__setitem__("mode", "frobnicate") or obj)),
        ("instruction non-integer amountBase", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.__setitem__("amountBase", "10.5") or obj)),
        ("instruction context order", "41-settlement-instruction-evm.json", "SettlementInstruction",
         lambda obj: (obj.__setitem__("@context", list(reversed(obj["@context"]))) or obj)),
        ("proof missing finality", "42-settlement-proof-evm.json", "SettlementProof",
         lambda obj: (obj.pop("finality", None), obj)[1]),
        ("proof bad finality value", "42-settlement-proof-evm.json", "SettlementProof",
         lambda obj: (obj.__setitem__("finality", "kinda-final") or obj)),
        ("escrow refund missing settlementProof", "52-escrow-refund-evm.json", "EscrowRefund",
         lambda obj: (obj.pop("settlementProof", None), obj)[1]),
        ("binding missing subject", "40-payee-account-binding.json", "PayeeAccountBinding",
         lambda obj: (obj.pop("subject", None), obj)[1]),
    ])
```

- [ ] **Step 5: Run validate**

Run: `cd spec && python validate.py`
Expected: ends with `PASS: all artifact checks passed.` (exit 0). If a SHACL `FAIL` prints, the report's last line names the offending shape/path — reconcile the vector field name with the shape's `sh:path` (reused terms must expand to `avp:`/`dsa:`, new terms to `stl:`).

- [ ] **Step 6: Commit**

```bash
git add spec/validate.py
git commit -m "test(settlement): register bundle in validate.py (expand/schema/shacl/negatives)"
```

---

## Task 11: Simulator rail adapters (`sim.py`) — EVM / x402 / Lightning, mock-only

**Files:**
- Modify: `spec/sim.py`
- Test: `spec/test_settlement.py` (add adapter tests)

- [ ] **Step 1: Write failing adapter tests**

Append to `spec/test_settlement.py`:

```python
import sim


def test_evm_rail_confirmation_state_machine():
    rail = sim.EvmStablecoinRail({"agent": "10", "payee": "0"})
    ref, settled = rail.settle("agent", "payee", "1.00", "k1")
    assert str(settled) == "1.00"
    assert ref.startswith("eip155:8453:0x")
    assert rail.finality_of("k1") == "pending"
    rail.advance_confirmations(12)
    assert rail.finality_of("k1") == "final"


def test_lightning_rail_finality_is_immediate():
    rail = sim.LightningRail({"agent": "10", "payee": "0"})
    rail.settle("agent", "payee", "1.00", "k1")
    assert rail.finality_of("k1") == "final"  # preimage reveal, no confirmations


def test_escrow_lock_release_moves_funds_on_release():
    rail = sim.EvmStablecoinRail({"agent": "10", "payee": "0"})
    rail.lock("agent", "1.00", "lk")
    assert rail.bal["agent"] == sim.Decimal("9")     # locked out of agent's balance
    assert rail.bal.get("payee", sim.Decimal("0")) == sim.Decimal("0")
    rail.release("lk", "payee")
    assert rail.bal["payee"] == sim.Decimal("1.00")


def test_escrow_refund_returns_funds_to_payer():
    rail = sim.EvmStablecoinRail({"agent": "10", "payee": "0"})
    rail.lock("agent", "1.00", "lk")
    rail.refund("lk", "agent")
    assert rail.bal["agent"] == sim.Decimal("10")
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd spec && python -m pytest test_settlement.py -q -k "rail or escrow"`
Expected: FAIL — `AttributeError: module 'sim' has no attribute 'EvmStablecoinRail'`.

- [ ] **Step 3: Implement the adapters in `sim.py`**

Add `import settlement as st` to the imports (near line 50). Then add, immediately after the `SimulatedLedger` class (line ~137):

```python
class OnChainRail(SimulatedLedger):
    """A MOCK on-chain settlement rail. Subclasses the play-balance ledger and adds
    chain semantics: a chain-native settlementRef, a confirmation state machine, and
    an escrow (lock/release/refund) lifecycle. NEVER broadcasts -- balances are play
    money; chain refs are deterministic fixtures. This is the seam a real deployment
    would replace with a live adapter exposing the same settle() contract."""
    rail_id = "onchain"
    chain = "eip155:8453"
    threshold = 12

    def __init__(self, balances: dict):
        super().__init__(balances)
        self._conf: dict = {}     # settlement key -> confirmations
        self._locks: dict = {}    # lock key -> (payer, Decimal amount)

    def _ref(self, key: str) -> str:
        return f"{self.chain}:{st.fake_tx(self.rail_id + ':' + key)}"

    def settle(self, payer, payee, amount, key):
        if key in self._refs:
            return self._refs[key], Decimal(0)
        amt = _d(amount)
        avail = self.bal.get(payer, Decimal(0))
        settled = amt if avail >= amt else max(avail, Decimal(0))
        self.bal[payer] = avail - settled
        self.bal[payee] = self.bal.get(payee, Decimal(0)) + settled
        ref = self._ref(key)
        self._refs[key] = ref
        self._conf[key] = 0
        return ref, settled

    def advance_confirmations(self, n: int):
        for k in self._conf:
            self._conf[k] += n

    def finality_of(self, key: str) -> str:
        return "final" if self._conf.get(key, 0) >= self.threshold else "pending"

    # -- escrow lifecycle --
    def lock(self, payer, amount, key):
        amt = _d(amount)
        self.bal[payer] = self.bal.get(payer, Decimal(0)) - amt
        self._locks[key] = (payer, amt)
        return f"lock:{self.rail_id}:{key}"

    def release(self, key, payee):
        _payer, amt = self._locks.pop(key)
        self.bal[payee] = self.bal.get(payee, Decimal(0)) + amt

    def refund(self, key, payer):
        _payer, amt = self._locks.pop(key)
        self.bal[payer] = self.bal.get(payer, Decimal(0)) + amt


class EvmStablecoinRail(OnChainRail):
    rail_id = "evm-stablecoin"
    chain = "eip155:8453"
    threshold = 12


class X402Rail(OnChainRail):
    rail_id = "x402"
    chain = "eip155:8453"
    threshold = 12


class LightningRail(OnChainRail):
    """Lightning: finality is the preimage reveal, so settlement is final immediately
    (no confirmation accumulation)."""
    rail_id = "lightning"
    chain = "bip122:000000000019d6689c085ae165831e93"
    threshold = 0

    def finality_of(self, key: str) -> str:
        return "final" if key in self._conf else "pending"


RAIL_CLASSES = {
    "evm-stablecoin": EvmStablecoinRail,
    "x402": X402Rail,
    "lightning": LightningRail,
}
```

- [ ] **Step 4: Run the adapter tests**

Run: `cd spec && python -m pytest test_settlement.py -q`
Expected: PASS (15 passed).

- [ ] **Step 5: Confirm existing scenarios still pass (no regression)**

Run: `cd spec && python sim.py`
Expected: ends with `PASS: all N scenarios behaved as specified.` (unchanged N — the default `SimulatedLedger` path is untouched).

- [ ] **Step 6: Commit**

```bash
git add spec/sim.py spec/test_settlement.py
git commit -m "feat(settlement): mock EVM/x402/Lightning SettlementRail adapters in sim"
```

---

## Task 12: Wire rail selection + settlement actions into the scenario engine

**Files:**
- Modify: `spec/sim.py`
- Modify: `spec/sim-scenarios.json`

- [ ] **Step 1: Select the rail by scenario, defaulting to the play ledger**

In `World.__init__` (line ~159), replace:
```python
        self.ledger = SimulatedLedger(sc.get("balances", {}))
```
with:
```python
        rail_cls = RAIL_CLASSES.get(sc.get("rail")) if sc.get("rail") else SimulatedLedger
        self.ledger = rail_cls(sc.get("balances", {}))
```

- [ ] **Step 2: Add settlement step handlers**

Add these handler functions after `build_resolution` (line ~607):

```python
# ---- on-chain settlement steps (operate the rail directly) ------------------

def settle_onchain(world: World, step: dict) -> dict:
    """Settle the standing authorization over the scenario's on-chain rail."""
    authz = world.ctx["authz"]
    ref, settled = world.ledger.settle("agent", authz["payee"], authz["amount"], authz["id"])
    world.ctx["_settleKey"] = authz["id"]
    return {"ref": ref, "settled": str(settled),
            "finality": world.ledger.finality_of(authz["id"])}


def advance_blocks(world: World, step: dict) -> dict:
    world.ledger.advance_confirmations(int(step.get("blocks", 1)))
    key = world.ctx.get("_settleKey")
    return {"finality": world.ledger.finality_of(key)}


def escrow_lock(world: World, step: dict) -> dict:
    authz = world.ctx["authz"]
    world.ledger.lock("agent", authz["amount"], authz["id"])
    world.ctx["_lockKey"] = authz["id"]
    return {"ok": True}


def escrow_release(world: World, step: dict) -> dict:
    authz = world.ctx["authz"]
    world.ledger.release(world.ctx["_lockKey"], authz["payee"])
    return {"ok": True}


def escrow_refund(world: World, step: dict) -> dict:
    world.ledger.refund(world.ctx["_lockKey"], "agent")
    return {"ok": True}
```

Register them in `HANDLERS` (line ~617):
```python
    "settle_onchain": lambda w, s: _settle_outcome(settle_onchain(w, s), s),
    "advance_blocks": lambda w, s: _settle_outcome(advance_blocks(w, s), s),
    "escrow_lock": lambda w, s: escrow_lock(w, s),
    "escrow_release": lambda w, s: escrow_release(w, s),
    "escrow_refund": lambda w, s: escrow_refund(w, s),
```

Add the small outcome helper just above `HANDLERS`:
```python
def _settle_outcome(result: dict, step: dict) -> dict:
    """Pass through ref/settled/finality so a step's expect can assert finality."""
    return {"ok": True, **result}
```

- [ ] **Step 3: Extend `_matches` to assert finality**

In `_matches` (line ~695), add before the final `return True`:
```python
    if "finality" in expect and got.get("finality") != expect["finality"]:
        return False
```

- [ ] **Step 4: Add three settlement scenarios to `sim-scenarios.json`**

Append these objects to the JSON array in `spec/sim-scenarios.json` (before the closing `]`; add a comma after the previous last element):

```json
  {
    "name": "evm-direct-settlement-finality",
    "description": "USDC-on-Base direct settlement: pending until the confirmation threshold, then final.",
    "rail": "evm-stablecoin",
    "policy": {"currency": "USD", "maxPerTransaction": "5.00", "allowedPayees": ["payee"]},
    "balances": {"agent": "10.00", "payee": "0.00"},
    "now": "2026-06-12T10:00:00Z",
    "steps": [
      {"action": "quote", "amount": "1.00", "payee": "payee"},
      {"action": "authorize"},
      {"action": "settle_onchain", "expect": {"finality": "pending"}},
      {"action": "advance_blocks", "blocks": 6, "expect": {"finality": "pending"}},
      {"action": "advance_blocks", "blocks": 6, "expect": {"finality": "final"}}
    ],
    "finalBalances": {"agent": "9.00", "payee": "1.00"}
  },
  {
    "name": "lightning-escrow-release",
    "description": "Lightning hold-invoice escrow: lock, deliver, release; finality is immediate.",
    "rail": "lightning",
    "policy": {"currency": "USD", "maxPerTransaction": "5.00", "allowedPayees": ["payee"]},
    "balances": {"agent": "10.00", "payee": "0.00"},
    "now": "2026-06-12T10:00:00Z",
    "steps": [
      {"action": "quote", "amount": "1.00", "payee": "payee"},
      {"action": "authorize"},
      {"action": "escrow_lock"},
      {"action": "escrow_release"}
    ],
    "finalBalances": {"agent": "9.00", "payee": "1.00"}
  },
  {
    "name": "evm-escrow-timeout-refund",
    "description": "EVM escrow that times out before delivery: funds refunded to the payer.",
    "rail": "evm-stablecoin",
    "policy": {"currency": "USD", "maxPerTransaction": "5.00", "allowedPayees": ["payee"]},
    "balances": {"agent": "10.00", "payee": "0.00"},
    "now": "2026-06-12T10:00:00Z",
    "steps": [
      {"action": "quote", "amount": "1.00", "payee": "payee"},
      {"action": "authorize"},
      {"action": "escrow_lock"},
      {"action": "escrow_refund"}
    ],
    "finalBalances": {"agent": "10.00", "payee": "0.00"}
  }
```

- [ ] **Step 5: Run the simulator**

Run: `cd spec && python sim.py`
Expected: the three new scenarios print `[PASS]`, and the final line is `PASS: all N scenarios behaved as specified.` (N increased by 3).

- [ ] **Step 6: Commit**

```bash
git add spec/sim.py spec/sim-scenarios.json
git commit -m "feat(settlement): rail selection + on-chain settlement scenarios in the simulator"
```

---

## Task 13: ReSpec prose (`index.html`) + bundle README

**Files:**
- Create: `spec/settlement/index.html`
- Create: `spec/settlement/README.md`

- [ ] **Step 1: Create `spec/settlement/index.html`**

Copy the ReSpec shell (the `<head>`, the `respecConfig` `<script>`, and the `<body>` boilerplate sections) verbatim from `spec/disputes/index.html`, then change the title, `shortName` (to `avp-micro-settlement`), and the abstract, and replace the body sections with the settlement content. The document MUST contain these normative sections (each a `<section>` with the stated `RFC 2119` content):

1. **Introduction** — settlement is scoped out of Payments; this bundle binds it to a public-chain rail by reference; cite the design doc.
2. **Terminology** — `SettlementInstruction`, `SettlementProof`, `PayeeAccountBinding`, `EscrowLock`/`Release`/`Refund`, finality states, CAIP-2/10/19.
3. **Securing mechanism** — every settlement object MUST carry an `ecdsa-jcs-2022` `DataIntegrityProof`; `PayeeAccountBinding` MUST be signed by its `subject`; all other objects MUST be signed by the wallet (the same key that signs the `PaymentExecution`).
4. **Core binding** — `SettlementInstruction` MUST reference a `PaymentAuthorization` (id + digest); `amount`/`currency` MUST equal the authorization; `amountBase` MUST equal `amount × 10^decimals` for stablecoin assets, or the agreed `rate` conversion otherwise; `confirmationThreshold` and `mode` MUST be present.
5. **Account binding** — `payeeAccount` MUST be bound to the payee DID by `did:pkh` identity OR a `PayeeAccountBinding`; a verifier MUST reject an unbound `payeeAccount`.
6. **Finality** — a `fulfilled` `PaymentReceipt` MUST NOT be issued before `SettlementProof.finality == "final"`; confirmation rails reach `final` at `confirmations ≥ confirmationThreshold`; Lightning reaches `final` when `sha256(preimage) == transaction`.
7. **Escrow profile (optional)** — `EscrowLock` → `EscrowRelease` (delivery) or `EscrowRefund` (timeout/dispute); each release/refund MUST carry a final `SettlementProof`.
8. **Reversal** — an on-chain reversal MUST be a new compensating transfer (payer/payee swapped); a disputes `Reversal.settlementRef` points at the reverse `SettlementProof`.
9. **Rail profiles** — one subsection each for EVM stablecoin, x402, Lightning, stating the `chain`/`payeeAccount`/`asset`/proof/finality/escrow specifics from the design-doc table (§9).
10. **Security considerations** — payment redirection (mitigated by §5), reorg/finality (mitigated by §6), FX/precision (mitigated by §4), irreversibility (mitigated by §8).

Use `<sup><a class="self-link"></a></sup>` term anchors as in `disputes/index.html`. Reference each test vector by filename in the relevant section.

- [ ] **Step 2: Verify the HTML is well-formed**

Run: `cd spec && python -c "import xml.dom.minidom as m; m.parse('settlement/index.html'); print('well-formed')"`
Expected: `well-formed` (if it errors on HTML entities, that's acceptable — ReSpec HTML need not be XML; instead confirm the file opens and contains all ten `<section>` ids with `grep -c '<section' settlement/index.html` ≥ 10).

- [ ] **Step 3: Create `spec/settlement/README.md`**

Model it on `spec/disputes/README.md`: title, one-paragraph summary (the on-chain settlement binding, rides on Payments by reference, three rail profiles), namespace/context lines, an Artifacts table (context, settlement.ttl, rails.ttl, schema, shapes, index.html), and a Test-vectors table listing all 15 vectors (40–54) with their type, plus the regenerate/verify/validate/sim command block from the disputes README.

- [ ] **Step 4: Commit**

```bash
git add spec/settlement/index.html spec/settlement/README.md
git commit -m "docs(settlement): ReSpec prose and bundle README"
```

---

## Task 14: Update repo-level docs (four bundles → five)

**Files:**
- Modify: `spec/README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `spec/README.md`**

After the `disputes/` bullet (line 29), add:
```markdown
- **`settlement/`** — On-chain settlement binding: maps AVP-Micro payments onto public-blockchain rails (EVM stablecoin, Coinbase x402, Bitcoin Lightning) via a rail-agnostic `SettlementInstruction`/`SettlementProof` core, an optional escrow lifecycle, and a DID↔account binding. Built on Payments + DSA, by reference. Namespace `https://w3id.org/avp-micro/settlement/v1#`.
```

In the "Validate everything" section, the existing commands already cover all bundles (they run the shared harness), so add one bullet to the canonical-URLs list:
```markdown
- Settlement context: `https://w3id.org/avp-micro/settlement/v1` → `settlement/context/v1.jsonld`
- Settlement namespace: `https://w3id.org/avp-micro/settlement/v1#`
```

- [ ] **Step 2: Update `CLAUDE.md`**

Change "Four peer bundles live under `spec/`" → "Five peer bundles live under `spec/`" and add after the `spec/disputes/` bullet:
```markdown
- **`spec/settlement/`** — On-chain settlement binding: EVM stablecoin / x402 / Lightning profiles over a rail-agnostic core (`SettlementInstruction`, `SettlementProof`, escrow, `PayeeAccountBinding`); rides on Payments by reference. Namespace `https://w3id.org/avp-micro/settlement/v1#`.
```

Add to the "Harness architecture" list a bullet for `settlement.py`:
```markdown
- **`settlement.py`**: base-unit/FX conversion (exact, reject non-representable), CAIP-2/10/19 + `did:pkh` parsing, the DID↔account binding rule, the finality predicate (confirmation threshold and Lightning preimage), and deterministic chain fixtures. Used by the Settlement bundle.
```

Add to the "Namespace / context URLs" list:
```markdown
- Settlement context: `https://w3id.org/avp-micro/settlement/v1` → `spec/settlement/context/v1.jsonld`
```

- [ ] **Step 3: Commit**

```bash
git add spec/README.md CLAUDE.md
git commit -m "docs: add settlement as the fifth peer bundle (four -> five)"
```

---

## Task 15: Full-harness green gate + final regeneration

**Files:** none (verification only)

- [ ] **Step 1: Regenerate everything from scratch and run all four gates**

Run:
```bash
cd spec && python generate.py && python verify.py && python validate.py && python sim.py && python -m pytest test_settlement.py -q
```
Expected: `generate.py` writes all vectors; `verify.py` → `PASS: all checks passed.`; `validate.py` → `PASS: all artifact checks passed.`; `sim.py` → `PASS: all N scenarios behaved as specified.`; pytest → all passed.

- [ ] **Step 2: Confirm no Payments/DSA/disputes/interop vectors changed (by-reference invariant held)**

Run: `git status --porcelain spec/authority spec/payments spec/disputes spec/interop-sd-jwt-vc`
Expected: **empty output** — the only changed vectors are under `spec/settlement/test-vectors/`. (Interop vectors are non-deterministic per project memory; if `git status` shows only interop vectors changed, that is expected — re-run is fine. Any change under authority/payments/disputes means the by-reference invariant was violated; investigate before proceeding.)

- [ ] **Step 3: Final commit (if any regenerated vectors are pending)**

```bash
git add -A spec/settlement/test-vectors
git commit -m "chore(settlement): regenerate vectors; full harness green (verify/validate/sim PASS)" || echo "nothing to commit"
```

---

## Self-Review (completed by plan author)

**1. Spec coverage** (design doc §→task):
- §1 goal / by-reference seam → Tasks 5–8 (instructions reuse `settlementMethod`/`Target`/`Ref` semantics; Payments untouched, asserted in Task 15 Step 2).
- §2 finality/irreversibility forces → finality predicate (Task 1 `finality_ok`, Task 9 checks); reversal as compensating transfer (Task 8 vectors 53–54, Task 9 swap check).
- §3 bundle layout → Tasks 2–4, 13 (context/vocab/rails/schema/shapes/index/README).
- §4 core objects → Task 3 ($defs) + Tasks 5–8 (vectors).
- §5 DID↔account binding → Task 1 `account_binding_ok`, Task 6 binding vector, Task 9 binding checks.
- §6 amount precision & FX → Task 1 `to_base_units`/`usd_to_msat`, Task 9 base-unit invariant checks.
- §7 flows (direct + escrow) → Tasks 5–8 vectors + Task 12 scenarios.
- §8 reversal/disputes alignment → Task 8 vectors 53–54, Task 9 swap check (disputes bundle untouched, asserted Task 15).
- §9 three profiles → Tasks 5/6/7 vectors + Task 13 §9 prose + `rails.ttl` (Task 2).
- §10 harness integration → Tasks 9 (verify), 10 (validate), 11–12 (sim); §10 "no live broadcast" → adapters are mock subclasses of `SimulatedLedger` (Task 11) and the confirmed CAIP-only / no-testnet decision is honored (no network code anywhere).
- §11 CAIP identifiers → used throughout (Task 1 parsers, Task 3 `caip2` $def, all vectors).
- §12 numbering & docs → Tasks 5–8 (40–54), Task 14 (README/CLAUDE).
- §13 open questions: `confirmationThreshold` encoded as integer (Task 3); `PayeeAccountBinding` is a standalone type (Tasks 2–3); x402 stays facilitator-neutral (proof only requires a tx-bearing `SettlementProof`, Task 3/7). All three resolved in the plan; flag to the user if they want different choices.

**2. Placeholder scan:** none — every code/JSON/TTL step contains complete content. `index.html` (Task 13) is prose, not logic; it is specified as a concrete ten-section normative outline copied from the existing `disputes/index.html` shell (the established pattern for this repo), not a "TODO".

**3. Type consistency:** field names are identical across context (Task 2), schema (Task 3), shapes (Task 4), generators (Tasks 5–8), and verifier (Task 9): `amountBase`, `confirmationThreshold`, `payeeAccount`, `payeeAccountBinding`, `settledAmountBase`, `instructionDigest`, `lockDigest`, `settlementProof`, `settlementProofDigest`. Helper signatures match their call sites: `to_base_units(amount, decimals)`, `usd_to_msat(amount, rate)`, `account_binding_ok(instruction, binding|None)`, `finality_ok(proof, threshold)`. Rail ids (`evm-stablecoin`/`x402`/`lightning`) match between `settlement.RAILS`, `sim.RAIL_CLASSES`, and scenario `rail` fields.
