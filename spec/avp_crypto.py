"""Reference primitives for AVP-Micro test vectors.

Implements just enough of the building blocks the specification mandates so that
the vectors are reproducible and independently checkable:

  * base58btc (Bitcoin alphabet) encode/decode
  * multibase + multicodec did:key for Ed25519 (Multikey)
  * JSON Canonicalization Scheme (JCS, RFC 8785) for our value types
    (strings, integers, booleans, null, arrays, objects -- no floats)
  * the W3C ``eddsa-jcs-2022`` Data Integrity cryptosuite (vc-di-eddsa)
  * the AVP-Micro content-digest form ``<alg>:<base64url-nopad>``

The eddsa-jcs-2022 verify-data is, per vc-di-eddsa:
    hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
where proofConfig is the proof object (without ``proofValue``) augmented with the
secured document's ``@context``. proofConfig hash is FIRST. Signing and
verification here use exactly this construction, so the vectors are internally
consistent and reproducible; cross-check against an independent Data Integrity
implementation before treating them as normative interop fixtures.

TEST KEYS ONLY -- private seeds are derived deterministically from labels and
MUST NOT be used outside these fixtures.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"  # varint for "ed25519-pub"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + full


def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for the value types used by AVP-Micro."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def content_digest(data: bytes, alg: str = "sha-256") -> str:
    if alg != "sha-256":
        raise ValueError(f"unsupported digest alg: {alg}")
    return f"{alg}:{b64url_nopad(hashlib.sha256(data).digest())}"


def jcs_digest(obj: dict, alg: str = "sha-256") -> str:
    """Content digest of an object's JCS form with any ``proof`` removed."""
    unsecured = {k: v for k, v in obj.items() if k != "proof"}
    return content_digest(jcs(unsecured), alg)


# ---- did:key (Ed25519 / Multikey) ----

def seed_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(("avp-micro-test:" + label).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_multikey(pub: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "z" + b58encode(_ED25519_MULTICODEC + raw)


def did_key(pub: Ed25519PublicKey) -> str:
    return "did:key:" + public_multikey(pub)


def verification_method(pub: Ed25519PublicKey) -> str:
    mk = public_multikey(pub)
    return f"did:key:{mk}#{mk}"


def public_from_did_key(did: str) -> Ed25519PublicKey:
    """Resolve a did:key (or its #fragment vm) back to an Ed25519 public key."""
    mb = did.split("#", 1)[0]
    mb = mb[len("did:key:"):]
    assert mb.startswith("z"), "expected base58btc multibase"
    decoded = b58decode(mb[1:])
    assert decoded[:2] == _ED25519_MULTICODEC, "not an ed25519-pub multikey"
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


# ---- eddsa-jcs-2022 Data Integrity proof ----

def _proof_config(doc: dict, proof_opts: dict) -> dict:
    cfg = dict(proof_opts)
    if "@context" in doc:
        cfg["@context"] = doc["@context"]
    return cfg


def _verify_data(doc: dict, proof_opts: dict) -> bytes:
    cfg_hash = hashlib.sha256(jcs(_proof_config(doc, proof_opts))).digest()
    unsecured = {k: v for k, v in doc.items() if k != "proof"}
    doc_hash = hashlib.sha256(jcs(unsecured)).digest()
    return cfg_hash + doc_hash  # proofConfig hash FIRST


def sign_eddsa_jcs_2022(doc: dict, priv: Ed25519PrivateKey, created: str) -> dict:
    vm = verification_method(priv.public_key())
    proof_opts = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": created,
        "verificationMethod": vm,
        "proofPurpose": "assertionMethod",
    }
    signature = priv.sign(_verify_data(doc, proof_opts))
    proof = dict(proof_opts)
    proof["proofValue"] = "z" + b58encode(signature)
    out = dict(doc)
    out["proof"] = proof
    return out


def verify_eddsa_jcs_2022(secured: dict) -> bool:
    """Verify a DataIntegrityProof(eddsa-jcs-2022). Returns True/False."""
    proof = secured.get("proof")
    if not proof or proof.get("cryptosuite") != "eddsa-jcs-2022":
        return False
    proof_value = proof.get("proofValue", "")
    if not proof_value.startswith("z"):
        return False
    try:
        signature = b58decode(proof_value[1:])
        pub = public_from_did_key(proof["verificationMethod"])
        proof_opts = {k: v for k, v in proof.items() if k != "proofValue"}
        pub.verify(signature, _verify_data(secured, proof_opts))
        return True
    except Exception:
        return False
