"""Reference primitives for AVP-Micro test vectors.

Implements just enough of the building blocks the specification mandates so that
the vectors are reproducible and independently checkable:

  * base58btc (Bitcoin alphabet) encode/decode
  * multibase + multicodec did:key for P-256 (Multikey, ``p256-pub`` 0x1200)
  * JSON Canonicalization Scheme (JCS, RFC 8785) for our value types
    (strings, integers, booleans, null, arrays, objects -- no floats)
  * the W3C ``ecdsa-jcs-2022`` Data Integrity cryptosuite (vc-di-ecdsa), P-256
  * the AVP-Micro content-digest form ``<alg>:<base64url-nopad>``

The ecdsa-jcs-2022 verify-data is, per vc-di-ecdsa:
    hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))
where proofConfig is the proof object (without ``proofValue``) augmented with the
secured document's ``@context``. proofConfig hash is FIRST. ECDSA (P-256) then
signs ``hashData`` with SHA-256, exactly as for the EdDSA cryptosuite's
construction, so the vectors are internally consistent and reproducible;
cross-check against an independent Data Integrity implementation before treating
them as normative interop fixtures.

This profile pins two hardening rules on top of the base cryptosuite, both
because they are payments-appropriate and because they keep the generated
vectors byte-stable:

  * **Deterministic ECDSA (RFC 6979).** Nonces are derived deterministically, so
    re-running ``generate.py`` reproduces identical signatures and a leaked or
    biased RNG cannot expose the private key.
  * **Canonical low-s, raw R‖S.** Signatures are emitted in IEEE P1363 raw
    R‖S form (64 bytes) with ``s`` normalized to the lower half of the group
    order, and verifiers reject the high-s variant. This removes ECDSA signature
    malleability, which matters for a non-malleable payments wire format.

TEST KEYS ONLY -- private scalars are derived deterministically from labels and
MUST NOT be used outside these fixtures.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_P256_MULTICODEC = b"\x80\x24"  # unsigned-varint of multicodec "p256-pub" (0x1200)
# secp256r1 (P-256) group order n
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


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
    """RFC 8785 canonical JSON for the value types used by AVP-Micro.

    Python's ``json`` with ``ensure_ascii=False`` emits U+2028 (LINE SEPARATOR) and
    U+2029 (PARAGRAPH SEPARATOR) raw, but RFC 8785 (per ECMAScript serialization)
    requires them escaped. Fix that up so a document containing those code points
    canonicalizes — and therefore signs/verifies — identically across implementations.
    """
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _bs = chr(92)
    s = s.replace(chr(0x2028), _bs + "u2028").replace(chr(0x2029), _bs + "u2029")
    return s.encode("utf-8")


def content_digest(data: bytes, alg: str = "sha-256") -> str:
    if alg != "sha-256":
        raise ValueError(f"unsupported digest alg: {alg}")
    return f"{alg}:{b64url_nopad(hashlib.sha256(data).digest())}"


def jcs_digest(obj: dict, alg: str = "sha-256") -> str:
    """Content digest of an object's JCS form with any ``proof`` removed."""
    unsecured = {k: v for k, v in obj.items() if k != "proof"}
    return content_digest(jcs(unsecured), alg)


# ---- deterministic P-256 test keys ----

def seed_key(label: str) -> ec.EllipticCurvePrivateKey:
    h = hashlib.sha256(("avp-micro-test:" + label).encode()).digest()
    secret = (int.from_bytes(h, "big") % (_P256_N - 1)) + 1  # in [1, n-1]
    return ec.derive_private_key(secret, ec.SECP256R1())


# ---- did:key (P-256 / Multikey) ----

def public_multikey(pub: ec.EllipticCurvePublicKey) -> str:
    compressed = pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return "z" + b58encode(_P256_MULTICODEC + compressed)


def did_key(pub: ec.EllipticCurvePublicKey) -> str:
    return "did:key:" + public_multikey(pub)


def verification_method(pub: ec.EllipticCurvePublicKey) -> str:
    mk = public_multikey(pub)
    return f"did:key:{mk}#{mk}"


def public_from_did_key(did: str) -> ec.EllipticCurvePublicKey:
    """Resolve a did:key (or its #fragment vm) back to a P-256 public key."""
    mb = did.split("#", 1)[0]
    mb = mb[len("did:key:"):]
    if not mb.startswith("z"):  # explicit raise (not assert -- survives python -O)
        raise ValueError("expected base58btc multibase did:key")
    decoded = b58decode(mb[1:])
    if decoded[:2] != _P256_MULTICODEC:
        raise ValueError("not a p256-pub multikey")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), decoded[2:])


# ---- raw ECDSA (P-256), deterministic + canonical low-s ----

def _ecdsa_raw_sign(priv: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Deterministic ECDSA (RFC 6979) over SHA-256(message); canonical low-s; raw R‖S."""
    der = priv.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > _P256_N // 2:  # canonical low-s -> non-malleable
        s = _P256_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _ecdsa_raw_verify(pub: ec.EllipticCurvePublicKey, message: bytes, raw: bytes) -> bool:
    if len(raw) != 64:
        return False
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    # enforce canonical low-s: reject the malleable high-s variant
    if not (1 <= r < _P256_N and 1 <= s <= _P256_N // 2):
        return False
    pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    return True


# ---- ecdsa-jcs-2022 Data Integrity proof ----

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


def sign_ecdsa_jcs_2022(doc: dict, priv: ec.EllipticCurvePrivateKey, created: str) -> dict:
    vm = verification_method(priv.public_key())
    proof_opts = {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-jcs-2022",
        "created": created,
        "verificationMethod": vm,
        "proofPurpose": "assertionMethod",
    }
    signature = _ecdsa_raw_sign(priv, _verify_data(doc, proof_opts))
    proof = dict(proof_opts)
    proof["proofValue"] = "z" + b58encode(signature)
    out = dict(doc)
    out["proof"] = proof
    return out


def verify_ecdsa_jcs_2022(secured: dict) -> bool:
    """Verify a DataIntegrityProof(ecdsa-jcs-2022). Returns True/False."""
    proof = secured.get("proof")
    if not proof or proof.get("cryptosuite") != "ecdsa-jcs-2022":
        return False
    proof_value = proof.get("proofValue", "")
    if not proof_value.startswith("z"):
        return False
    try:
        signature = b58decode(proof_value[1:])
        pub = public_from_did_key(proof["verificationMethod"])
        proof_opts = {k: v for k, v in proof.items() if k != "proofValue"}
        return _ecdsa_raw_verify(pub, _verify_data(secured, proof_opts), signature)
    except Exception:
        return False
