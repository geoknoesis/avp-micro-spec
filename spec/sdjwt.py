"""Reference primitives for the SD-JWT-VC side of the interop bridge.

Implements just enough of JOSE / SD-JWT to make the interop test vectors
reproducible and independently checkable, in the same self-contained spirit as
``avp_crypto.py`` (no third-party JOSE dependency -- only ``cryptography``, which
the harness already requires):

  * deterministic P-256 (secp256r1) test keys
  * ES256 (ECDSA P-256 + SHA-256) JWS compact sign/verify with raw R||S signatures
    (RFC 7515 / RFC 7518)
  * JWK import/export for EC P-256 public keys (RFC 7517)
  * SD-JWT compact handling for the degenerate (no-disclosure) case this profile
    uses in proof-preserving mode: ``<JWS>~``

TEST KEYS ONLY -- private scalars are derived deterministically from labels and
MUST NOT be used outside these fixtures.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

# secp256r1 group order
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_json(obj: Any) -> str:
    # Compact, sorted JSON so vectors are byte-stable and reproducible.
    return b64u_encode(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8"))


# ---- deterministic P-256 test keys ----

def seed_p256(label: str) -> ec.EllipticCurvePrivateKey:
    h = hashlib.sha256(("avp-micro-test:" + label).encode()).digest()
    secret = (int.from_bytes(h, "big") % (_P256_N - 1)) + 1  # in [1, n-1]
    return ec.derive_private_key(secret, ec.SECP256R1())


# ---- JWK ----

def p256_public_jwk(pub: ec.EllipticCurvePublicKey) -> dict:
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(nums.x.to_bytes(32, "big")),
        "y": b64u_encode(nums.y.to_bytes(32, "big")),
    }


def p256_public_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


# ---- ES256 JWS (compact) ----

def es256_sign(header: dict, payload: dict, priv: ec.EllipticCurvePrivateKey) -> str:
    signing_input = (_b64u_json(header) + "." + _b64u_json(payload)).encode("ascii")
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input.decode("ascii") + "." + b64u_encode(raw)


def es256_verify(jws: str, pub: ec.EllipticCurvePublicKey) -> bool:
    try:
        h_b64, p_b64, sig_b64 = jws.split(".")
        signing_input = (h_b64 + "." + p_b64).encode("ascii")
        raw = b64u_decode(sig_b64)
        if len(raw) != 64:
            return False
        der = encode_dss_signature(
            int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        )
        pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def jws_header(jws: str) -> dict:
    return json.loads(b64u_decode(jws.split(".")[0]))


def jws_payload(jws: str) -> dict:
    return json.loads(b64u_decode(jws.split(".")[1]))


def sd_hash(sd_input: str) -> str:
    """SD-JWT ``sd_hash``: base64url(SHA-256(everything up to the KB-JWT))."""
    return b64u_encode(hashlib.sha256(sd_input.encode("ascii")).digest())


# ---- SD-JWT compact + selective-disclosure ----

def sdjwt_compact(jws: str) -> str:
    """Wrap a JWS as an SD-JWT with zero disclosures and no key-binding JWT."""
    return jws + "~"


def sdjwt_jws(compact: str) -> str:
    """Return the issuer-signed JWS from an SD-JWT compact serialization."""
    return compact.split("~", 1)[0]


def make_disclosure(salt: str, name: str, value) -> str:
    """An SD-JWT disclosure: base64url(JSON([salt, claim_name, claim_value]))."""
    return b64u_encode(json.dumps([salt, name, value], separators=(",", ":")).encode("utf-8"))


def disclosure_digest(disclosure: str) -> str:
    """The ``_sd`` digest of a disclosure: base64url(SHA-256(ascii(disclosure)))."""
    return b64u_encode(hashlib.sha256(disclosure.encode("ascii")).digest())


def split_presentation(compact: str):
    """Split a compact SD-JWT(+KB) into (issuer_jws, [disclosures], kb_jwt | None).

    Disclosures are single-segment base64url; a key-binding JWT is a 3-segment JWS.
    """
    parts = [p for p in compact.split("~") if p != ""]
    issuer_jws = parts[0]
    rest = parts[1:]
    kb = rest[-1] if rest and rest[-1].count(".") == 2 else None
    disclosures = [p for p in rest if p.count(".") != 2]
    return issuer_jws, disclosures, kb
