"""Bitstring Status List v1.0 codec (W3C VC Bitstring Status List).

Deterministic, pure-stdlib helpers to build and read the `encodedList` of a
`BitstringStatusListCredential`:

- a bitstring of `length` bits (default 131072 = 16 KB, the spec minimum for herd
  privacy), one bit per credential, indexed by `statusListIndex`;
- bit set => the credential is revoked/suspended for that `statusPurpose`;
- the bitstring is GZIP-compressed then base64url-encoded (no padding) and given the
  multibase `u` prefix, matching `BitstringStatusListEntry`/`encodedList`.

`encode_status_list` pins `mtime=0` so the GZIP output (and therefore the signed
status-list vector) is byte-identical across runs.
"""
from __future__ import annotations

import base64
import gzip

MIN_LENGTH = 131072  # bits (16 KB) -- the Bitstring Status List minimum


def _bytelen(length: int) -> int:
    return (length + 7) // 8


def encode_status_list(revoked: set[int], length: int = MIN_LENGTH) -> str:
    """Encode a status list with `revoked` indices set (MSB-first within each byte)."""
    if length < MIN_LENGTH:
        length = MIN_LENGTH
    ba = bytearray(_bytelen(length))
    for i in revoked:
        if i < 0 or i >= length:
            raise ValueError(f"index {i} out of range for length {length}")
        ba[i // 8] |= 1 << (7 - (i % 8))
    comp = gzip.compress(bytes(ba), mtime=0)  # mtime=0 -> deterministic output
    return "u" + base64.urlsafe_b64encode(comp).decode("ascii").rstrip("=")


def decode_status_list(encoded: str) -> bytes:
    """Inverse of `encode_status_list` -> the raw decompressed bitstring bytes."""
    if not encoded or encoded[0] != "u":
        raise ValueError("encodedList must use the multibase 'u' (base64url) prefix")
    body = encoded[1:]
    pad = "=" * (-len(body) % 4)
    return gzip.decompress(base64.urlsafe_b64decode(body + pad))


def is_revoked(encoded: str, index: int) -> bool:
    """True if the bit at `index` is set in the encoded status list."""
    raw = decode_status_list(encoded)
    if index < 0 or index // 8 >= len(raw):
        raise ValueError(f"index {index} out of range for this status list")
    return bool(raw[index // 8] & (1 << (7 - (index % 8))))
