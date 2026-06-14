# Design: Operational revocation & status freshness

**Date:** 2026-06-14
**Status:** Approved (program increment #2)
**Bundle:** `spec/authority/` (DSA — where credentials + `credentialStatus` live).

## 1. Summary

AVP-Micro credentials carry a `BitstringStatusListEntry` (`statusListIndex` 94567 →
`https://issuer.example/status/3`), but the suite ships **no actual status list** and pins
**no operational rules** for checking it. This increment adds:
- a real, signed **`BitstringStatusListCredential`** (W3C Bitstring Status List v1.0) in two
  states — **active** and **revoked** — produced by a deterministic `status.py` helper;
- normative **freshness / re-check-before-settle / revoked-mid-flight** rules;
- harness checks that decode the bitstring and confirm the credential's bit, the issuer
  signature, and the freshness window.

The status-list terms (`BitstringStatusListCredential`, `BitstringStatusList`,
`encodedList`, `statusPurpose`, …) are already defined in the vendored
`credentials/v2` context, so no new JSON-LD context is needed.

## 2. `status.py` — Bitstring Status List codec

Pure-stdlib, deterministic (W3C Bitstring Status List v1.0):
- `encode_status_list(revoked: set[int], length=131072) -> str` — set the bit at each
  revoked index (MSB-first within each byte), GZIP-compress (`mtime=0` for byte-stability),
  base64url-no-pad encode, prefix multibase `u`. Length 131,072 (16 KB) is the spec minimum
  (herd privacy).
- `decode_status_list(encoded) -> bytes` — inverse.
- `is_revoked(encoded, index) -> bool` — decode and test the bit.

## 3. Vectors (`generate.py`, written to `authority/test-vectors/`)

Both issuer-signed (`ecdsa-jcs-2022`), `@context = [VC2, data-integrity/v2]`:
- **`status-list-active.json`** — `id = https://issuer.example/status/3` (matches the SAC's
  `statusListCredential`), `credentialSubject.encodedList = encode_status_list(∅)` — every
  bit 0. `validFrom` before the authorization; valid window covers it.
- **`status-list-revoked.json`** — same list with the SAC's index (94567) set;
  `validFrom = 2026-03-26T09:00:00Z`, **after** the authorization (models a credential
  revoked *mid-flight*, between authorize and settle).

## 4. Schema (`authority/schemas/dsa.schema.json`)

Add a 2-entry `statusListContext` and a `BitstringStatusListCredential` `$def` (required:
`@context,id,type,issuer,validFrom,credentialSubject,proof`; subject requires
`type:BitstringStatusList`, `statusPurpose`, `encodedList` matching `^u[A-Za-z0-9_-]+$`).
The shared primitive `$defs` are reused unchanged (drift guard stays green).

## 5. Harness

- **`validate.py`:** add the two vectors to `AUTH_VECTORS → BitstringStatusListCredential`
  (expand + schema + SHACL; SHACL is vacuously satisfied — `dsa-shapes` targets DSA classes,
  not the status list).
- **`verify.py`:** both proofs verify and are issuer-signed; `id` of the active list equals
  the SAC's `statusListCredential`; `is_revoked(active, 94567) == False`,
  `is_revoked(revoked, 94567) == True`; freshness window well-formed and active-at-auth; the
  revoked list's `validFrom` is **after** the authorization (mid-flight).
- **`spec/test_status.py`:** roundtrip, empty list, determinism, min-length (≥16 KB).

## 6. Normative prose (`authority/index.html`, new "Credential status & freshness")

- **MUST** resolve `credentialStatus` and test the bit **before settling**.
- **Freshness:** the status list carries `validFrom`/`validUntil`; verifiers **MUST** reject
  a list outside its window and **SHOULD** refetch if older than a deployment-defined max-age.
- **Re-check before settle:** the wallet **MUST** re-check status at settlement, not only at
  authorization, so a credential revoked between authorize and execute is refused with
  `credential-revoked` (the transport bundle's error code).

## 7. Acceptance

- `generate.py` deterministic (gzip `mtime=0`); `verify.py`/`validate.py` PASS; pytest green
  (incl. `test_status.py`); shared `$def` drift guard green; the other four bundles unchanged.
- A negative control confirms a tampered status-list proof fails and the revoked bit reads 1.
