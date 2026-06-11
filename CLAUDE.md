# CLAUDE.md

This file provides guidance to Claude Code when working in the `avp-micro-spec` repository.

## What this repo is

Formal W3C specifications, conformance tests, and signed test vectors for the **AVP-Micro** trust and authorization layer for AI agent payments.

Three peer bundles live under `spec/`:

- **`spec/authority/`** — Delegated Spending Authority (DSA): identity, `SpendingAuthorizationCredential`, securing mechanisms, trust framework. Namespace `https://w3id.org/spending-authority/v1#`.
- **`spec/payments/`** — AVP-Micro Payments: quotes, authorizations, executions, receipts, streaming, built on DSA. Namespace `https://w3id.org/avp-micro/v1#`.
- **`spec/interop-sd-jwt-vc/`** — Bridge/binding between AVP-Micro and SD-JWT-VC credentials (Mastercard/Google Verifiable Intent, Google AP2). Namespace `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#`.

Each bundle has: `context/v1.jsonld`, `schemas/*.schema.json`, `shapes/*.ttl`, `vocab/*.ttl`, and signed `test-vectors/`. A shared harness at `spec/` root generates and validates all three.

Start at `spec/README.md`.

## Commands

Platform: Windows; shell: PowerShell. A virtualenv is at `.venv`.

```powershell
# one-time setup
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# regenerate all signed test vectors
python spec/generate.py

# verify crypto proofs + bindings + policy + interop round-trip (must report PASS)
python spec/verify.py

# validate Turtle / JSON-LD / JSON Schema / SHACL for all three bundles (must report PASS)
python spec/validate.py
```

`validate.py` is **fully offline**: stable external W3C contexts are vendored under `spec/contexts/` and served by the local document loader.

## Harness architecture

`generate.py` is the canonical source of truth — it (re)writes every test vector using the deterministic key derivation in `avp_crypto.py` and `sdjwt.py`. Running it overwrites existing vectors; that is intended.

- **`avp_crypto.py`**: Ed25519 key derivation (`seed_key`), `did:key` encoding, JCS canonicalization, `eddsa-jcs-2022` sign/verify. The mandatory-to-implement cryptosuite for AVP-Micro.
- **`sdjwt.py`**: P-256 key derivation (`seed_p256`), ES256 sign/verify (raw R‖S), JWK encode/decode, `sdjwt_compact`, `sdjwt_jws`, `make_disclosure`, `disclosure_digest`, `sd_hash`, EdDSA key-binding JWT helpers. Used only by the interop bundle.
- **`interop.py`**: AVP-Micro ⇄ SD-JWT-VC translator. Claim mapping, three bridge modes (proof-preserving / co-issued / attested), cross-stack verification, lossy-case `importAdvisory` surfacing, L3 key-binding JWT.
- **`pricing.py`**: Pricing-model evaluator (flat, per-call, tiered, composite) used by the Payments bundle.

## Key invariants

- `python spec/verify.py` and `python spec/validate.py` must both report **PASS** after any change. Run both before committing.
- Never edit test vectors by hand — always run `generate.py` to regenerate them.
- `validate.py` parses SHACL shapes graphs fresh per vector instance (`shapes_graph` inside the loop) because `pyshacl` with `advanced=True` mutates the graph between runs.
- Contexts in `spec/contexts/` (vendored `credentials-v2.jsonld`, `data-integrity-v2.jsonld`) must be refreshed from canonical URLs if the W3C specs change.

## Namespace / context URLs (registration pending)

- DSA context: `https://w3id.org/spending-authority/v1` → `spec/authority/context/v1.jsonld`
- Payments context: `https://w3id.org/avp-micro/v1` → `spec/payments/context/v1.jsonld`
- Interop context: `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1` → `spec/interop-sd-jwt-vc/context/v1.jsonld`
