# AVP-Micro — specifications and conformance harness

Formal W3C specifications and signed test vectors for the **AVP-Micro** (*Agent Verifiable Micropayments*) trust and authorization layer for AI agent payments.

## What's here

Six peer specification bundles, a shared Python harness, and design documents.

| Bundle | Directory | Namespace |
|--------|-----------|-----------|
| Delegated Spending Authority (DSA) | `spec/authority/` | `https://w3id.org/spending-authority/v1#` |
| AVP-Micro Payments | `spec/payments/` | `https://w3id.org/avp-micro/v1#` |
| AVP-Micro ⇄ SD-JWT-VC interop profile | `spec/interop-sd-jwt-vc/` | `https://w3id.org/avp-micro/interop/sd-jwt-vc/v1#` |
| Refunds, Reversals & Disputes | `spec/disputes/` | `https://w3id.org/avp-micro/disputes/v1#` |
| On-Chain Settlement Binding | `spec/settlement/` | `https://w3id.org/avp-micro/settlement/v1#` |
| Transport & Protocol Binding | `spec/transport/` | `https://w3id.org/avp-micro/transport/v1#` |

See [`spec/README.md`](spec/README.md) for the full bundle overview.

## Install and run the harness

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python spec/generate.py   # (re)build signed test vectors for all six bundles
python spec/verify.py     # verify proofs, bindings, policy, and interop round-trip
python spec/validate.py   # Turtle / JSON-LD / JSON Schema / SHACL for all six bundles
python spec/sim.py        # run the protocol simulator over the declarative use cases
```

All checks must report `PASS`.

An interactive **Streamlit demo** of the simulator lives in the separate
`avp-micro-sim-demo` repository (`streamlit run app.py`).

## Harness files (`spec/` root)

| File | Purpose |
|------|---------|
| `spec/avp_crypto.py` | P-256 key derivation, JCS canonicalization, `ecdsa-jcs-2022` sign/verify (deterministic, low-s) |
| `spec/sdjwt.py` | P-256 keys, ES256/JOSE, JWK, SD-JWT primitives for the interop bundle |
| `spec/interop.py` | AVP-Micro ⇄ SD-JWT-VC translator: claim mapping, both envelopes, cross-stack verification |
| `spec/pricing.py` | Pricing-model evaluator (flat, per-call, tiered, composite) |
| `spec/generate.py` | Writes deterministic signed test vectors into every bundle's `test-vectors/` directory |
| `spec/verify.py` | Verifies proofs, bindings, policy, and the interop round-trip |
| `spec/validate.py` | Turtle parse, JSON-LD expansion (offline), JSON Schema, and SHACL validation |
| `spec/sim.py` + `spec/sim-scenarios.json` | Protocol simulator: full message flow + wallet policy enforcement against a simulated play-money ledger; declarative use cases |

## Design documents

`docs/superpowers/specs/` holds the design notes behind each bundle, including the SD-JWT-VC bridge design and the Mastercard/Google Verifiable Intent competitive analysis.

## Vision document

[`docs/blog/avp-micro-introduction.md`](docs/blog/avp-micro-introduction.md) (and `.pdf`) — the high-level vision for AVP-Micro as a vendor-neutral trust and authorization layer over pluggable payment rails.
