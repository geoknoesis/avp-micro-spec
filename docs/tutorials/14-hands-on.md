# Tutorial 14 — Hands-on

> **Series:** [AVP-Micro Tutorials](README.md) · **Previous:** [13 — Conformance](13-conformance.md)
>
> **You'll learn:** how to run the whole stack yourself — regenerate and verify the vectors,
> validate the artifacts, certify the reference wallet, explore the interactive demo, hit a real
> 402 server, and wire your own wallet in.

---

## 1. Setup

You need Python 3 and Git. From a clone of
[`avp-micro-spec`](https://github.com/geoknoesis/avp-micro-spec):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

All commands below assume the venv is active and you're at the repo root.

## 2. The four harness programs

These are the source of truth — everything in Tutorials 03–13 is checked by them.

```powershell
.venv\Scripts\python spec\generate.py     # (re)write every signed test vector, deterministically
.venv\Scripts\python spec\verify.py       # crypto proofs + signer bindings + digest links  → PASS
.venv\Scripts\python spec\validate.py     # JSON-LD + JSON Schema + SHACL + OpenAPI          → PASS
.venv\Scripts\python spec\conformance.py  # certify the reference wallet against the WCP      → PASS
.venv\Scripts\python -m pytest spec\ -q   # the unit/guard tests
```

What each proves:

- **`generate.py`** is deterministic — run it twice and `git status` stays clean. Never hand-edit
  a vector; change the generator and regenerate.
- **`verify.py`** walks the signed lifecycle (Tutorials 04–12) and the negative controls
  (tampering breaks signatures).
- **`validate.py`** checks the JSON-LD contexts, JSON Schemas, SHACL shapes, and that the
  OpenAPI contract matches the example exchanges.
- **`conformance.py`** runs the Wallet Conformance Profile (Tutorial 13).

## 3. The simulator

`sim.py` is the behavioural reference engine; `sim-scenarios.json` is a declarative list of use
cases (one-off, streaming, human-present, AP2 bridge, disputes, every settlement rail). Each
scenario declares the expected outcome per step, and the engine replays it with real
`ecdsa-jcs-2022` signatures against a play-money ledger. This is the layer the conformance
profile certifies.

You can read any scenario as a template for your own:

```powershell
.venv\Scripts\python -c "import sys; sys.path.insert(0,'spec'); import sim, json; s={x['name']:x for x in sim.load_scenarios()}; print(json.dumps(s['one-off-happy-path'], indent=2))"
```

## 4. The interactive demo

The Streamlit demo ([`avp-micro-sim-demo`](https://github.com/geoknoesis/avp-micro-sim-demo), or the
[hosted version](https://avp-micro-sim-demo-jhjzp6ra4fvqgxmpr7b3x8.streamlit.app/)) visualises
all of the above. From the demo repo:

```powershell
pip install -r requirements.txt
streamlit run app.py
```

Its six views:

- **Walk a use case** — one scenario end to end: outcome banner, message-flow diagram,
  play-money ledger, and the signed JSON behind every step.
- **All use cases** — every scenario at a glance with pass/fail.
- **Transport (HTTP 402)** — the 402 exchange rendered as a real HTTP conversation.
- **Live (try it)** — set the policy and run a *real* 402 exchange with live signatures.
- **Wallet conformance** — the reference engine certified against the WCP (Tutorial 13).
- **Conformance vectors** — every signed spec vector, each with its proof verified.

## 5. A real local server

The demo also ships a tiny runnable payee+wallet HTTP server — the 402 binding (Tutorial 08)
over real sockets. Run it from your `avp-micro-sim-demo` clone (it is not part of this spec repo):

```powershell
python server.py     # http://localhost:8402, from the avp-micro-sim-demo repo
curl -i "http://localhost:8402/.well-known/avp-micro"
curl -i "http://localhost:8402/resource/premium?amount=1.00&cap=5.00&payee=allowed"                                 # 402 + challenge
curl -i "http://localhost:8402/resource/premium?amount=1.00&cap=5.00&payee=allowed" -H "Authorization: AVP-Micro x" # 200
curl -i "http://localhost:8402/resource/premium?amount=10.00&cap=5.00&payee=allowed" -H "Authorization: AVP-Micro x" # 402 over-cap
```

Real signatures, the reference wallet's real policy, and single-use challenge nonces (a replayed
authorized call returns `409 nonce-reuse`).

## 6. Wire in your own wallet

To integrate or certify your implementation:

1. **Read the vectors** under `spec/*/test-vectors/` — these are the exact object shapes your
   wallet must produce/consume.
2. **Verify like the reference** — reproduce `verify.py`'s checks: proofs (`ecdsa-jcs-2022`),
   the digest bindings (`quoteDigest`, `requestHash`, `authorizationDigest`…), and the mandate
   policy (caps, allow-lists, status, freshness).
3. **Enforce the refusals** — your wallet must say *no* with the right codes (`overCap`,
   `payeeNotAllowed`, `nonceReuse`, `credentialRevoked`, `accountRedirection`, …).
4. **Certify** — implement a `WalletAdapter` (Tutorial 13) and run `conformance.py` against your
   wallet until it reports `PASS`.

## 7. Where to go next

- **Spec bundles** — each bundle's `spec/<bundle>/index.html` is the normative ReSpec document,
  with `schemas/`, `shapes/`, `vocab/`, and `context/` alongside.
- **Suite overview** — [`spec/README.md`](../../spec/README.md).
- **Problem & state of the art** — [`docs/problem-challenges-and-sota.md`](../../docs/problem-challenges-and-sota.md).
- **Re-read** Tutorial 03 with the code open — the end-to-end flow will now map onto exact files.

## 8. Recap

- Four programs (`generate` / `verify` / `validate` / `conformance`) plus `pytest` are the
  ground truth; the simulator drives declarative scenarios with real signatures.
- The Streamlit demo and the runnable `server.py` let you *see* and *touch* the protocol.
- Integrating means: match the vectors, reproduce the verification + refusals, and certify with a
  `WalletAdapter`.

## Glossary

- **Harness** — the `generate`/`verify`/`validate`/`conformance` programs.
- **Reference engine** — `sim.py`, the behavioural wallet the suite certifies.
- **Scenario** — a declarative use case in `sim-scenarios.json`.
- **WalletAdapter** — the seam for certifying your own implementation.

## Try it

```powershell
.venv\Scripts\python spec\verify.py | findstr /R "^PASS FAIL"
.venv\Scripts\python spec\validate.py | findstr /R "^PASS FAIL"
.venv\Scripts\python spec\conformance.py | findstr "satisfied"
```

Three green lines = the whole stack — crypto, artifacts, and wallet behaviour — checks out on
your machine. **You've finished the series.** 🎉

---

**That's the series.** Back to [the curriculum](README.md) · [the spec suite](../../spec/README.md).
