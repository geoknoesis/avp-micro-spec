# Transport Flow-Coverage + OpenAPI Conformance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add signed example exchanges for the four undocumented-by-example transport flows (explicit-quote, streaming, async settlement, idempotency), make the OpenAPI contract and the example exchanges provably consistent via a new harness check, and surface the new flows as tabs in the Streamlit demo.

**Architecture:** Each new exchange is an `HttpExchangeLog` whose bodies are existing committed vectors reloaded from disk (the `40/41` pattern) — no new economic objects, no edits to the other five bundles. A new `openapi_exchange_check()` in `validate.py` validates every exchange body against the schema the OpenAPI documents for that path+status+content-type. `verify.py` gains byte-identity + flow-binding checks. The demo's generic `_render_exchange` renderer gets four new tabs.

**Tech Stack:** Python 3 (deterministic generator), JSON Schema Draft 2020-12 (`jsonschema` + `referencing`), OpenAPI 3.1 (YAML via PyYAML), Streamlit.

**Reference design:** `docs/superpowers/specs/2026-06-13-transport-flow-coverage-design.md`.

**Repos:** `avp-micro-spec` (branch `feat/transport-flow-coverage`, already created) for Tasks 1–3 & 5; `avp-micro-sim-demo` for Task 4.

---

## Pre-flight

- Spec commands use the repo venv: `./.venv/Scripts/python` (Git Bash) / `.venv\Scripts\python` (PowerShell).
- **Invariants:** `python spec/verify.py` and `python spec/validate.py` must both report **PASS** after every change-bearing task. `generate.py` is deterministic — never hand-edit vectors; running it twice must leave a clean tree.
- Baseline (branch `feat/transport-flow-coverage` off master, transport bundle present):
  ```bash
  ./.venv/Scripts/python spec/verify.py | tail -1 && ./.venv/Scripts/python spec/validate.py | tail -1
  ```
  Expected: both `PASS: ...`.
- Canonical vectors the exchanges wrap (confirmed ids): quote `urn:avp:quote:789` (01), submission `urn:avp:txp:submission:def456` (transport 20), execution `urn:avp:exec:555` (03), receipt `urn:avp:receipt:222` (04, `execution`=exec:555), session `urn:avp:session:001` (05), session-budget (06), accrual (07), session-receipt `urn:avp:receipt:sess-final` (09), settlement proof `urn:avp:settle-proof:evm` (settlement 42, `finality:final`).

---

## Task 1: Generate the four new exchange vectors

**Files:**
- Modify: `spec/generate.py` (append to the transport block, before the interop comment at line ~897)

- [ ] **Step 1: Insert the new exchanges into the transport block**

In `spec/generate.py`, find:

```python
    write(TXP, "41-exchange-over-cap.json", over_cap)

    # ---- Interop (SD-JWT-VC) bundle ----
```

Replace with:

```python
    write(TXP, "41-exchange-over-cap.json", over_cap)

    # ---- additional flow exchanges (explicit-quote, streaming, async, idempotency) ----
    exec_c = json.loads((PAY / "03-payment-execution.json").read_text(encoding="utf-8"))
    sess_c = json.loads((PAY / "05-usage-session.json").read_text(encoding="utf-8"))
    budget_c = json.loads((PAY / "06-session-budget-authorization.json").read_text(encoding="utf-8"))
    accrual_c = json.loads((PAY / "07-usage-accrual.json").read_text(encoding="utf-8"))
    sess_receipt_c = json.loads((PAY / "09-payment-receipt-session.json").read_text(encoding="utf-8"))
    settle_proof_c = json.loads((SETTLE / "42-settlement-proof-evm.json").read_text(encoding="utf-8"))
    JCT = {"Content-Type": "application/avp-micro+json"}
    PCT = {"Content-Type": "application/problem+json"}

    quote_flow = {
        "description": "Explicit (non-gated) flow: request a quote, submit the authorization, fetch the receipt.",
        "steps": [
            {"request": {"method": "POST", "path": "/quote",
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": quote_c}},
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": submission["idempotencyKey"]},
                         "body": submission},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "GET", "path": "/receipt/" + receipt_c["id"],
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": receipt_c}},
        ],
    }
    write(TXP, "42-exchange-quote-flow.json", quote_flow)

    streaming = {
        "description": "Streaming session: open, commit a budget, report accruals, then close and settle.",
        "steps": [
            {"request": {"method": "POST", "path": "/session", "headers": JCT},
             "response": {"status": 200, "headers": JCT, "body": sess_c}},
            {"request": {"method": "POST", "path": "/session/" + sess_c["id"] + "/budget",
                         "headers": JCT, "body": budget_c},
             "response": {"status": 200, "headers": JCT, "body": sess_c}},
            {"request": {"method": "GET", "path": "/session/" + sess_c["id"] + "/accruals",
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": accrual_c}},
            {"request": {"method": "POST", "path": "/session/" + sess_c["id"] + "/close", "headers": JCT},
             "response": {"status": 200, "headers": JCT, "body": sess_receipt_c}},
        ],
    }
    write(TXP, "43-exchange-streaming.json", streaming)

    settle_loc = "/settlement/" + settle_proof_c["id"]
    async_settle = {
        "description": "Async settlement: execute returns 200 + Location; poll /settlement/{id} until the proof is final.",
        "steps": [
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": submission["idempotencyKey"]},
                         "body": submission},
             "response": {"status": 200, "headers": {**JCT, "Location": settle_loc}, "body": exec_c}},
            {"request": {"method": "GET", "path": settle_loc,
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "GET", "path": settle_loc,
                         "headers": {"Accept": "application/avp-micro+json"}},
             "response": {"status": 200, "headers": JCT, "body": settle_proof_c}},
        ],
    }
    write(TXP, "44-exchange-async-settlement.json", async_settle)

    # a genuinely distinct, validly-signed submission for the conflict step
    submission_alt = json.loads(json.dumps(submission))
    submission_alt.pop("proof", None)
    submission_alt["id"] = "urn:avp:txp:submission:def457"
    submission_alt["callbackUrl"] = "https://agent.example.com/avp/callback-2"
    submission_alt = ac.sign_ecdsa_jcs_2022(submission_alt, agent, "2026-03-25T21:33:00Z")
    conflict = {
        "type": TXP_URL + "#idempotency-conflict",
        "title": "Idempotency key reused with a different request",
        "status": 409,
        "detail": "The Idempotency-Key was already used for a different AuthorizationSubmission.",
        "field": "Idempotency-Key",
    }
    idem = {
        "description": "Idempotency: a repeated key returns the same execution; a different body under the same key is a 409 conflict.",
        "steps": [
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": "idemp-2026-03-25-0001"}, "body": submission},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": "idemp-2026-03-25-0001"}, "body": submission},
             "response": {"status": 200, "headers": JCT, "body": exec_c}},
            {"request": {"method": "POST", "path": "/authorize",
                         "headers": {**JCT, "Idempotency-Key": "idemp-2026-03-25-0001"}, "body": submission_alt},
             "response": {"status": 409, "headers": PCT, "body": conflict}},
        ],
    }
    write(TXP, "45-exchange-idempotency.json", idem)

    # ---- Interop (SD-JWT-VC) bundle ----
```

- [ ] **Step 2: Generate + confirm determinism**

Run:
```bash
./.venv/Scripts/python spec/generate.py >/dev/null
ls spec/transport/test-vectors/4*.json
./.venv/Scripts/python spec/generate.py >/dev/null
git status --porcelain spec/transport/test-vectors | grep -E "^ M" && echo "CHURN!" || echo "deterministic (no modified vectors)"
```
Expected: lists `40`–`45`; second line prints `deterministic (no modified vectors)`.

- [ ] **Step 3: Sanity-check the new vectors are well-formed + the conflict submission verifies**

Run:
```bash
./.venv/Scripts/python -c "import sys; sys.path.insert(0,'spec'); import json,avp_crypto as ac; \
idem=json.load(open('spec/transport/test-vectors/45-exchange-idempotency.json',encoding='utf-8')); \
s1=idem['steps'][0]['request']['body']; s3=idem['steps'][2]['request']['body']; \
print('same key replay:', idem['steps'][0]['request']['headers']['Idempotency-Key']==idem['steps'][1]['request']['headers']['Idempotency-Key']); \
print('conflict body differs:', s1!=s3); \
print('conflict submission valid:', ac.verify_ecdsa_jcs_2022(s3)); \
print('conflict is 409:', idem['steps'][2]['response']['status']==409); \
asett=json.load(open('spec/transport/test-vectors/44-exchange-async-settlement.json',encoding='utf-8')); \
print('async Location:', bool(asett['steps'][0]['response']['headers'].get('Location'))); \
print('async final proof:', asett['steps'][2]['response']['body']['finality']=='final')"
```
Expected: all six lines `True`.

- [ ] **Step 4: Commit**

```bash
git add spec/generate.py spec/transport/test-vectors
git commit -m "feat(transport): exchange vectors for quote/streaming/async/idempotency flows"
```

---

## Task 2: OpenAPI↔exchange cross-validation (`validate.py`)

**Files:**
- Modify: `spec/validate.py`

- [ ] **Step 1: Register the new exchange logs for HttpExchangeLog schema-check + define the exchange list**

In `spec/validate.py`, find:

```python
    "41-exchange-over-cap.json": "HttpExchangeLog",
}
```

Replace with:

```python
    "41-exchange-over-cap.json": "HttpExchangeLog",
    "42-exchange-quote-flow.json": "HttpExchangeLog",
    "43-exchange-streaming.json": "HttpExchangeLog",
    "44-exchange-async-settlement.json": "HttpExchangeLog",
    "45-exchange-idempotency.json": "HttpExchangeLog",
}
# Exchange logs whose every step is cross-checked against the OpenAPI contract.
EXCHANGE_VECTORS = [
    "40-exchange-402-flow.json", "41-exchange-over-cap.json",
    "42-exchange-quote-flow.json", "43-exchange-streaming.json",
    "44-exchange-async-settlement.json", "45-exchange-idempotency.json",
]
```

- [ ] **Step 2: Add the `openapi_exchange_check()` function**

In `spec/validate.py`, find:

```python
def shared_defs_check():
```

Insert this function immediately **before** it:

```python
def openapi_exchange_check():
    """Validate every exchange step body against the schema the OpenAPI documents for
    that path+status+content-type. Responses are fully validated; request bodies are
    validated only where the operation documents a requestBody."""
    oa = TRANSPORT / "openapi" / "avp-micro.openapi.yaml"
    doc = yaml.safe_load(oa.read_text(encoding="utf-8"))

    # registry of every bundle schema the OpenAPI refs, keyed by $id; plus file->$id
    # so we can rewrite the OpenAPI's relative $refs into resolvable $id form.
    schema_paths = [TRANSPORT / "schemas" / "transport.schema.json",
                    PAY / "schemas" / "avp-micro.schema.json",
                    SETTLE / "schemas" / "settlement.schema.json"]
    registry = Registry()
    fileid = {}
    for p in schema_paths:
        s = json.loads(p.read_text(encoding="utf-8"))
        registry = registry.with_resource(uri=s["$id"], resource=Resource(contents=s, specification=DRAFT202012))
        fileid[p.resolve()] = s["$id"]

    def rewrite(ref):
        rel, name = ref.split("#/$defs/", 1)
        sid = fileid.get((oa.parent / rel).resolve())
        return {"$ref": f"{sid}#/$defs/{name}"} if sid else None

    def to_schema(node):
        if not isinstance(node, dict):
            return None
        if "$ref" in node:
            return rewrite(node["$ref"])
        if "oneOf" in node:
            subs = [rewrite(x["$ref"]) for x in node["oneOf"] if isinstance(x, dict) and "$ref" in x]
            return {"oneOf": subs} if subs and all(s is not None for s in subs) else None
        return None

    def match_path(concrete):
        cseg = concrete.split("/")
        for tmpl in doc.get("paths", {}):
            tseg = tmpl.split("/")
            if len(tseg) == len(cseg) and all(
                    t == c or (t.startswith("{") and t.endswith("}")) for t, c in zip(tseg, cseg)):
                return tmpl
        return None

    def validate_body(label, schema_node, body):
        sch = to_schema(schema_node)
        if sch is None:
            ok(label, False, f"could not resolve OpenAPI schema {schema_node}")
            return
        v = Draft202012Validator(sch, registry=registry,
                                 format_checker=Draft202012Validator.FORMAT_CHECKER)
        errs = sorted(v.iter_errors(body), key=lambda e: e.json_path)
        ok(label, not errs, "; ".join(f"{e.json_path}: {e.message}" for e in errs[:3]))

    for name in EXCHANGE_VECTORS:
        log = json.loads((TRANSPORT / "test-vectors" / name).read_text(encoding="utf-8"))
        for i, step in enumerate(log["steps"], 1):
            req, res = step["request"], step["response"]
            tmpl = match_path(req["path"])
            ok(f"{name} step {i}: path '{req['path']}' is documented", tmpl is not None)
            if tmpl is None:
                continue
            op = doc["paths"][tmpl].get(req["method"].lower())
            ok(f"{name} step {i}: {req['method']} {tmpl} is documented", op is not None)
            if op is None:
                continue
            resp = (op.get("responses") or {}).get(str(res["status"]))
            ok(f"{name} step {i}: {res['status']} documented on {req['method']} {tmpl}", resp is not None)
            if resp is not None and "body" in res:
                ct = res.get("headers", {}).get("Content-Type", "application/avp-micro+json")
                content = resp.get("content") or {}
                media = content.get(ct) or (next(iter(content.values()), None))
                if media and "schema" in media:
                    validate_body(f"{name} step {i}: response body conforms "
                                  f"({req['method']} {tmpl} -> {res['status']})", media["schema"], res["body"])
            if "body" in req and op.get("requestBody"):
                ct = req.get("headers", {}).get("Content-Type", "application/avp-micro+json")
                content = op["requestBody"].get("content") or {}
                media = content.get(ct) or (next(iter(content.values()), None))
                if media and "schema" in media:
                    validate_body(f"{name} step {i}: request body conforms ({req['method']} {tmpl})",
                                  media["schema"], req["body"])


def shared_defs_check():
```

- [ ] **Step 3: Call it in `main()` after the ref-check**

Find:

```python
    section("OpenAPI contract")
    openapi_ref_check()
```

Replace with:

```python
    section("OpenAPI contract")
    openapi_ref_check()
    openapi_exchange_check()
```

- [ ] **Step 4: Run validate.py — full green incl. the cross-check**

Run:
```bash
./.venv/Scripts/python spec/validate.py 2>&1 | grep -E "exchange .* conforms|step .* documented|FAIL|^PASS" | grep -v "RequestsDep\|warnings"
./.venv/Scripts/python spec/validate.py 2>&1 | tail -1
```
Expected: many `[PASS] … response body conforms (…)` and `… is documented` lines, no `[FAIL]`, final line `PASS: all artifact checks passed.`

If a body fails to conform: that is a real contract↔example mismatch — diagnose whether the exchange (Task 1) or the OpenAPI documents the wrong schema for that path/status; do not weaken the check. If only this task's wiring is at fault (typo), fix `validate.py`.

- [ ] **Step 5: Commit**

```bash
git add spec/validate.py
git commit -m "feat(transport): OpenAPI<->exchange cross-validation (full body schema check)"
```

---

## Task 3: `verify.py` flow bindings

**Files:**
- Modify: `spec/verify.py`

- [ ] **Step 1: Add the flow-binding checks**

In `spec/verify.py`, find:

```python
    check("over-cap exchange status is 402", over_cap["steps"][0]["response"]["status"] == 402)

    print("Negative control (tamper detection):")
```

Replace with:

```python
    check("over-cap exchange status is 402", over_cap["steps"][0]["response"]["status"] == 402)

    # additional flow exchanges (explicit-quote, streaming, async settlement, idempotency)
    exec_c = load(PAY, "03-payment-execution.json")
    sess_c = load(PAY, "05-usage-session.json")
    accrual_c = load(PAY, "07-usage-accrual.json")
    sess_receipt_c = load(PAY, "09-payment-receipt-session.json")
    settle_proof_c = load(SETTLE, "42-settlement-proof-evm.json")
    qflow = load(TXP, "42-exchange-quote-flow.json")
    stream = load(TXP, "43-exchange-streaming.json")
    asett = load(TXP, "44-exchange-async-settlement.json")
    idem = load(TXP, "45-exchange-idempotency.json")

    check("quote-flow embeds the canonical quote, execution, and receipt",
          qflow["steps"][0]["response"]["body"] == quote
          and qflow["steps"][1]["response"]["body"] == exec_c
          and qflow["steps"][2]["response"]["body"] == receipt)
    check("quote-flow receipt binds the execution", receipt["execution"] == exec_c["id"])
    check("streaming opens the session and closes with the session receipt",
          stream["steps"][0]["response"]["body"] == sess_c
          and stream["steps"][3]["response"]["body"] == sess_receipt_c)
    check("streaming reports a usage accrual", stream["steps"][2]["response"]["body"] == accrual_c)
    check("async settlement returns a Location and polls to a final proof",
          bool(asett["steps"][0]["response"]["headers"].get("Location"))
          and asett["steps"][1]["response"]["body"] == exec_c
          and asett["steps"][2]["response"]["body"] == settle_proof_c)
    check("async settlement final proof has finality=final", settle_proof_c["finality"] == "final")
    _k0 = idem["steps"][0]["request"]["headers"]["Idempotency-Key"]
    check("idempotency replay returns the same execution under the same key",
          idem["steps"][1]["request"]["headers"]["Idempotency-Key"] == _k0
          and idem["steps"][0]["response"]["body"] == exec_c
          and idem["steps"][1]["response"]["body"] == exec_c)
    _conf = idem["steps"][2]
    check("idempotency conflict: same key + different body -> 409",
          _conf["request"]["headers"]["Idempotency-Key"] == _k0
          and _conf["request"]["body"] != idem["steps"][0]["request"]["body"]
          and _conf["response"]["status"] == 409)
    check("idempotency conflict body is an idempotency-conflict ProblemDetails",
          _conf["response"]["body"]["type"].rsplit("#", 1)[-1] == "idempotency-conflict")
    check("the conflict submission is a valid, distinct signed AuthorizationSubmission",
          ac.verify_ecdsa_jcs_2022(_conf["request"]["body"]))

    print("Negative control (tamper detection):")
```

Note: `quote` and `receipt` are already loaded earlier in `main()` (quote = payments 01, receipt = payments 04); the checks reuse them.

- [ ] **Step 2: Run verify.py**

Run:
```bash
./.venv/Scripts/python spec/verify.py 2>&1 | grep -E "quote-flow|streaming|async settlement|idempotency|conflict|FAIL|^PASS"
```
Expected: each new line `[PASS]`, final line `PASS: all checks passed.`

- [ ] **Step 3: Commit**

```bash
git add spec/verify.py
git commit -m "feat(transport): verify.py bindings for the new flow exchanges"
```

---

## Task 4: Demo tabs (`avp-micro-sim-demo/app.py`)

**Files:**
- Modify: `C:\Users\steph\work\avp-micro-sim-demo\app.py`

> Work in the demo repo on a new branch: `git -C C:/Users/steph/work/avp-micro-sim-demo checkout -b feat/transport-flow-tabs`. The demo reads the spec repo live, so Tasks 1–3 must be present on the spec checkout (they are, on `feat/transport-flow-coverage`).

- [ ] **Step 1: Expand the Transport tabs**

In `app.py`, find:

```python
    t1, t2, t3 = st.tabs(["💳 402 happy path", "⛔ Over-cap rejection", "🛰️ Discovery document"])
    with t1:
        _render_exchange(_txp("40-exchange-402-flow.json"))
    with t2:
        _render_exchange(_txp("41-exchange-over-cap.json"))
    with t3:
        _render_discovery(_txp("00-service-description.json"))
```

Replace with:

```python
    tabs = st.tabs(["💳 402 happy path", "🧾 explicit quote", "📡 streaming",
                    "⏳ async settle", "🔁 idempotency", "⛔ over-cap", "🛰️ discovery"])
    with tabs[0]:
        _render_exchange(_txp("40-exchange-402-flow.json"))
    with tabs[1]:
        _render_exchange(_txp("42-exchange-quote-flow.json"))
    with tabs[2]:
        _render_exchange(_txp("43-exchange-streaming.json"))
    with tabs[3]:
        _render_exchange(_txp("44-exchange-async-settlement.json"))
    with tabs[4]:
        _render_exchange(_txp("45-exchange-idempotency.json"))
    with tabs[5]:
        _render_exchange(_txp("41-exchange-over-cap.json"))
    with tabs[6]:
        _render_discovery(_txp("00-service-description.json"))
```

- [ ] **Step 2: Add request-body annotation for the session-budget commit**

In `app.py`, in `_render_exchange`, find:

```python
            if _body_type(rb) == "AuthorizationSubmission":
```

Insert this branch immediately **before** that line (so the budget case is handled, then the existing submission case):

```python
            if _body_type(rb) == "SessionBudgetAuthorization":
                st.caption("commits the session budget cap the payee meters against.")
            if _body_type(rb) == "AuthorizationSubmission":
```

- [ ] **Step 3: Add response annotations for the streaming/async body types + the Location hint**

In `app.py`, in `_render_exchange`, find:

```python
            elif bt == "PaymentReceipt":
                st.markdown(":green[✓ delivered — payee-signed PaymentReceipt]")
            _body_expander("response body", sb)
```

Replace with:

```python
            elif bt == "PaymentReceipt":
                st.markdown(":green[✓ delivered — payee-signed PaymentReceipt]")
            elif bt == "PaymentExecution":
                st.markdown(":green[✓ wallet-signed PaymentExecution]")
            elif bt == "UsageSession":
                st.markdown(":green[✓ metered session — UsageSession]")
            elif bt == "UsageAccrual":
                st.markdown(":green[✓ incremental metered usage — UsageAccrual]")
            elif bt == "SettlementProof":
                fin = sb.get("finality")
                tone = "green" if fin == "final" else "orange"
                st.markdown(f":{tone}[✓ SettlementProof — finality **{fin}**]")
            if res.get("headers", {}).get("Location"):
                st.caption("↪ Location — the client polls this URL until the SettlementProof is final.")
            _body_expander("response body", sb)
```

- [ ] **Step 4: Headless smoke test (renders every tab against the live spec checkout)**

Run (from the demo repo dir; uses the spec venv which has `cryptography`):
```bash
cd /c/Users/steph/work/avp-micro-sim-demo
AVP_SPEC_DIR="/c/Users/steph/work/avp-micro-spec/spec" /c/Users/steph/work/avp-micro-spec/.venv/Scripts/python - <<'PY'
import sys, types
class _Ctx:
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def __getattr__(self,n): return lambda *a,**k: _Ctx()
class _SS(dict):
    def __getattr__(self,n):
        try: return self[n]
        except KeyError: raise AttributeError(n)
    def __setattr__(self,n,v): self[n]=v
class _ST(types.ModuleType):
    session_state=_SS()
    def __getattr__(self,name):
        if name=="sidebar": return _Ctx()
        def f(*a,**k):
            if name=="columns":
                n=a[0] if a else 1; n=len(n) if isinstance(n,(list,tuple)) else n
                return [_Ctx() for _ in range(n)]
            if name=="tabs": return [_Ctx() for _ in a[0]]
            if name in ("container","expander","form","spinner","status","popover"): return _Ctx()
            if name in ("radio","selectbox"):
                opts=a[1] if len(a)>1 else k.get("options",[]); key=k.get("key")
                if key and key in _ST.session_state: return _ST.session_state[key]
                return opts[0] if opts else None
            if name=="button": return False
            return _Ctx()
        return f
sys.modules["streamlit"]=_ST("streamlit"); sys.argv=["app.py"]
import importlib.util
spec=importlib.util.spec_from_file_location("app","app.py")
app=importlib.util.module_from_spec(spec); spec.loader.exec_module(app)
app.render_transport()
for n in ("42-exchange-quote-flow.json","43-exchange-streaming.json",
          "44-exchange-async-settlement.json","45-exchange-idempotency.json"):
    app._render_exchange(app._txp(n))
print("ALL TABS RENDER OK")
PY
```
Expected: `ALL TABS RENDER OK` with no traceback.

- [ ] **Step 5: Commit (in the demo repo)**

```bash
git -C /c/Users/steph/work/avp-micro-sim-demo add app.py
git -C /c/Users/steph/work/avp-micro-sim-demo commit -m "feat: add explicit-quote, streaming, async-settle, idempotency tabs to the Transport view"
```

---

## Task 5: Full-suite verification + finish

**Files:** none (verification + branch completion).

- [ ] **Step 1: Spec determinism + full suite**

Run (spec repo):
```bash
./.venv/Scripts/python spec/generate.py >/dev/null && test -z "$(git status --porcelain)" && echo CLEAN || echo DIRTY
./.venv/Scripts/python spec/verify.py | tail -1
./.venv/Scripts/python spec/validate.py | tail -1
./.venv/Scripts/python -m pytest spec/ -q 2>&1 | tail -1
```
Expected: `CLEAN`; `PASS: all checks passed.`; `PASS: all artifact checks passed.`; pytest all pass.

- [ ] **Step 2: Other five bundles unchanged**

```bash
git diff --stat master -- spec/authority spec/payments spec/interop-sd-jwt-vc spec/disputes spec/settlement
```
Expected: **empty** (no other bundle touched).

- [ ] **Step 3: Final review + finish both branches**

Use **superpowers:finishing-a-development-branch** for each repo: verify tests (Steps 1 & Task 4 smoke), then present the merge/PR options and execute the user's choice. Recommended (user's standing preference): merge `feat/transport-flow-coverage` → `master` in `avp-micro-spec` (then push to origin), and merge `feat/transport-flow-tabs` → `master` in `avp-micro-sim-demo`.

---

## Self-Review

**Spec coverage** — design §2 (4 vectors) → Task 1; §3 (openapi_exchange_check, path-match, oneOf, response-full/request-conditional) → Task 2; §4 (verify bindings) → Task 3; §5 (demo tabs + annotations) → Task 4; §6 acceptance → Task 5.

**Placeholder scan** — none; every step has complete code/commands.

**Type/name consistency** — vector filenames `42`–`45` identical across generate (Task 1), `TRANSPORT_UNSIGNED_VECTORS` + `EXCHANGE_VECTORS` (Task 2), verify loads (Task 3), demo tabs (Task 4). Wrapped-vector ids match the confirmed values (exec `urn:avp:exec:555`, receipt `urn:avp:receipt:222`, session `urn:avp:session:001`, settle-proof `urn:avp:settle-proof:evm`). The conflict ProblemDetails `type` local-name `idempotency-conflict` matches the `errors.ttl` concept and `verify.py`'s check and the demo's `TXP_WHY` key.

**Known modelling notes (from the design, carried honestly):** async is `execution → (still executing) → final proof` because no non-final `SettlementProof` vector exists; execution(03) and proof(42) are not cryptographically bound (illustrative HTTP shape only); `verify.py` asserts body-type + `finality`, not an exec↔proof binding. The `/quote` step carries no request body (the OpenAPI documents none). GET-with-illustrative-body retries (`40/41`) skip request-body validation by design.
