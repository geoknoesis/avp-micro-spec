# Tutorial 04 — Identity & Cryptography

> **Series:** [AVP-Micro Tutorials](README.md) · **Previous:** [03 — The Stack at a Glance](03-the-stack-at-a-glance.md) · **Next:** 05 — Delegated Spending Authority
>
> **You'll learn:** the four cryptographic primitives every AVP-Micro object rests on — DIDs,
> JCS canonicalization, the `ecdsa-jcs-2022` Data Integrity proof, and content digests — from
> first principles, with the exact choices this stack makes and why.

---

## 1. Why this tutorial matters

Everything in Tutorials 05–14 is "a signed object that references another signed object." This
lesson is the *because*: how identity, signing, and binding actually work here. Get this, and
the rest of the stack is just vocabulary.

There are four primitives:

1. **DIDs** — decentralized identifiers (who signed).
2. **JCS** — a canonical JSON form (so a signature is reproducible).
3. **`ecdsa-jcs-2022`** — the Data Integrity proof (the signature itself).
4. **Content digests** — hashing one object to bind it into another.

## 2. Identity: `did:key` with P-256

A **DID** (Decentralized Identifier) is a URI that resolves to public key material **without a
central registry**. AVP-Micro uses the `did:key` method, which encodes the public key *directly
in the identifier* — no network lookup, no registrar. Self-certifying identity is exactly what
Requirement R5 (open interoperability) demands.

The key type is **P-256** (NIST secp256r1), encoded as a W3C **Multikey** using the
`p256-pub` multicodec, multibase-base58btc. A DID looks like:

```
did:key:zDnaew8NDU8VgvxWpWWxBeLWaVbGNEuXYyRFk2uLMjCdhxkSU
```

The leading `z` is the multibase prefix for base58btc; the rest encodes the multicodec tag plus
the compressed public key. Because the key *is* the identifier, anyone can verify a signature
attributed to that DID with no infrastructure. A signed object names its key in
`proof.verificationMethod` as `<did>#<fragment>`.

> In code: `avp_crypto.seed_key(label)` derives a deterministic test key, and
> `avp_crypto.did_key(pub)` produces the `did:key`. (Test keys are deterministic so vectors are
> reproducible — never use them for real value.)

## 3. JCS: making JSON signable

Here's the problem signatures have with JSON: `{"a":1,"b":2}` and `{"b":2,"a":1}` are the same
*data* but different *bytes* — and a signature is over bytes. Re-serialize an object and the
signature breaks, even though nothing meaningful changed.

The fix is **canonicalization**: a deterministic rule for turning a JSON value into one exact
byte sequence. AVP-Micro uses **JCS, the JSON Canonicalization Scheme (RFC 8785)**: object keys
sorted, minimal whitespace, canonical number and string forms, UTF-8. Two implementations that
both apply JCS produce byte-identical output, so they compute the same signature.

One subtlety the harness checks explicitly: JCS requires the line/paragraph separators
**U+2028 / U+2029** to be `\u`-escaped (they're legal in JSON strings but illegal in
JavaScript, and interop suffers otherwise). `verify.py` asserts this.

> In code: `avp_crypto.jcs(obj)` returns the canonical bytes.

## 4. `ecdsa-jcs-2022`: the signature

The signature suite — the **mandatory-to-implement cryptosuite** for AVP-Micro — is
`ecdsa-jcs-2022`. To sign an object:

1. Take the object **without** its `proof` value, add the proof's metadata, and JCS-canonicalize.
2. SHA-256 the canonical bytes.
3. Sign with **ECDSA over P-256**, using **RFC 6979 deterministic nonces** (no randomness — so
   the same input always yields the same signature: reproducible vectors, no weak-RNG risk).
4. Normalize to **canonical low-`s`** form (rejects signature malleability).
5. Emit the signature as **raw R‖S** (64 bytes), multibase-base58btc encoded with a `z` prefix.

The result is wrapped in a **`DataIntegrityProof`**:

```json
"proof": {
  "type": "DataIntegrityProof",
  "cryptosuite": "ecdsa-jcs-2022",
  "created": "2026-03-25T21:30:00Z",
  "verificationMethod": "did:key:zDnae…#zDnae…",
  "proofPurpose": "assertionMethod",
  "proofValue": "z5MbMnuTG3At…"
}
```

Verifying inverts the process: recompute the canonical bytes, decode the key from the
`verificationMethod` DID, and check the signature. **Change one byte of the object and
verification fails** — that's R3 (verifiability) made concrete.

> In code: `avp_crypto.sign_ecdsa_jcs_2022(doc, key, created)` and
> `avp_crypto.verify_ecdsa_jcs_2022(doc)`.

## 5. Content digests: binding objects together

A signature proves *who* wrote an object and that it's *unaltered*. To bind objects into a
chain — "this authorization is for *that exact* quote" — AVP-Micro uses **content digests**: a
SHA-256 over the referenced object's JCS bytes, written as a self-describing string:

```
sha-256:EuScAr2qixUd_K3KSPlSR0HAlToOR7tuPZODlQZMbFg
```

(base64url, no padding). The authorization carries `quoteDigest = jcs_digest(quote)`; the
receipt carries the execution's id; the settlement proof carries `instructionDigest`. Because a
digest changes if a single byte of the target changes, you cannot swap in a different quote,
amount, or payee without detection. This is the glue of the whole protocol.

> In code: `avp_crypto.jcs_digest(obj)` → `"sha-256:<base64url>"`.

## 6. The `@context`: shared meaning

AVP-Micro objects are **JSON-LD**, so terms like `amount` or `payee` have globally-unambiguous
meaning. Signed objects carry a fixed, ordered **5-entry `@context`**:

```json
["https://www.w3.org/ns/credentials/v2",
 "https://w3id.org/security/data-integrity/v2",
 "https://w3id.org/spending-authority/v1",
 "https://w3id.org/avp-micro/v1",
 "https://w3id.org/avp-micro/<bundle>/v1"]
```

Each bundle's context is `@protected`, so terms can't be silently redefined. The order matters
and is enforced by the schema. (Tutorial 08 has a nice example: the transport `challenge` field
deliberately *reuses* the Data Integrity `challenge` term rather than redefining it.)

## 7. Recap

- **DIDs (`did:key`, P-256 Multikey)** give registrar-free, self-certifying identity.
- **JCS (RFC 8785)** turns JSON into reproducible bytes so signatures are stable.
- **`ecdsa-jcs-2022`** signs those bytes: P-256, RFC 6979 deterministic, low-`s`, raw R‖S, in a
  `DataIntegrityProof`.
- **Content digests** bind one object into another, making the whole lifecycle tamper-evident.

## Glossary

- **DID** — Decentralized Identifier; a URI resolving to key material without a registry.
- **Multikey / multicodec** — self-describing encodings of a public key (`p256-pub`) / value.
- **Canonicalization (JCS)** — deterministic byte form of a JSON value (RFC 8785).
- **Data Integrity Proof** — the W3C envelope carrying a cryptosuite signature.
- **RFC 6979** — deterministic ECDSA nonce generation (no randomness needed).
- **Low-`s` / malleability** — normalizing a signature so it has one canonical form.
- **Content digest** — a hash of an object's canonical bytes, used to bind references.

## Try it

```powershell
.venv\Scripts\python -c "import sys; sys.path.insert(0,'spec'); import json, avp_crypto as ac; q=json.load(open('spec/payments/test-vectors/01-payment-quote.json',encoding='utf-8')); print('proof verifies:', ac.verify_ecdsa_jcs_2022(q)); print('digest:', ac.jcs_digest(q))"
```

You'll see the quote's proof verify and its content digest — the exact value the *next* object
in the chain (the authorization) embeds as `quoteDigest`.

---

**Next:** Tutorial 05 — *Delegated Spending Authority.*
