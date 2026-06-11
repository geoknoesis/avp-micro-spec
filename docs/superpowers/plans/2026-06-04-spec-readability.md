# Spec Readability Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add newcomer on-ramp sections, inline SVG figures, member-definition tables, and rationale asides to both W3C peer specifications without changing any normative requirement.

**Architecture:** Two-phase sequential: Phase 1 applies every readability convention to `spec/authority/index.html` (the smaller DSA pilot); Phase 2 applies the identical conventions to `spec/payments/index.html`. Machine artifacts (contexts, schemas, shapes, vectors) are never touched. The green-bar gate — `spec/verify.py` and `spec/validate.py` both ending in PASS — is the regression test for every task.

**Tech stack:** HTML5 / W3C ReSpec, inline SVG (hand-authored), no external libraries or build tools. Python `.venv/Scripts/python.exe` for verification commands.

---

## Reference: shared CSS block

This block is inserted once into **each** spec's `<head>`, immediately before the ReSpec `<script>` tag. It is identical in both files.

```html
  <style>
    /* Object-definition summary */
    p.object-summary { font-style: italic; color: #333; margin-bottom: 0.5em; }
    /* Figures */
    figure { margin: 1.5em 0; text-align: center; }
    figure svg { max-width: 100%; height: auto; }
    figcaption { font-size: 0.9em; color: #555; margin-top: 0.4em; }
  </style>
```

## Reference: structural check command

Run after every task that edits an HTML file:

```bash
# DSA
python -c "
import re, sys
h = open('spec/authority/index.html').read()
for tag in ['section','pre','dl','table','ul','ol']:
    o = len(re.findall(f'<{tag}[ >]', h))
    c = len(re.findall(f'</{tag}>', h))
    print(f'{tag}: {o}/{c}', 'OK' if o==c else 'MISMATCH')
"
# Payments (same command, different path)
```

## Reference: harness command (run after both phases complete)

```bash
.venv/Scripts/python.exe spec/verify.py | tail -1
.venv/Scripts/python.exe spec/validate.py | tail -1
```

Both must end with `PASS`.

---

# PHASE 1: Delegated Spending Authority (pilot)

---

## Task 1: Feature branch + shared CSS block (DSA)

**Files:**
- Modify: `spec/authority/index.html` (line 6 — before the ReSpec `<script>`)

- [ ] **Step 1: Create the feature branch**

```bash
git checkout -b spec-readability
```

- [ ] **Step 2: Add the CSS block**

In `spec/authority/index.html`, insert the shared CSS block (from the Reference section above) between the `<meta charset="utf-8">` line and the `<script src="…respec-w3c"…>` line. The result should look like:

```html
<head>
  <meta charset="utf-8">
  <title>Delegated Spending Authority</title>
  <style>
    p.object-summary { font-style: italic; color: #333; margin-bottom: 0.5em; }
    figure { margin: 1.5em 0; text-align: center; }
    figure svg { max-width: 100%; height: auto; }
    figcaption { font-size: 0.9em; color: #555; margin-top: 0.4em; }
  </style>
  <script src="https://www.w3.org/Tools/respec/respec-w3c" class="remove" defer></script>
```

- [ ] **Step 3: Structural check**

Run the structural check command for DSA (Reference section). Expected: all tags OK.

- [ ] **Step 4: Commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): add shared readability CSS block"
```

---

## Task 2: DSA overview section — prose + tables

**Files:**
- Modify: `spec/authority/index.html`

Insert a new `<section class="informative" id="overview">` immediately after the closing `</section>` tag of the introduction section (currently at line 175). This section has three subsections: how-it-works prose, a roles table, and an object catalog table. It is entirely informative.

- [ ] **Step 1: Locate the insertion point**

Find the line `  </section>` that closes `<section class="informative" id="introduction">`. In the current file this is line 175. The next line is blank followed by `<section id="conformance">`.

- [ ] **Step 2: Insert the overview section**

Insert the following HTML between the closing `</section>` of introduction and the opening of conformance:

```html

  <section class="informative" id="overview">
    <h2>How it works</h2>

    <p>
      Delegated Spending Authority defines how an <strong>organisation (the
      principal)</strong> grants a bounded right to spend to an autonomous
      <strong>payer agent</strong>. The grant is encoded in a
      <a>Spending Authorization Credential</a> — a
      <a data-cite="vc-data-model-2.0#dfn-verifiable-credentials">Verifiable
      Credential</a> that names the agent DID as its subject and carries
      constraints: maximum amount per transaction, a daily cap, a list of
      approved payees, and acceptable service categories.
    </p>

    <p>
      A <strong>relying party</strong> (a wallet service or verifier) that
      receives a message signed by the agent first verifies the
      <a>Spending Authorization Credential</a> and checks that its issuer is
      listed in the relying party's local <a>TrustedIssuer</a> configuration.
      Optionally, an <a>IssuerScope</a> further restricts what that issuer is
      trusted to authorise — the <em>more restrictive</em> of the credential
      and the scope applies.
    </p>

    <p>
      Trust in <strong>payee services</strong> is established via a
      <a>Merchant Credential</a>, issued by a third-party trust anchor such as
      an industry registry. A relying party can match the payee's attested
      service categories against the agent's <code>allowedServiceTypes</code>
      to enforce categorical spending policies.
    </p>

    <p>
      All commitments — credentials, authorisations, receipts — are secured
      with cryptographic proofs using the W3C Data Integrity
      <code>eddsa-jcs-2022</code> cryptosuite over <code>did:key</code>
      Ed25519 keys, making every spending decision independently verifiable
      and auditable. See <a href="#fig-arch"></a> for the role relationships
      and <a href="#fig-trust"></a> for the delegation/constraint model.
    </p>

    <section id="overview-glance">
      <h3>Roles and objects at a glance</h3>

      <table class="simple" id="tab-roles">
        <caption>Roles defined by this specification</caption>
        <thead>
          <tr>
            <th scope="col">Role</th>
            <th scope="col">Produces</th>
            <th scope="col">Verifies / consumes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><a>Principal</a></td>
            <td><a>Spending Authorization Credential</a></td>
            <td>—</td>
          </tr>
          <tr>
            <td><a>Payer agent</a></td>
            <td>—</td>
            <td><a>Spending Authorization Credential</a>, <a>Merchant Credential</a></td>
          </tr>
          <tr>
            <td>Trust anchor</td>
            <td><a>Merchant Credential</a>, <a>Payment Capability Credential</a></td>
            <td>—</td>
          </tr>
          <tr>
            <td>Relying party (wallet / <a>Verifier</a>)</td>
            <td>—</td>
            <td>All credentials; evaluates against <a>TrustedIssuer</a> config</td>
          </tr>
        </tbody>
      </table>

      <table class="simple" id="tab-objects">
        <caption>Objects defined by this specification</caption>
        <thead>
          <tr>
            <th scope="col">Object</th>
            <th scope="col">One-line purpose</th>
            <th scope="col">Signer</th>
            <th scope="col">Section</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><a>Spending Authorization Credential</a></td>
            <td>Delegates bounded spending authority from a principal to a payer agent DID</td>
            <td>Principal</td>
            <td><a href="#spending-authorization-credential"></a></td>
          </tr>
          <tr>
            <td><a>Payment Capability Credential</a></td>
            <td>Attests a payer agent's funding capability and account address</td>
            <td>Wallet provider / financial institution</td>
            <td><a href="#payment-capability-credential"></a></td>
          </tr>
          <tr>
            <td><a>Merchant Credential</a></td>
            <td>Third-party attestation of a payee service's identity and categories</td>
            <td>Trust anchor</td>
            <td><a href="#merchant-credential"></a></td>
          </tr>
        </tbody>
      </table>
    </section>
  </section>

```

- [ ] **Step 3: Structural check**

Run the DSA structural check. Expected: all tags OK (section count goes up by exactly 2 — the overview and its overview-glance subsection).

- [ ] **Step 4: Commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): add informative overview section with roles and object tables"
```

---

## Task 3: DSA figure — architecture/roles diagram (`fig-arch`)

**Files:**
- Modify: `spec/authority/index.html`

The figure is inserted at the end of the new `id="overview"` section, after the `</section>` that closes `id="overview-glance"` but before the closing `</section>` of the outer overview block.

- [ ] **Step 1: Locate the insertion point**

Find `</section>` that closes `id="overview-glance"`. Insert the figure below it, still inside the outer `id="overview"` section.

- [ ] **Step 2: Insert the figure**

```html
    <figure id="fig-arch">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 330"
           role="img" aria-labelledby="fig-arch-title fig-arch-desc">
        <title id="fig-arch-title">Delegated Spending Authority — roles and relationships</title>
        <desc id="fig-arch-desc">
          Two credential flows. Top row: the Principal issues a
          SpendingAuthorizationCredential whose subject is the Payer Agent.
          Bottom row: a Trust Anchor issues a MerchantCredential about a
          Payee, which the Relying Party evaluates using its local TrustedIssuer
          and IssuerScope configuration. The Payer Agent also presents its
          credential to the Relying Party for verification.
        </desc>
        <defs>
          <marker id="a-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#333"/>
          </marker>
          <marker id="a-arr-b" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#005a9c"/>
          </marker>
          <marker id="a-arr-g" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#888"/>
          </marker>
        </defs>

        <!-- ── Row 1: identity delegation ─────────────────────────── -->
        <rect x="20" y="28" width="120" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="80" y="53" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Principal</text>
        <text x="80" y="70" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">controls funds</text>

        <rect x="190" y="16" width="260" height="66" rx="5"
              fill="#ddeeff" stroke="#005a9c" stroke-width="1.5"/>
        <text x="320" y="40" text-anchor="middle"
              font-family="sans-serif" font-size="12" font-weight="bold"
              fill="#005a9c">SpendingAuthorizationCredential</text>
        <text x="320" y="57" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#333">issuer: Principal · subject: Payer Agent</text>
        <text x="320" y="73" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#555">currency, maxPerTransaction, allowedPayees…</text>

        <rect x="500" y="28" width="120" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="560" y="53" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Payer Agent</text>
        <text x="560" y="70" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">software agent</text>

        <line x1="140" y1="55" x2="188" y2="50"
              stroke="#005a9c" stroke-width="1.5" marker-end="url(#a-arr-b)"/>
        <text x="165" y="44" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#005a9c">issues</text>
        <line x1="450" y1="50" x2="498" y2="55"
              stroke="#005a9c" stroke-width="1.5" marker-end="url(#a-arr-b)"/>
        <text x="473" y="44" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#005a9c">held by</text>

        <!-- ── Row 2: merchant trust ───────────────────────────────── -->
        <rect x="20" y="220" width="120" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="80" y="245" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Trust Anchor</text>
        <text x="80" y="262" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">e.g. industry registry</text>

        <rect x="190" y="212" width="260" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="320" y="237" text-anchor="middle"
              font-family="sans-serif" font-size="12" font-weight="bold"
              fill="#333">MerchantCredential</text>
        <text x="320" y="254" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#555">issuer: Trust Anchor · subject: payee service</text>

        <rect x="500" y="210" width="120" height="76" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="560" y="234" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Relying Party</text>
        <text x="560" y="250" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">wallet / verifier</text>
        <rect x="508" y="256" width="104" height="24" rx="3"
              fill="#fffde7" stroke="#aaa" stroke-width="1" stroke-dasharray="3,2"/>
        <text x="560" y="268" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#666">TrustedIssuer</text>
        <text x="560" y="278" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#666">+ IssuerScope config</text>

        <line x1="140" y1="247" x2="188" y2="242"
              stroke="#333" stroke-width="1.5" marker-end="url(#a-arr)"/>
        <text x="165" y="235" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#555">issues</text>
        <line x1="450" y1="242" x2="498" y2="247"
              stroke="#333" stroke-width="1.5" marker-end="url(#a-arr)"/>
        <text x="473" y="235" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#555">evaluated by</text>

        <!-- ── Vertical: Payer Agent presents to Relying Party ──────── -->
        <line x1="560" y1="82" x2="560" y2="208"
              stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"
              marker-end="url(#a-arr-g)"/>
        <text x="610" y="150" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#888"
              transform="rotate(90,610,150)">presents credential to</text>
      </svg>
      <figcaption>Figure: Delegated Spending Authority roles. The Principal issues a
        <a>Spending Authorization Credential</a> naming the Payer Agent; a Trust Anchor
        attests the Payee via a <a>Merchant Credential</a>; the Relying Party
        evaluates both against its <a>TrustedIssuer</a> / <a>IssuerScope</a> policy.
      </figcaption>
    </figure>
```

- [ ] **Step 3: Structural check**

Run the DSA structural check. All tags balanced.

- [ ] **Step 4: Commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): add architecture/roles SVG figure (fig-arch)"
```

---

## Task 4: DSA figure — delegation and constraint model (`fig-trust`)

**Files:**
- Modify: `spec/authority/index.html`

Insert after `fig-arch`'s closing `</figure>` tag, still inside `id="overview"`.

- [ ] **Step 1: Insert the figure**

```html
    <figure id="fig-trust">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 270"
           role="img" aria-labelledby="fig-trust-title fig-trust-desc">
        <title id="fig-trust-title">Spending authority delegation and constraints</title>
        <desc id="fig-trust-desc">
          The Principal issues a SpendingAuthorizationCredential with
          constraint fields (currency, maxPerTransaction, dailyLimit,
          allowedPayees, allowedServiceTypes). The credential's subject is
          the Payer Agent DID. At the Relying Party, an IssuerScope entry
          may further restrict what the issuer is trusted to authorise;
          the more restrictive of credential and scope applies.
        </desc>
        <defs>
          <marker id="t-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#333"/>
          </marker>
          <marker id="t-arr-b" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#005a9c"/>
          </marker>
        </defs>

        <!-- Principal -->
        <rect x="20" y="100" width="110" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="75" y="124" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Principal</text>
        <text x="75" y="141" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">DID issuer</text>

        <!-- SAC with constraints -->
        <rect x="170" y="18" width="300" height="200" rx="6"
              fill="#ddeeff" stroke="#005a9c" stroke-width="2"/>
        <text x="320" y="40" text-anchor="middle"
              font-family="sans-serif" font-size="12" font-weight="bold"
              fill="#005a9c">SpendingAuthorizationCredential</text>
        <text x="320" y="57" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#333">subject = Payer Agent DID</text>
        <!-- constraint rows -->
        <rect x="184" y="64" width="272" height="18" rx="3" fill="#fff" stroke="#aac" stroke-width="1"/>
        <text x="194" y="77" font-family="sans-serif" font-size="10" fill="#333">currency: "USD"</text>
        <rect x="184" y="86" width="272" height="18" rx="3" fill="#fff" stroke="#aac" stroke-width="1"/>
        <text x="194" y="99" font-family="sans-serif" font-size="10" fill="#333">maxPerTransaction: "0.05"</text>
        <rect x="184" y="108" width="272" height="18" rx="3" fill="#fff" stroke="#aac" stroke-width="1"/>
        <text x="194" y="121" font-family="sans-serif" font-size="10" fill="#333">dailyLimit: "5.00"</text>
        <rect x="184" y="130" width="272" height="18" rx="3" fill="#fff" stroke="#aac" stroke-width="1"/>
        <text x="194" y="143" font-family="sans-serif" font-size="10" fill="#333">allowedPayees: ["did:web:provider.com:…"]</text>
        <rect x="184" y="152" width="272" height="18" rx="3" fill="#fff" stroke="#aac" stroke-width="1"/>
        <text x="194" y="165" font-family="sans-serif" font-size="10" fill="#333">allowedServiceTypes: ["cat:ChatCompletionApi"]</text>
        <text x="320" y="203" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#888">absent = "not constrained by this credential"</text>

        <!-- Payer Agent -->
        <rect x="510" y="100" width="110" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="565" y="124" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Payer Agent</text>
        <text x="565" y="141" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">DID subject</text>

        <!-- Issue and grant arrows -->
        <line x1="130" y1="127" x2="168" y2="120"
              stroke="#005a9c" stroke-width="1.5" marker-end="url(#t-arr-b)"/>
        <text x="149" y="113" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#005a9c">issues</text>
        <line x1="470" y1="120" x2="508" y2="127"
              stroke="#005a9c" stroke-width="1.5" marker-end="url(#t-arr-b)"/>
        <text x="489" y="113" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#005a9c">grants to</text>

        <!-- Relying Party IssuerScope note -->
        <rect x="160" y="234" width="320" height="30" rx="4"
              fill="#fffde7" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <text x="320" y="248" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#555">Relying Party: IssuerScope may further restrict</text>
        <text x="320" y="260" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#555">→ more restrictive of credential + scope applies</text>
        <line x1="320" y1="218" x2="320" y2="232"
              stroke="#888" stroke-width="1" stroke-dasharray="3,2" marker-end="url(#t-arr)"/>
      </svg>
      <figcaption>Figure: Constraint encoding in a
        <a>Spending Authorization Credential</a>. Absent members are not
        constraints; present members are enforced. The Relying Party's
        <a>IssuerScope</a> may additionally restrict the issuer's authority.
      </figcaption>
    </figure>
```

- [ ] **Step 2: Structural check + commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): add delegation/constraint SVG figure (fig-trust)"
```

---

## Task 5: SpendingAuthorizationCredential — member table

**Files:**
- Modify: `spec/authority/index.html` (section `id="spending-authorization-credential"`, currently starting at line 502)

The section currently has a prose paragraph and a `<ul>` of member bullets. Replace the `<ul>` with a summary paragraph + the member table defined here. The prose paragraph about `type` and signing stays. All RFC 2119 keywords in the bullets become the `Req.` column.

- [ ] **Step 1: Locate the `<ul>` in the SpendingAuthorizationCredential section**

The `<ul>` starts after the paragraph ending "…not substitute a more permissive default. Where a deployment policy imposes an additional limit, the *more restrictive* of credential and policy applies." It contains 7 `<li>` elements for `currency`, `maxPerTransaction`, `dailyLimit`, `limitTimezone`, `allowedPayees`, `allowedServiceTypes`, `requiresApprovalAbove`.

- [ ] **Step 2: Replace that `<ul>` with the summary line + member table**

Delete the entire `<ul>…</ul>` block and insert in its place:

```html
        <p class="object-summary">
          A verifiable credential issued by a <a>principal</a> to a
          <a>payer agent</a>, encoding the principal's spending-authority
          constraints as claims on the agent DID.
        </p>

        <table class="simple">
          <caption><code>credentialSubject</code> claims</caption>
          <thead>
            <tr>
              <th scope="col">Member</th>
              <th scope="col">Req.</th>
              <th scope="col">Type</th>
              <th scope="col">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>id</code></td>
              <td><em class="rfc2119">REQUIRED</em></td>
              <td>DID</td>
              <td>The payer agent's DID (the credential subject).</td>
            </tr>
            <tr>
              <td><code>currency</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>string</td>
              <td>ISO 4217 alphabetic currency code or deployment-defined asset code (see <a href="#i18n"></a>).</td>
            </tr>
            <tr>
              <td><code>maxPerTransaction</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>decimal string</td>
              <td>Maximum amount the agent may spend in a single payment.</td>
            </tr>
            <tr>
              <td><code>dailyLimit</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>decimal string</td>
              <td>Aggregate cap per calendar day. Day boundary is determined by <code>limitTimezone</code>.</td>
            </tr>
            <tr>
              <td><code>limitTimezone</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>string</td>
              <td>IANA time-zone name defining the day boundary for <code>dailyLimit</code>; absent means UTC.</td>
            </tr>
            <tr>
              <td><code>allowedPayees</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>list of DIDs</td>
              <td>Payee DIDs the agent is permitted to pay. Values <em class="rfc2119">MUST</em> be DIDs; pattern matching is out of scope.</td>
            </tr>
            <tr>
              <td><code>allowedServiceTypes</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>list of IRIs</td>
              <td>Service-category IRIs (typically <code>cat:</code> concepts) the agent may pay; matching per <a href="#category-matching"></a>.</td>
            </tr>
            <tr>
              <td><code>requiresApprovalAbove</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>decimal string</td>
              <td>Threshold above which the agent <em class="rfc2119">MUST</em> obtain out-of-band human approval. This is an agent-side obligation outside cryptographic enforcement.</td>
            </tr>
          </tbody>
        </table>
```

- [ ] **Step 3: Structural check + commit**

Run the DSA structural check. Table count should increase by 1.

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): convert SpendingAuthorizationCredential to member table"
```

---

## Task 6: PaymentCapabilityCredential — member table

**Files:**
- Modify: `spec/authority/index.html` (section `id="payment-capability-credential"`)

The section has a short prose paragraph with `<code>account</code>`, `<code>currency</code>`, `<code>asset</code>`, `<code>assetScale</code>`, `<code>expires</code>` mentioned inline (no `<ul>`). Replace the member-listing sentence with a summary + table.

- [ ] **Step 1: Locate the section**

Find `<section id="payment-capability-credential">`. It contains a single paragraph beginning "Issued by a wallet provider…" and ending "…and optionally <code>asset</code>, <code>assetScale</code>, and <code>expires</code>."

- [ ] **Step 2: Keep the first sentence (issuer/type); replace the member-listing sentence**

The paragraph currently reads (two sentences):
1. "Issued by a wallet provider or financial institution. The <code>type</code> array MUST include…"
2. "The <code>credentialSubject</code> MUST identify the agent DID and SHOULD include <code>account</code>…"

Keep sentence 1 verbatim. Replace sentence 2 with the summary + table:

```html
        <p class="object-summary">
          A verifiable credential attesting a payer agent's payment capability
          — account address, currency, and optional asset scale — issued by
          the wallet provider or financial institution.
        </p>

        <table class="simple">
          <caption><code>credentialSubject</code> claims</caption>
          <thead>
            <tr>
              <th scope="col">Member</th>
              <th scope="col">Req.</th>
              <th scope="col">Type</th>
              <th scope="col">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>id</code></td>
              <td><em class="rfc2119">REQUIRED</em></td>
              <td>DID</td>
              <td>The payer agent's DID.</td>
            </tr>
            <tr>
              <td><code>account</code></td>
              <td><em class="rfc2119">SHOULD</em></td>
              <td>string</td>
              <td>Payment pointer, account URL, or on-ledger address.</td>
            </tr>
            <tr>
              <td><code>currency</code></td>
              <td><em class="rfc2119">SHOULD</em></td>
              <td>string</td>
              <td>ISO 4217 currency code.</td>
            </tr>
            <tr>
              <td><code>asset</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>string</td>
              <td>Non-ISO asset code (for example a token symbol).</td>
            </tr>
            <tr>
              <td><code>assetScale</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>integer ≥ 0</td>
              <td>Number of decimal places for the asset.</td>
            </tr>
            <tr>
              <td><code>expires</code></td>
              <td><em class="rfc2119">OPTIONAL</em></td>
              <td>RFC 3339</td>
              <td>Capability expiry; relying parties <em class="rfc2119">MUST</em> reject a credential used after this instant.</td>
            </tr>
          </tbody>
        </table>
```

- [ ] **Step 3: Structural check + commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): convert PaymentCapabilityCredential to member table"
```

---

## Task 7: MerchantCredential — member table

**Files:**
- Modify: `spec/authority/index.html` (section `id="merchant-credential"`)

- [ ] **Step 1: Locate the credentialSubject member list**

The section has a paragraph mentioning `<code>merchantName</code> or <code>companyName</code>` and `<code>categories</code>` inline (no `<ul>`). Replace the member-listing clause with the summary + table.

- [ ] **Step 2: Insert summary + table**

After the first paragraph (which describes the credential type and subject id requirement), insert:

```html
        <p class="object-summary">
          A verifiable credential issued by a trust anchor (such as an industry
          registry) attesting a payee service's identity and the service
          categories it provides.
        </p>

        <table class="simple">
          <caption><code>credentialSubject</code> claims</caption>
          <thead>
            <tr>
              <th scope="col">Member</th>
              <th scope="col">Req.</th>
              <th scope="col">Type</th>
              <th scope="col">Description</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>id</code></td>
              <td><em class="rfc2119">REQUIRED</em></td>
              <td>DID</td>
              <td>The payee service's DID.</td>
            </tr>
            <tr>
              <td><code>merchantName</code> / <code>companyName</code></td>
              <td><em class="rfc2119">SHOULD</em></td>
              <td>string</td>
              <td>Human-readable name of the payee service or organisation. May use VC 2.0 language-tagged values.</td>
            </tr>
            <tr>
              <td><code>categories</code></td>
              <td><em class="rfc2119">SHOULD</em></td>
              <td>list of IRIs</td>
              <td>Service-category IRIs from the agreed concept scheme. These are <strong>third-party attested</strong> and used for policy-enforcement matching (see <a href="#category-matching"></a>).</td>
            </tr>
          </tbody>
        </table>
```

Then remove the inline member-listing clause from the existing paragraph (since the table now carries it). The existing paragraph currently ends "…and <em class="rfc2119">SHOULD</em> include <code>merchantName</code> or <code>companyName</code> and <code>categories</code> (service-category IRIs)." — trim that clause.

- [ ] **Step 3: Structural check + commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): convert MerchantCredential to member table"
```

---

## Task 8: DSA rationale asides (4 notes)

**Files:**
- Modify: `spec/authority/index.html`

Four `<aside class="note">` blocks inserted immediately after the normative paragraph they explain. All are informative; no normative wording changes.

- [ ] **Step 1: `@protected` / no-`@vocab` aside (namespace section)**

Find the `<p class="note">` block that begins "The AVP-Micro context is declared with `@protected`: true…". Insert the following `<aside class="note">` **immediately after** that `<p class="note">` closing tag:

```html
      <aside class="note">
        <p>
          <strong>Why this matters for security.</strong>
          Without <code>@protected</code> and without a <code>@vocab</code>
          fallback, any JSON member whose name is not defined in an included
          context is silently dropped during JSON-LD expansion. This is a
          deliberate security property: an attacker who can add extra members
          to a signed object cannot inject semantically meaningful claims by
          choosing a term that happens to expand to a significant IRI.
          Extensions are therefore required to ship their own context — if
          they don't, their terms vanish on expansion.
        </p>
      </aside>
```

- [ ] **Step 2: Verification-method binding aside (securing section)**

Find the paragraph with `id="key-binding"` (the "Verification-method binding." paragraph). Insert the following immediately after its closing `</p>`:

```html
      <aside class="note">
        <p>
          <strong>Why key binding closes the "credential theft" attack.</strong>
          An entity that obtains a <a>Spending Authorization Credential</a> —
          say by intercepting it in transit — cannot use it to authorise
          spending unless it also holds the corresponding private key. The
          <code>proof.verificationMethod</code> check is what ties the
          credential's authority to the specific key. Mere possession of the
          credential is not sufficient.
        </p>
      </aside>
```

- [ ] **Step 3: Category-matching direction aside (category-matching section)**

Find the paragraph in `id="category-matching"` that begins "a wallet that enforces categorical constraints MUST require…". Insert the following immediately after its closing `</p>`:

```html
        <aside class="note">
          <p>
            <strong>Why the match direction matters.</strong>
            The rule is "the asserted category must be the same as, or
            <em>narrower than</em>, an allowed type" — not the reverse. A
            payee self-asserting a <em>broader</em> category
            (e.g. <code>cat:ComputeAndInference</code>) does not satisfy an
            agent restricted to a narrower one
            (e.g. <code>cat:ChatCompletionApi</code>). This prevents a payee
            from claiming a permissive parent category to bypass a specific
            restriction.
          </p>
        </aside>
```

- [ ] **Step 4: Daily-limit timezone aside (daily-limit-claim section)**

Find the paragraph that contains `<code>limitTimezone</code>` and the phrase "absent means UTC". Insert the following immediately after its closing `</p>`:

```html
      <aside class="note">
        <p>
          <strong>Why the timezone is in the credential.</strong>
          "End of day" is ambiguous. Without <code>limitTimezone</code> a
          daily limit resets at UTC midnight, which may not match the
          principal's operational timezone. Encoding the intended timezone
          in the credential itself lets the wallet enforce the correct day
          boundary regardless of where it is deployed.
        </p>
      </aside>
```

- [ ] **Step 5: Structural check + commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): add 4 rationale asides (namespace, key-binding, category-matching, daily-limit)"
```

---

## Task 9: DSA example annotations + verification

**Files:**
- Modify: `spec/authority/index.html` (section `id="examples"`)

Add `title=""` attributes to the `<pre class="example json">` blocks in the examples section. ReSpec renders the title as a figure caption.

- [ ] **Step 1: Annotate the SAC example**

Find `<pre class="example json">` for the SpendingAuthorizationCredential fragment. Change it to:

```html
<pre class="example json" title="SpendingAuthorizationCredential (credentialSubject constraints)">
```

- [ ] **Step 2: Annotate the MerchantCredential example (if present)**

If there is a `<pre class="example json">` for the MerchantCredential, change it to:

```html
<pre class="example json" title="MerchantCredential (third-party-attested payee categories)">
```

- [ ] **Step 3: Final structural check**

Run the DSA structural check. All tags balanced.

- [ ] **Step 4: Final harness check for Phase 1**

```bash
.venv/Scripts/python.exe spec/verify.py | tail -1
.venv/Scripts/python.exe spec/validate.py | tail -1
```

Both must end with `PASS: all checks passed.` and `PASS: all artifact checks passed.`

- [ ] **Step 5: Commit**

```bash
git add spec/authority/index.html
git commit -m "feat(dsa): annotate examples with descriptive titles; Phase 1 complete"
```

---

# PHASE 2: AVP-Micro Payments

---

## Task 10: Payments — CSS block + overview section + tables

**Files:**
- Modify: `spec/payments/index.html`

- [ ] **Step 1: Add the CSS block**

Insert the shared CSS block (identical to Task 1 Step 2) between the `<meta charset>` line and the ReSpec `<script>` in `spec/payments/index.html`.

- [ ] **Step 2: Insert the overview section**

Insert the following immediately after the closing `</section>` of `id="introduction"` (currently line 212):

```html

  <section class="informative" id="overview">
    <h2>How it works</h2>

    <p>
      AVP-Micro Payments defines how a <strong>payer agent</strong> buys a
      service from a <strong>payee service</strong> in a way that is
      cryptographically auditable end-to-end. Identity, the spending-authority
      credential, and trust are defined by [[DSA]]; this specification
      handles the per-transaction messages.
    </p>

    <p>
      For a <strong>one-off payment</strong>: the payee issues a signed
      <a>PaymentQuote</a> bound to the exact service request; the payer
      agent constructs a signed <a>PaymentAuthorization</a> that restates
      the economic terms and embeds a verifiable presentation carrying its
      <a data-cite="spending-authority#dfn-spending-authorization-credential">Spending
      Authorization Credential</a>; the wallet verifies the authorization and
      settles via the chosen rail; the wallet emits a signed
      <a>PaymentExecution</a>; the payee issues a signed
      <a>PaymentReceipt</a> binding delivery to the agreed terms.
      See <a href="#fig-seq-oneoff"></a>.
    </p>

    <p>
      For a <strong>streaming or metered session</strong>: the payee opens a
      <a>UsageSession</a> with a budget cap; the payer agent commits with a
      signed <a>SessionBudgetAuthorization</a>; the payee emits signed
      <a>UsageAccrual</a> reports as usage accrues; the wallet enforces the
      budget cap in real time; at close, the payee issues a session
      <a>PaymentReceipt</a>. The budget cap may be raised mid-session via a
      <a>UsageSessionExtension</a> followed by a fresh
      <a>SessionBudgetAuthorization</a>. See <a href="#fig-seq-streaming"></a>.
    </p>

    <p>
      Every signed object carries a <code>DataIntegrityProof</code>
      (<code>eddsa-jcs-2022</code>), making the full chain — offer, quote,
      authorization, execution, receipt — independently re-verifiable by an
      auditor long after the transaction.
    </p>

    <section id="overview-glance">
      <h3>Roles and objects at a glance</h3>

      <table class="simple" id="tab-pay-roles">
        <caption>Roles in AVP-Micro Payments</caption>
        <thead>
          <tr>
            <th scope="col">Role</th>
            <th scope="col">Produces</th>
            <th scope="col">Verifies / consumes</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><a>Payer agent</a></td>
            <td><a>PaymentAuthorization</a>, <a>SessionBudgetAuthorization</a></td>
            <td><a>PaymentQuote</a>, <a>UsageSession</a>, <a>UsageAccrual</a>, <a>PaymentReceipt</a></td>
          </tr>
          <tr>
            <td><a>Payee service</a></td>
            <td><a>PaymentOffer</a>, <a>PaymentQuote</a>, <a>UsageSession</a>, <a>UsageAccrual</a>, <a>UsageSessionExtension</a>, <a>PaymentReceipt</a></td>
            <td><a>PaymentAuthorization</a>, <a>SessionBudgetAuthorization</a></td>
          </tr>
          <tr>
            <td><a>Wallet service</a></td>
            <td><a>PaymentExecution</a></td>
            <td><a>PaymentAuthorization</a>, <a>SessionBudgetAuthorization</a>, <a>UsageAccrual</a>; initiates rail settlement</td>
          </tr>
          <tr>
            <td>Settlement rail</td>
            <td>Settlement reference</td>
            <td>Settlement instruction from the wallet</td>
          </tr>
        </tbody>
      </table>

      <table class="simple" id="tab-pay-objects">
        <caption>Objects defined by this specification</caption>
        <thead>
          <tr>
            <th scope="col">Object</th>
            <th scope="col">One-line purpose</th>
            <th scope="col">Signer</th>
            <th scope="col">Section</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><a>PaymentOffer</a></td>
            <td>Payee advertisement of pricing and a quote endpoint</td>
            <td>Payee (optional)</td>
            <td><a href="#payment-offer"></a></td>
          </tr>
          <tr>
            <td><a>PaymentQuote</a></td>
            <td>Time-bound, payee-signed price bound to a specific request</td>
            <td>Payee</td>
            <td><a href="#payment-quote"></a></td>
          </tr>
          <tr>
            <td><a>PaymentAuthorization</a></td>
            <td>Payer commitment to pay, restating the economic terms and embedding a credential VP</td>
            <td>Payer agent</td>
            <td><a href="#payment-authorization"></a></td>
          </tr>
          <tr>
            <td><a>PaymentExecution</a></td>
            <td>Wallet record of a settlement attempt with status and rail reference</td>
            <td>Wallet service</td>
            <td><a href="#payment-execution"></a></td>
          </tr>
          <tr>
            <td><a>PaymentReceipt</a></td>
            <td>Payee acknowledgement binding delivery to the agreed terms</td>
            <td>Payee</td>
            <td><a href="#payment-receipt"></a></td>
          </tr>
          <tr>
            <td><a>UsageSession</a></td>
            <td>Metering contract with budget cap and pricing model for a streaming period</td>
            <td>Payee</td>
            <td><a href="#usage-session"></a></td>
          </tr>
          <tr>
            <td><a>UsageAccrual</a></td>
            <td>Incremental or cumulative meter report during an active session</td>
            <td>Payee</td>
            <td><a href="#usage-accrual"></a></td>
          </tr>
          <tr>
            <td><a>SessionBudgetAuthorization</a></td>
            <td>Payer commitment to honour session charges up to a budget cap</td>
            <td>Payer agent</td>
            <td><a href="#session-budget-authorization"></a></td>
          </tr>
          <tr>
            <td><a>UsageSessionExtension</a></td>
            <td>Payee amendment raising an existing session's budget cap or expiry</td>
            <td>Payee</td>
            <td><a href="#session-extension"></a></td>
          </tr>
        </tbody>
      </table>
    </section>
  </section>

```

- [ ] **Step 3: Structural check**

Run the structural check for Payments (same script, replace `authority` with `payments`). All tags balanced.

- [ ] **Step 4: Commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): add CSS block and informative overview section with tables"
```

---

## Task 11: Payments figure — architecture/roles diagram (`fig-arch`)

**Files:**
- Modify: `spec/payments/index.html`

Insert after the `</section>` closing `id="overview-glance"`, still inside `id="overview"`.

- [ ] **Step 1: Insert the figure**

```html
    <figure id="fig-arch">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 380"
           role="img" aria-labelledby="pay-fig-arch-title pay-fig-arch-desc">
        <title id="pay-fig-arch-title">AVP-Micro Payments — roles and message flows</title>
        <desc id="pay-fig-arch-desc">
          Five roles: Payer Agent (left centre), Payee Service (right centre),
          Wallet Service (bottom left), Settlement Rail (bottom right), and
          Principal (top left, issuing the spending credential). Arrows
          show the main message flows: the Payer Agent exchanges
          PaymentQuote / PaymentAuthorization / PaymentReceipt with the Payee;
          submits PaymentAuthorization to the Wallet; the Wallet instructs
          the Settlement Rail and receives a reference; the Wallet returns
          PaymentExecution to the Payer Agent; for streaming, UsageSession /
          UsageAccrual flows between Payee and Payer Agent.
        </desc>
        <defs>
          <marker id="p-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#333"/>
          </marker>
          <marker id="p-arr-b" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#005a9c"/>
          </marker>
          <marker id="p-arr-g" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#888"/>
          </marker>
        </defs>

        <!-- Principal (top-left, small) -->
        <rect x="10" y="10" width="100" height="44" rx="4"
              fill="#f5f5f5" stroke="#aaa" stroke-width="1"/>
        <text x="60" y="30" text-anchor="middle"
              font-family="sans-serif" font-size="11" fill="#555">Principal</text>
        <text x="60" y="45" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#888">(issues credential)</text>

        <!-- Payer Agent (left, main) -->
        <rect x="60" y="150" width="140" height="64" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="130" y="180" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Payer Agent</text>
        <text x="130" y="197" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">holds spending credential</text>

        <!-- SAC arrow from Principal to Payer Agent -->
        <line x1="80" y1="54" x2="110" y2="148"
              stroke="#005a9c" stroke-width="1" stroke-dasharray="4,3"
              marker-end="url(#p-arr-b)"/>
        <text x="60" y="105" font-family="sans-serif" font-size="9"
              fill="#005a9c">SpendingAuth-</text>
        <text x="60" y="117" font-family="sans-serif" font-size="9"
              fill="#005a9c">orizationCred.</text>

        <!-- Payee Service (right, main) -->
        <rect x="440" y="150" width="140" height="64" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="510" y="180" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Payee Service</text>
        <text x="510" y="197" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">issues quote, receipt</text>

        <!-- Payer ↔ Payee messages -->
        <line x1="200" y1="168" x2="438" y2="168"
              stroke="#005a9c" stroke-width="1.5" marker-end="url(#p-arr-b)"/>
        <text x="320" y="162" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#005a9c">PaymentAuthorization + VP</text>
        <line x1="438" y1="185" x2="200" y2="185"
              stroke="#333" stroke-width="1.5" marker-end="url(#p-arr)"/>
        <text x="320" y="198" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#333">PaymentQuote / PaymentReceipt</text>

        <!-- Streaming messages (below main arrows) -->
        <line x1="438" y1="205" x2="200" y2="205"
              stroke="#888" stroke-width="1" stroke-dasharray="4,3"
              marker-end="url(#p-arr-g)"/>
        <text x="320" y="218" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#888">UsageSession / UsageAccrual (streaming)</text>

        <!-- Wallet Service (bottom-left) -->
        <rect x="60" y="300" width="140" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="130" y="325" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Wallet Service</text>
        <text x="130" y="342" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">verifies + settles</text>

        <!-- Settlement Rail (bottom-right) -->
        <rect x="440" y="300" width="140" height="54" rx="5"
              fill="#f5f5f5" stroke="#333" stroke-width="1.5"/>
        <text x="510" y="325" text-anchor="middle"
              font-family="sans-serif" font-size="13" fill="#333">Settlement Rail</text>
        <text x="510" y="342" text-anchor="middle"
              font-family="sans-serif" font-size="10" fill="#666">moves value</text>

        <!-- Payer Agent → Wallet -->
        <line x1="130" y1="214" x2="130" y2="298"
              stroke="#333" stroke-width="1.5" marker-end="url(#p-arr)"/>
        <text x="78" y="258" font-family="sans-serif" font-size="9"
              fill="#333">PaymentAuth-</text>
        <text x="78" y="270" font-family="sans-serif" font-size="9"
              fill="#333">orization</text>

        <!-- Wallet → Payer Agent (execution) -->
        <line x1="148" y1="298" x2="148" y2="214"
              stroke="#333" stroke-width="1.5" marker-end="url(#p-arr)"/>
        <text x="155" y="258" font-family="sans-serif" font-size="9"
              fill="#333">Payment-</text>
        <text x="155" y="270" font-family="sans-serif" font-size="9"
              fill="#333">Execution</text>

        <!-- Wallet → Rail -->
        <line x1="200" y1="327" x2="438" y2="327"
              stroke="#333" stroke-width="1.5" marker-end="url(#p-arr)"/>
        <text x="320" y="320" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#333">initiate settlement</text>

        <!-- Rail → Wallet (ref) -->
        <line x1="438" y1="342" x2="200" y2="342"
              stroke="#333" stroke-width="1.5" marker-end="url(#p-arr)"/>
        <text x="320" y="358" text-anchor="middle"
              font-family="sans-serif" font-size="9" fill="#333">settlement reference</text>
      </svg>
      <figcaption>Figure: AVP-Micro Payments roles and message flows.
        Solid arrows: one-off payment messages.
        Dashed: streaming messages and the credential issuance path.
      </figcaption>
    </figure>
```

- [ ] **Step 2: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): add architecture/roles SVG figure (fig-arch)"
```

---

## Task 12: Payments figure — one-off sequence diagram (`fig-seq-oneoff`)

**Files:**
- Modify: `spec/payments/index.html`

Insert after `fig-arch`'s closing `</figure>`, still inside `id="overview"`.

- [ ] **Step 1: Insert the figure**

```html
    <figure id="fig-seq-oneoff">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 420"
           role="img" aria-labelledby="seq1-title seq1-desc">
        <title id="seq1-title">One-off payment sequence</title>
        <desc id="seq1-desc">
          Four participants: Payer Agent, Payee Service, Wallet Service,
          Settlement Rail. Steps: 1. Payer Agent sends service request with
          serviceRequestHash to Payee. 2. Payee returns signed PaymentQuote.
          3. Payer Agent sends PaymentAuthorization plus verifiable presentation
          to Wallet. 4. Wallet verifies and sends settlement instruction to Rail.
          5. Rail returns settlement reference to Wallet. 6. Wallet sends signed
          PaymentExecution to Payer Agent. 7. Payer Agent notifies Payee.
          8. Payee returns signed PaymentReceipt to Payer Agent.
        </desc>
        <defs>
          <marker id="s1-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#333"/>
          </marker>
          <marker id="s1-arr-b" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#005a9c"/>
          </marker>
        </defs>

        <!-- Lifeline positions: x = 80, 260, 450, 590 -->
        <!-- Lifeline boxes -->
        <rect x="20"  y="10" width="120" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="80"  y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Payer Agent</text>
        <rect x="200" y="10" width="120" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="260" y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Payee Service</text>
        <rect x="390" y="10" width="120" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="450" y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Wallet Service</text>
        <rect x="530" y="10" width="100" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="580" y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Rail</text>

        <!-- Lifeline dashes -->
        <line x1="80"  y1="50" x2="80"  y2="420" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <line x1="260" y1="50" x2="260" y2="420" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <line x1="450" y1="50" x2="450" y2="420" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <line x1="580" y1="50" x2="580" y2="420" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>

        <!-- Step labels (left margin) -->
        <text x="6" y="93"  font-family="sans-serif" font-size="9" fill="#888">1</text>
        <text x="6" y="133" font-family="sans-serif" font-size="9" fill="#888">2</text>
        <text x="6" y="173" font-family="sans-serif" font-size="9" fill="#888">3</text>
        <text x="6" y="223" font-family="sans-serif" font-size="9" fill="#888">4</text>
        <text x="6" y="263" font-family="sans-serif" font-size="9" fill="#888">5</text>
        <text x="6" y="303" font-family="sans-serif" font-size="9" fill="#888">6</text>
        <text x="6" y="343" font-family="sans-serif" font-size="9" fill="#888">7</text>
        <text x="6" y="383" font-family="sans-serif" font-size="9" fill="#888">8</text>

        <!-- 1. Agent → Payee: service request + serviceRequestHash -->
        <line x1="82" y1="90" x2="258" y2="90" stroke="#333" stroke-width="1.5" marker-end="url(#s1-arr)"/>
        <text x="170" y="83" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">service request + serviceRequestHash</text>

        <!-- 2. Payee → Agent: PaymentQuote (signed) -->
        <line x1="258" y1="130" x2="82" y2="130" stroke="#005a9c" stroke-width="1.5" marker-end="url(#s1-arr-b)"/>
        <text x="170" y="123" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#005a9c">PaymentQuote ✓ (payee-signed)</text>

        <!-- 3. Agent → Wallet: PaymentAuthorization + VP -->
        <line x1="82" y1="170" x2="448" y2="170" stroke="#333" stroke-width="1.5" marker-end="url(#s1-arr)"/>
        <text x="265" y="163" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">PaymentAuthorization + VP (payer-signed)</text>

        <!-- 4. Wallet → Rail: settle -->
        <line x1="452" y1="220" x2="578" y2="220" stroke="#333" stroke-width="1.5" marker-end="url(#s1-arr)"/>
        <text x="516" y="213" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">settle</text>

        <!-- 5. Rail → Wallet: ref -->
        <line x1="578" y1="260" x2="452" y2="260" stroke="#333" stroke-width="1.5" marker-end="url(#s1-arr)"/>
        <text x="516" y="253" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">settlement ref</text>

        <!-- 6. Wallet → Agent: PaymentExecution -->
        <line x1="448" y1="300" x2="82" y2="300" stroke="#005a9c" stroke-width="1.5" marker-end="url(#s1-arr-b)"/>
        <text x="265" y="293" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#005a9c">PaymentExecution ✓ (wallet-signed)</text>

        <!-- 7. Agent → Payee: payment confirmed -->
        <line x1="82" y1="340" x2="258" y2="340" stroke="#333" stroke-width="1.5" marker-end="url(#s1-arr)"/>
        <text x="170" y="333" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">payment confirmed</text>

        <!-- 8. Payee → Agent: PaymentReceipt -->
        <line x1="258" y1="380" x2="82" y2="380" stroke="#005a9c" stroke-width="1.5" marker-end="url(#s1-arr-b)"/>
        <text x="170" y="373" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#005a9c">PaymentReceipt ✓ (payee-signed)</text>
      </svg>
      <figcaption>Figure: One-off payment sequence. ✓ = signed commitment.
        The wallet verifies the <a>PaymentAuthorization</a> (including
        the embedded credential and <code>quoteDigest</code>) before
        initiating settlement.</figcaption>
    </figure>
```

- [ ] **Step 2: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): add one-off payment sequence diagram (fig-seq-oneoff)"
```

---

## Task 13: Payments figure — streaming sequence diagram (`fig-seq-streaming`)

**Files:**
- Modify: `spec/payments/index.html`

Insert after `fig-seq-oneoff`'s `</figure>`, still inside `id="overview"`.

- [ ] **Step 1: Insert the figure**

```html
    <figure id="fig-seq-streaming">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 460"
           role="img" aria-labelledby="seq2-title seq2-desc">
        <title id="seq2-title">Streaming / session-metering sequence</title>
        <desc id="seq2-desc">
          Three participants: Payer Agent, Payee Service, Wallet Service.
          Steps: 1. Payer Agent opens a session with Payee. 2. Payee returns
          signed UsageSession. 3. Payer Agent sends SessionBudgetAuthorization
          plus VP to Wallet. 4. Wallet confirms budget committed. 5 (loop).
          Payee sends signed UsageAccrual updates to Payer Agent; Wallet
          enforces maxAmount. 6. Either party closes the session. 7. Wallet
          settles net amount with Rail. 8. Payee sends signed PaymentReceipt
          with usageSession to Payer Agent.
        </desc>
        <defs>
          <marker id="s2-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#333"/>
          </marker>
          <marker id="s2-arr-b" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
            <polygon points="0 0,8 3,0 6" fill="#005a9c"/>
          </marker>
        </defs>

        <!-- Lifelines: x = 100, 320, 540 -->
        <rect x="30"  y="10" width="140" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="100" y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Payer Agent</text>
        <rect x="250" y="10" width="140" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="320" y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Payee Service</text>
        <rect x="470" y="10" width="140" height="40" rx="4" fill="#f0f0f0" stroke="#333" stroke-width="1.5"/>
        <text x="540" y="35" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#333">Wallet Service</text>

        <line x1="100" y1="50" x2="100" y2="460" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <line x1="320" y1="50" x2="320" y2="460" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <line x1="540" y1="50" x2="540" y2="460" stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>

        <!-- Step labels -->
        <text x="6" y="93"  font-family="sans-serif" font-size="9" fill="#888">1</text>
        <text x="6" y="133" font-family="sans-serif" font-size="9" fill="#888">2</text>
        <text x="6" y="173" font-family="sans-serif" font-size="9" fill="#888">3</text>
        <text x="6" y="213" font-family="sans-serif" font-size="9" fill="#888">4</text>
        <text x="6" y="253" font-family="sans-serif" font-size="9" fill="#888">5</text>
        <text x="6" y="313" font-family="sans-serif" font-size="9" fill="#888">6</text>
        <text x="6" y="363" font-family="sans-serif" font-size="9" fill="#888">7</text>
        <text x="6" y="420" font-family="sans-serif" font-size="9" fill="#888">8</text>

        <!-- 1. Agent → Payee: open session -->
        <line x1="102" y1="90" x2="318" y2="90" stroke="#333" stroke-width="1.5" marker-end="url(#s2-arr)"/>
        <text x="210" y="83" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">open session request</text>

        <!-- 2. Payee → Agent: UsageSession -->
        <line x1="318" y1="130" x2="102" y2="130" stroke="#005a9c" stroke-width="1.5" marker-end="url(#s2-arr-b)"/>
        <text x="210" y="123" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#005a9c">UsageSession ✓ (budget cap, pricing model)</text>

        <!-- 3. Agent → Wallet: SessionBudgetAuthorization + VP -->
        <line x1="102" y1="170" x2="538" y2="170" stroke="#333" stroke-width="1.5" marker-end="url(#s2-arr)"/>
        <text x="320" y="163" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">SessionBudgetAuthorization + VP (payer-signed)</text>

        <!-- 4. Wallet → Agent: budget committed -->
        <line x1="538" y1="210" x2="102" y2="210" stroke="#333" stroke-width="1.5" marker-end="url(#s2-arr)"/>
        <text x="320" y="203" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">budget committed</text>

        <!-- Loop box for accruals -->
        <rect x="88" y="228" width="244" height="70" rx="3"
              fill="none" stroke="#888" stroke-width="1" stroke-dasharray="5,3"/>
        <text x="95" y="242" font-family="sans-serif" font-size="9" fill="#888">loop [usage accrues]</text>

        <!-- 5. Payee → Agent: UsageAccrual -->
        <line x1="318" y1="258" x2="102" y2="258" stroke="#005a9c" stroke-width="1.5" marker-end="url(#s2-arr-b)"/>
        <text x="210" y="251" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#005a9c">UsageAccrual ✓ (meter + amount)</text>
        <text x="210" y="288" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#888">Wallet enforces maxAmount</text>

        <!-- 6. Close signal -->
        <line x1="102" y1="310" x2="318" y2="310" stroke="#333" stroke-width="1.5" marker-end="url(#s2-arr)"/>
        <text x="210" y="303" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#333">close session</text>

        <!-- 7. Wallet → Rail (settle net) -->
        <line x1="540" y1="360" x2="102" y2="360"
              stroke="#aaa" stroke-width="1" stroke-dasharray="4,3"/>
        <text x="340" y="350" text-anchor="middle" font-family="sans-serif" font-size="9" fill="#888">(Wallet settles net amount with Rail — off diagram)</text>

        <!-- 8. Payee → Agent: PaymentReceipt (session) -->
        <line x1="318" y1="415" x2="102" y2="415" stroke="#005a9c" stroke-width="1.5" marker-end="url(#s2-arr-b)"/>
        <text x="210" y="408" text-anchor="middle" font-family="sans-serif" font-size="10" fill="#005a9c">PaymentReceipt ✓ (usageSession)</text>
      </svg>
      <figcaption>Figure: Streaming / session-metering sequence. ✓ = signed commitment.
        Step 5 (UsageAccrual) repeats as usage accrues; the Wallet enforces
        <code>maxAmount</code> on each accrual. The session budget may be raised
        via a <a>UsageSessionExtension</a> + fresh
        <a>SessionBudgetAuthorization</a> (not shown).</figcaption>
    </figure>
```

- [ ] **Step 2: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): add streaming sequence diagram (fig-seq-streaming)"
```

---

## Task 14: PaymentOffer and PaymentQuote — member tables

**Files:**
- Modify: `spec/payments/index.html`

**PaymentOffer** — currently a `<ul>` of 7 bullets. **PaymentQuote** — currently a `<ul>` of 6 bullets.

- [ ] **Step 1: Replace the PaymentOffer `<ul>` with summary + table**

In section `id="payment-offer"`, after the prose paragraph about the offer being an advertisement, replace the `<ul>` with:

```html
        <p class="object-summary">
          A payee's advertisement of commercial terms — pricing model and a
          quote endpoint — optionally signed for integrity; a commitment is
          established only by the signed <a>PaymentQuote</a>.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>payee</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DID</td><td>Payee service's DID.</td></tr>
            <tr><td><code>pricingModel</code></td><td><em class="rfc2119">REQUIRED</em></td><td>object</td><td>Pricing structure for the offered service (see the RECOMMENDED per-unit form in <a href="#usage-session"></a>).</td></tr>
            <tr><td><code>quoteEndpoint</code></td><td><em class="rfc2119">REQUIRED</em></td><td>HTTPS URL</td><td>Endpoint where a payer agent requests a <a>PaymentQuote</a>.</td></tr>
            <tr><td><code>acceptedSettlementMethods</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>list of strings</td><td>Rail identifiers the payee accepts.</td></tr>
            <tr><td><code>acceptedCredentialIssuers</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>list of DIDs</td><td>Issuer DIDs the payee advertises as acceptable. This is a payee assertion only; wallets <em class="rfc2119">MUST NOT</em> treat it as a trust root.</td></tr>
            <tr><td><code>categories</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>list of IRIs</td><td>Self-asserted service-category IRIs. May be used for discovery or UX only; policy-enforcement matching <em class="rfc2119">MUST</em> use attested <a>Merchant Credential</a> categories.</td></tr>
            <tr><td><code>offerValidity</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>RFC 3339</td><td>Offer expiry.</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 2: Replace the PaymentQuote `<ul>` with summary + table**

In section `id="payment-quote"`, after the signing requirement sentence, replace the `<ul>` with:

```html
        <p class="object-summary">
          A time-bound, payee-signed price commitment for one specific service
          request, identified by <code>serviceRequestHash</code> and binding
          the exact economic terms.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>payer</code>, <code>payee</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DIDs</td><td>Parties to the quote.</td></tr>
            <tr><td><code>serviceRequestHash</code></td><td><em class="rfc2119">REQUIRED</em></td><td>content digest</td><td>Binds the quote to the exact service request (see <a href="#request-binding"></a>).</td></tr>
            <tr><td><code>amount</code>, <code>currency</code></td><td><em class="rfc2119">REQUIRED</em></td><td>decimal · string</td><td>The price. Decimal string per [[DSA]] amount format; strictly positive.</td></tr>
            <tr><td><code>settlementMethod</code>, <code>settlementTarget</code></td><td><em class="rfc2119">REQUIRED</em></td><td>strings</td><td>Together with <code>amount</code> and <code>currency</code> these form the <a>economic terms</a>.</td></tr>
            <tr><td><code>expires</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Quote expiry. Deployments <em class="rfc2119">SHOULD</em> keep this ≤ 300 s.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payee signature (<code>eddsa-jcs-2022</code>). Verifiers <em class="rfc2119">MUST</em> reject an unsigned quote.</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 3: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): convert PaymentOffer and PaymentQuote to member tables"
```

---

## Task 15: PaymentAuthorization — member table

**Files:**
- Modify: `spec/payments/index.html` (section `id="payment-authorization"`)

- [ ] **Step 1: Replace the `<ul>` with summary + table**

```html
        <p class="object-summary">
          A payer-signed commitment to pay the quoted price, restating all
          economic terms, committing to the exact quote via
          <code>quoteDigest</code>, and carrying a verifiable presentation
          with the spending-authority credential.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>quote</code></td><td><em class="rfc2119">REQUIRED</em></td><td>IRI</td><td>IRI of the accepted <a>PaymentQuote</a>.</td></tr>
            <tr><td><code>quoteDigest</code></td><td><em class="rfc2119">REQUIRED</em></td><td>content digest</td><td>Content digest of the referenced quote (proof removed). The payer's signature thereby commits to the exact quote bytes it observed, not just the IRI.</td></tr>
            <tr><td><code>payer</code>, <code>payee</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DIDs</td><td><code>payer</code> <em class="rfc2119">MUST</em> equal the quote's <code>payer</code>; <code>payee</code> <em class="rfc2119">MUST</em> equal the quote's <code>payee</code>.</td></tr>
            <tr><td><code>amount</code>, <code>currency</code>, <code>settlementMethod</code>, <code>settlementTarget</code></td><td><em class="rfc2119">REQUIRED</em></td><td>(as quote)</td><td>The <a>economic terms</a>. Each <em class="rfc2119">MUST</em> be byte-identical to the corresponding value in the referenced quote.</td></tr>
            <tr><td><code>serviceRequestHash</code></td><td><em class="rfc2119">REQUIRED</em></td><td>content digest</td><td><em class="rfc2119">MUST</em> be byte-identical to the quote's <code>serviceRequestHash</code>.</td></tr>
            <tr><td><code>timestamp</code>, <code>expires</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Validity window. Deployments <em class="rfc2119">SHOULD</em> keep the window ≤ 60 s.</td></tr>
            <tr><td><code>nonce</code></td><td><em class="rfc2119">REQUIRED</em></td><td>string</td><td>Unique within the verifier's retention window (scoped to the payer–verifier pair) for replay protection.</td></tr>
            <tr><td><code>wallet</code></td><td><em class="rfc2119">OPTIONAL</em> (<em class="rfc2119">RECOMMENDED</em>)</td><td>DID</td><td>Wallet service authorised to settle and sign the <a>PaymentExecution</a>. Required in the <a>auditable profile</a>.</td></tr>
            <tr><td><code>vp</code></td><td><em class="rfc2119">REQUIRED</em></td><td>VP</td><td>A verifiable presentation containing at least one <a data-cite="spending-authority#dfn-spending-authorization-credential">Spending Authorization Credential</a>.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payer signature bound to the <code>payer</code> DID (see <a href="#key-binding"></a>).</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 2: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): convert PaymentAuthorization to member table"
```

---

## Task 16: PaymentExecution and PaymentReceipt — member tables

**Files:**
- Modify: `spec/payments/index.html`

- [ ] **Step 1: Replace the PaymentExecution `<ul>` with summary + table**

```html
        <p class="object-summary">
          A wallet-signed record of a settlement attempt, linking status,
          amount settled, and a rail reference to the authorisation that
          triggered it.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>authorization</code> <em>or</em> <code>sessionBudgetAuthorization</code></td><td><em class="rfc2119">REQUIRED</em> (exactly one)</td><td>IRI</td><td>IRI of the triggering <a>PaymentAuthorization</a> (one-off) or <a>SessionBudgetAuthorization</a> (streaming). Exactly one <em class="rfc2119">MUST</em> be present.</td></tr>
            <tr><td><code>amount</code>, <code>currency</code></td><td><em class="rfc2119">REQUIRED</em></td><td>decimal · string</td><td>Amount executed. <em class="rfc2119">MUST</em> equal the authorised amount unless <code>status</code> is <code>partial</code>, in which case it <em class="rfc2119">MUST</em> be less.</td></tr>
            <tr><td><code>status</code></td><td><em class="rfc2119">REQUIRED</em></td><td>enum</td><td><code>pending</code> | <code>completed</code> | <code>partial</code> | <code>failed</code>. Rail lifecycle states (settled, reversed, etc.) are out of scope and conveyed by the rail or an extension.</td></tr>
            <tr><td><code>settlementRef</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>string</td><td>Rail-specific settlement reference.</td></tr>
            <tr><td><code>timestamp</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Time of execution attempt.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Wallet service signature (see <a href="#execution-binding"></a>).</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 2: Replace the PaymentReceipt `<ul>` with summary + table**

```html
        <p class="object-summary">
          A payee-signed acknowledgement that delivery was fulfilled at the
          agreed commercial terms, binding the outcome to the originating
          quote (one-off) or session (streaming).
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>quote</code> <em>or</em> <code>usageSession</code></td><td><em class="rfc2119">REQUIRED</em> (at least one)</td><td>IRI</td><td>One-off receipt includes <code>quote</code>; session receipt includes <code>usageSession</code>. Both <em class="rfc2119">MAY</em> be present.</td></tr>
            <tr><td><code>payee</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DID</td><td>The signing payee service.</td></tr>
            <tr><td><code>payer</code></td><td><em class="rfc2119">SHOULD</em></td><td>DID</td><td></td></tr>
            <tr><td><code>amount</code>, <code>currency</code></td><td><em class="rfc2119">SHOULD</em></td><td>decimal · string</td><td>Amount actually fulfilled.</td></tr>
            <tr><td><code>fulfilledAt</code></td><td><em class="rfc2119">SHOULD</em></td><td>RFC 3339</td><td>Time of delivery.</td></tr>
            <tr><td><code>execution</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>IRI</td><td>IRI of the <a>PaymentExecution</a>.</td></tr>
            <tr><td><code>serviceOutputHash</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>content digest</td><td>Content digest of the delivered output.</td></tr>
            <tr><td><code>totalMeterReading</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>string</td><td>Final meter value for a closed session.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payee signature.</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 3: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): convert PaymentExecution and PaymentReceipt to member tables"
```

---

## Task 17: UsageSession and UsageAccrual — member tables

**Files:**
- Modify: `spec/payments/index.html`

- [ ] **Step 1: Replace the UsageSession `<ul>` with summary + table**

```html
        <p class="object-summary">
          A payee-signed metering contract that establishes the budget cap,
          pricing model, and settlement parameters for a streaming usage
          period.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>payer</code>, <code>payee</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DIDs</td><td>Parties to the session.</td></tr>
            <tr><td><code>currency</code></td><td><em class="rfc2119">REQUIRED</em></td><td>string</td><td>Currency for all charges in this session.</td></tr>
            <tr><td><code>pricingModel</code></td><td><em class="rfc2119">REQUIRED</em></td><td>object</td><td>Pricing basis. RECOMMENDED form: <code>{"type":"PerUnit","amount":"0.001","unit":"token"}</code>. Enables the wallet to verify accrual consistency.</td></tr>
            <tr><td><code>maxAmount</code></td><td><em class="rfc2119">REQUIRED</em></td><td>decimal string</td><td>Upper bound on total charges for this session.</td></tr>
            <tr><td><code>meterType</code></td><td><em class="rfc2119">RECOMMENDED</em></td><td>string</td><td>What is metered (e.g. <code>llmTokens</code>, <code>cpuSeconds</code>, <code>bytes</code>).</td></tr>
            <tr><td><code>meterUnit</code></td><td><em class="rfc2119">RECOMMENDED</em></td><td>string</td><td>Unit a <code>meterReading</code> counts (e.g. <code>token</code>, <code>second</code>).</td></tr>
            <tr><td><code>settlementMethod</code>, <code>settlementTarget</code></td><td><em class="rfc2119">REQUIRED</em></td><td>strings</td><td>Settlement rail and destination for this session.</td></tr>
            <tr><td><code>timestamp</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Session start time.</td></tr>
            <tr><td><code>expires</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Session expiry. Accruals after this instant are not admitted unless the session is extended (see <a href="#session-extension"></a>).</td></tr>
            <tr><td><code>settlementMode</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>enum</td><td><code>incremental</code> (settle each accrual/batch) or <code>deferred</code> (settle at close); default <code>deferred</code>.</td></tr>
            <tr><td><code>startingBalance</code></td><td><em class="rfc2119">OPTIONAL</em></td><td>decimal string</td><td>Prepayment counted toward the session total; <em class="rfc2119">MUST</em> be ≤ <code>maxAmount</code>. Any unused remainder <em class="rfc2119">SHOULD</em> be released at close.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payee signature.</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 2: Replace the UsageAccrual `<ul>` with summary + table**

```html
        <p class="object-summary">
          A payee-signed incremental or cumulative meter report emitted
          during an active <a>UsageSession</a>, recording charges and a
          meter reading for wallet budget enforcement.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>session</code></td><td><em class="rfc2119">REQUIRED</em></td><td>IRI</td><td>IRI of the <a>UsageSession</a> this accrual belongs to.</td></tr>
            <tr><td><code>accrualKind</code></td><td><em class="rfc2119">REQUIRED</em></td><td>enum</td><td><code>cumulative</code> — <code>amountAccrued</code> is the running session total; <code>incremental</code> — <code>amountAccrued</code> is the delta since the previous accrual.</td></tr>
            <tr><td><code>amountAccrued</code></td><td><em class="rfc2119">REQUIRED</em></td><td>decimal string</td><td>The cumulative or incremental charge amount.</td></tr>
            <tr><td><code>currency</code></td><td><em class="rfc2119">REQUIRED</em></td><td>string</td><td><em class="rfc2119">MUST</em> match the session <code>currency</code>.</td></tr>
            <tr><td><code>meterReading</code></td><td><em class="rfc2119">RECOMMENDED</em></td><td>string</td><td>Meter value in the session's <code>meterUnit</code> (tokens, seconds, bytes, etc.).</td></tr>
            <tr><td><code>sequence</code></td><td><em class="rfc2119">REQUIRED</em> for incremental; <em class="rfc2119">RECOMMENDED</em> otherwise</td><td>integer ≥ 0</td><td>Monotonically increasing ordering value. Wallets <em class="rfc2119">MUST</em> reject out-of-order or duplicate values.</td></tr>
            <tr><td><code>timestamp</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Time of accrual report.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payee signature.</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 3: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): convert UsageSession and UsageAccrual to member tables"
```

---

## Task 18: SessionBudgetAuthorization and UsageSessionExtension — member tables

**Files:**
- Modify: `spec/payments/index.html`

- [ ] **Step 1: Replace the SessionBudgetAuthorization `<ul>` with summary + table**

```html
        <p class="object-summary">
          A payer-signed commitment to honour session charges up to a budget
          cap — the streaming analogue of <a>PaymentAuthorization</a> for a
          single quote.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>usageSession</code></td><td><em class="rfc2119">REQUIRED</em></td><td>IRI</td><td>IRI of the <a>UsageSession</a> being authorised.</td></tr>
            <tr><td><code>sessionDigest</code></td><td><em class="rfc2119">REQUIRED</em></td><td>content digest</td><td>Content digest of the session (proof removed). Commits the payer to the exact session terms it observed.</td></tr>
            <tr><td><code>payer</code>, <code>payee</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DIDs</td><td><em class="rfc2119">MUST</em> match the session's <code>payer</code> and <code>payee</code>.</td></tr>
            <tr><td><code>committedAmount</code></td><td><em class="rfc2119">REQUIRED</em></td><td>decimal string</td><td>Amount the wallet commits; <em class="rfc2119">MUST</em> be ≤ session <code>maxAmount</code>.</td></tr>
            <tr><td><code>currency</code></td><td><em class="rfc2119">REQUIRED</em></td><td>string</td><td><em class="rfc2119">MUST</em> match the session currency.</td></tr>
            <tr><td><code>timestamp</code>, <code>expires</code>, <code>nonce</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339 · string</td><td>Replay protection (see <a href="#integrity"></a>).</td></tr>
            <tr><td><code>wallet</code></td><td><em class="rfc2119">OPTIONAL</em> (<em class="rfc2119">RECOMMENDED</em>)</td><td>DID</td><td>Wallet service authorised to settle session charges. Required in the <a>auditable profile</a>.</td></tr>
            <tr><td><code>vp</code></td><td><em class="rfc2119">REQUIRED</em></td><td>VP</td><td>Verifiable presentation with at least one <a data-cite="spending-authority#dfn-spending-authorization-credential">Spending Authorization Credential</a>.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payer signature bound to the <code>payer</code> DID (see <a href="#key-binding"></a>).</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 2: Replace the UsageSessionExtension `<ul>` with summary + table**

```html
        <p class="object-summary">
          A payee-signed amendment to an existing <a>UsageSession</a> that
          raises the budget cap (<code>newMaxAmount</code>) and/or extends
          the expiry (<code>newExpires</code>). At least one of the two
          <em class="rfc2119">MUST</em> be present.
        </p>

        <table class="simple">
          <thead>
            <tr><th scope="col">Member</th><th scope="col">Req.</th><th scope="col">Type</th><th scope="col">Description</th></tr>
          </thead>
          <tbody>
            <tr><td><code>usageSession</code></td><td><em class="rfc2119">REQUIRED</em></td><td>IRI</td><td>IRI of the session being extended.</td></tr>
            <tr><td><code>sessionDigest</code></td><td><em class="rfc2119">REQUIRED</em></td><td>content digest</td><td>Digest of the original session (proof removed), binding the extension to the exact session state it amends.</td></tr>
            <tr><td><code>newMaxAmount</code></td><td><em class="rfc2119">OPTIONAL</em>*</td><td>decimal string</td><td>Raised budget cap; <em class="rfc2119">MUST</em> be &gt; current <code>maxAmount</code>. *At least one of <code>newMaxAmount</code> / <code>newExpires</code> required.</td></tr>
            <tr><td><code>newExpires</code></td><td><em class="rfc2119">OPTIONAL</em>*</td><td>RFC 3339</td><td>Extended session expiry; <em class="rfc2119">MUST</em> be later than current <code>expires</code>. *At least one required.</td></tr>
            <tr><td><code>timestamp</code></td><td><em class="rfc2119">REQUIRED</em></td><td>RFC 3339</td><td>Time the extension was created.</td></tr>
            <tr><td><code>proof</code></td><td><em class="rfc2119">REQUIRED</em></td><td>DataIntegrityProof</td><td>Payee signature. A wallet <em class="rfc2119">MUST NOT</em> admit extended accruals on the strength of this alone; it <em class="rfc2119">MUST</em> first obtain a fresh <a>SessionBudgetAuthorization</a>.</td></tr>
          </tbody>
        </table>
```

- [ ] **Step 3: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): convert SessionBudgetAuthorization and UsageSessionExtension to member tables"
```

---

## Task 19: Payments rationale asides (6 notes)

**Files:**
- Modify: `spec/payments/index.html`

- [ ] **Step 1: quoteDigest aside (payment-authorization section)**

Find the row or sentence explaining `quoteDigest`. Insert immediately after the `quoteDigest` table row or its surrounding sentence:

```html
        <aside class="note">
          <p>
            <strong>Why <code>quoteDigest</code> is needed.</strong>
            <code>quoteDigest</code> is a hash of the complete signed quote
            (proof removed). It commits the payer's signature to the exact
            price and terms the payer observed — not just to a mutable IRI.
            Without it, a compromised quote server could swap the quote's
            terms after the payer signed and before the wallet verified.
          </p>
        </aside>
```

- [ ] **Step 2: payee-binding aside (payment-authorization section)**

Find the sentence "payee MUST equal the quote's payee." Insert immediately after the paragraph containing it:

```html
        <aside class="note">
          <p>
            <strong>Why <code>payee</code> must equal the quote's payee.</strong>
            Without this binding, a payer could reference a legitimate quote
            from a payee it is not supposed to pay, name a permitted payee DID
            in the authorization, satisfy the <code>allowedPayees</code> check,
            and have the wallet settle to the original quote's settlement target.
            Binding <code>payee</code> in the authorization to the quote's
            <code>payee</code> closes this policy-bypass.
          </p>
        </aside>
```

- [ ] **Step 3: @context array-order aside (namespace section)**

Find the normative paragraph about the 4-entry array and the array-order-is-signature-significant statement. Insert immediately after it:

```html
      <aside class="note">
        <p>
          <strong>Why array order is significant.</strong>
          The <code>eddsa-jcs-2022</code> proof is computed over the
          JSON Canonicalization Scheme (JCS) serialisation of the object,
          and JCS preserves JSON array order. Reordering the
          <code>@context</code> entries produces a different canonical form,
          a different hash, and therefore an invalid proof — even though the
          JSON-LD semantics are unchanged.
        </p>
      </aside>
```

- [ ] **Step 4: Nonce scoping aside (integrity section)**

Find the paragraph about nonce uniqueness scoped to the (payer, verifier) pair. Insert immediately after it:

```html
      <aside class="note">
        <p>
          <strong>Why nonce uniqueness is scoped to the payer–verifier pair.</strong>
          A payer using two independent wallet services for different merchants
          can reuse the same nonce string without enabling cross-wallet replay,
          because the verifier component of the pair differs. Implementations
          need only retain nonces within the window [issue, expires + skew
          budget] for each (payer, verifier) pair.
        </p>
      </aside>
```

- [ ] **Step 5: Execution-signer binding aside (securing section, after #execution-binding paragraph)**

Find the paragraph with `id="execution-binding"`. Insert immediately after its closing `</p>`:

```html
      <aside class="note">
        <p>
          <strong>Why naming the authorized wallet matters for audit.</strong>
          Without the <code>wallet</code> member, an auditor re-checking the
          message chain after the fact cannot determine whether the wallet that
          signed the execution was the one the payer intended. The
          <code>wallet</code> member is RECOMMENDED in all deployments and
          REQUIRED in the auditable profile precisely because its absence makes
          retrospective audit depend on out-of-band trust.
        </p>
      </aside>
```

- [ ] **Step 6: startingBalance release aside (usage-session section)**

Find the `startingBalance` table row or the paragraph that mentions "unused remainder SHOULD be released at close." Insert after that section:

```html
        <aside class="note">
          <p>
            <strong>Why the unused <code>startingBalance</code> SHOULD be released.</strong>
            <code>startingBalance</code> is a prepayment counted toward the
            session total. The SHOULD release at close ensures the payer is
            not charged for unused committed balance. Where the wallet cannot
            release programmatically (for example due to rail finality
            constraints), the excess shows up in the difference between the
            receipt's <code>amount</code> and the original
            <code>startingBalance</code>, giving the payer evidence for a
            reconciliation claim.
          </p>
        </aside>
```

- [ ] **Step 7: Structural check + commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): add 6 rationale asides (quoteDigest, payee-binding, context-order, nonce, execution-binding, startingBalance)"
```

---

## Task 20: Payments example annotations + final verification

**Files:**
- Modify: `spec/payments/index.html` (section `id="examples"`)

- [ ] **Step 1: Annotate example `<pre>` blocks with descriptive titles**

Find each `<pre class="example json">` in the examples section. Add `title=""` attributes:

- PaymentAuthorization example → `title="PaymentAuthorization (payer-signed; embeds credential VP)"`
- UsageSession example → `title="UsageSession (payee-signed budget contract)"`
- SessionBudgetAuthorization example → `title="SessionBudgetAuthorization (payer-signed; commits to session budget)"`
- UsageAccrual example → `title="UsageAccrual (cumulative meter report)"`
- Session PaymentReceipt example → `title="PaymentReceipt (session settlement)"`

- [ ] **Step 2: Structural check**

Run the Payments structural check. All tags balanced.

- [ ] **Step 3: Final green-bar verification (both specs)**

```bash
.venv/Scripts/python.exe spec/verify.py | tail -1
.venv/Scripts/python.exe spec/validate.py | tail -1
```

Both must end with `PASS: all checks passed.` and `PASS: all artifact checks passed.`

- [ ] **Step 4: Commit**

```bash
git add spec/payments/index.html
git commit -m "feat(pay): annotate examples with descriptive titles; Phase 2 complete"
```

---

## Task 21: Merge to master

- [ ] **Step 1: Final structural checks on both files**

```bash
for f in spec/authority/index.html spec/payments/index.html; do
  python -c "
import re, sys
h = open('$f').read()
for tag in ['section','pre','dl','table','ul','ol']:
    o = len(re.findall(f'<{tag}[ >]', h))
    c = len(re.findall(f'</{tag}>', h))
    print(f'{tag}: {o}/{c}', 'OK' if o==c else 'MISMATCH')
print()
"
done
```

All lines must print `OK`.

- [ ] **Step 2: Final harness run**

```bash
.venv/Scripts/python.exe spec/verify.py | tail -1
.venv/Scripts/python.exe spec/validate.py | tail -1
```

Both PASS.

- [ ] **Step 3: Merge**

```bash
git checkout master
git merge spec-readability
git branch -d spec-readability
```

---

## Self-review notes (completed by plan author)

**Spec coverage:**
- §3 (CSS): Task 1 (DSA) + Task 10 step 1 (Payments). ✓
- §4 (on-ramp, tables, figures): Tasks 2–4 (DSA), Tasks 10–13 (Payments). ✓
- §5 (object template): Tasks 5–7 (DSA 3 credentials), Tasks 14–18 (Payments 9 objects). ✓
- §6 diagram inventory: 2 DSA figs (Tasks 3–4), 3 Payments figs (Tasks 11–13). ✓
- §7 (CSS): Covered in Tasks 1 and 10. ✓
- §8 (phase ordering): Phase 1 (Tasks 1–9), Phase 2 (Tasks 10–21). ✓

**Placeholder scan:** No TBD, TODO, or "similar to Task N" patterns. Every member table is written in full. All SVG code is complete and self-contained.

**Type consistency:** All `<section id="…">` targets used in `<a href="#…">` references within tables match the IDs confirmed present in the spec files (checked via grep earlier). The `data-cite="spending-authority#dfn-…"` cross-refs in Payments tables follow the ReSpec xref convention for the DSA `[[DSA]]` dependency.

**Normative constraint:** No MUST/SHOULD wording was changed in any table row — keywords were moved from prose bullets into the `Req.` column verbatim.
