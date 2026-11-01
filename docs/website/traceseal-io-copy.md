# traceseal.io: website copy update

Copy for traceseal.io matching traceseal-observe 1.6 and traceseal-verify
1.2. The site's source isn't in any repository this work
could reach, and the domain wasn't reachable from the build environment.
So this is a copy deck to paste into whatever builds the site, not a
drop-in page. Section names are suggestions; keep the existing visual
design.

Claims below are limited to what the code does and the tests verify.
Avoid "makes you compliant": the product produces *evidence*, and
compliance is the customer's (and their assessor's) conclusion.

---

## 1. Hero

**Headline:** Verifiable evidence of what your AI agents did.

**Subhead:** Every instrumented model call, tool call, data flow and human
decision becomes a signed, hash-chained receipt, with checkpoints that can
be independently timestamped. Your auditor verifies them on their own
machine, without access to yours.

**Primary CTA:** `pip install traceseal-observe` → Get started
**Secondary CTA:** Verify a receipt → `/verify`

---

## 2. The problem

> "Show me what your agent did between 2pm and 4pm yesterday. Which
> model, on whose behalf, who approved it, what data left your systems,
> and show me nothing is missing."

For high-risk AI systems, the EU AI Act asks for automatic logs
(Art. 12), human oversight (Art. 14), at least six months of retention
(Art. 19, 26) and serious-incident reports within days (Art. 73). As
amended by Regulation (EU) 2026/1744, these apply from 2 December 2027
(Annex III systems) and 2 August 2028 (Annex I systems). GDPR and DORA
already apply, and NIS2 applies through national law, each with its own
reporting clock.
Customers are writing the same questions into procurement forms.
"Trust our logs" doesn't answer them.

---

## 3. How it works (three steps)

1. **Sign.** Wrap your model and tool calls, or pass a recording transport
   to your SDK clients. Each action becomes a signed receipt that records
   hashes of your data, not the data.
2. **Chain and timestamp.** Receipts are hash-linked. Checkpoints go to a
   timestamping authority (RFC 3161, eIDAS-qualified if you choose) or a
   transparency-log witness, so deleting or replacing a receipt becomes
   detectable up to any checkpoint someone else holds.
3. **Show.** One command produces an evidence pack: the receipts verified,
   the findings mapped to the obligations they support, and signed. Anyone
   holding your public key can re-check it offline.

---

## 4. Feature grid

| Title | One line |
|---|---|
| Gaps show | Hash-chained receipts and Merkle checkpoints: gaps and forks are detected, and deleted tails up to any checkpoint a third party holds. |
| Trusted time | RFC 3161 timestamps show records existed by a time set by a clock that isn't yours (eIDAS-qualified if you use a qualified provider). |
| Who, for whom, why | Agent identity, the user it acted for (pseudonymised), authorisation scopes, and the model request behind every tool call. |
| Human oversight | Signed approvals, rejections, edits and stops, optionally countersigned by a reviewer key you register. |
| Guardrails on the record | Policy and filter decisions you wrap, bound to the exact policy version. |
| Evidence vault | Payloads encrypted under the receipt hashes. Erase per user with a signed erasure record; disclose to one auditor with post-quantum-ready encryption. |
| Incidents on the clock | Incident records with AI Act, GDPR, NIS2 and DORA deadlines, and first-notification timing as you record it. |
| Evidence packs | One command: verify, map to obligations, sign. Informational, not a compliance verdict. |
| Drop-in capture | An HTTP transport that receipts every request sent through clients you configure with it, and blocks undeclared destinations. |
| Fits your stack | Anthropic, OpenAI, any provider; sync, async and streaming; OpenTelemetry; LangChain. |
| Production keys | KMS/HSM signing, rotation, compromise handling, a published key directory. |

---

## 5. Code: one minute

```python
from traceseal_observe import OperatorKey, ReceiptChain, observe_anthropic

chain = ReceiptChain.open("/var/lib/agent/chain", OperatorKey.load_from_file("operator.key"),
                          "support-agent")
response, receipt = observe_anthropic(client, request, chain.signer)
```

```bash
traceseal-verify receipts/*.json
traceseal-report build receipts/ --checkpoint cp.txt --output evidence-pack/
```

---

## 6. For auditors (`/verify` page)

**Headline:** Verify without access to their systems.

- `pip install traceseal-verify`: one dependency, Apache 2.0.
- It checks:
  - the operator's signature;
  - that the displayed identity is derived from the signing key;
  - across the receipts you supply, gaps, forks, broken links and key
    changes not made through a dual-signed rotation (missing tails and
    which key to trust need a checkpoint and a key you trust).
- With traceseal-observe it can also check checkpoints, inclusion proofs,
  timestamps, time windows, causality, approvals and evidence packs.
- The receipt format is an open specification: implement your own
  verifier in any language.

---

## 7. Obligations we produce evidence for

Keep the disclaimer next to this table.

| | |
|---|---|
| EU AI Act (high-risk systems, from Dec 2027 / Aug 2028) | Art. 12, 14, 19, 26, 72, 73 |
| GDPR | Art. 5, 15, 17, 25, 30, 33, 34 |
| NIS2 / DORA | incident reporting |
| ISO/IEC 42001 · NIST AI RMF (voluntary) | logging, monitoring, incident response |

*Disclaimer:* TraceSeal produces verifiable evidence. It is not legal
advice, a conformity assessment or a certification, and using it does not
by itself make you compliant. Whether an obligation applies depends on your
role and your system. Provided as is, without warranty. Full notice:
[LEGAL.md](https://github.com/Traceseal/traceseal-observe/blob/main/LEGAL.md).

Do **not** link receipts to EU AI Act Art. 50. Art. 50 is about telling
people they are dealing with AI and marking AI-generated content, which
receipts do not do. Do not say the high-risk obligations "apply now" or
"have applied since 2 August 2026": the Digital Omnibus postponed them.

---

## 8. Honest trust model (keep this section; it builds credibility)

**What a receipt proves:**
- this operator key signed this exact record;
- with a chain and a checkpoint held by someone other than the operator,
  nothing up to that checkpoint was removed or altered afterwards;
- with a timestamp, it existed by then (an upper bound, not the moment it
  was made).

**What it doesn't prove:** that the model provider really returned what
was recorded, or that an operator who was dishonest *at the time* recorded
everything. Receipts defend against after-the-fact tampering.

---

## 9. Spec page (`/spec`) updates

The envelope (RECEIPT-SPEC v1.0) is unchanged and every addition is a
signed, additive profile. List and link:

- Receipt Chains (completeness, checkpoints, proofs, key rotation) and
  Streaming
- Trusted Time (RFC 3161 / eIDAS)
- Agent Context and Causality
- Human Oversight and Policy Decisions
- Evidence Vault (escrow, crypto-shredding, disclosure)
- Incidents and Evidence Packs
- Capture, Async and OpenTelemetry
- Key Management and the operator key directory
- Model provenance profiles (resolution, identity, publisher
  attestation, binding, key history)

Source: `github.com/traceseal/traceseal-observe` (each profile is a
markdown file at the repository root).

---

## 10. Checklist before publishing

- [ ] Replace any old example model ids (`claude-sonnet-4`, `gpt-4`) with
      current ones.
- [ ] Remove "skill" wording from the agent-receipt pages; keep it for the
      sandboxed-skill product.
- [ ] Don't announce features before the release that contains them is
      published.
- [ ] Never claim receipts "prove" what happened, that nothing is missing
      without a third-party checkpoint, or that they are "safe to share".
- [ ] Have the regulation table reviewed by counsel.
- [ ] Remove any statement that receipts "prove" provider behaviour.
