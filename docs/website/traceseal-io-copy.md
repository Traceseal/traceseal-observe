# traceseal.io: website copy update

Copy for traceseal.io matching traceseal-observe 1.5.0 and the updated
traceseal-verify. The site's source isn't in any repository this work
could reach, and the domain wasn't reachable from the build environment.
So this is a copy deck to paste into whatever builds the site, not a
drop-in page. Section names are suggestions; keep the existing visual
design.

Claims below are limited to what the code does and the tests verify.
Avoid "makes you compliant": the product produces *evidence*, and
compliance is the customer's (and their assessor's) conclusion.

---

## 1. Hero

**Headline:** Prove what your AI agents did.

**Subhead:** Every model call, tool call, data flow and human decision
becomes a signed, hash-chained, independently timestamped receipt. Your
auditor verifies it on their own machine, without access to yours.

**Primary CTA:** `pip install traceseal-observe` → Get started
**Secondary CTA:** Verify a receipt → `/verify`

---

## 2. The problem

> "Show me what your agent did between 2pm and 4pm yesterday. Which
> model, on whose behalf, who approved it, what data left your systems,
> and prove nothing is missing."

The EU AI Act asks for automatic logs (Art. 12), human oversight
(Art. 14), at least six months of retention (Art. 19, 26), and incident
reports within days (Art. 73). GDPR, NIS2 and DORA add their own clocks.
Customers are writing the same questions into procurement forms.
"Trust our logs" doesn't answer them.

---

## 3. How it works (three steps)

1. **Sign.** Wrap your model and tool calls, or drop in a transport that
   captures every SDK request. Each action becomes a signed receipt that
   records hashes, not your data.
2. **Chain and timestamp.** Receipts are hash-linked. Checkpoints go to a
   timestamping authority (RFC 3161, eIDAS-qualified if you choose) or a
   transparency-log witness, so deleting or back-dating a receipt becomes
   detectable.
3. **Prove.** One command produces an evidence pack: everything verified,
   mapped to the obligations it supports, signed, and checkable offline
   by anyone.

---

## 4. Feature grid

| Title | One line |
|---|---|
| Nothing missing | Hash-chained receipts and Merkle checkpoints: gaps, forks and deleted tails are detected. |
| Trusted time | RFC 3161 / eIDAS timestamps prove when, from a clock that isn't yours. |
| Who, for whom, why | Agent identity, the user it acted for (privacy-preserving), authorisation scopes, and the model request behind every tool call. |
| Human oversight | Signed approvals, rejections, edits and stops, countersigned by the reviewer's own key. |
| Guardrails on the record | Every policy and filter decision, bound to the exact policy version. |
| Evidence vault | Payloads encrypted under the receipt hashes. Erase per user with signed proof; disclose to one auditor with post-quantum-ready encryption. |
| Incidents on the clock | Incident records with AI Act, GDPR and NIS2 deadlines, plus late-report detection. |
| Evidence packs | One command: verify, map to obligations, sign. |
| Zero-code capture | A drop-in HTTP transport that receipts every request your SDKs make, and blocks undeclared destinations. |
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

**Headline:** Verify without trusting us, or them.

- `pip install traceseal-verify`: one dependency, Apache 2.0.
- It checks:
  - the operator's signature;
  - that the displayed identity is derived from the signing key;
  - across a set of receipts, that none are missing, duplicated or
    re-signed by an unauthorised key.
- With traceseal-observe it can also check checkpoints, inclusion proofs,
  timestamps, time windows, causality, approvals and evidence packs.
- The receipt format is an open specification: implement your own
  verifier in any language.

---

## 7. Obligations we produce evidence for

Keep the disclaimer next to this table.

| | |
|---|---|
| EU AI Act | Art. 12, 14, 19, 26, 72, 73 |
| GDPR | Art. 5, 15, 17, 25, 30, 33 |
| NIS2 / DORA | incident reporting |
| ISO/IEC 42001 · NIST AI RMF | logging, monitoring, incident response |

*Disclaimer:* TraceSeal produces verifiable evidence. It is not a
conformity assessment or legal advice.

---

## 8. Honest trust model (keep this section; it builds credibility)

**What a receipt proves:**
- this operator key signed this exact record;
- with a chain and checkpoint, nothing was removed or altered afterwards;
- with a timestamp, it existed by then.

**What it doesn't prove:** that the model provider really returned what
was recorded, or that an operator who was dishonest *at the time* recorded
everything. Receipts defend against after-the-fact tampering, the failure
that audits actually catch.

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
- [ ] Don't announce traceseal-verify's new checks until the release is
      approved and published (see its RELEASE.md).
- [ ] Have the regulation table reviewed by counsel.
- [ ] Remove any statement that receipts "prove" provider behaviour.
