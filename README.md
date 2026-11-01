# traceseal-observe

**Verifiable evidence of what your AI agents did.** Every model call, tool
call, data flow, human decision and policy check becomes a signed,
hash-chained, timestamped receipt. Anyone (your auditor, your regulator,
your customer) can verify it on their own machine, without access to yours.

---

## The question your auditor is about to ask

> *"Prove what your AI agent did between 2pm and 4pm yesterday. Which
> model, on whose behalf, who approved it, what data left the system, and
> show me nothing is missing. Not a screenshot: something I can verify
> independently."*

The EU AI Act (record-keeping, human oversight, log retention and incident
reporting for high-risk systems, from December 2027), GDPR, NIS2, DORA and
the procurement questionnaires that follow them all ask versions of this
question. "Trust our logs" doesn't answer it. Signed, chained,
independently timestamped receipts give you evidence you can hand over.
They are evidence, not a compliance verdict: see [LEGAL.md](LEGAL.md).

## One minute

```bash
pip install traceseal-observe
```

```python
from anthropic import Anthropic
from traceseal_observe import OperatorKey, ReceiptChain, observe_anthropic

key = OperatorKey.load_from_file("~/.traceseal/keys/operator.key")
chain = ReceiptChain.open("/var/lib/agent/chain", key, "support-agent")

response, receipt = observe_anthropic(
    Anthropic(),
    {"model": "claude-sonnet-5-5", "max_tokens": 512,
     "messages": [{"role": "user", "content": "Hi"}]},
    chain.signer,
)
receipt.to_json()            # signed, chained, shareable
checkpoint = chain.checkpoint()
```

Your auditor runs:

```bash
pip install traceseal-verify
traceseal-verify receipts/*.json            # signatures, fingerprints, chain links
traceseal-chain verify receipts/*.json --checkpoint checkpoint.txt
```

No API keys exchanged, no access to your systems, no shared infrastructure.

## What you get

| Capability | What it gives you | Docs |
|---|---|---|
| **Signed receipts** | model calls (requested *and* served model, tokens, tool calls requested), tool calls, outbound data flows, workflows, outcomes | [RECEIPT-SPEC](RECEIPT-SPEC.md), [OUTCOME-RECEIPTS](OUTCOME-RECEIPTS.md) |
| **Streaming** | streamed responses hashed chunk by chunk; sync and async | [RECEIPT-CHAINS §2](RECEIPT-CHAINS.md) |
| **Completeness** | hash-chained receipts, RFC 6962 checkpoints in C2SP format, inclusion and consistency proofs; gaps, forks and truncation detected | [RECEIPT-CHAINS](RECEIPT-CHAINS.md) |
| **Trusted time** | RFC 3161 / eIDAS timestamps on checkpoints; provable time windows | [TRUSTED-TIME](TRUSTED-TIME.md) |
| **Who, for whom, why** | signed agent identity, principal (privacy-preserving), tenant, session, W3C trace ids, authorisation scopes and expiry, causal links from model request to tool action | [AGENT-CONTEXT](AGENT-CONTEXT.md) |
| **Human oversight** | approve / reject / modify / stop / resume receipts, reviewer countersignatures, review timing; verifier enforces required approvals | [HUMAN-OVERSIGHT](HUMAN-OVERSIGHT.md) |
| **Policy decisions** | every guardrail or filter decision, bound to the policy version | [HUMAN-OVERSIGHT §2](HUMAN-OVERSIGHT.md) |
| **Evidence vault** | encrypted payload escrow under the receipt hashes; crypto-shredding with signed erasure receipts; retention floors, legal holds; HPKE disclosure to auditors (post-quantum option) | [EVIDENCE-VAULT](EVIDENCE-VAULT.md) |
| **Incidents** | incident receipts with statutory deadlines (AI Act Art. 73, GDPR Art. 33, NIS2 Art. 23) and late-report detection | [EVIDENCE-PACKS](EVIDENCE-PACKS.md) |
| **Evidence packs** | one command verifies everything, maps it to obligations, writes a signed, self-checking pack | [EVIDENCE-PACKS](EVIDENCE-PACKS.md) |
| **Zero-code capture** | an HTTP transport for any SDK that receipts every request, and can block undeclared destinations | [CAPTURE](CAPTURE.md) |
| **OpenTelemetry** | GenAI semantic-convention attributes and receipt hashes on your existing traces | [CAPTURE](CAPTURE.md) |
| **Production keys** | KMS/HSM signers, chained key rotation, compromise handling, published operator key directory | [KEY-MANAGEMENT](KEY-MANAGEMENT.md) |
| **Model provenance** | Open Registry resolution, cross-registry identity, publisher attestations, bindings and key history | [below](#model-provenance-open-registry) |

## A complete agent turn

```python
from traceseal_observe import (Authorization, Principal, agent_context, caused_by,
                               observe_anthropic, observe_tool, observe_policy, sign_oversight)

with agent_context(agent_id="support-bot", agent_version="2.3.1", session_id=session_id,
                   principal=Principal.user(user_id, pepper=PEPPER),
                   authorization=Authorization(scopes=["refunds:write"], grant=oauth_claims)):
    response, model_receipt = observe_anthropic(client, request, signer)

    for call in response.content:
        if call.type != "tool_use":
            continue
        _, policy = observe_policy("spend-limit", check_limit, call.input, signer, stage="tool_call")
        approval = sign_oversight(decision="approved", operator_key=signer,
                                  reviewer=Principal.user(reviewer_id, pepper=PEPPER),
                                  subjects=[model_receipt], tool_call_ids=[call.id],
                                  presented=review_screen, review_started_at=opened_at)
        with caused_by(model_receipt, policy, approval, tool_call_id=call.id):
            result, tool_receipt = observe_tool(call.name, signer, lambda: run(call), args=call.input)

    vault.put_for(model_receipt, "input_hash", request, domain=f"tenant:{tenant}")
```

```bash
traceseal-trace verify receipts/*.json --require-approval issue_refund \
    --require-policy issue_refund=spend-limit --require-scope issue_refund=refunds:write
```

The verifier reports each of these as an error:
- a tool call the model never requested;
- arguments that differ from what the model asked for, or from what the
  reviewer approved;
- an action after a human rejected or stopped it;
- an action despite a policy *deny*;
- an action outside its scope, or after its authorisation expired.

## Receipt types

All receipts share one envelope (`RECEIPT-SPEC.md` v1.0: canonical JSON,
Ed25519) and verify with `traceseal-verify`.

| `receipt_type` | Records |
|---|---|
| `model` | provider, requested and served model, endpoint, prompt/response hashes, tokens, stop reason, tool definitions offered, tool calls requested, stream completeness |
| `tool` | tool name, transport (python / MCP / HTTP / shell), input/output hashes, exit status, tool definition hash |
| `data_flow` | destination host and URL, request/response hashes and sizes, PII-pattern counts, allow-list match |
| `orchestration` | ordered child receipt hashes for a workflow |
| `outcome` | a later claim about what an action led to (succeeded / failed / reversed …) |
| `oversight` | a human decision, with reviewer, what was shown, rationale hash, timing, optional reviewer signature |
| `policy_decision` | an automated control's decision, bound to the policy's hash |
| `incident` | an incident stage, with affected receipts and statutory deadlines |
| `erasure` | a crypto-shredding event, committing to what was destroyed |
| `evidence_pack` | the operator's signature over an evidence pack manifest |
| `chain_key_rotation` | a dual-signed handover of a chain to a new key |
| `model_resolution`, `model_identity_observation`, and their `*_cosignature` witnesses | Open Registry model provenance (below) |

Operational receipts can carry a signed `context` (agent, principal,
authorisation, trace, causes) and chain fields (`chain_id`, `chain_seq`,
`chain_prev_hash`, `chained_at`).

## Command-line tools

| Command | For |
|---|---|
| `traceseal-verify` | (separate package) verify any receipt's signature and fingerprint; check chain links across files |
| `traceseal-chain verify / timestamp / timestamp-verify` | completeness, checkpoints, proofs, trusted time windows |
| `traceseal-trace verify / find-principal` | causality, authorisation, oversight and policy; GDPR access lookups |
| `traceseal-report build / verify-pack` | evidence packs with control mapping |
| `traceseal-keys publish / verify` | operator key directory |
| `traceseal-resolution`, `traceseal-identity`, `traceseal-selection`, `publisher-attest`, `publisher-bind`, `publisher-key` | model provenance |

## Mapping to obligations

**Informational, not legal advice.** TraceSeal produces verifiable
evidence. It is not a conformity assessment or a certification, and using
it does not by itself make anyone compliant with anything. Read
[LEGAL.md](LEGAL.md) before relying on this table. `traceseal-report`
produces the mapping from your actual receipts, with the problems it found.

The EU AI Act obligations below apply to **high-risk** AI systems only.
As amended by Regulation (EU) 2026/1744 (the Digital Omnibus on AI), they
apply from **2 December 2027** for Annex III systems and **2 August 2028**
for Annex I systems. Most agent deployments are not high-risk; whether
yours is depends on its intended purpose. GDPR, NIS2 and DORA already apply
where you are in scope.

| Obligation | Applies to | Evidence TraceSeal can supply |
|---|---|---|
| EU AI Act Art. 12: record-keeping | providers (system design) | chained receipts, checkpoints, trusted time |
| Art. 12(2): logs that support risk identification and monitoring | providers | signed context, input/output hashes |
| Art. 14 / 26(2): human oversight | providers (design) / deployers (assign people) | oversight receipts, required-approval checks, reviewer signatures |
| Art. 19 / 26(6): keep logs ≥ 6 months | providers / deployers | vault retention floors, chains, checkpoints |
| Art. 26(5): monitoring | deployers | causality checks, unprompted actions, changed arguments, policy decisions |
| Art. 72 / 73: post-market monitoring, serious incidents | providers (deployers inform them) | outcome and incident receipts, deadline tracking |
| GDPR Art. 5, 25: minimisation, data protection by design | controllers | hashes not values, pseudonymised principal commitments |
| GDPR Art. 15 / 17: access, erasure | controllers | principal lookups, crypto-shredding with erasure receipts |
| GDPR Art. 30, 33, 34: records, breach notification | controllers (processors notify them) | data-flow receipts (input only), incident deadlines |
| NIS2 Art. 23 | essential and important entities | incident receipts and timelines |
| DORA Art. 19 | financial entities | incident receipts, 24-hour outer limit |
| ISO/IEC 42001, NIST AI RMF (voluntary) | adopters | event logging, monitoring, incident response evidence |

"Evidence" means relevant records exist and pass verification, not that
the obligation is met. Pseudonymised data (principal commitments, hashes
of guessable values) is still personal data under GDPR.

## Privacy

Receipts contain **hashes, not values**. Principals are keyed commitments
(pseudonymised, not anonymised), never raw user ids. Data-flow receipts carry **counts** of PII-shaped
patterns: emails, phone numbers (US, UK, international), cards, IBANs,
IPv4 addresses, US SSNs, credentials. Payloads you need to keep live
encrypted in the evidence vault, erasable per user or tenant.

Hashes of low-entropy values (`"yes"`, a short code) can be guessed by
brute force. Bear that in mind before publishing receipts, rather than
sharing them with an auditor.

## What receipts prove, and what they don't

**Prove:**
- The holder of an Ed25519 key signed this exact record.
- With a chain: no receipt was removed, inserted or replaced, up to the
  newest checkpoint someone else holds.
- With a timestamp: the receipts existed by the TSA's time.
- With a reviewer countersignature: the reviewer, not just the operator,
  made that decision.

**Don't prove:**
- That the provider really returned what the operator recorded, or that
  the operator recorded everything. Receipts are *operator attestations*,
  and an operator dishonest at the time of the action can leave it out of
  the chain altogether. What they defend against is after-the-fact
  tampering: logs altered once someone wants something to disappear.
  `provider_attestation` is reserved for provider-signed responses when
  providers offer them.
- Attributions such as the user or the scope are what the operator
  signed, not facts the library can check.

Further limits:
- Operator fingerprints in the v1 envelope are truncated to 128 bits.
  Newer profiles use the full SHA-256.
- `attestation.attested_at` sits outside the v1 signed payload. Chained
  receipts sign `chained_at` instead.

## Model provenance (Open Registry)

Separate from agent actions, TraceSeal signs and witnesses evidence about
*which model* you ran. Each profile is additive to the v1 envelope and has
its own document:

- **Resolution** (`traceseal-resolution sign / witness / witness-reobserve`):
  Open Registry's deterministic candidate, policy and source-decision
  hashes, independently re-derived or freshly re-observed by a witness key.
  [MODEL-RESOLUTION-RECEIPTS](MODEL-RESOLUTION-RECEIPTS.md)
- **Identity** (`traceseal-identity sign / witness`): a bounded
  identity over locally hashed files observed at Hugging Face and
  ModelScope. The claim is `selected_files_equivalent`, never
  full-model equivalence. [MODEL-IDENTITY-RECEIPTS](MODEL-IDENTITY-RECEIPTS.md)
- **Publisher attestation** (`publisher-attest`): a publisher key authorises
  one canonical identity. [PUBLISHER-ATTESTATIONS](PUBLISHER-ATTESTATIONS.md)
- **Repository binding** (`publisher-bind`): the publisher key bound to a
  provider/account/repository at a pinned revision.
  [PUBLISHER-BINDINGS](PUBLISHER-BINDINGS.md)
- **Key history** (`publisher-key`): dual-signed rotation and revocation,
  optionally published under a witnessed TraceSeal log checkpoint.
  [PUBLISHER-KEY-HISTORY](PUBLISHER-KEY-HISTORY.md)
- **Selection** (`traceseal-selection sign / witness`): deterministic
  source-policy decisions, re-run and countersigned by a witness.

Nothing in this package uploads or publishes on your behalf.

## Integrations

- **Anthropic**: `observe_anthropic`, `observe_anthropic_stream`, and
  `aobserve_*` for `AsyncAnthropic`.
- **OpenAI**: `observe_openai`, `observe_openai_stream`, and `aobserve_*`.
- **Any provider**: `observe_model_call` / `observe_model_stream` /
  `aobserve_model_call`.
- **Any SDK, zero code**: `capture.ReceiptTransport` / `AsyncReceiptTransport`
  (httpx or httpx2).
- **Tools**: `observe_tool`, `observe_tool_fn`, `observe_mcp_tool`,
  `observe_http_tool`, `observe_shell_tool`, `aobserve_tool`.
- **LangChain / LangGraph**: [`traceseal-langchain`](https://github.com/traceseal/traceseal-langchain).
- **OpenTelemetry**: `traceseal_observe.otel`.

## Install

```bash
pip install traceseal-observe                      # core: one dependency (cryptography>=42)
pip install "traceseal-observe[timestamp]"         # RFC 3161 tokens (asn1crypto)
pip install "traceseal-observe[disclosure]"        # HPKE sealed disclosure (cryptography>=47)
pip install "traceseal-observe[otel]"              # OpenTelemetry export
pip install traceseal-verify                       # the auditor's verifier
```

Python 3.9+. CI covers 3.9 to 3.13 and the minimum `cryptography`.

## Spec and changes

The receipt format is open and language-agnostic: see
[RECEIPT-SPEC.md](RECEIPT-SPEC.md) and the profile documents linked above.
Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

Apache 2.0: no barriers to signing, no barriers to verification. Provided
"as is", without warranty. Regulatory references are informational and
not legal advice; see [LEGAL.md](LEGAL.md).
