# traceseal-observe

**Every model and tool call your AI agent makes — signed, timestamped, third-party verifiable.**
One line of code. Hand the receipts to your auditor.

---

## The question your auditor is about to ask

> *"Prove what your AI agent did yesterday. Which model, which prompt, what did it send to which provider, what came back. Not a screenshot — something I can verify independently."*

Today, the honest answer is "trust our logs." Tomorrow, under the EU AI Act, the NIS2 directive, the UK AI Bill, and half the compliance frameworks your customers are writing into their procurement forms, "trust our logs" won't cut it.

`traceseal-observe` is the cryptographic primitive that makes the question answerable. Every model call, every tool call, every data-flow leaving your system produces a signed JSON receipt. Anyone — your auditor, your regulator, your customer — can verify it with a one-line command, on any machine, with no access to yours.

## One minute

```python
from traceseal_observe import OperatorKey, observe_anthropic
from anthropic import Anthropic

key = OperatorKey.load_from_file("~/.traceseal/keys/my-operator.key")
client = Anthropic()

response, receipt = observe_anthropic(
    client,
    {"model": "claude-sonnet-4", "messages": [{"role": "user", "content": "Hi"}]},
    key,
)

receipt.to_json()  # shareable, signed, verifiable
```

Your auditor runs:

```bash
pip install traceseal-verify
traceseal-verify receipt.json
```

```
[OK] receipt.json
  operator:  ed25519:9dae521400bb39e17e74d8bc1222c45d
```

That's the whole loop. No API keys exchanged. No access to your machine. No shared infrastructure.

## What gets signed

| Receipt type | What it proves |
|---|---|
| **Model call** | which provider, which model, hash of prompt, hash of response, tokens, latency, operator signature |
| **Tool call** | which tool, transport (python / MCP / HTTP / shell), input/output hash, exit code, operator signature |
| **Data flow** | outbound HTTP destination, payload hashes, PII pattern count, allow-list match — the signed answer to *"did you send user data to OpenAI between 2pm and 4pm yesterday?"* |
| **Workflow** | ordered chain of child receipt hashes + wall-clock times, forming a single signed trace of a multi-step run |

All four formats verify with the same `traceseal-verify` tool.

## Integrations

- **Anthropic SDK** — `observe_anthropic(client, request, key)`
- **OpenAI SDK** — `observe_openai(client, request, key)`
- **Any model provider** — `observe_model_call(...)` with your own serializer
- **LangChain / LangGraph** — [`traceseal-langchain`](https://github.com/traceseal/traceseal-langchain): one callback handler, receipts for every node
- **MCP tools** — `observe_mcp_tool(...)`
- **HTTP APIs and shell tools** — `observe_http_tool(...)`, `observe_shell_tool(...)` — with secret redaction built in (header values and env values are excluded from hashes)

## Privacy

Receipts contain **hashes of inputs and outputs, not the values.** You can send a receipt to your auditor without leaking the prompt your user typed. If the auditor needs to verify a specific value, you provide it separately and they recompute the hash.

Data-flow receipts add a **PII fingerprint** — count of email/phone/credit-card/JWT/API-key-shaped patterns detected in the payload. Counts only. No values. A signed answer to "did this request contain PII" without the request being in the receipt.

## What receipts prove, and what they don't

Be honest about the trust model.

**Prove:** the holder of this ed25519 key signed this exact payload at this time.
**Don't prove:** that the provider actually returned what you recorded. A compromised operator could fabricate a receipt. This is an *operator attestation*, not a zero-knowledge proof of execution. The guarantee is: the same guarantee your audit logs give you today, but cryptographically portable and tamper-evident.

When providers start signing their responses (the obvious next step — we have a proposal out with Anthropic), the receipt format is designed to carry a `provider_attestation` field alongside yours, closing the loop.

## Install

```bash
pip install traceseal-observe                   # the signing library
pip install traceseal-verify                    # the verifier (one-command audit)
pip install traceseal-langchain                 # LangChain / LangGraph callback
```

## Spec

The receipt format is open and language-agnostic. Anyone can implement a verifier in any language from the [Execution Receipt Specification](https://traceseal.io/spec) without touching Traceseal source code.

## License

Apache 2.0 — no barriers to signing, no barriers to verification.
