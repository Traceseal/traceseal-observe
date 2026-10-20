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
| **Model call** | which provider, which model, hash of prompt, hash of response, tokens, latency, optional hash of the full tool definitions offered, operator signature |
| **Tool call** | which tool, transport (python / MCP / HTTP / shell), input/output hash, exit code, optional hash of the tool's definition, operator signature |
| **Outcome** | a later signed claim about what a call led to (succeeded / failed / partial / reversed / unknown), committing to the original receipt's hash; may be signed by a different key |
| **Data flow** | outbound HTTP destination, payload hashes, PII pattern count, allow-list match — the signed answer to *"did you send user data to OpenAI between 2pm and 4pm yesterday?"* |
| **Workflow** | ordered chain of child receipt hashes + wall-clock times, forming a single signed trace of a multi-step run |
| **Model resolution** | Open Registry's deterministic candidate, policy and source-decision hashes, without the raw repository identity |
| **Resolution witness** | a different key independently re-derived a supplied resolution bundle and confirmed its signed hash chain |
| **Fresh resolution witness** | a different key independently contacted Hugging Face and confirmed the signed public revision within a declared time gap |
| **Model identity observation** | a bounded registry-neutral identity over four locally SHA-256-hashed files observed at Hugging Face and ModelScope |
| **Model identity witness** | a different key freshly re-observed both sources and confirmed only selected-file equivalence |
| **Publisher artefact authorisation** | a separate publisher key authorised one exact canonical model identity/equivalence statement |
| **Publisher repository binding** | the publisher key signed an exact provider/account/repository subject retrieved from that provider namespace at a pinned revision |
| **Publisher key history** | planned rotation was authorised by the old key and accepted by the new key, or a revocation was supplied/re-observed with its exact assurance method |
| **Publisher history publication** | exact binding/rotation/revocation commitments were included beneath a TraceSeal checkpoint carrying a valid C2SP witness cosignature |

All formats verify with the same `traceseal-verify` tool.

The additive resolution discriminators use the same v1 envelope and ordinary
verifier; they do not introduce another signature format. Their narrower trust
claims and offline operator commands are specified in
`MODEL-RESOLUTION-RECEIPTS.md`.

Outcome receipts and tool-definition hashes are specified in
`OUTCOME-RECEIPTS.md`:

```python
from traceseal_observe import sign_outcome, verify_outcome

outcome = sign_outcome(tool_receipt, status="reversed",
                       outcome={"refund_id": "re_123"}, operator_key=key)
verify_outcome(outcome, tool_receipt)
```

New Phase 2A receipts declare domain profile `1.1` and put strict UTC
`observed_at`, `verified_at` or `reobserved_at` claims inside signed
`execution`. Historical receipts without the profile marker remain valid.
These are signed clock claims, not trusted timestamps or replay prevention.

## Open Registry resolution evidence

After Open Registry has produced a deterministic evidence bundle, sign and
witness it outside the long-running gateway:

```bash
traceseal-resolution sign \
  --evidence resolution-evidence.json \
  --key resolver.key \
  --output resolution.receipt.json \
  --observed-at 2026-08-30T06:30:00Z

traceseal-resolution witness \
  --evidence resolution-evidence.json \
  --receipt resolution.receipt.json \
  --key independent-witness.key \
  --output resolution.cosignature.json
```

Both outputs verify with `traceseal-verify`. The witness command is offline,
recomputes the complete Open Registry evidence chain, refuses the original
signer's key, and writes nothing on semantic or signature failure.

Phase 2A.1 adds a separately labelled networked witness without changing that
offline claim:

```bash
traceseal-resolution witness-reobserve \
  --evidence resolution-evidence.json \
  --receipt resolution.receipt.json \
  --model hf-internal-testing/tiny-random-gpt2 \
  --key independent-witness.key \
  --output resolution.reobserved.cosignature.json
```

It verifies the original receipt, then uses a fresh non-caching client to the
fixed public Hugging Face origin. A changed revision is `source_changed`; the
historical operator receipt remains cryptographically valid.

Bounded Hugging Face + ModelScope evidence produced by Open Registry is signed
and freshly witnessed with `traceseal-identity sign` and
`traceseal-identity witness`. The exact claim is
`selected_files_equivalent`, never full-model equivalence. See
`MODEL-IDENTITY-RECEIPTS.md`.

Phase 2A.2 adds a separate offline publisher authorisation without putting a
publisher key into Open Registry or conflating it with an operator receipt:

```bash
publisher-attest sign \
  --identity canonical-identity.json \
  --huggingface-observation huggingface.observation.json \
  --modelscope-observation modelscope.observation.json \
  --key demo-publisher.key \
  --issued-at 2026-08-30T08:00:00Z \
  --output publisher-attestation.json

publisher-attest verify \
  --identity canonical-identity.json \
  --huggingface-observation huggingface.observation.json \
  --modelscope-observation modelscope.observation.json \
  publisher-attestation.json
```

The publisher fingerprint is the full SHA-256 of the raw Ed25519 public key.
The signed statement binds canonical ID, selected-file equivalence root and a
strict issuance-time claim. It does not prove a platform account controls the
key, and it makes no full-model, safety or licence claim. Optional publisher
commitments in `traceseal-identity` receipts are independently re-verified by
the identity witness. See `PUBLISHER-ATTESTATIONS.md`.

Phase 2A.3 adds a read-only repository-scoped account-binding profile. The
publisher generates one signed document offline and deliberately publishes the
exact bytes at `.well-known/open-registry/publisher.json`; TraceSeal never
uploads it:

```bash
publisher-bind generate \
  --provider huggingface \
  --account example-org \
  --repository example-org/model \
  --key demo-publisher.key \
  --issued-at 2026-08-30T09:00:00Z \
  --output publisher.json

publisher-bind verify \
  --provider huggingface \
  --repository example-org/model \
  --output publisher-binding-evidence.json
```

The verify path uses a fixed trusted origin and immutable provider revision.
Provider/account/repository are signed, so copying a valid document into
another repository or provider does not create a matching binding. The result
is `publisher_key_platform_bound`, not provider-native key verification or
account-wide authority. Identity receipts can commit the binding root, and a
fresh witness refetches the provider document before countersigning. See
`PUBLISHER-BINDINGS.md`.

Phase 2A.4 keeps that exact v1 binding valid and adds a strict history wrapper
at the same path. Planned rotation is a two-step handover: K1 signs a proposal
and K2 signs acceptance of the identical canonical bytes. Self-revocation is
signed by the affected key; platform revocation is a deliberately weaker,
unsigned-by-that-key document whose platform-control assurance exists only
after fresh pinned retrieval.

```bash
publisher-key rotate-propose \
  --old-key k1.key --new-public-key '<64-lowercase-hex-public-key>' \
  --provider huggingface --account example-org \
  --repository example-org/model --output proposal.json

publisher-key rotate-accept \
  --proposal proposal.json --new-key k2.key --output rotation.json

publisher-key assemble \
  --binding k1-binding.json --binding k2-binding.json \
  --rotation rotation.json --provider huggingface \
  --repository example-org/model --output publisher-history.json
```

The verifier derives one bounded linear chain, rejects cycles/forks and keeps
`publisher_signature_valid` separate from `active`, `superseded` or `revoked`
key status. Identity receipts may commit the resulting history root; the witness
either re-derives supplied documents or freshly refetches the providers. No
command uploads. See `PUBLISHER-KEY-HISTORY.md`.

Phase 2A.5 derives governed publisher-history log events from that already-
verified history and commits only hashes, scope commitments and predecessor
roots. An isolated TraceSeal log can append them, issue RFC 6962 inclusion
proofs and assemble a witnessed evidence bundle. `traceseal-identity` accepts
that bundle with `--publisher-history-log-evidence`, verifies the TraceSeal log
signature plus C2SP cosignature and refuses publisher forks. Nothing publishes
to `log.traceseal.io` automatically; production publication remains a separate
operator decision.

Phase 2B.0 signs deterministic Open Registry source-policy decisions without
changing the TraceSeal v1 envelope. `traceseal-selection sign` commits the
policy, candidate set, explicit requirement outcomes, preference trace and
selected-or-no-eligible decision. `traceseal-selection witness` independently
reruns the Python policy evaluator and countersigns only an exact match. This is
offline supplied-evidence re-derivation, not fresh provider observation.

## Integrations

- **Anthropic SDK** — `observe_anthropic(client, request, key)`
- **OpenAI SDK** — `observe_openai(client, request, key)`
- **Any model provider** — `observe_model_call(...)` with your own serializer
- **LangChain / LangGraph** — [`traceseal-langchain`](https://github.com/traceseal/traceseal-langchain): one callback handler, receipts for every node
- **MCP tools** — `observe_mcp_tool(...)`
- **Tool definitions** — `observe_model_call(..., tools=...)` and `observe_tool(..., tool_definition=...)`; the Anthropic and OpenAI wrappers pick up `tools` from the request
- **Outcomes** — `sign_outcome(receipt, status=..., outcome=..., operator_key=...)`, checked with `verify_outcome(outcome, receipt)`
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
