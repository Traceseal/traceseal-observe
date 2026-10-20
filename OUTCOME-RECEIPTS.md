# TraceSeal outcome receipts and tool-definition hashes

Two additive v1 extensions. Both keep TraceSeal's existing four-section
envelope, canonical JSON, Ed25519 keys, signature payload and ordinary
verifier. Neither introduces a new cryptographic format, and receipts that do
not use them are byte-identical to before.

## Outcome receipts (`receipt_type: "outcome"`)

A receipt records a call at the moment it ran. What the call led to (a
payment settling, a deploy being rolled back) is often only known later. An
outcome receipt is a separate signed record, made whenever the outcome is
known, that commits to the hash of the original ("subject") receipt.

```python
from traceseal_observe import sign_outcome, verify_outcome

outcome = sign_outcome(
    tool_receipt,
    status="reversed",
    outcome={"refund_id": "re_123"},
    operator_key=downstream_key,
)
verify_outcome(outcome, tool_receipt)  # raises ValueError on any mismatch
```

### Fields

All fields are REQUIRED and live inside signed `execution`.

| Field | Type | Description |
|---|---|---|
| `receipt_type` | string | `"outcome"` |
| `outcome_version` | string | `"1.0"` |
| `subject_receipt_hash` | string | `sha256:` of the subject receipt's canonical JSON (`Receipt.receipt_hash`) |
| `subject_receipt_type` | string | the subject's `execution.receipt_type`, or `""` if it has none |
| `subject_operator_fingerprint` | string | the fingerprint of the key that signed the subject |
| `outcome_status` | string | one of `succeeded`, `failed`, `partial`, `reversed`, `unknown` |
| `outcome_hash` | string | `sha256:` of the canonical JSON outcome evidence, or `"sha256:empty"` when none was supplied |
| `observed_at` | string | when the outcome was observed, UTC RFC 3339 seconds (`2026-10-20T12:00:00Z`) |

### Rules

`sign_outcome` refuses to sign when:

- the subject's signature does not verify;
- the subject is itself an outcome receipt;
- `status` is not one of the five values above;
- the outcome evidence is not plain JSON (NaN, sets, bytes, tuples, non-string
  keys and arbitrary objects are rejected, so the hash is reproducible);
- `observed_at` is malformed or earlier than the subject's `attested_at`.

`verify_outcome(outcome, subject)` checks both signatures, the outcome fields,
that `subject_receipt_hash`, `subject_receipt_type` and
`subject_operator_fingerprint` match the supplied subject, and that
`observed_at` is not earlier than the subject's `attested_at`.

The outcome may be signed by a different key from the subject, for example
the downstream system that saw the payment settle. Which keys to trust is the
verifier's policy decision.

`traceseal-verify` checks an outcome receipt's envelope and signature like any
other receipt. Checking the link to its subject needs both files and
`verify_outcome`.

### What an outcome receipt does not prove

It proves that the holder of a key signed this outcome claim about that exact
subject receipt, at or after the time it states. It does not prove the outcome
actually happened, and it does not prove no other, contradictory outcome
receipt exists for the same subject.

## Tool-definition hashes

A tool-call receipt shows which tool ran. It does not, on its own, show what
the model was told that tool does. A tool whose description or input schema was
quietly changed keeps the same name.

### Model receipts: `tools_offered_hash`, `tools_offered_count`

Optional fields on `receipt_type: "model"` receipts, both present when the
tools offered to the model are known:

| Field | Type | Description |
|---|---|---|
| `tools_offered_hash` | string | `tool_definitions_hash(tools)` of the full tool definitions offered on this call |
| `tools_offered_count` | integer | how many definitions were offered |

`tool_definitions_hash` hashes each definition whole (name, description and
schema) in canonical JSON, sorted by canonical bytes, so list order does not
change the hash. It accepts any provider's shape. Duplicate definitions and
non-JSON values are rejected. An empty list is valid and hashes differently
from "no tools recorded" (the fields are then absent).

`observe_model_call(..., tools=...)` records these, including when the call
fails. `observe_anthropic` and `observe_openai` take them from the request's
`tools` key automatically.

Numbers are hashed as written: a schema containing `1.0` hashes differently
from one containing `1`.

### Tool receipts: `tool_definition_hash`

Optional field on `receipt_type: "tool"` receipts: `sha256:` of the canonical
JSON of that tool's own definition, set by `observe_tool(...,
tool_definition=...)`.

This is a hash of one definition. It is not the same value as
`tool_definitions_hash([definition])`, which hashes a one-item list; compare
like with like.

### What these hashes do not prove

They prove which definitions the operator says were offered or used. They do
not prove the model saw exactly those bytes, because the operator records them
on its side of the API call.
