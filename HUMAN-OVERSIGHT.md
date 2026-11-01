# Human Oversight and Policy Decisions

**Version:** 1.0 (additive to RECEIPT-SPEC.md v1.0)

EU AI Act Art. 14 requires that high-risk AI systems are designed so
people can understand, monitor, override and stop them. Art. 26(2)
requires deployers to assign that oversight to competent people. These
duties apply to high-risk systems only: from 2 December 2027 (Annex III)
and 2 August 2028 (Annex I), as amended by Regulation (EU) 2026/1744.
Receipts record that oversight happened. Whether the oversight measures
are adequate is not something a receipt can show. See [LEGAL.md](LEGAL.md). Two receipt types turn each
intervention, human or automated, into a signed, chainable record that a
verifier can hold the agent's actions against.

## 1. `oversight`: a person decided

```python
approval = sign_oversight(
    decision="approved",                 # approved|rejected|modified|escalated|stopped|resumed
    operator_key=chain.signer,
    reviewer=Principal.user(reviewer_id, pepper=PEPPER),
    reviewer_role="claims-officer",
    subjects=[model_receipt], tool_call_ids=["toolu_A"],
    presented=review_screen_payload,     # what the reviewer saw (hashed)
    rationale=reason_text,               # why (hashed)
    review_started_at=opened_at,         # signed review_seconds = decided_at - review_started_at
    reviewer_key=reviewer_security_key,  # optional: the reviewer countersigns
)
with caused_by(model_receipt, approval, tool_call_id="toolu_A"):
    observe_tool("issue_refund", chain.signer, run, args=call.input)
```

| Field | Meaning |
|---|---|
| `decision` | one of the six decisions above |
| `reviewer`, `reviewer_role` | principal commitment (AGENT-CONTEXT.md §2.1) and role |
| `subject_receipt_hashes`, `tool_call_ids` | what the decision is about |
| `presented_hash` | hash of what the reviewer was shown: evidence of what they had in front of them (relevant to Art. 14(4)(a), (c); it does not show they understood it) |
| `rationale_hash` | hash of the reviewer's reason |
| `modified_input_hash` | with `modified`: the arguments the reviewer approved instead |
| `review_started_at`, `decided_at`, `review_seconds` | signed review timing |
| `reviewer_public_key`, `reviewer_signature` | optional. The reviewer's own Ed25519 signature over canonical JSON of the oversight fields plus `purpose: "traceseal-oversight-reviewer/1"` |

Without a reviewer countersignature, an oversight receipt is the
operator's attestation that a person decided. With one, the operator can't
forge or alter the decision without the reviewer's key. A hardware
security key per reviewer, used through `RemoteOperatorKey`, is the strong
setup.

`stopped` and `resumed` apply to the `session_id` in the receipt's
`agent_context`.

## 2. `policy_decision`: an automated control decided

```python
result, decision = observe_policy(
    "pii-filter", evaluate, content, chain.signer,
    stage="output",                      # input|output|tool_call|retrieval|data_flow|other
    policy_definition=filter_config,     # policy_hash: a changed policy shows up
    engine="presidio-2.2",
)
```

`evaluate(content)` returns `"allow" | "deny" | "modify" | "flag"`, or a
dict with `decision`, optional `categories`, `rule_ids` and (for `modify`)
`output`. If `evaluate` raises, `observe_policy` signs nothing: a control
that didn't run must not look as if it allowed.

## 3. What `verify_trace` checks

```bash
traceseal-trace verify receipts/*.json \
    --require-approval issue_refund \
    --require-policy send_email=pii-filter \
    --min-review-seconds 10
```

These are **errors**:
- a `--require-approval` tool with no cited `approved`/`modified`
  decision covering its `tool_call_id`;
- a tool call executed although a human **rejected** it, *whether or not*
  the tool receipt cites the rejection;
- an action citing a `rejected` or `stopped` decision;
- an action whose arguments differ from what the model requested after a
  plain approval, or from `modified_input_hash` after a modification;
- an action in a session after it was `stopped` and before it was
  `resumed`;
- an action citing a `deny` policy decision, or a `--require-policy`
  tool without a passing decision from that policy;
- a malformed oversight receipt, or a reviewer countersignature that
  doesn't verify.

Reported, not failing:
- each human decision, whether it was reviewer-signed, and its review
  time;
- approvals faster than `--min-review-seconds` (possible
  rubber-stamping);
- every policy decision.

## 4. Limits

- Ordering for stops uses signed times. It holds under the same
  honest-at-the-time assumption as RECEIPT-CHAINS.md §1.4, and is
  strongest when both sides are in one chain with timestamped checkpoints.
- A human decision that was never recorded is invisible. The evidence
  value comes from `require_approval` *policies*: if an action needs an
  approval, its absence is an error.
- `presented_hash` proves *what* was shown, not that the reviewer read it.
  `review_seconds` and the countersignature are the supporting evidence.
