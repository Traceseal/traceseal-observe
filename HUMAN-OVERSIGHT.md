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
    subjects=[model_receipt], tool_call_ids=["toolu_A"],   # required for approved/modified
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
| `subject_receipt_hashes`, `tool_call_ids` | what the decision is about. `approved` and `modified` must name both: the model receipt that requested the call and the call ids. `resumed` must name the `stopped` decision it lifts |
| `presented_hash` | hash of what the reviewer was shown: evidence of what they had in front of them (relevant to Art. 14(4)(a), (c); it does not show they understood it) |
| `rationale_hash` | hash of the reviewer's reason |
| `modified_input_hash` | with `modified`: the arguments the reviewer approved instead |
| `review_started_at`, `decided_at`, `review_seconds` | signed review timing |
| `reviewer_public_key`, `reviewer_signature` | optional. The reviewer's own Ed25519 signature over canonical JSON of the oversight fields plus `purpose: "traceseal-oversight-reviewer/1"` |

Without a reviewer countersignature, an oversight receipt is the
operator's attestation that a person decided. A countersignature on its
own proves only that *some* key signed: the operator can generate a key
and countersign with it. It binds the decision to the reviewer only when
the verifier knows which keys belong to which reviewer, so verification
takes a **reviewer key registry**: a JSON object mapping each
`reviewer.ref` to the Ed25519 public key(s) (64 hex characters) allowed to
countersign for that reviewer.

```json
{"hmac-sha256:3f1c...": ["9a0b...e1"], "id:ops-lead": ["77d2...0c", "c41a...9f"]}
```

```python
verify_trace(receipts, reviewer_keys=registry)          # or
traceseal-trace verify receipts/*.json --reviewer-keys reviewers.json
```

| Countersignature | `reviewer_signed` |
|---|---|
| none | `false` (operator-attested) |
| valid, no registry supplied | `"unverified"`, with a warning. Never `true` |
| valid, key registered for this `reviewer.ref` | `true` |
| valid, key not registered for this `reviewer.ref` | **error**; the decision is not counted |
| made with the receipt's operator key (or any operator key in the set) | **error**; `sign_oversight` refuses it |
| invalid | **error** |

Keep the registry outside the operator's control (for example published by
the team that issues the reviewers' security keys). A hardware security
key per reviewer, used through `RemoteOperatorKey`, is the strong setup.

### Approvals

`sign_oversight(decision="approved" | "modified")` refuses to sign without
`subjects` and `tool_call_ids`, and refuses subject receipts that are not
model receipts. `verify_trace` applies the same rule when reading: an
approval or modification without both is an error and approves nothing,
so a blanket or id-only approval never satisfies `--require-approval`. An
approval covers a tool receipt only if the tool cites the approval, cites
a model receipt the approval names, and its `tool_call_id` is one the
approval names. It doesn't carry over to another model response that
reuses the same call id.

### Timing

Every approval must satisfy, in signed time:

    subject model receipt started_at <= review_started_at <= decided_at <= tool started_at

`sign_oversight` refuses a `review_started_at` or `decided_at` earlier than
the subject receipt's signed time. `verify_trace` reports a violation as an
error: an approval decided after the tool started, or a review that
"started" before the model response existed. `review_seconds` is signed as
given. Rubber-stamp detection (`--min-review-seconds`) uses the
**effective** review window, from the later of `review_started_at` and the
subject model receipt's time to `decided_at` (reported as
`effective_review_seconds`). With neither known, the check is reported as
not performed.

### Stops and resumes

A `stopped` decision applies, in signed order from the stop onwards:
- to every receipt in the same `session_id` (the receipt's
  `agent_context`);
- to tool receipts **without** a `session_id` in the same agent/tenant
  scope (a stop or action that leaves out `agent.id` or `tenant` doesn't
  narrow the scope);
- if the stop itself has no `session_id`, to every tool receipt in its
  agent/tenant scope.

A `resumed` decision lifts a stop only if it cites the stop
(`subjects=[stop_receipt]`; `sign_oversight` refuses a resume without one)
and is **strictly later** in signed order: by `chain_seq` when both are in
the same chain, otherwise by a strictly greater signed `decided_at`. On a
tie the stop wins. An action is covered by the resume only if it is
strictly later than the resume.

Signed order means `chain_seq` within one chain, otherwise the receipt's
signed time (`started_at`, `observed_at`, `decided_at` or `chained_at`,
strict `YYYY-MM-DDTHH:MM:SSZ`). The unsigned `attestation.attested_at` is
never used. `policy_decision` receipts carry a signed `decided_at` (from
1.6.0). A receipt whose order against a stop cannot be established is an
error: the check is reported as not performed, never passed.

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
    --min-review-seconds 10 \
    --reviewer-keys reviewers.json
```

These are **errors**:
- a `--require-approval` tool with no cited `approved`/`modified`
  decision naming the model receipt it cites and its `tool_call_id`;
- an `approved`/`modified` decision without `subjects` and
  `tool_call_ids`, or whose subject is not a model receipt;
- approval timing violations (see *Timing*), or an approval whose timing
  can't be checked because the tool or subject has no valid signed time
  (or, for a `--require-approval` tool, the approved model receipt wasn't
  supplied);
- a tool call executed although a human **rejected** it, *whether or not*
  the tool receipt cites the rejection. A rejection naming a model receipt
  but no `tool_call_ids` rejects every call that response requested;
- an action citing a `rejected` or `stopped` decision;
- an action whose arguments differ from what the model requested after a
  plain approval, or from `modified_input_hash` after a modification;
- an action after a `stopped` decision in its scope and not after a
  valid `resumed` (see *Stops and resumes*), or one whose order against
  the stop can't be established;
- an authorization expiry that can't be checked because the receipt has
  no valid signed time;
- an action citing a `deny` policy decision, or a `--require-policy`
  tool without a passing decision from that policy;
- a malformed oversight receipt, or a reviewer countersignature that
  doesn't verify, uses an operator key, or (with a registry) uses a key
  not registered for the reviewer.

Reported, not failing:
- each human decision, whether it was reviewer-signed (`true`,
  `"unverified"` or `false`), its signed and effective review time;
- countersignatures not checked against a registry;
- a `resumed` that cites no stop or isn't strictly later than it;
- approvals faster than `--min-review-seconds` (possible
  rubber-stamping);
- every policy decision.

## 4. Limits

- Ordering for stops and approvals uses `chain_seq` within a chain and
  signed times otherwise, at one-second resolution. It holds under the same
  honest-at-the-time assumption as RECEIPT-CHAINS.md §1.4, and is
  strongest when both sides are in one chain with timestamped checkpoints.
- A human decision that was never recorded is invisible. The evidence
  value comes from `require_approval` *policies*: if an action needs an
  approval, its absence is an error.
- `presented_hash` proves *what* was shown, not that the reviewer read it.
  `review_seconds` and the countersignature are the supporting evidence.
