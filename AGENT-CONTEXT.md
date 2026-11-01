# Agent Context and Causality

**Version:** 1.0 (additive to RECEIPT-SPEC.md v1.0)
**Status:** Draft

A receipt proves *what* happened. Audits and incident reviews also ask:

- **Who** acted: which agent, which version, in which deployment?
- **For whom:** on whose behalf?
- **Under what authority:** which scopes, granted by whom, valid until when?
- **Because of what:** which model response asked for this action?

This profile adds one optional signed object, `execution.context`, to
operational receipts (`model`, `tool`, `data_flow`, `orchestration`,
`outcome`, `oversight`, `policy_decision`, `incident`, `erasure`,
`evidence_pack`). It sits inside `execution`, so the existing signature
covers it. Model receipts also gain `requested_tool_calls`.

## 1. Recording it

```python
from traceseal_observe import Authorization, Principal, agent_context, caused_by, requested_tool_calls

with agent_context(
    agent_id="support-bot", agent_version="2.3.1", deployment="prod-eu",
    tenant="acme", session_id=session.id,
    principal=Principal.user(user.id, pepper=PEPPER),
    authorization=Authorization(scopes=["refunds:write"], grant=oauth_claims,
                                granted_by=Principal.public("organisation", "acme-ops"),
                                expires_at="2026-11-01T00:00:00Z"),
):
    response, model_receipt = observe_anthropic(client, request, key)
    for block in response.content:
        if block.type == "tool_use":
            with caused_by(model_receipt, tool_call_id=block.id):
                result, tool_receipt = observe_tool(block.name, key,
                                                    lambda: run(block), args=block.input)
```

No call site changes. Every operational receipt signed inside the block
carries the context, including chained receipts and streams. A stream
records the context that was active when the call *started*. Contexts nest
(inner fields override outer ones) and follow Python `contextvars`, so they
are isolated per thread and per asyncio task. Threads you start don't
inherit a context unless you copy it in with `contextvars.copy_context()`.

If an OpenTelemetry span is active and no `trace_id` is set, the span's
W3C trace and span ids are recorded, which links receipts to existing
traces.

## 2. Fields

```json
"context": {
  "context_version": "1.0",
  "agent":         {"id": "support-bot", "version": "2.3.1", "deployment": "prod-eu"},
  "principal":     {"kind": "user", "ref": "hmac-sha256:<64 hex>"},
  "tenant":        "acme",
  "session_id":    "s-42",
  "trace":         {"trace_id": "<32 hex>", "span_id": "<16 hex>", "parent_span_id": "<16 hex>"},
  "authorization": {"scopes": ["refunds:write"], "grant_hash": "sha256:<hex>",
                    "granted_by": {"kind": "organisation", "ref": "id:acme-ops"},
                    "expires_at": "2026-11-01T00:00:00Z"},
  "caused_by":     ["sha256:<receipt hash>"],
  "tool_call_id":  "toolu_01..."
}
```

All fields except `context_version` are optional. Text fields are 1–128
printable characters. Scopes are sorted, unique, printable, with no spaces,
and at most 64 of them. `caused_by` holds at most 64 receipt hashes. A
receipt can only cite receipts that already existed when it was signed,
because it commits to their hashes, so the causal graph is acyclic by
construction. Causes may be receipts from *other operators* (agent-to-agent
hand-offs across organisations).

### 2.1 Principals are commitments, not identifiers

```
ref = "hmac-sha256:" + hex(HMAC-SHA256(pepper, "<kind>:<id>"))
```

- Receipts can be shared with auditors or published without revealing who
  the user was.
- Whoever holds the pepper can find every receipt about a person
  (`find_receipts_for_principal`, `traceseal-trace find-principal`), which
  serves GDPR Art. 15 access requests.
- **Destroying the pepper** makes those references permanently unlinkable
  while every signature stays valid. Use one pepper per tenant or per
  retention period so you can erase at that granularity.

`Principal.public(kind, id)` records a public identifier (`id:<value>`)
for services, agents and organisations. Refusing it for `user` is
deliberate. Kinds: `user`, `service`, `agent`, `organisation`.

### 2.2 Authorization

`grant` is the authorisation artefact: OAuth token claims, a signed
mandate, an approval record. Only `sha256_of(grant)` is recorded. Keep the
artefact itself; an auditor can then confirm it is the one the action ran
under.

### 2.3 `requested_tool_calls` on model receipts

```json
"requested_tool_calls": [{"id": "toolu_A", "name": "issue_refund", "input_hash": "sha256:<hex>"}]
```

The tool calls are extracted from the response:

| Source | Where the calls come from |
|---|---|
| Anthropic Messages | `tool_use` content blocks |
| OpenAI Chat Completions | `choices[0].message.tool_calls` |
| OpenAI Responses | `function_call` output items |
| Streams | reassembled from the deltas, for both providers |

`input_hash` is `sha256_of(arguments)`. JSON-string arguments are parsed
first, so it equals the `input_hash` of `observe_tool(args=<the same
arguments>)`. There are at most 128 entries; if a response had more,
`requested_tool_call_count` gives the total.

## 3. Verifying it

```bash
traceseal-trace verify receipts/*.json --require-scope issue_refund=refunds:write
```

```
[FAIL] 3 receipts, 1 causal links, agents: {'support-bot': 3}
  model:claude-x -> tool:issue_refund  [toolu_A] arguments_differ
  requested, not executed: send_email [toolu_B] from model:claude-x
  unprompted (no model cause): tool:export_customers
  ERROR: tool:issue_refund: missing required scope(s) ['refunds:write']
  warning: tool:issue_refund: ran with different arguments than the model requested
```

For each tool receipt that cites a model receipt with a `tool_call_id`,
the result is one of:

| Status | Meaning |
|---|---|
| `matched` | the model requested this call, with this name and these exact arguments |
| `arguments_differ` | the call was requested, but the tool ran with different arguments (the agent's code changed them) |
| `name_differs` | the call id matched, but the tool name did not |
| `not_requested` | the cited model response never requested this call. **Error.** |

The verifier also reports:
- requested calls that no supplied receipt executed;
- tool receipts with no model cause (`unprompted_tool_receipts`): the
  agent's own code acted, not the model;
- causes that weren't supplied (`unresolved_causes`).

Authorisation **errors**:
- an action whose time (`started_at`, otherwise `observed_at` or
  `chained_at`) is after `authorization.expires_at`;
- with `required_scopes`, a tool receipt whose context lacks a required
  scope.

## 4. What this proves, and what it doesn't

**Proves:**
- The operator signed these attributions at the time.
- A tool receipt cites exactly that model receipt.
- The model response, as the operator recorded it, did or did not request
  that call with those arguments.

**Doesn't prove:**
- That the model provider actually returned that response. Receipts are
  operator attestations; see the README's trust model.
- That the attributions are true. An operator could label an action with
  the wrong user or a scope it didn't have. What it can't do is change the
  label later without breaking the signature, the chain and any checkpoint
  a third party holds.

## 5. Mapping to obligations

This mapping is informational, not legal advice.

- **EU AI Act Art. 12(2)** (high-risk systems; from 2 December 2027 for
  Annex III and 2 August 2028 for Annex I): logs that support identifying
  risk situations and monitoring operation. `agent`, `principal` and
  `trace` supply that context. The extra content listed in Art. 12(3)
  applies only to remote biometric identification systems.
- **Art. 14 human oversight:** `granted_by` and `authorization` record who
  authorised the agent. Human decisions are recorded with `oversight`
  receipts ([HUMAN-OVERSIGHT](HUMAN-OVERSIGHT.md)).
- **Art. 26(5)–(6) deployer monitoring:** `unprompted_tool_receipts` and
  `arguments_differ` are anomalies a deployer would want to notice; they
  support, and do not replace, monitoring under the provider's
  instructions for use.
- **GDPR Art. 15 / 17:** principal commitments allow access lookups.
  Destroying the pepper removes the ability to link *every* commitment
  under it to a person. Whether that amounts to erasure, or makes the
  data anonymous, is a legal assessment. Until then, commitments are
  **pseudonymised personal data** for whoever holds the pepper (GDPR
  Art. 4(5), Recital 26), and so are hashes of guessable values.
  Art. 5(1)(c): receipts hold hashes and commitments, not values.
