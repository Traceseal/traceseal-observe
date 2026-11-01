"""Human oversight and policy-decision receipts.

EU AI Act Art. 14 requires high-risk AI systems to be designed so people can
understand, monitor, override and stop them, and deployers must assign that
oversight to competent people (Art. 26(2)). Proving it happened needs more
than "a human was in the loop" in a slide deck. These two receipt types make
each intervention a signed, chainable, verifiable record.

oversight — a person decided something about an agent action:
    approved | rejected | modified | escalated | stopped | resumed

    approval = sign_oversight(
        decision="approved", operator_key=key,
        subjects=[model_receipt], tool_call_ids=["toolu_A"],
        reviewer=Principal.user(reviewer_id, pepper=PEPPER), reviewer_role="claims-officer",
        presented={"summary": "...", "amount": 20},   # what the reviewer was shown
        rationale="customer verified by phone",        # why (hashed)
        review_started_at="2026-10-01T12:00:00Z",
        reviewer_key=reviewer_personal_key,            # optional countersignature
    )                                                  # (verified against a reviewer key registry)
    with caused_by(model_receipt, approval, tool_call_id="toolu_A"):
        observe_tool("issue_refund", key, run, args=call_input)

policy_decision — an automated control evaluated something:
    allow | deny | modify | flag

    result, decision = observe_policy("pii-filter", evaluate, content, key,
                                      stage="output", policy_definition=policy_config)

Both types are operational receipts: they pick up the ambient agent_context,
are chained by a ReceiptChain signer, and are checked by verify_trace
(require_approval, require_policy, executed-despite-rejection/deny, actions
after a stop, rubber-stamp review times).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Callable

OVERSIGHT_VERSION = "1.0"
POLICY_DECISION_VERSION = "1.0"
OVERSIGHT_DECISIONS = frozenset(
    {"approved", "rejected", "modified", "escalated", "stopped", "resumed"}
)
POLICY_DECISIONS = frozenset({"allow", "deny", "modify", "flag"})
POLICY_STAGES = frozenset(
    {"input", "output", "tool_call", "retrieval", "data_flow", "other"}
)
_REVIEWER_PURPOSE = "traceseal-oversight-reviewer/1"
_APPROVALS = frozenset({"approved", "modified"})

_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_LABEL_RE = re.compile(r"^[!-~]{1,128}$")
_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^(hmac-sha256:[0-9a-f]{64}|id:[^\x00-\x1f\x7f]{1,128})$")
_MAX_LIST = 64

# Fields of an oversight receipt the reviewer's countersignature covers.
_REVIEWER_STATEMENT_FIELDS = (
    "oversight_version", "decision", "subject_receipt_hashes", "tool_call_ids",
    "reviewer", "reviewer_role", "presented_hash", "rationale_hash",
    "modified_input_hash", "review_started_at", "decided_at", "reviewer_public_key",
)


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _hashes(items: Any, label: str) -> list[str]:
    from traceseal_observe.context import _receipt_hash

    items = list(items or ())
    if len(items) > _MAX_LIST:
        raise ValueError(f"at most {_MAX_LIST} {label}")
    return list(dict.fromkeys(_receipt_hash(i) for i in items))


def _labels(items: Any, label: str) -> list[str]:
    items = list(items or ())
    if len(items) > _MAX_LIST or any(
        not isinstance(i, str) or _LABEL_RE.fullmatch(i) is None for i in items
    ):
        raise ValueError(f"{label} must be at most {_MAX_LIST} printable tokens")
    return sorted(set(items))


def _hash_value(value: Any, label: str) -> str:
    from traceseal_observe import _require_strict_json, sha256_of

    _require_strict_json(value, label)
    return sha256_of(value)


def _signed_time(receipt: Any) -> datetime | None:
    """The receipt's own signed time (never the unsigned attested_at)."""
    ex = receipt.execution
    for key in ("started_at", "observed_at", "decided_at", "chained_at"):
        if key in ex:
            value = ex[key]
            if isinstance(value, str) and _UTC_RE.fullmatch(value):
                return _utc(value, key)
            return None
    return None


def _check_subject_receipts(
    decision: str, subjects: Any, decided: datetime, review_started_at: str | None
) -> None:
    """Refuse decisions whose subjects (given as Receipts) can't be right."""
    from traceseal_observe import Receipt

    started = _utc(review_started_at, "review_started_at") if review_started_at else None
    for subject in subjects or ():
        if not isinstance(subject, Receipt):
            continue
        rtype = subject.execution.get("receipt_type")
        if decision in _APPROVALS and rtype != "model":
            raise ValueError(f'decision="{decision}" subjects must be model receipts, got {rtype!r}')
        if decision == "resumed" and not (
                rtype == "oversight" and subject.execution.get("decision") == "stopped"):
            raise ValueError('decision="resumed" subjects must be the "stopped" decisions it lifts')
        if decision in _APPROVALS:
            when = _signed_time(subject)
            if when is None:
                raise ValueError("subject model receipt has no valid signed time")
            if started is not None and started < when:
                raise ValueError("review_started_at is before the subject model receipt existed")
            if decided < when:
                raise ValueError("decided_at is before the subject model receipt existed")


def normalize_reviewer_keys(registry: Any) -> dict[str, frozenset[str]]:
    """Validate a reviewer key registry.

    Maps a reviewer ref (the `reviewer.ref` of an oversight receipt, e.g.
    Principal.user(id, pepper=...).ref, or "id:...") to the Ed25519 public
    keys (64 hex characters, or a list of them) allowed to countersign for
    that reviewer. Raises ValueError if malformed.
    """
    if not isinstance(registry, dict):
        raise ValueError("reviewer key registry must map reviewer refs to public keys")
    out: dict[str, frozenset[str]] = {}
    for ref, keys in registry.items():
        if not isinstance(ref, str) or _REF_RE.fullmatch(ref) is None:
            raise ValueError(f"reviewer key registry: {ref!r} is not a reviewer ref")
        if isinstance(keys, str):
            keys = [keys]
        elif isinstance(keys, (set, frozenset, tuple)):
            keys = list(keys)
        if not isinstance(keys, list) or not keys or any(
                not isinstance(k, str) or _KEY_RE.fullmatch(k.lower()) is None for k in keys):
            raise ValueError(
                f"reviewer key registry: {ref!r} needs Ed25519 public keys as 64 hex characters")
        out[ref] = frozenset(k.lower() for k in keys)
    return out


def reviewer_statement(execution: dict[str, Any]) -> bytes:
    """Canonical bytes a reviewer's own key signs (and verifiers rebuild)."""
    from traceseal_observe import canonical_dumps

    body = {k: execution[k] for k in _REVIEWER_STATEMENT_FIELDS if k in execution}
    body["purpose"] = _REVIEWER_PURPOSE
    return canonical_dumps(body)


# ---------------------------------------------------------------------------
# Human oversight
# ---------------------------------------------------------------------------


def sign_oversight(
    *,
    decision: str,
    operator_key: Any,
    reviewer: Any,
    subjects: Any = (),
    tool_call_ids: Any = (),
    reviewer_role: str | None = None,
    presented: Any = None,
    presented_hash: str | None = None,
    rationale: Any = None,
    modified_input: Any = None,
    review_started_at: str | None = None,
    decided_at: str | None = None,
    reviewer_key: Any = None,
) -> Any:
    """Sign a human-oversight decision.

    subjects: receipts (or receipt hashes) the decision is about, e.g. the
        model receipt whose requested tool call is being approved.
    tool_call_ids: which requested calls the decision covers.
    reviewer: a Principal (users are recorded as keyed commitments).
    presented / presented_hash: what the reviewer was shown (hashed). This is
        the evidence that the reviewer could understand what they approved.
    rationale: the reviewer's reason (hashed, never stored).
    modified_input: for decision="modified", the arguments the reviewer
        approved instead of the model's (hashed like observe_tool(args=...)).
    review_started_at / decided_at: when review began and ended; their
        difference is signed as review_seconds.
    reviewer_key: the reviewer's own key (OperatorKey or RemoteOperatorKey,
        e.g. backed by a security key). If given, it countersigns the
        decision. It must not be the operator key. Verifiers count it as
        the reviewer's only if the key is in their reviewer key registry
        for this reviewer (see check_oversight).

    approved/modified need subjects (model receipts) and tool_call_ids;
    resumed needs the stopped decision(s) it lifts in subjects. Subject
    receipts passed as Receipts must not be later than review_started_at
    or decided_at.
    """
    from traceseal_observe import _now_iso, sign_execution_receipt
    from traceseal_observe.context import Principal

    if decision not in OVERSIGHT_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(OVERSIGHT_DECISIONS)}")
    if not isinstance(reviewer, Principal):
        raise ValueError("reviewer must be a Principal")
    decided = decided_at or _now_iso()
    decided_dt = _utc(decided, "decided_at")
    execution: dict[str, Any] = {
        "receipt_type": "oversight",
        "oversight_version": OVERSIGHT_VERSION,
        "decision": decision,
        "reviewer": reviewer.to_dict(),
        "decided_at": decided,
    }
    subject_hashes = _hashes(subjects, "subjects")
    if decision in _APPROVALS and (not subject_hashes or not tool_call_ids):
        raise ValueError(
            f'decision="{decision}" needs subjects (the model receipt that requested the '
            "call) and tool_call_ids: an approval is valid only for the response and calls it names"
        )
    if decision == "resumed" and not subject_hashes:
        raise ValueError('decision="resumed" needs the stop receipt it lifts in subjects')
    _check_subject_receipts(decision, subjects, decided_dt, review_started_at)
    if subject_hashes:
        execution["subject_receipt_hashes"] = subject_hashes
    if tool_call_ids:
        ids = list(tool_call_ids)
        if len(ids) > _MAX_LIST or any(
            not isinstance(i, str) or _TEXT_RE.fullmatch(i) is None for i in ids
        ):
            raise ValueError("tool_call_ids must be at most 64 printable strings")
        if not subject_hashes:
            raise ValueError("tool_call_ids need the model receipt in subjects")
        execution["tool_call_ids"] = sorted(set(ids))
    if reviewer_role is not None:
        if not isinstance(reviewer_role, str) or _TEXT_RE.fullmatch(reviewer_role) is None:
            raise ValueError("reviewer_role must be 1-128 printable characters")
        execution["reviewer_role"] = reviewer_role
    if presented is not None and presented_hash is not None:
        raise ValueError("pass presented or presented_hash, not both")
    if presented is not None:
        execution["presented_hash"] = _hash_value(presented, "presented")
    elif presented_hash is not None:
        if _SHA_RE.fullmatch(str(presented_hash)) is None:
            raise ValueError("presented_hash must be sha256:<hex>")
        execution["presented_hash"] = presented_hash
    if rationale is not None:
        execution["rationale_hash"] = _hash_value(rationale, "rationale")
    if decision == "modified":
        if modified_input is None:
            raise ValueError('decision="modified" needs modified_input')
        execution["modified_input_hash"] = _hash_value(modified_input, "modified_input")
    elif modified_input is not None:
        raise ValueError('modified_input is only valid with decision="modified"')
    if review_started_at is not None:
        started = _utc(review_started_at, "review_started_at")
        if started > decided_dt:
            raise ValueError("review_started_at is after decided_at")
        execution["review_started_at"] = review_started_at
        execution["review_seconds"] = int((decided_dt - started).total_seconds())
    if reviewer_key is not None:
        operator_hex = getattr(operator_key, "public_key_hex", None)
        if operator_hex is not None and reviewer_key.public_key_hex.lower() == str(operator_hex).lower():
            raise ValueError("reviewer_key is the operator key: a countersignature must come "
                             "from the reviewer's own key")
        execution["reviewer_public_key"] = reviewer_key.public_key_hex
        execution["reviewer_signature"] = reviewer_key.sign(
            reviewer_statement(execution)
        ).hex()
    provenance = {"provenance_version": "1.0", "provider_attestation": "none"}
    return sign_execution_receipt(execution, provenance, operator_key)


def check_oversight(
    receipt: Any,
    *,
    reviewer_keys: Any = None,
    operator_keys: Any = (),
) -> dict[str, Any]:
    """Validate an oversight receipt's fields (signature checked elsewhere).

    reviewer_keys: optional reviewer key registry (see
        normalize_reviewer_keys). A countersignature counts as
        reviewer_signed=True only if its key is registered for the
        receipt's reviewer.ref. Without a registry a valid countersignature
        is reported as reviewer_signed="unverified": anyone, including the
        operator, can make a key and countersign with it.
    operator_keys: further operator public keys (hex) a countersignature
        must not use; the receipt's own operator key is always refused.

    Returns a summary; raises ValueError if malformed, if an approval does
    not name its subject model receipt and tool_call_ids, or if a reviewer
    countersignature is present but invalid, made with an operator key, or
    (with a registry) made with a key not registered for the reviewer.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ex = receipt.execution
    if ex.get("oversight_version") != OVERSIGHT_VERSION:
        raise ValueError("unsupported oversight_version")
    if ex.get("decision") not in OVERSIGHT_DECISIONS:
        raise ValueError("oversight decision is invalid")
    reviewer = ex.get("reviewer")
    if not isinstance(reviewer, dict) or set(reviewer) != {"kind", "ref"} or not isinstance(
            reviewer.get("ref"), str):
        raise ValueError("oversight reviewer is malformed")
    decided = _utc(ex.get("decided_at"), "decided_at")
    for key in ("subject_receipt_hashes",):
        if key in ex and (not isinstance(ex[key], list) or any(
                not isinstance(h, str) or not _SHA_RE.fullmatch(h) for h in ex[key])):
            raise ValueError(f"{key} is malformed")
    if "tool_call_ids" in ex and (not isinstance(ex["tool_call_ids"], list) or any(
            not isinstance(i, str) for i in ex["tool_call_ids"])):
        raise ValueError("tool_call_ids is malformed")
    if ex.get("tool_call_ids") and not ex.get("subject_receipt_hashes"):
        raise ValueError("tool_call_ids without the model receipt in subject_receipt_hashes")
    if ex["decision"] in _APPROVALS and not (
            ex.get("subject_receipt_hashes") and ex.get("tool_call_ids")):
        raise ValueError(f"human {ex['decision']!r} decision does not name its subject model "
                         "receipt and tool_call_ids; it approves nothing")
    for key in ("presented_hash", "rationale_hash", "modified_input_hash"):
        if key in ex and not _SHA_RE.fullmatch(str(ex[key])):
            raise ValueError(f"{key} is malformed")
    if (ex["decision"] == "modified") != ("modified_input_hash" in ex):
        raise ValueError("modified_input_hash must appear exactly with decision 'modified'")
    review_seconds = None
    started = None
    if "review_started_at" in ex:
        started = _utc(ex["review_started_at"], "review_started_at")
        review_seconds = int((decided - started).total_seconds())
        if review_seconds < 0 or ex.get("review_seconds") != review_seconds:
            raise ValueError("review_seconds does not match the review times")
    reviewer_signed: bool | str = False
    if "reviewer_signature" in ex or "reviewer_public_key" in ex:
        try:
            key_hex = str(ex["reviewer_public_key"]).lower()
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
            key.verify(bytes.fromhex(ex["reviewer_signature"]), reviewer_statement(ex))
        except (KeyError, ValueError, TypeError, InvalidSignature):
            raise ValueError("reviewer countersignature is invalid") from None
        forbidden = {str(k).lower() for k in operator_keys or ()}
        forbidden.add(str((receipt.attestation or {}).get("operator_public_key", "")).lower())
        if key_hex in forbidden:
            raise ValueError("reviewer countersignature is made with the operator's own key; "
                             "it is not a reviewer signature")
        if reviewer_keys is None:
            reviewer_signed = "unverified"
        elif key_hex not in normalize_reviewer_keys(reviewer_keys).get(reviewer["ref"], ()):
            raise ValueError("reviewer countersignature key is not registered for this "
                             "reviewer in the reviewer key registry")
        else:
            reviewer_signed = True
    return {
        "hash": receipt.receipt_hash,
        "decision": ex["decision"],
        "reviewer": reviewer["ref"],
        "reviewer_role": ex.get("reviewer_role"),
        "subjects": ex.get("subject_receipt_hashes", []),
        "tool_call_ids": ex.get("tool_call_ids", []),
        "modified_input_hash": ex.get("modified_input_hash"),
        "decided_at": ex["decided_at"],
        "decided_at_dt": decided,
        "review_started_at_dt": started,
        "review_seconds": review_seconds,
        "reviewer_signed": reviewer_signed,
        "presented": "presented_hash" in ex,
    }


# ---------------------------------------------------------------------------
# Policy decisions
# ---------------------------------------------------------------------------


def sign_policy_decision(
    *,
    policy_id: str,
    decision: str,
    stage: str,
    operator_key: Any,
    subject: Any = None,
    subject_hash: str | None = None,
    subject_receipts: Any = (),
    policy_definition: Any = None,
    policy_hash: str | None = None,
    engine: str | None = None,
    categories: Any = (),
    rule_ids: Any = (),
    output: Any = None,
    decided_at: str | None = None,
) -> Any:
    """Sign the outcome of an automated control (guardrail, filter, policy).

    decided_at: when the control decided (UTC seconds, default now). Signed,
        so verify_trace can order the decision against stops and expiry.

    subject / subject_hash: what was evaluated (hashed).
    policy_definition / policy_hash: the exact policy configuration, so a
        later change to the policy shows up as a different hash.
    output: for decision="modify", the content after modification (hashed).
    """
    from traceseal_observe import _now_iso, sign_execution_receipt

    decided = decided_at or _now_iso()
    _utc(decided, "decided_at")
    if decision not in POLICY_DECISIONS:
        raise ValueError(f"decision must be one of {sorted(POLICY_DECISIONS)}")
    if stage not in POLICY_STAGES:
        raise ValueError(f"stage must be one of {sorted(POLICY_STAGES)}")
    if not isinstance(policy_id, str) or _LABEL_RE.fullmatch(policy_id) is None:
        raise ValueError("policy_id must be a printable token")
    execution: dict[str, Any] = {
        "receipt_type": "policy_decision",
        "policy_decision_version": POLICY_DECISION_VERSION,
        "policy_id": policy_id,
        "decision": decision,
        "stage": stage,
        "decided_at": decided,
    }
    if subject is not None and subject_hash is not None:
        raise ValueError("pass subject or subject_hash, not both")
    if subject is not None:
        execution["subject_hash"] = _hash_value(subject, "subject")
    elif subject_hash is not None:
        if _SHA_RE.fullmatch(str(subject_hash)) is None:
            raise ValueError("subject_hash must be sha256:<hex>")
        execution["subject_hash"] = subject_hash
    receipts = _hashes(subject_receipts, "subject_receipts")
    if receipts:
        execution["subject_receipt_hashes"] = receipts
    if policy_definition is not None and policy_hash is not None:
        raise ValueError("pass policy_definition or policy_hash, not both")
    if policy_definition is not None:
        execution["policy_hash"] = _hash_value(policy_definition, "policy_definition")
    elif policy_hash is not None:
        if _SHA_RE.fullmatch(str(policy_hash)) is None:
            raise ValueError("policy_hash must be sha256:<hex>")
        execution["policy_hash"] = policy_hash
    if engine is not None:
        if not isinstance(engine, str) or _TEXT_RE.fullmatch(engine) is None:
            raise ValueError("engine must be 1-128 printable characters")
        execution["engine"] = engine
    cats = _labels(categories, "categories")
    if cats:
        execution["categories"] = cats
    rules = _labels(rule_ids, "rule_ids")
    if rules:
        execution["rule_ids"] = rules
    if decision == "modify":
        if output is None:
            raise ValueError('decision="modify" needs output')
        execution["output_hash"] = _hash_value(output, "output")
    elif output is not None:
        raise ValueError('output is only valid with decision="modify"')
    provenance = {"provenance_version": "1.0", "provider_attestation": "none"}
    return sign_execution_receipt(execution, provenance, operator_key)


def observe_policy(
    policy_id: str,
    evaluate: Callable[[Any], Any],
    content: Any,
    operator_key: Any,
    *,
    stage: str,
    subject_receipts: Any = (),
    policy_definition: Any = None,
    engine: str | None = None,
) -> tuple[Any, Any]:
    """Run a guardrail and receipt its decision.

    `evaluate(content)` returns either a decision string, or a dict with
    "decision" and optionally "categories", "rule_ids" and "output" (the
    modified content). Exceptions in `evaluate` propagate: a control that
    failed to run did not decide anything, and must not look as if it allowed.
    Returns (evaluate's result, receipt).
    """
    result = evaluate(content)
    if isinstance(result, str):
        fields: dict[str, Any] = {"decision": result}
    elif isinstance(result, dict) and "decision" in result:
        fields = result
    else:
        raise ValueError('evaluate must return a decision string or a dict with "decision"')
    receipt = sign_policy_decision(
        policy_id=policy_id,
        decision=fields["decision"],
        stage=stage,
        operator_key=operator_key,
        subject=content,
        subject_receipts=subject_receipts,
        policy_definition=policy_definition,
        engine=engine,
        categories=fields.get("categories", ()),
        rule_ids=fields.get("rule_ids", ()),
        output=fields.get("output") if fields["decision"] == "modify" else None,
    )
    return result, receipt


def check_policy_decision(receipt: Any) -> dict[str, Any]:
    ex = receipt.execution
    if ex.get("policy_decision_version") != POLICY_DECISION_VERSION:
        raise ValueError("unsupported policy_decision_version")
    if ex.get("decision") not in POLICY_DECISIONS or ex.get("stage") not in POLICY_STAGES:
        raise ValueError("policy decision or stage is invalid")
    if not isinstance(ex.get("policy_id"), str):
        raise ValueError("policy_id is malformed")
    for key in ("subject_hash", "policy_hash", "output_hash"):
        if key in ex and not _SHA_RE.fullmatch(str(ex[key])):
            raise ValueError(f"{key} is malformed")
    if (ex["decision"] == "modify") != ("output_hash" in ex):
        raise ValueError("output_hash must appear exactly with decision 'modify'")
    if "decided_at" in ex:
        _utc(ex["decided_at"], "decided_at")
    return {
        "hash": receipt.receipt_hash,
        "policy_id": ex["policy_id"],
        "decision": ex["decision"],
        "stage": ex["stage"],
        "policy_hash": ex.get("policy_hash"),
        "categories": ex.get("categories", []),
    }
