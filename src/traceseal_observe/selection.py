"""Deterministic policy-selection receipts for Open Registry Phase 2B.0.

This module is intentionally an independent Python implementation of Open
Registry's pure Go selection contract.  It never observes a source, reads a
repository, or trusts a resolver-supplied selection.  Signing and witnessing
both reconstruct every policy, candidate, evaluation, preference, and decision
commitment from the supplied bundle before using TraceSeal's public receipt API.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from traceseal_observe import (
    Receipt,
    canonical_dumps,
    sign_execution_receipt,
    verify_receipt_signature,
)
from traceseal_observe.resolution import (
    ResolutionWitnessError,
    _load_key_safely,
    _read_json_safely,
    _receipt_from_dict,
    _write_receipt_safely,
)
from traceseal_observe.signed_time import (
    SIGNED_TIME_PROFILE_VERSION,
    SignedTimeProfileError,
    format_utc_seconds,
    parse_utc_seconds,
    validate_signed_time_profile,
)

POLICY_SELECTION_VERSION = "1.0"
_POLICY_VERSION = "1.0"
_CANDIDATE_VERSION = "1.0"
_CANDIDATE_SET_VERSION = "1.0"
_EVIDENCE_VERSION = "1.0"
_DECISION_VERSION = "1.0"
_MAX_CANDIDATES = 16
_MAX_PREFERENCES = 5
_MAX_REASON_CODES = 9
_PROVIDERS = ("native", "huggingface", "modelscope")
_PROVIDER_RANK = {provider: index for index, provider in enumerate(_PROVIDERS)}
_CONTENT_RANK = {
    "remote_metadata_observed": 0,
    "selected_files_equivalent": 1,
    "native_content_verified": 2,
}
_PREFERENCES = {
    "platform_binding",
    "witnessed_history",
    "publisher_signature",
    "content_evidence",
    "provider_order",
}
_HASH_PREFIX = "sha256:"
_PROVENANCE = {
    "attestation_scope": "operator_policy_selection_evidence",
    "decision_semantics": "deterministic_requirements_preferences",
    "provider_truth": "not_attested",
    "provenance_version": "1.0",
}


class SelectionWitnessError(ValueError):
    """A stable, non-sensitive policy-selection refusal."""

    def __init__(self, code: str = "selection_evidence_invalid"):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DerivedSelectionEvidence:
    bundle_hash: str
    candidate_set_hash: str
    decision_hash: str
    decision_status: str
    evaluation_root: str
    policy_hash: str
    reason_codes: tuple[str, ...]
    selected_source: str


def _fail(code: str = "selection_evidence_invalid") -> None:
    raise SelectionWitnessError(code)


def _hash(value: Any) -> str:
    return _HASH_PREFIX + hashlib.sha256(canonical_dumps(value)).hexdigest()


def _is_hash(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith(_HASH_PREFIX):
        return False
    suffix = value[len(_HASH_PREFIX) :]
    return all(character in "0123456789abcdef" for character in suffix)


def _object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail()
    fields = set(value)
    if not required.issubset(fields) or not fields.issubset(required | optional):
        _fail()
    return value


def _exact_bool(value: Any) -> bool:
    if type(value) is not bool:
        _fail()
    return value


def _normalise_policy(value: Any) -> dict[str, Any]:
    policy = _object(
        value,
        {
            "allowed_sources",
            "preferences",
            "provider_order",
            "requirements",
            "selection_policy_version",
        },
    )
    if policy["selection_policy_version"] != _POLICY_VERSION:
        _fail("selection_policy_invalid")
    allowed = policy["allowed_sources"]
    provider_order = policy["provider_order"]
    preferences = policy["preferences"]
    if (
        not isinstance(allowed, list)
        or not 1 <= len(allowed) <= len(_PROVIDERS)
        or any(provider not in _PROVIDER_RANK for provider in allowed)
        or len(set(allowed)) != len(allowed)
        or not isinstance(provider_order, list)
        or len(provider_order) != len(_PROVIDERS)
        or set(provider_order) != set(_PROVIDERS)
        or not isinstance(preferences, list)
        or len(preferences) > _MAX_PREFERENCES
        or any(preference not in _PREFERENCES for preference in preferences)
        or len(set(preferences)) != len(preferences)
    ):
        _fail("selection_policy_invalid")
    requirements = _object(
        policy["requirements"],
        {
            "allow_superseded_publishers",
            "allow_unknown_publisher_status",
            "minimum_content_evidence",
            "reject_publisher_equivocation",
            "reject_revoked_publishers",
            "require_log_inclusion",
            "require_platform_binding",
            "require_publisher_signature",
            "require_witnessed_history",
        },
    )
    if requirements["minimum_content_evidence"] not in _CONTENT_RANK:
        _fail("selection_policy_invalid")
    normalised_requirements = {"minimum_content_evidence": requirements["minimum_content_evidence"]}
    for field in requirements:
        if field != "minimum_content_evidence":
            normalised_requirements[field] = _exact_bool(requirements[field])
    return {
        "allowed_sources": sorted(allowed, key=_PROVIDER_RANK.__getitem__),
        "preferences": list(preferences),
        "provider_order": list(provider_order),
        "requirements": normalised_requirements,
        "selection_policy_version": _POLICY_VERSION,
    }


def _publisher(value: Any) -> dict[str, Any]:
    publisher = _object(
        value,
        {
            "binding_status",
            "checkpoint_status",
            "history_state",
            "key_status",
            "log_inclusion",
            "signature_status",
        },
        {
            "binding_evidence_root",
            "history_evidence_root",
            "key_history_root",
            "log_evidence_root",
            "signature_evidence_root",
        },
    )

    def optional_root(status: str, absent: str, root: str) -> bool:
        present = root in publisher
        return (status == absent and not present) or (
            status != absent and present and _is_hash(publisher[root])
        )

    signature = publisher["signature_status"]
    binding = publisher["binding_status"]
    key = publisher["key_status"]
    history = publisher["history_state"]
    inclusion = publisher["log_inclusion"]
    checkpoint = publisher["checkpoint_status"]
    if (
        signature
        not in {
            "publisher_unsigned",
            "publisher_signature_valid",
            "publisher_signature_invalid",
            "publisher_attestation_stale",
        }
        or binding
        not in {
            "publisher_binding_missing",
            "publisher_key_self_claimed",
            "publisher_key_platform_bound",
            "publisher_binding_invalid",
        }
        or key not in {"active", "superseded", "revoked", "unknown"}
        or history not in {"unforked", "equivocation", "unknown"}
        or inclusion not in {"included", "not_provided"}
        or checkpoint not in {"witnessed", "not_witnessed"}
        or not optional_root(signature, "publisher_unsigned", "signature_evidence_root")
        or not optional_root(binding, "publisher_binding_missing", "binding_evidence_root")
        or not optional_root(key, "unknown", "key_history_root")
        or not optional_root(history, "unknown", "history_evidence_root")
    ):
        _fail("source_candidate_invalid")
    if inclusion == "not_provided":
        if "log_evidence_root" in publisher or checkpoint != "not_witnessed":
            _fail("source_candidate_invalid")
    elif not _is_hash(publisher.get("log_evidence_root")):
        _fail("source_candidate_invalid")
    return dict(publisher)


def _candidate(value: Any) -> dict[str, Any]:
    candidate = _object(
        value,
        {
            "availability",
            "candidate_evidence_root",
            "candidate_evidence_version",
            "content_evidence_level",
            "content_evidence_root",
            "provider",
            "publisher",
            "revision_hash",
            "source_identity_hash",
        },
    )
    if (
        candidate["candidate_evidence_version"] != _CANDIDATE_VERSION
        or candidate["provider"] not in _PROVIDER_RANK
        or candidate["availability"] not in {"available", "unavailable"}
        or candidate["content_evidence_level"] not in _CONTENT_RANK
        or (
            candidate["content_evidence_level"] == "native_content_verified"
            and candidate["provider"] != "native"
        )
        or any(
            not _is_hash(candidate[field])
            for field in (
                "candidate_evidence_root",
                "content_evidence_root",
                "revision_hash",
                "source_identity_hash",
            )
        )
    ):
        _fail("source_candidate_invalid")
    publisher = _publisher(candidate["publisher"])
    root_record = {
        "availability": candidate["availability"],
        "candidate_evidence_version": _CANDIDATE_VERSION,
        "content_evidence_level": candidate["content_evidence_level"],
        "content_evidence_root": candidate["content_evidence_root"],
        "provider": candidate["provider"],
        "publisher": publisher,
        "revision_hash": candidate["revision_hash"],
        "source_identity_hash": candidate["source_identity_hash"],
    }
    if candidate["candidate_evidence_root"] != _hash(root_record):
        _fail("source_candidate_invalid")
    return dict(candidate)


def _candidate_key(candidate: dict[str, Any]) -> tuple[int, str]:
    return _PROVIDER_RANK[candidate["provider"]], candidate["source_identity_hash"]


def _candidate_reference(candidate: dict[str, Any]) -> dict[str, str]:
    return {
        "provider": candidate["provider"],
        "source_identity_hash": candidate["source_identity_hash"],
    }


def _candidate_set(value: Any) -> dict[str, Any]:
    candidate_set = _object(
        value,
        {
            "candidate_set_hash",
            "candidate_set_version",
            "candidates",
            "canonical_id",
            "equivalence_root",
        },
    )
    candidates_value = candidate_set["candidates"]
    if (
        candidate_set["candidate_set_version"] != _CANDIDATE_SET_VERSION
        or not _is_hash(candidate_set["candidate_set_hash"])
        or not _is_hash(candidate_set["canonical_id"])
        or not _is_hash(candidate_set["equivalence_root"])
        or not isinstance(candidates_value, list)
        or not 1 <= len(candidates_value) <= _MAX_CANDIDATES
    ):
        _fail("candidate_set_invalid")
    candidates = sorted((_candidate(item) for item in candidates_value), key=_candidate_key)
    keys = [(item["provider"], item["source_identity_hash"]) for item in candidates]
    if len(set(keys)) != len(keys):
        _fail("candidate_set_invalid")
    normalised = {
        "candidate_set_hash": candidate_set["candidate_set_hash"],
        "candidate_set_version": _CANDIDATE_SET_VERSION,
        "candidates": candidates,
        "canonical_id": candidate_set["canonical_id"],
        "equivalence_root": candidate_set["equivalence_root"],
    }
    root_record = {key: value for key, value in normalised.items() if key != "candidate_set_hash"}
    if candidate_set["candidate_set_hash"] != _hash(root_record):
        _fail("candidate_set_invalid")
    return normalised


def _outcome(rule: str, evidence: str, passed: bool, reason: str) -> dict[str, Any]:
    return {
        "evidence": evidence,
        "reason_code": "" if passed else reason,
        "result": "pass" if passed else "fail",
        "rule": rule,
    }


def _signature_requirement(requirements: dict[str, Any], status: str) -> tuple[bool, str]:
    if status == "publisher_signature_invalid":
        return False, "publisher_signature_invalid"
    if status == "publisher_attestation_stale":
        return False, "publisher_attestation_stale"
    if status == "publisher_unsigned":
        return not requirements["require_publisher_signature"], "publisher_signature_missing"
    return True, ""


def _binding_requirement(requirements: dict[str, Any], status: str) -> tuple[bool, str]:
    if status == "publisher_binding_invalid":
        return False, "publisher_binding_invalid"
    if status == "publisher_key_platform_bound":
        return True, ""
    if status == "publisher_key_self_claimed":
        return not requirements["require_platform_binding"], "publisher_binding_not_platform_bound"
    return not requirements["require_platform_binding"], "publisher_binding_missing"


def _key_requirement(requirements: dict[str, Any], status: str) -> tuple[bool, str]:
    if status == "active":
        return True, ""
    if status == "superseded":
        return requirements["allow_superseded_publishers"], "publisher_key_superseded"
    if status == "revoked":
        return not requirements["reject_revoked_publishers"], "publisher_key_revoked"
    return requirements["allow_unknown_publisher_status"], "publisher_key_unknown"


def _evaluate_candidate(policy: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    requirements = policy["requirements"]
    publisher = candidate["publisher"]
    outcomes: list[dict[str, Any]] = []
    outcomes.append(
        _outcome(
            "source_allowed",
            candidate["provider"],
            candidate["provider"] in policy["allowed_sources"],
            "source_not_allowed",
        )
    )
    outcomes.append(
        _outcome(
            "source_available",
            candidate["availability"],
            candidate["availability"] == "available",
            "source_unavailable",
        )
    )
    outcomes.append(
        _outcome(
            "minimum_content_evidence",
            candidate["content_evidence_level"],
            _CONTENT_RANK[candidate["content_evidence_level"]]
            >= _CONTENT_RANK[requirements["minimum_content_evidence"]],
            "content_equivalence_insufficient",
        )
    )
    passed, reason = _signature_requirement(requirements, publisher["signature_status"])
    outcomes.append(_outcome("publisher_signature", publisher["signature_status"], passed, reason))
    passed, reason = _binding_requirement(requirements, publisher["binding_status"])
    outcomes.append(_outcome("publisher_binding", publisher["binding_status"], passed, reason))
    passed, reason = _key_requirement(requirements, publisher["key_status"])
    outcomes.append(_outcome("publisher_key_status", publisher["key_status"], passed, reason))
    outcomes.append(
        _outcome(
            "publisher_history",
            publisher["history_state"],
            publisher["history_state"] != "equivocation"
            or not requirements["reject_publisher_equivocation"],
            "publisher_history_equivocation",
        )
    )
    outcomes.append(
        _outcome(
            "publisher_history_log_inclusion",
            publisher["log_inclusion"],
            publisher["log_inclusion"] == "included"
            or not requirements["require_log_inclusion"],
            "publisher_history_unlogged",
        )
    )
    outcomes.append(
        _outcome(
            "publisher_history_witness",
            publisher["checkpoint_status"],
            publisher["checkpoint_status"] == "witnessed"
            or not requirements["require_witnessed_history"],
            "publisher_history_unwitnessed",
        )
    )
    reasons = [outcome["reason_code"] for outcome in outcomes if outcome["result"] == "fail"]
    if len(reasons) > _MAX_REASON_CODES:
        _fail()
    eligible = not reasons
    return {
        "candidate": _candidate_reference(candidate),
        "eligible": eligible,
        "reason_codes": ["candidate_eligible"] if eligible else reasons,
        "requirements": outcomes,
    }


def _preference_rank(
    policy: dict[str, Any], dimension: str, candidate: dict[str, Any]
) -> tuple[int, str]:
    publisher = candidate["publisher"]
    if dimension == "platform_binding":
        return (
            (1, "publisher_key_platform_bound")
            if publisher["binding_status"] == "publisher_key_platform_bound"
            else (0, "not_platform_bound")
        )
    if dimension == "witnessed_history":
        return (
            (1, "witnessed")
            if publisher["checkpoint_status"] == "witnessed"
            else (0, "not_witnessed")
        )
    if dimension == "publisher_signature":
        return (
            (1, "publisher_signature_valid")
            if publisher["signature_status"] == "publisher_signature_valid"
            else (0, "not_valid")
        )
    if dimension == "content_evidence":
        level = candidate["content_evidence_level"]
        return _CONTENT_RANK[level], level
    if dimension == "provider_order":
        index = policy["provider_order"].index(candidate["provider"])
        return len(policy["provider_order"]) - index, candidate["provider"]
    _fail("selection_policy_invalid")


def _preferences(
    policy: dict[str, Any], candidates: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contenders = list(candidates)
    trace: list[dict[str, Any]] = []
    for dimension in policy["preferences"]:
        if not contenders:
            break
        ranks = [_preference_rank(policy, dimension, candidate) for candidate in contenders]
        best_rank = max(rank for rank, _ in ranks)
        best_value = next(value for rank, value in ranks if rank == best_rank)
        contenders = sorted(
            [
                candidate
                for candidate in contenders
                if _preference_rank(policy, dimension, candidate)[0] == best_rank
            ],
            key=_candidate_key,
        )
        trace.append(
            {
                "dimension": dimension,
                "preferred_value": best_value,
                "remaining_candidates": [
                    _candidate_reference(candidate) for candidate in contenders
                ],
            }
        )
    return trace, contenders


def _derive_bundle(value: Any) -> tuple[dict[str, Any], DerivedSelectionEvidence]:
    bundle = _object(
        value,
        {
            "candidate_evaluations",
            "candidate_set",
            "candidate_set_hash",
            "decision",
            "evaluation_root",
            "event_type",
            "policy",
            "policy_hash",
            "preference_trace",
            "selection_evidence_version",
        },
    )
    if bundle["selection_evidence_version"] != _EVIDENCE_VERSION or bundle["event_type"] != "model_resolution":
        _fail()
    policy = _normalise_policy(bundle["policy"])
    policy_hash = _hash(policy)
    candidate_set = _candidate_set(bundle["candidate_set"])
    if bundle["policy_hash"] != policy_hash or bundle["candidate_set_hash"] != candidate_set["candidate_set_hash"]:
        _fail()
    evaluations = [_evaluate_candidate(policy, candidate) for candidate in candidate_set["candidates"]]
    eligible = [
        candidate
        for candidate, evaluation in zip(candidate_set["candidates"], evaluations)
        if evaluation["eligible"]
    ]
    trace, contenders = _preferences(policy, eligible)
    evaluation_root = _hash(
        {"candidate_evaluations": evaluations, "preference_trace": trace}
    )
    decision: dict[str, Any] = {
        "decision_status": "no_eligible_source",
        "decision_version": _DECISION_VERSION,
        "reason_codes": ["no_eligible_source"],
        "selected_source": "none",
    }
    if contenders:
        selected = sorted(contenders, key=_candidate_key)[0]
        decision.update(
            {
                "decision_status": "selected",
                "reason_codes": ["candidate_selected"],
                "selected_candidate": _candidate_reference(selected),
                "selected_source": selected["provider"],
            }
        )
    decision_record = {
        "candidate_set_hash": candidate_set["candidate_set_hash"],
        "decision_status": decision["decision_status"],
        "decision_version": _DECISION_VERSION,
        "evaluation_root": evaluation_root,
        "policy_hash": policy_hash,
        "reason_codes": decision["reason_codes"],
        "selected_source": decision["selected_source"],
    }
    if "selected_candidate" in decision:
        decision_record["selected_candidate"] = decision["selected_candidate"]
    decision["decision_hash"] = _hash(decision_record)
    expected = {
        "candidate_evaluations": evaluations,
        "candidate_set": candidate_set,
        "candidate_set_hash": candidate_set["candidate_set_hash"],
        "decision": decision,
        "evaluation_root": evaluation_root,
        "event_type": "model_resolution",
        "policy": policy,
        "policy_hash": policy_hash,
        "preference_trace": trace,
        "selection_evidence_version": _EVIDENCE_VERSION,
    }
    if canonical_dumps(expected) != canonical_dumps(bundle):
        _fail()
    derived = DerivedSelectionEvidence(
        bundle_hash=_hash(expected),
        candidate_set_hash=candidate_set["candidate_set_hash"],
        decision_hash=decision["decision_hash"],
        decision_status=decision["decision_status"],
        evaluation_root=evaluation_root,
        policy_hash=policy_hash,
        reason_codes=tuple(decision["reason_codes"]),
        selected_source=decision["selected_source"],
    )
    return expected, derived


def derive_selection_evidence(bundle: Any) -> DerivedSelectionEvidence:
    """Re-evaluate a Go selection bundle without trusting its decision fields."""
    return _derive_bundle(bundle)[1]


def _execution(derived: DerivedSelectionEvidence) -> dict[str, Any]:
    return {
        "candidate_set_hash": derived.candidate_set_hash,
        "decision_hash": derived.decision_hash,
        "decision_status": derived.decision_status,
        "evaluation_root": derived.evaluation_root,
        "evidence_bundle_hash": derived.bundle_hash,
        "event_type": "model_resolution",
        "policy_hash": derived.policy_hash,
        "policy_selection_version": POLICY_SELECTION_VERSION,
        "reason_codes": list(derived.reason_codes),
        "receipt_type": "model_resolution",
        "selected_source": derived.selected_source,
    }


def sign_selection_evidence(
    bundle: dict[str, Any],
    key_path: Path | str,
    *,
    observed_at: str | None = None,
) -> Receipt:
    derived = derive_selection_evidence(bundle)
    key = _load_key_safely(key_path)
    execution = _execution(derived)
    execution.update(
        {
            "observed_at": observed_at if observed_at is not None else format_utc_seconds(),
            "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
        }
    )
    return sign_execution_receipt(execution, dict(_PROVENANCE), key)


def _verify_original(value: Any, derived: DerivedSelectionEvidence) -> Receipt:
    receipt = _receipt_from_dict(value)
    try:
        verify_receipt_signature(receipt, "policy selection receipt")
        status = validate_signed_time_profile(receipt.execution, receipt.attestation)
    except (ValueError, SignedTimeProfileError) as exc:
        raise SelectionWitnessError("receipt_invalid") from exc
    if status != "valid":
        _fail("receipt_invalid")
    execution = dict(receipt.execution)
    execution.pop("observed_at", None)
    execution.pop("receipt_profile_version", None)
    if execution != _execution(derived) or receipt.provenance != _PROVENANCE:
        _fail("evidence_substitution")
    return receipt


def witness_selection_evidence(
    bundle: dict[str, Any],
    receipt_value: dict[str, Any],
    key_path: Path | str,
    *,
    now: datetime | None = None,
) -> Receipt:
    """Re-run policy evaluation and countersign only an identical decision."""
    derived = derive_selection_evidence(bundle)
    original = _verify_original(receipt_value, derived)
    key = _load_key_safely(key_path)
    original_signer = original.attestation.get("operator_fingerprint", "")
    original_public_key = original.attestation.get("operator_public_key", "")
    if key.fingerprint == original_signer or key.public_key_hex == original_public_key:
        _fail("witness_key_not_independent")
    try:
        resolver_observed_at = parse_utc_seconds(original.execution.get("observed_at"))
        verified_at = parse_utc_seconds(format_utc_seconds(now))
    except SignedTimeProfileError as exc:
        raise SelectionWitnessError("signed_time_invalid") from exc
    if resolver_observed_at > verified_at:
        _fail("signed_time_order_invalid")
    execution = _execution(derived)
    execution.update(
        {
            "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
            "receipt_type": "model_resolution_cosignature",
            "resolution_receipt_hash": original.receipt_hash,
            "resolver_observed_at": format_utc_seconds(resolver_observed_at),
            "verified_at": format_utc_seconds(verified_at),
            "verdict": "CONFIRMED",
            "witness_method": "policy_decision_rederivation",
        }
    )
    return sign_execution_receipt(
        execution,
        {
            "claim": "policy_decision_independently_rederived_and_confirmed",
            "method": "open_registry_policy_selection_v1",
            "original_signer": original_signer,
            "provenance_version": "1.0",
            "role": "witness",
        },
        key,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="traceseal-selection")
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign", help="sign policy-selection evidence")
    sign.add_argument("--evidence", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument("--observed-at")
    witness = commands.add_parser(
        "witness", help="independently re-evaluate and countersign a decision"
    )
    witness.add_argument("--evidence", required=True)
    witness.add_argument("--receipt", required=True)
    witness.add_argument("--key", required=True)
    witness.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        evidence = _read_json_safely(args.evidence)
        if args.command == "sign":
            receipt = sign_selection_evidence(
                evidence, args.key, observed_at=args.observed_at
            )
            label = "model_resolution policy receipt"
        else:
            receipt_value = _read_json_safely(args.receipt)
            receipt = witness_selection_evidence(evidence, receipt_value, args.key)
            label = "model_resolution_cosignature policy receipt"
        _write_receipt_safely(args.output, receipt)
        print(f"PASS {label}")
        return 0
    except SelectionWitnessError as exc:
        print(f"REFUSED {exc.code}", file=sys.stderr)
        return 1
    except ResolutionWitnessError as exc:
        print(f"REFUSED {exc.code}", file=sys.stderr)
        return 1
    except (ValueError, SignedTimeProfileError):
        print("REFUSED receipt_profile_invalid", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
