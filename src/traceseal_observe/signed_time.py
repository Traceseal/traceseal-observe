"""Additive signed-time rules for TraceSeal Phase 2A receipt profiles.

The TraceSeal v1 envelope remains unchanged.  Only domain receipts declaring
``receipt_profile_version=1.1`` opt into these rules; historical receipts that
do not declare a profile version retain their original verification semantics.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

SIGNED_TIME_PROFILE_VERSION = "1.1"

_UTC_SECONDS_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ED25519_FINGERPRINT_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")
_OPERATOR_RECEIPT_TYPES = frozenset(
    {"model_resolution", "model_identity_observation"}
)
_WITNESS_RECEIPT_TYPES = frozenset(
    {"model_resolution_cosignature", "model_identity_cosignature"}
)
_PHASE2A_RECEIPT_TYPES = _OPERATOR_RECEIPT_TYPES | _WITNESS_RECEIPT_TYPES
_NEW_ONLY_FIELDS = frozenset(
    {"observed_at", "resolver_observed_at", "verified_at"}
)
_POLICY_SELECTION_FIELDS = frozenset(
    {
        "candidate_set_hash",
        "decision_hash",
        "decision_status",
        "evaluation_root",
        "evidence_bundle_hash",
        "event_type",
        "policy_hash",
        "policy_selection_version",
        "reason_codes",
        "selected_source",
    }
)
_POLICY_SELECTION_ONLY_FIELDS = frozenset(
    {"decision_status", "evaluation_root", "policy_selection_version", "reason_codes"}
)
_POLICY_SELECTION_OPERATOR_FIELDS = _POLICY_SELECTION_FIELDS | frozenset(
    {"observed_at", "receipt_profile_version", "receipt_type"}
)
_POLICY_SELECTION_WITNESS_FIELDS = _POLICY_SELECTION_FIELDS | frozenset(
    {
        "receipt_profile_version",
        "receipt_type",
        "resolution_receipt_hash",
        "resolver_observed_at",
        "verified_at",
        "verdict",
        "witness_method",
    }
)


class SignedTimeProfileError(ValueError):
    """A receipt's additive signed-time profile is invalid."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_utc_seconds(value: Any) -> datetime:
    """Parse the one canonical signed-time form: UTC RFC3339 seconds."""
    if not isinstance(value, str) or _UTC_SECONDS_RE.fullmatch(value) is None:
        raise SignedTimeProfileError("signed_time_invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SignedTimeProfileError("signed_time_invalid") from exc
    return parsed.replace(tzinfo=timezone.utc)


def format_utc_seconds(value: datetime | None = None) -> str:
    """Return an aware time as canonical UTC RFC3339 seconds."""
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise SignedTimeProfileError("signed_time_invalid")
    return (
        current.astimezone(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def is_signed_time_profile(execution: dict[str, Any]) -> bool:
    return execution.get("receipt_profile_version") == SIGNED_TIME_PROFILE_VERSION


def validate_signed_time_profile(
    execution: dict[str, Any], attestation: dict[str, Any]
) -> str:
    """Validate the additive profile and return its signed-time status.

    Status is ``valid`` for profile 1.1, ``legacy_not_required`` for the four
    historical Phase 2A profiles, and ``not_applicable`` for other TraceSeal
    receipt types.  No historical profile is globally reinterpreted.
    """
    receipt_type = execution.get("receipt_type")
    if receipt_type not in _PHASE2A_RECEIPT_TYPES:
        return "not_applicable"

    profile_version = execution.get("receipt_profile_version")
    if profile_version is None:
        if _NEW_ONLY_FIELDS.intersection(execution):
            raise SignedTimeProfileError("signed_time_profile_downgrade")
        return "legacy_not_required"
    if profile_version != SIGNED_TIME_PROFILE_VERSION:
        raise SignedTimeProfileError("receipt_profile_version_invalid")

    attested = parse_utc_seconds(attestation.get("attested_at"))
    if receipt_type in _OPERATOR_RECEIPT_TYPES:
        signed_time = parse_utc_seconds(execution.get("observed_at"))
    else:
        resolver_time = parse_utc_seconds(execution.get("resolver_observed_at"))
        method = execution.get("witness_method")
        if receipt_type == "model_identity_cosignature":
            if method != "remote_source_reobservation":
                raise SignedTimeProfileError("witness_method_invalid")
            signed_time = parse_utc_seconds(execution.get("reobserved_at"))
        elif method == "remote_source_reobservation":
            signed_time = parse_utc_seconds(execution.get("reobserved_at"))
        elif method == "supplied_evidence_rederivation":
            signed_time = parse_utc_seconds(execution.get("verified_at"))
        elif method == "policy_decision_rederivation":
            if execution.get("policy_selection_version") != "1.0":
                raise SignedTimeProfileError("witness_method_invalid")
            signed_time = parse_utc_seconds(execution.get("verified_at"))
        else:
            raise SignedTimeProfileError("witness_method_invalid")
        if resolver_time > signed_time:
            raise SignedTimeProfileError("signed_time_order_invalid")

    if signed_time > attested:
        raise SignedTimeProfileError("signed_time_order_invalid")
    _validate_policy_selection_profile(execution, receipt_type)
    history_fields = {
        "current_publisher_fingerprint",
        "publisher_key_history_root",
        "publisher_key_status",
    }
    present_history_fields = history_fields.intersection(execution)
    if present_history_fields:
        if present_history_fields != history_fields:
            raise SignedTimeProfileError("publisher_key_history_profile_invalid")
        if (
            not isinstance(execution["current_publisher_fingerprint"], str)
            or _ED25519_FINGERPRINT_RE.fullmatch(
                execution["current_publisher_fingerprint"]
            )
            is None
            or not isinstance(execution["publisher_key_history_root"], str)
            or _SHA256_RE.fullmatch(execution["publisher_key_history_root"])
            is None
            or execution["publisher_key_status"] not in {"active", "revoked"}
        ):
            raise SignedTimeProfileError("publisher_key_history_profile_invalid")
        if receipt_type == "model_identity_cosignature" and execution.get(
            "publisher_key_history_witness_method"
        ) not in {
            "platform_key_history_reobservation",
            "publisher_key_history_rederivation",
        }:
            raise SignedTimeProfileError("publisher_key_history_profile_invalid")
    return "valid"


def _validate_policy_selection_profile(
    execution: dict[str, Any], receipt_type: str
) -> None:
    marker = execution.get("policy_selection_version")
    if marker is None:
        if _POLICY_SELECTION_ONLY_FIELDS.intersection(execution):
            raise SignedTimeProfileError("policy_selection_profile_invalid")
        return
    if (
        marker != "1.0"
        or receipt_type not in {"model_resolution", "model_resolution_cosignature"}
        or not _POLICY_SELECTION_FIELDS.issubset(execution)
        or execution.get("event_type") != "model_resolution"
        or any(
            not isinstance(execution.get(field), str)
            or _SHA256_RE.fullmatch(execution[field]) is None
            for field in (
                "candidate_set_hash",
                "decision_hash",
                "evaluation_root",
                "evidence_bundle_hash",
                "policy_hash",
            )
        )
    ):
        raise SignedTimeProfileError("policy_selection_profile_invalid")
    expected_fields = (
        _POLICY_SELECTION_OPERATOR_FIELDS
        if receipt_type == "model_resolution"
        else _POLICY_SELECTION_WITNESS_FIELDS
    )
    if set(execution) != expected_fields:
        raise SignedTimeProfileError("policy_selection_profile_invalid")
    status = execution.get("decision_status")
    selected = execution.get("selected_source")
    reasons = execution.get("reason_codes")
    if status == "selected":
        valid_decision = selected in {"native", "huggingface", "modelscope"} and reasons == [
            "candidate_selected"
        ]
    elif status == "no_eligible_source":
        valid_decision = selected == "none" and reasons == ["no_eligible_source"]
    else:
        valid_decision = False
    if not valid_decision:
        raise SignedTimeProfileError("policy_selection_profile_invalid")
    if receipt_type == "model_resolution":
        if any(
            field in execution
            for field in (
                "resolution_receipt_hash",
                "resolver_observed_at",
                "verified_at",
                "verdict",
                "witness_method",
            )
        ):
            raise SignedTimeProfileError("policy_selection_profile_invalid")
    elif (
        execution.get("witness_method") != "policy_decision_rederivation"
        or execution.get("verdict") != "CONFIRMED"
        or not isinstance(execution.get("resolution_receipt_hash"), str)
        or _SHA256_RE.fullmatch(execution["resolution_receipt_hash"]) is None
    ):
        raise SignedTimeProfileError("policy_selection_profile_invalid")
