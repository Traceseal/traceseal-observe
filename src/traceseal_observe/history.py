"""Portable publisher-key rotation, revocation and provider-pinned history.

Historical Phase 2A.3 binding documents remain valid at the one fixed path.
The additive history wrapper embeds those exact documents and adds bounded,
strict rotation and revocation statements. No private key enters Open Registry.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traceseal_observe import canonical_dumps
from traceseal_observe.binding import (
    BINDING_PATH,
    BindingError,
    canonical_publisher_binding_bytes,
    decode_publisher_binding_document,
    validate_pinned_publisher_file,
    validate_publisher_binding_subject,
    verify_publisher_binding_document,
)
from traceseal_observe.publisher import (
    PUBLISHER_ALGORITHM,
    PublisherAttestationError,
    publisher_fingerprint,
    verify_detached_publisher_signature,
)
from traceseal_observe.resolution import (
    ResolutionWitnessError,
    _load_key_safely,
    _read_json_safely,
    _write_json_safely,
)
from traceseal_observe.signed_time import (
    SignedTimeProfileError,
    format_utc_seconds,
    parse_utc_seconds,
)
from traceseal_observe.source_identity import (
    MAX_SELECTED_FILE_BYTES,
    HuggingFaceSourceAdapter,
    ModelScopeSourceAdapter,
    SourceObservationError,
)

HISTORY_PATH = BINDING_PATH
HISTORY_VERSION = "1.0"
HISTORY_EVIDENCE_VERSION = "1.0"
CONTINUITY_VERSION = "1.0"
ROTATION_VERSION = "1.0"
REVOCATION_VERSION = "1.0"
ROTATION_STATEMENT_TYPE = "publisher_key_rotation"
REVOCATION_STATEMENT_TYPE = "publisher_key_revocation"
MAX_ROTATION_CHAIN_LENGTH = 16

KEY_ACTIVE = "active"
KEY_SUPERSEDED = "superseded"
KEY_REVOKED = "revoked"
KEY_UNKNOWN = "unknown"

REVOCATION_KEY_SELF = "key_self_revocation"
REVOCATION_PLATFORM = "platform_revocation"
REVOCATION_PLATFORM_SUPPLIED = "platform_revocation_supplied"
REVOCATION_PLATFORM_OBSERVED = "platform_revocation_observed"
REVOCATION_REASONS = frozenset({"compromised", "retired", "lost", "other"})

HISTORY_SUPPLIED = "publisher_key_history_supplied"
HISTORY_PLATFORM_OBSERVED = "publisher_key_history_platform_observed"
HISTORY_OFFLINE_METHOD = "publisher_key_history_rederivation"
HISTORY_REOBSERVATION_METHOD = "platform_key_history_reobservation"

HISTORY_LOG_ENTRY_TYPE = "publisher_identity_history"
HISTORY_LOG_ENTRY_VERSION = "1.0"
HISTORY_LOG_EVENT_BINDING = "binding"
HISTORY_LOG_EVENT_ROTATION = "rotation"
HISTORY_LOG_EVENT_REVOCATION = "revocation"
HISTORY_LOG_METHOD_PLATFORM_BINDING = "platform_binding_observed"
HISTORY_LOG_METHOD_DUAL_ROTATION = "dual_signature_rotation"

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")
_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")


class HistoryError(ValueError):
    """Key history is malformed, ambiguous, untrusted or source-changed."""

    def __init__(self, message: str, code: str = "publisher_history_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class HistoryVerification:
    binding_statement_hashes: tuple[str, ...]
    continuity_root: str
    current_fingerprint: str
    current_status: str
    keys: tuple[dict[str, str], ...]
    revocation_statement_hashes: tuple[str, ...]
    revocations: tuple[dict[str, str], ...]
    rotation_statement_hashes: tuple[str, ...]
    rotations: tuple[dict[str, str], ...]
    subject_hash: str


@dataclass(frozen=True)
class DerivedHistoryEvidence:
    continuity_root: str
    current_fingerprint: str
    current_status: str
    key_states: tuple[dict[str, str], ...]
    observations: tuple[dict[str, Any], ...]
    publisher_key_history_root: str


def _fail(message: str, code: str = "publisher_history_invalid") -> None:
    raise HistoryError(message, code)


def _hash_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _require_object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("publisher history object shape is invalid")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        _fail("publisher history object shape is invalid")
    return value


def _validate_effective_at(value: Any) -> str:
    if not isinstance(value, str):
        _fail("publisher history effective time is invalid", "publisher_issued_at_invalid")
    try:
        canonical = format_utc_seconds(parse_utc_seconds(value))
    except (SignedTimeProfileError, TypeError, ValueError) as exc:
        raise HistoryError(
            "publisher history effective time is invalid",
            "publisher_issued_at_invalid",
        ) from exc
    if canonical != value:
        _fail("publisher history effective time is invalid", "publisher_issued_at_invalid")
    return value


def _expected_subject(provider: str, repository: str) -> dict[str, str]:
    parts = repository.split("/") if isinstance(repository, str) else []
    subject = {
        "account": parts[0] if len(parts) == 2 else "",
        "provider": provider,
        "repository": repository,
        "scope": "repository",
    }
    try:
        return validate_publisher_binding_subject(subject)
    except BindingError as exc:
        raise HistoryError("publisher history subject is invalid", exc.code) from exc


def _validate_subject(value: Any, expected: dict[str, str]) -> dict[str, str]:
    try:
        subject = validate_publisher_binding_subject(value)
    except BindingError as exc:
        raise HistoryError("publisher history subject is invalid", exc.code) from exc
    if subject != expected:
        _fail("publisher history subject differs", "binding_subject_mismatch")
    return subject


def _validate_reference(value: Any) -> str:
    reference = _require_object(value, {"fingerprint"})["fingerprint"]
    if not isinstance(reference, str) or _FINGERPRINT_RE.fullmatch(reference) is None:
        _fail("publisher fingerprint is invalid", "publisher_fingerprint_mismatch")
    return reference


def _validate_signature_envelope(
    value: Any,
    expected_fingerprint: str,
    *,
    require_value: bool,
    missing_code: str,
) -> dict[str, str]:
    signature = _require_object(
        value, {"algorithm", "fingerprint", "public_key", "value"}
    )
    if signature["algorithm"] != PUBLISHER_ALGORITHM:
        _fail("publisher signature algorithm is invalid", "publisher_algorithm_invalid")
    public_key = signature["public_key"]
    if not isinstance(public_key, str) or _PUBLIC_KEY_RE.fullmatch(public_key) is None:
        _fail("publisher public key is invalid", "publisher_key_invalid")
    derived = publisher_fingerprint(bytes.fromhex(public_key))
    if (
        not isinstance(signature["fingerprint"], str)
        or _FINGERPRINT_RE.fullmatch(signature["fingerprint"]) is None
        or signature["fingerprint"] != derived
        or expected_fingerprint != derived
    ):
        _fail("publisher fingerprint does not match key", "publisher_fingerprint_mismatch")
    signature_value = signature["value"]
    if signature_value == "" and require_value:
        _fail("publisher history signature is missing", missing_code)
    if not isinstance(signature_value, str) or (
        signature_value != "" and _SIGNATURE_RE.fullmatch(signature_value) is None
    ):
        _fail("publisher signature is invalid", "publisher_signature_invalid")
    return dict(signature)


def _verify_signature(
    signature: dict[str, str], fingerprint: str, payload: bytes, missing_code: str
) -> None:
    _validate_signature_envelope(
        signature,
        fingerprint,
        require_value=True,
        missing_code=missing_code,
    )
    try:
        verify_detached_publisher_signature(signature, fingerprint, payload)
    except PublisherAttestationError as exc:
        raise HistoryError("publisher history signature is invalid", exc.code) from exc


def _validate_rotation_statement(value: Any) -> dict[str, Any]:
    statement = _require_object(
        value,
        {
            "effective_at",
            "new_publisher",
            "old_publisher",
            "statement_type",
            "subject",
        },
    )
    if statement["statement_type"] != ROTATION_STATEMENT_TYPE:
        _fail("publisher rotation statement type is invalid", "publisher_rotation_invalid")
    old_fingerprint = _validate_reference(statement["old_publisher"])
    new_fingerprint = _validate_reference(statement["new_publisher"])
    if old_fingerprint == new_fingerprint:
        _fail("publisher key cannot rotate to itself", "rotation_self")
    _validate_effective_at(statement["effective_at"])
    try:
        validate_publisher_binding_subject(statement["subject"])
    except BindingError as exc:
        raise HistoryError("publisher rotation subject is invalid", exc.code) from exc
    return statement


def publisher_key_rotation_signing_bytes(document: Any) -> bytes:
    value = _require_object(
        document, {"acceptance", "authorisation", "rotation_version", "statement"}
    )
    if value["rotation_version"] != ROTATION_VERSION:
        _fail("publisher rotation version is invalid", "publisher_rotation_invalid")
    statement = _validate_rotation_statement(value["statement"])
    return canonical_dumps(
        {"rotation_version": value["rotation_version"], "statement": statement}
    )


def verify_publisher_key_rotation(
    document: Any, expected_subject: dict[str, str]
) -> dict[str, Any]:
    value = _require_object(
        document, {"acceptance", "authorisation", "rotation_version", "statement"}
    )
    payload = publisher_key_rotation_signing_bytes(value)
    statement = value["statement"]
    _validate_subject(statement["subject"], expected_subject)
    old_fingerprint = statement["old_publisher"]["fingerprint"]
    new_fingerprint = statement["new_publisher"]["fingerprint"]
    _verify_signature(
        value["authorisation"],
        old_fingerprint,
        payload,
        "rotation_authorisation_missing",
    )
    _verify_signature(
        value["acceptance"],
        new_fingerprint,
        payload,
        "rotation_acceptance_missing",
    )
    return copy.deepcopy(value)


def _load_publisher_key(path: Path | str):  # noqa: ANN202
    try:
        return _load_key_safely(path)
    except ResolutionWitnessError as exc:
        raise HistoryError("publisher private key is invalid", "publisher_key_invalid") from exc


def sign_publisher_key_rotation_proposal(
    provider: str,
    account: str,
    repository: str,
    old_key_path: Path | str,
    new_public_key: str,
    *,
    effective_at: str | None = None,
) -> dict[str, Any]:
    expected = _expected_subject(provider, repository)
    if expected["account"] != account:
        _fail("publisher history subject differs", "binding_subject_mismatch")
    old_key = _load_publisher_key(old_key_path)
    if not isinstance(new_public_key, str) or _PUBLIC_KEY_RE.fullmatch(new_public_key) is None:
        _fail("successor public key is invalid", "publisher_key_invalid")
    old_fingerprint = publisher_fingerprint(bytes.fromhex(old_key.public_key_hex))
    new_fingerprint = publisher_fingerprint(bytes.fromhex(new_public_key))
    if old_fingerprint == new_fingerprint:
        _fail("publisher key cannot rotate to itself", "rotation_self")
    document: dict[str, Any] = {
        "acceptance": {
            "algorithm": PUBLISHER_ALGORITHM,
            "fingerprint": new_fingerprint,
            "public_key": new_public_key,
            "value": "",
        },
        "authorisation": {
            "algorithm": PUBLISHER_ALGORITHM,
            "fingerprint": old_fingerprint,
            "public_key": old_key.public_key_hex,
            "value": "",
        },
        "rotation_version": ROTATION_VERSION,
        "statement": {
            "effective_at": _validate_effective_at(
                effective_at if effective_at is not None else format_utc_seconds()
            ),
            "new_publisher": {"fingerprint": new_fingerprint},
            "old_publisher": {"fingerprint": old_fingerprint},
            "statement_type": ROTATION_STATEMENT_TYPE,
            "subject": expected,
        },
    }
    payload = publisher_key_rotation_signing_bytes(document)
    document["authorisation"]["value"] = old_key.sign(payload).hex()
    return document


def accept_publisher_key_rotation(
    proposal: Any, new_key_path: Path | str
) -> dict[str, Any]:
    value = _require_object(
        copy.deepcopy(proposal),
        {"acceptance", "authorisation", "rotation_version", "statement"},
    )
    payload = publisher_key_rotation_signing_bytes(value)
    statement = value["statement"]
    old_fingerprint = statement["old_publisher"]["fingerprint"]
    new_fingerprint = statement["new_publisher"]["fingerprint"]
    _verify_signature(
        value["authorisation"],
        old_fingerprint,
        payload,
        "rotation_authorisation_missing",
    )
    _validate_signature_envelope(
        value["acceptance"],
        new_fingerprint,
        require_value=False,
        missing_code="rotation_acceptance_missing",
    )
    if value["acceptance"]["value"] != "":
        _fail("rotation proposal is already accepted", "publisher_rotation_invalid")
    new_key = _load_publisher_key(new_key_path)
    actual = publisher_fingerprint(bytes.fromhex(new_key.public_key_hex))
    if actual != new_fingerprint or new_key.public_key_hex != value["acceptance"]["public_key"]:
        _fail("successor key differs", "rotation_successor_mismatch")
    value["acceptance"]["value"] = new_key.sign(payload).hex()
    verify_publisher_key_rotation(value, value["statement"]["subject"])
    return value


def _validate_revocation_statement(value: Any) -> dict[str, Any]:
    statement = _require_object(
        value,
        {
            "effective_at",
            "publisher",
            "reason_code",
            "statement_type",
            "subject",
        },
    )
    if statement["statement_type"] != REVOCATION_STATEMENT_TYPE:
        _fail("publisher revocation statement type is invalid", "publisher_revocation_invalid")
    _validate_reference(statement["publisher"])
    _validate_effective_at(statement["effective_at"])
    try:
        validate_publisher_binding_subject(statement["subject"])
    except BindingError as exc:
        raise HistoryError("publisher revocation subject is invalid", exc.code) from exc
    if statement["reason_code"] not in REVOCATION_REASONS:
        _fail("publisher revocation reason is invalid", "revocation_reason_invalid")
    return statement


def publisher_key_revocation_signing_bytes(document: Any) -> bytes:
    value = _require_object(
        document,
        {"method", "revocation_version", "statement"},
        {"signature"},
    )
    if value["revocation_version"] != REVOCATION_VERSION or value["method"] not in {
        REVOCATION_KEY_SELF,
        REVOCATION_PLATFORM,
    }:
        _fail("publisher revocation is invalid", "publisher_revocation_invalid")
    statement = _validate_revocation_statement(value["statement"])
    return canonical_dumps(
        {
            "method": value["method"],
            "revocation_version": value["revocation_version"],
            "statement": statement,
        }
    )


def verify_publisher_key_revocation(
    document: Any, expected_subject: dict[str, str]
) -> dict[str, Any]:
    value = _require_object(
        document,
        {"method", "revocation_version", "statement"},
        {"signature"},
    )
    payload = publisher_key_revocation_signing_bytes(value)
    _validate_subject(value["statement"]["subject"], expected_subject)
    fingerprint = value["statement"]["publisher"]["fingerprint"]
    if value["method"] == REVOCATION_KEY_SELF:
        if "signature" not in value:
            _fail("self revocation signature is missing", "publisher_signature_invalid")
        _verify_signature(
            value["signature"], fingerprint, payload, "publisher_signature_invalid"
        )
    elif "signature" in value:
        _fail("platform revocation cannot impersonate self revocation", "publisher_revocation_invalid")
    return copy.deepcopy(value)


def sign_publisher_key_self_revocation(
    provider: str,
    account: str,
    repository: str,
    key_path: Path | str,
    reason_code: str,
    *,
    effective_at: str | None = None,
) -> dict[str, Any]:
    subject = _expected_subject(provider, repository)
    if subject["account"] != account:
        _fail("publisher history subject differs", "binding_subject_mismatch")
    key = _load_publisher_key(key_path)
    fingerprint = publisher_fingerprint(bytes.fromhex(key.public_key_hex))
    document: dict[str, Any] = {
        "method": REVOCATION_KEY_SELF,
        "revocation_version": REVOCATION_VERSION,
        "signature": {
            "algorithm": PUBLISHER_ALGORITHM,
            "fingerprint": fingerprint,
            "public_key": key.public_key_hex,
            "value": "",
        },
        "statement": {
            "effective_at": _validate_effective_at(
                effective_at if effective_at is not None else format_utc_seconds()
            ),
            "publisher": {"fingerprint": fingerprint},
            "reason_code": reason_code,
            "statement_type": REVOCATION_STATEMENT_TYPE,
            "subject": subject,
        },
    }
    payload = publisher_key_revocation_signing_bytes(document)
    document["signature"]["value"] = key.sign(payload).hex()
    verify_publisher_key_revocation(document, subject)
    return document


def build_platform_revocation(
    provider: str,
    account: str,
    repository: str,
    fingerprint: str,
    reason_code: str,
    *,
    effective_at: str | None = None,
) -> dict[str, Any]:
    subject = _expected_subject(provider, repository)
    if subject["account"] != account or _FINGERPRINT_RE.fullmatch(fingerprint or "") is None:
        _fail("platform revocation subject is invalid", "binding_subject_mismatch")
    document = {
        "method": REVOCATION_PLATFORM,
        "revocation_version": REVOCATION_VERSION,
        "statement": {
            "effective_at": _validate_effective_at(
                effective_at if effective_at is not None else format_utc_seconds()
            ),
            "publisher": {"fingerprint": fingerprint},
            "reason_code": reason_code,
            "statement_type": REVOCATION_STATEMENT_TYPE,
            "subject": subject,
        },
    }
    verify_publisher_key_revocation(document, subject)
    return document


def _history_continuity_root(
    current_fingerprint: str,
    current_status: str,
    keys: list[dict[str, str]],
    rotations: list[dict[str, str]],
    revocations: list[dict[str, str]],
) -> str:
    semantic_revocations = [
        {
            "effective_at": item["effective_at"],
            "evidence_method": item["evidence_method"],
            "fingerprint": item["fingerprint"],
            "reason_code": item["reason_code"],
        }
        for item in revocations
    ]
    return _hash_bytes(
        canonical_dumps(
            {
                "current_fingerprint": current_fingerprint,
                "current_status": current_status,
                "keys": keys,
                "publisher_key_continuity_version": CONTINUITY_VERSION,
                "revocations": semantic_revocations,
                "rotations": rotations,
            }
        )
    )


def _legacy_history(
    document: dict[str, Any], provider: str, repository: str, platform_observed: bool
) -> HistoryVerification:
    return _verify_history_wrapper(
        {
            "bindings": [document],
            "publisher_history_version": HISTORY_VERSION,
            "revocations": [],
            "rotations": [],
        },
        provider,
        repository,
        platform_observed=platform_observed,
    )


def _verify_history_wrapper(
    document: Any,
    provider: str,
    repository: str,
    *,
    platform_observed: bool,
) -> HistoryVerification:
    value = _require_object(
        document,
        {"bindings", "publisher_history_version", "revocations", "rotations"},
    )
    bindings, rotations, revocations = (
        value["bindings"],
        value["rotations"],
        value["revocations"],
    )
    if not isinstance(bindings, list) or not isinstance(rotations, list) or not isinstance(revocations, list):
        _fail("publisher history arrays are invalid")
    if (
        value["publisher_history_version"] != HISTORY_VERSION
        or not 1 <= len(bindings) <= MAX_ROTATION_CHAIN_LENGTH + 1
        or len(rotations) > MAX_ROTATION_CHAIN_LENGTH
        or len(revocations) > MAX_ROTATION_CHAIN_LENGTH + 1
    ):
        if (
            len(bindings) > MAX_ROTATION_CHAIN_LENGTH + 1
            or len(rotations) > MAX_ROTATION_CHAIN_LENGTH
            or len(revocations) > MAX_ROTATION_CHAIN_LENGTH + 1
        ):
            _fail("publisher history exceeds limits", "publisher_history_limit")
        _fail("publisher history version or size is invalid")
    expected = _expected_subject(provider, repository)

    binding_by_fingerprint: dict[str, Any] = {}
    for binding in bindings:
        try:
            verified = verify_publisher_binding_document(binding, provider, repository)
        except BindingError as exc:
            raise HistoryError("publisher history binding is invalid", exc.code) from exc
        if verified.publisher_fingerprint in binding_by_fingerprint:
            _fail("publisher history contains a duplicate key", "publisher_history_ambiguous")
        binding_by_fingerprint[verified.publisher_fingerprint] = verified

    edges: dict[str, str] = {}
    incoming: dict[str, str] = {}
    rotation_by_old: dict[str, dict[str, Any]] = {}
    for rotation in rotations:
        verified_rotation = verify_publisher_key_rotation(rotation, expected)
        statement = verified_rotation["statement"]
        old_fingerprint = statement["old_publisher"]["fingerprint"]
        new_fingerprint = statement["new_publisher"]["fingerprint"]
        if old_fingerprint not in binding_by_fingerprint or new_fingerprint not in binding_by_fingerprint:
            _fail("rotation references an unbound key")
        if old_fingerprint in edges or new_fingerprint in incoming:
            _fail("publisher history forks or merges", "publisher_history_ambiguous")
        edges[old_fingerprint] = new_fingerprint
        incoming[new_fingerprint] = old_fingerprint
        rotation_by_old[old_fingerprint] = verified_rotation

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(fingerprint: str) -> None:
        if fingerprint in visiting:
            _fail("publisher history cycles", "publisher_history_cycle")
        if fingerprint in visited:
            return
        visiting.add(fingerprint)
        if fingerprint in edges:
            visit(edges[fingerprint])
        visiting.remove(fingerprint)
        visited.add(fingerprint)

    for fingerprint in binding_by_fingerprint:
        visit(fingerprint)
    roots = [fingerprint for fingerprint in binding_by_fingerprint if fingerprint not in incoming]
    if len(roots) != 1 or len(edges) != len(binding_by_fingerprint) - 1:
        _fail("publisher history is disconnected or ambiguous", "publisher_history_ambiguous")
    chain: list[str] = []
    current = roots[0]
    while True:
        chain.append(current)
        if current not in edges:
            break
        current = edges[current]
    if len(chain) != len(binding_by_fingerprint):
        _fail("publisher history is disconnected", "publisher_history_ambiguous")

    rotation_records: list[dict[str, str]] = []
    rotation_hashes: list[str] = []
    for fingerprint in chain[:-1]:
        rotation = rotation_by_old[fingerprint]
        statement = rotation["statement"]
        rotation_records.append(
            {
                "effective_at": statement["effective_at"],
                "new_fingerprint": statement["new_publisher"]["fingerprint"],
                "old_fingerprint": statement["old_publisher"]["fingerprint"],
            }
        )
        rotation_hashes.append(_hash_bytes(canonical_dumps(statement)))

    revocation_by_fingerprint: dict[str, dict[str, str]] = {}
    for revocation in revocations:
        verified_revocation = verify_publisher_key_revocation(revocation, expected)
        statement = verified_revocation["statement"]
        fingerprint = statement["publisher"]["fingerprint"]
        if fingerprint not in binding_by_fingerprint:
            _fail("revocation references an unbound key")
        if fingerprint in revocation_by_fingerprint:
            _fail("publisher key has ambiguous revocations", "publisher_history_ambiguous")
        method = REVOCATION_KEY_SELF
        if verified_revocation["method"] == REVOCATION_PLATFORM:
            method = (
                REVOCATION_PLATFORM_OBSERVED
                if platform_observed
                else REVOCATION_PLATFORM_SUPPLIED
            )
        revocation_by_fingerprint[fingerprint] = {
            "effective_at": statement["effective_at"],
            "evidence_method": method,
            "fingerprint": fingerprint,
            "reason_code": statement["reason_code"],
            "statement_hash": _hash_bytes(canonical_dumps(statement)),
        }

    key_states: list[dict[str, str]] = []
    ordered_revocations: list[dict[str, str]] = []
    binding_hashes: list[str] = []
    for index, fingerprint in enumerate(chain):
        status = KEY_ACTIVE if index == len(chain) - 1 else KEY_SUPERSEDED
        if fingerprint in revocation_by_fingerprint:
            status = KEY_REVOKED
            ordered_revocations.append(revocation_by_fingerprint[fingerprint])
        key_states.append({"fingerprint": fingerprint, "status": status})
        binding_hashes.append(binding_by_fingerprint[fingerprint].statement_hash)
    current_fingerprint = chain[-1]
    current_status = key_states[-1]["status"]
    continuity_root = _history_continuity_root(
        current_fingerprint,
        current_status,
        key_states,
        rotation_records,
        ordered_revocations,
    )
    return HistoryVerification(
        binding_statement_hashes=tuple(binding_hashes),
        continuity_root=continuity_root,
        current_fingerprint=current_fingerprint,
        current_status=current_status,
        keys=tuple(copy.deepcopy(key_states)),
        revocation_statement_hashes=tuple(
            item["statement_hash"] for item in ordered_revocations
        ),
        revocations=tuple(copy.deepcopy(ordered_revocations)),
        rotation_statement_hashes=tuple(rotation_hashes),
        rotations=tuple(copy.deepcopy(rotation_records)),
        subject_hash=binding_by_fingerprint[chain[0]].subject_hash,
    )


def verify_publisher_key_history_document(
    document: Any,
    provider: str,
    repository: str,
    *,
    platform_observed: bool = False,
) -> HistoryVerification:
    value = _require_object(
        document,
        set(),
        {
            "binding_version",
            "signature",
            "statement",
            "bindings",
            "publisher_history_version",
            "revocations",
            "rotations",
        },
    )
    legacy = "binding_version" in value
    history = "publisher_history_version" in value
    if legacy == history:
        _fail("publisher document shape is ambiguous")
    if legacy:
        try:
            verify_publisher_binding_document(value, provider, repository)
        except BindingError as exc:
            raise HistoryError("publisher binding is invalid", exc.code) from exc
        return _legacy_history(value, provider, repository, platform_observed)
    return _verify_history_wrapper(
        value,
        provider,
        repository,
        platform_observed=platform_observed,
    )


def decode_publisher_key_history_document(payload: bytes) -> dict[str, Any]:
    try:
        value = decode_publisher_binding_document(payload)
    except BindingError as exc:
        raise HistoryError("publisher history document is invalid", exc.code) from exc
    legacy = "binding_version" in value
    history = "publisher_history_version" in value
    if legacy == history:
        _fail("publisher document shape is ambiguous")
    if history:
        _require_object(
            value,
            {"bindings", "publisher_history_version", "revocations", "rotations"},
        )
    return value


def canonical_publisher_key_history_bytes(document: Any) -> bytes:
    value = copy.deepcopy(document)
    if "binding_version" in value:
        try:
            return canonical_publisher_binding_bytes(value)
        except BindingError as exc:
            raise HistoryError("publisher binding is invalid", exc.code) from exc
    wrapper = _require_object(
        value,
        {"bindings", "publisher_history_version", "revocations", "rotations"},
    )
    if not wrapper["bindings"]:
        _fail("publisher history has no binding")
    subject = wrapper["bindings"][0].get("statement", {}).get("subject", {})
    provider = subject.get("provider")
    repository = subject.get("repository")
    verify_publisher_key_history_document(wrapper, provider, repository)
    return canonical_dumps(wrapper)


def current_binding_from_publisher_document(
    document: Any, provider: str, repository: str
) -> dict[str, Any]:
    """Return the current key's exact v1 binding from either accepted shape."""
    value = copy.deepcopy(document)
    verified = verify_publisher_key_history_document(value, provider, repository)
    if "binding_version" in value:
        return value
    matches = [
        binding
        for binding in value["bindings"]
        if binding.get("signature", {}).get("fingerprint")
        == verified.current_fingerprint
    ]
    if len(matches) != 1:
        _fail("current publisher binding is ambiguous", "publisher_history_ambiguous")
    return copy.deepcopy(matches[0])


def assemble_publisher_key_history(
    bindings: list[dict[str, Any]],
    rotations: list[dict[str, Any]],
    revocations: list[dict[str, Any]],
    provider: str,
    repository: str,
) -> dict[str, Any]:
    document = {
        "bindings": copy.deepcopy(bindings),
        "publisher_history_version": HISTORY_VERSION,
        "revocations": copy.deepcopy(revocations),
        "rotations": copy.deepcopy(rotations),
    }
    verify_publisher_key_history_document(document, provider, repository)
    return document


def discover_publisher_key_history(
    provider: str, repository: str, adapter: Any
) -> dict[str, Any]:
    if provider not in {"huggingface", "modelscope"} or adapter is None:
        _fail("publisher history provider is invalid", "publisher_history_source_unavailable")
    try:
        file = adapter.fetch_pinned_file(repository, HISTORY_PATH)
        validate_pinned_publisher_file(file, provider, repository)
    except (SourceObservationError, BindingError) as exc:
        code = (
            "binding_document_too_large"
            if getattr(exc, "code", "") in {"response_too_large", "selected_file_too_large"}
            else "publisher_history_source_unavailable"
        )
        raise HistoryError("publisher history source is unavailable", code) from exc
    document = decode_publisher_key_history_document(file.content)
    verified = verify_publisher_key_history_document(
        document, provider, repository, platform_observed=True
    )
    return {
        "binding_path_hash": _hash_text(HISTORY_PATH),
        "binding_statement_hashes": list(verified.binding_statement_hashes),
        "continuity_root": verified.continuity_root,
        "current_fingerprint": verified.current_fingerprint,
        "current_status": verified.current_status,
        "document_hash": file.content_hash,
        "key_states": list(copy.deepcopy(verified.keys)),
        "provider": provider,
        "revocation_statement_hashes": list(verified.revocation_statement_hashes),
        "rotation_statement_hashes": list(verified.rotation_statement_hashes),
        "revision": copy.deepcopy(file.revision),
        "scope": "repository",
        "source_identity_hash": file.source_identity_hash,
        "status": HISTORY_PLATFORM_OBSERVED,
        "subject_hash": verified.subject_hash,
    }


def _require_hash(value: Any) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        _fail("publisher history hash is invalid", "publisher_history_evidence_invalid")
    return value


def _validate_key_states(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ROTATION_CHAIN_LENGTH + 1:
        _fail("publisher key states are invalid", "publisher_history_evidence_invalid")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        state = _require_object(item, {"fingerprint", "status"})
        fingerprint, status = state["fingerprint"], state["status"]
        if (
            not isinstance(fingerprint, str)
            or _FINGERPRINT_RE.fullmatch(fingerprint) is None
            or fingerprint in seen
            or status not in {KEY_ACTIVE, KEY_SUPERSEDED, KEY_REVOKED}
        ):
            _fail("publisher key state is invalid", "publisher_history_evidence_invalid")
        seen.add(fingerprint)
        result.append(dict(state))
    if any(
        state["status"] not in {KEY_SUPERSEDED, KEY_REVOKED}
        for state in result[:-1]
    ) or result[-1]["status"] not in {KEY_ACTIVE, KEY_REVOKED}:
        _fail("publisher key state sequence is invalid", "publisher_history_evidence_invalid")
    return result


def _validate_history_entry(value: Any) -> dict[str, Any]:
    entry = _require_object(
        value,
        {
            "binding_path_hash",
            "binding_statement_hashes",
            "continuity_root",
            "current_fingerprint",
            "current_status",
            "document_hash",
            "key_states",
            "provider",
            "revocation_statement_hashes",
            "rotation_statement_hashes",
            "revision",
            "scope",
            "source_identity_hash",
            "status",
            "subject_hash",
        },
    )
    provider = entry["provider"]
    revision = _require_object(entry["revision"], {"kind", "reference_hash", "value_hash"})
    expected_kind = "git_commit_sha1" if provider == "huggingface" else "file_commit_sha1"
    key_states = _validate_key_states(entry["key_states"])
    if (
        provider not in {"huggingface", "modelscope"}
        or entry["binding_path_hash"] != _hash_text(HISTORY_PATH)
        or entry["scope"] != "repository"
        or entry["status"] != HISTORY_PLATFORM_OBSERVED
        or entry["current_status"] not in {KEY_ACTIVE, KEY_REVOKED}
        or not isinstance(entry["current_fingerprint"], str)
        or _FINGERPRINT_RE.fullmatch(entry["current_fingerprint"]) is None
        or revision["kind"] != expected_kind
        or key_states[-1] != {
            "fingerprint": entry["current_fingerprint"],
            "status": entry["current_status"],
        }
    ):
        _fail("publisher history evidence entry is invalid", "publisher_history_evidence_invalid")
    for name in ("binding_statement_hashes", "rotation_statement_hashes", "revocation_statement_hashes"):
        hashes = entry[name]
        if not isinstance(hashes, list) or any(
            not isinstance(item, str) or _HASH_RE.fullmatch(item) is None for item in hashes
        ):
            _fail("publisher history statement hashes are invalid", "publisher_history_evidence_invalid")
    revoked_states = sum(state["status"] == KEY_REVOKED for state in key_states)
    if (
        len(entry["binding_statement_hashes"]) != len(key_states)
        or len(entry["rotation_statement_hashes"]) != len(key_states) - 1
        or len(entry["revocation_statement_hashes"]) != revoked_states
    ):
        _fail("publisher history statement counts differ", "publisher_history_evidence_invalid")
    for name in ("continuity_root", "document_hash", "source_identity_hash", "subject_hash"):
        _require_hash(entry[name])
    _require_hash(revision["reference_hash"])
    _require_hash(revision["value_hash"])
    result = copy.deepcopy(entry)
    result["key_states"] = key_states
    return result


def build_publisher_key_history_evidence(
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(entries, list) or not 1 <= len(entries) <= 2:
        _fail("publisher history observation set is invalid", "publisher_history_evidence_invalid")
    observations = sorted(
        (_validate_history_entry(entry) for entry in entries),
        key=lambda entry: entry["provider"],
    )
    first = observations[0]
    seen: set[str] = set()
    for observation in observations:
        if observation["provider"] in seen:
            _fail("publisher history provider is duplicated", "publisher_history_evidence_invalid")
        seen.add(observation["provider"])
        if (
            observation["continuity_root"] != first["continuity_root"]
            or observation["current_fingerprint"] != first["current_fingerprint"]
            or observation["current_status"] != first["current_status"]
            or observation["key_states"] != first["key_states"]
        ):
            _fail("publisher histories differ", "publisher_history_publisher_mismatch")
    evidence: dict[str, Any] = {
        "continuity_root": first["continuity_root"],
        "current_fingerprint": first["current_fingerprint"],
        "current_status": first["current_status"],
        "key_states": copy.deepcopy(first["key_states"]),
        "observations": observations,
        "publisher_key_history_evidence_version": HISTORY_EVIDENCE_VERSION,
    }
    evidence["publisher_key_history_root"] = _hash_bytes(canonical_dumps(evidence))
    return evidence


def derive_publisher_key_history_evidence(value: Any) -> DerivedHistoryEvidence:
    evidence = _require_object(
        value,
        {
            "continuity_root",
            "current_fingerprint",
            "current_status",
            "key_states",
            "observations",
            "publisher_key_history_evidence_version",
            "publisher_key_history_root",
        },
    )
    if evidence["publisher_key_history_evidence_version"] != HISTORY_EVIDENCE_VERSION:
        _fail("publisher history evidence version is invalid", "publisher_history_evidence_invalid")
    root = _require_hash(evidence["publisher_key_history_root"])
    expected = build_publisher_key_history_evidence(evidence["observations"])
    if canonical_dumps(expected) != canonical_dumps(evidence):
        _fail("publisher history evidence differs", "publisher_history_evidence_invalid")
    return DerivedHistoryEvidence(
        continuity_root=expected["continuity_root"],
        current_fingerprint=expected["current_fingerprint"],
        current_status=expected["current_status"],
        key_states=tuple(copy.deepcopy(expected["key_states"])),
        observations=tuple(copy.deepcopy(expected["observations"])),
        publisher_key_history_root=root,
    )


def verify_supplied_publisher_key_history(
    evidence: dict[str, Any],
    documents: dict[str, dict[str, Any]],
    repositories: dict[str, str],
) -> DerivedHistoryEvidence:
    """Re-derive portable history from supplied documents without platform claims.

    The provider-observed root is compared by separately reconstructing the
    observation-labelled semantics, while the witness method remains explicitly
    weaker because no registry was contacted.
    """
    derived = derive_publisher_key_history_evidence(evidence)
    providers = {entry["provider"] for entry in derived.observations}
    if (
        not isinstance(documents, dict)
        or not isinstance(repositories, dict)
        or set(documents) != providers
        or set(repositories) != providers
    ):
        _fail("supplied publisher history bundle is incomplete", "publisher_history_bundle_invalid")
    for entry in derived.observations:
        provider = entry["provider"]
        repository = repositories[provider]
        if _hash_text(repository) != entry["source_identity_hash"]:
            _fail("supplied publisher history subject differs", "binding_subject_mismatch")
        document = documents[provider]
        canonical = canonical_publisher_key_history_bytes(document)
        if _hash_bytes(canonical) != entry["document_hash"]:
            _fail("supplied publisher history document differs", "publisher_history_source_changed")
        # First verify the honest offline claim. Then reconstruct the original
        # provider-observed semantics only to compare its committed hashes.
        verify_publisher_key_history_document(document, provider, repository)
        observed = verify_publisher_key_history_document(
            document, provider, repository, platform_observed=True
        )
        if (
            observed.continuity_root != entry["continuity_root"]
            or observed.current_fingerprint != entry["current_fingerprint"]
            or observed.current_status != entry["current_status"]
            or list(observed.keys) != entry["key_states"]
            or list(observed.binding_statement_hashes)
            != entry["binding_statement_hashes"]
            or list(observed.rotation_statement_hashes)
            != entry["rotation_statement_hashes"]
            or list(observed.revocation_statement_hashes)
            != entry["revocation_statement_hashes"]
            or observed.subject_hash != entry["subject_hash"]
        ):
            _fail("supplied publisher history evidence differs", "publisher_history_source_changed")
    return derived


def verify_supplied_publisher_key_history_entry(
    evidence: dict[str, Any],
    document: dict[str, Any],
    provider: str,
    repository: str,
) -> DerivedHistoryEvidence:
    """Verify one provider-observed history commitment against supplied bytes.

    This is an offline re-derivation of a previously pinned observation; it is
    deliberately not labelled as a fresh provider re-observation.
    """
    derived = derive_publisher_key_history_evidence(evidence)
    matches = [
        entry for entry in derived.observations if entry["provider"] == provider
    ]
    if len(matches) != 1 or _hash_text(repository) != matches[0]["source_identity_hash"]:
        _fail(
            "supplied publisher history subject differs",
            "binding_subject_mismatch",
        )
    entry = matches[0]
    canonical = canonical_publisher_key_history_bytes(document)
    if _hash_bytes(canonical) != entry["document_hash"]:
        _fail(
            "supplied publisher history document differs",
            "publisher_history_source_changed",
        )
    verify_publisher_key_history_document(document, provider, repository)
    observed = verify_publisher_key_history_document(
        document, provider, repository, platform_observed=True
    )
    if (
        observed.continuity_root != entry["continuity_root"]
        or observed.current_fingerprint != entry["current_fingerprint"]
        or observed.current_status != entry["current_status"]
        or list(observed.keys) != entry["key_states"]
        or list(observed.binding_statement_hashes)
        != entry["binding_statement_hashes"]
        or list(observed.rotation_statement_hashes)
        != entry["rotation_statement_hashes"]
        or list(observed.revocation_statement_hashes)
        != entry["revocation_statement_hashes"]
        or observed.subject_hash != entry["subject_hash"]
    ):
        _fail(
            "supplied publisher history evidence differs",
            "publisher_history_source_changed",
        )
    return derived


def build_publisher_history_log_events(
    document: dict[str, Any], provider: str, repository: str
) -> list[dict[str, Any]]:
    """Derive deterministic governed log events from verified Phase 2A.4 state.

    The canonical event order is binding, all planned rotations in chain order,
    then semantic revocations in key-chain order. Claimed times never select a
    branch. Each event commits the exact Phase 2A.4 statement hash and the
    resulting continuity root.
    """
    verified = verify_publisher_key_history_document(
        document, provider, repository, platform_observed=True
    )
    value = copy.deepcopy(document)
    if "binding_version" in value:
        bindings = [value]
    else:
        bindings = value["bindings"]
    binding_by_fingerprint = {
        binding["signature"]["fingerprint"]: binding for binding in bindings
    }
    chain = [state["fingerprint"] for state in verified.keys]
    if set(binding_by_fingerprint) != set(chain):
        _fail("publisher history binding set differs")
    scope = {
        "account_hash": _hash_text(repository.split("/", 1)[0]),
        "provider": provider,
        "repository_hash": _hash_text(repository),
    }
    lineage = chain[0]
    events: list[dict[str, Any]] = []
    predecessor = "genesis"

    first_state = [{"fingerprint": lineage, "status": KEY_ACTIVE}]
    first_root = _history_continuity_root(lineage, KEY_ACTIVE, first_state, [], [])
    events.append(
        {
            "affected_fingerprint": lineage,
            "current_fingerprint": lineage,
            "current_key_status": KEY_ACTIVE,
            "entry_type": HISTORY_LOG_ENTRY_TYPE,
            "entry_version": HISTORY_LOG_ENTRY_VERSION,
            "event_time_claim": binding_by_fingerprint[lineage]["statement"][
                "issued_at"
            ],
            "event_type": HISTORY_LOG_EVENT_BINDING,
            "evidence_method": HISTORY_LOG_METHOD_PLATFORM_BINDING,
            "history_root": first_root,
            "predecessor_history_root": predecessor,
            "publisher_fingerprint": lineage,
            "scope": scope,
            "statement_hash": verified.binding_statement_hashes[0],
        }
    )
    predecessor = first_root

    rotation_prefix: list[dict[str, str]] = []
    for index, rotation in enumerate(verified.rotations):
        rotation_prefix.append(copy.deepcopy(rotation))
        prefix_chain = chain[: index + 2]
        key_states = [
            {
                "fingerprint": fingerprint,
                "status": KEY_ACTIVE
                if position == len(prefix_chain) - 1
                else KEY_SUPERSEDED,
            }
            for position, fingerprint in enumerate(prefix_chain)
        ]
        current = prefix_chain[-1]
        root = _history_continuity_root(
            current, KEY_ACTIVE, key_states, rotation_prefix, []
        )
        events.append(
            {
                "affected_fingerprint": current,
                "current_fingerprint": current,
                "current_key_status": KEY_ACTIVE,
                "entry_type": HISTORY_LOG_ENTRY_TYPE,
                "entry_version": HISTORY_LOG_ENTRY_VERSION,
                "event_time_claim": rotation["effective_at"],
                "event_type": HISTORY_LOG_EVENT_ROTATION,
                "evidence_method": HISTORY_LOG_METHOD_DUAL_ROTATION,
                "history_root": root,
                "predecessor_history_root": predecessor,
                "publisher_fingerprint": lineage,
                "scope": scope,
                "statement_hash": verified.rotation_statement_hashes[index],
            }
        )
        predecessor = root

    states = [
        {
            "fingerprint": fingerprint,
            "status": KEY_ACTIVE if index == len(chain) - 1 else KEY_SUPERSEDED,
        }
        for index, fingerprint in enumerate(chain)
    ]
    revocation_prefix: list[dict[str, str]] = []
    for index, revocation in enumerate(verified.revocations):
        method = revocation["evidence_method"]
        if method not in {REVOCATION_KEY_SELF, REVOCATION_PLATFORM_OBSERVED}:
            _fail(
                "publisher history log requires observed platform revocation",
                "publisher_history_log_platform_required",
            )
        for state in states:
            if state["fingerprint"] == revocation["fingerprint"]:
                state["status"] = KEY_REVOKED
                break
        revocation_prefix.append(copy.deepcopy(revocation))
        current = chain[-1]
        current_status = states[-1]["status"]
        root = _history_continuity_root(
            current,
            current_status,
            states,
            list(verified.rotations),
            revocation_prefix,
        )
        events.append(
            {
                "affected_fingerprint": revocation["fingerprint"],
                "current_fingerprint": current,
                "current_key_status": current_status,
                "entry_type": HISTORY_LOG_ENTRY_TYPE,
                "entry_version": HISTORY_LOG_ENTRY_VERSION,
                "event_time_claim": revocation["effective_at"],
                "event_type": HISTORY_LOG_EVENT_REVOCATION,
                "evidence_method": method,
                "history_root": root,
                "predecessor_history_root": predecessor,
                "publisher_fingerprint": lineage,
                "scope": scope,
                "statement_hash": verified.revocation_statement_hashes[index],
            }
        )
        predecessor = root
    if predecessor != verified.continuity_root:
        _fail("publisher history log event chain differs")
    return events


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "publisher-key: invalid invocation\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="publisher-key")
    commands = parser.add_subparsers(dest="command", required=True)

    propose = commands.add_parser("rotate-propose")
    propose.add_argument("--old-key", required=True)
    propose.add_argument("--new-public-key", required=True)
    for argument in (propose,):
        argument.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
        argument.add_argument("--account", required=True)
        argument.add_argument("--repository", required=True)
        argument.add_argument("--effective-at")
        argument.add_argument("--output", required=True)

    accept = commands.add_parser("rotate-accept")
    accept.add_argument("--proposal", required=True)
    accept.add_argument("--new-key", required=True)
    accept.add_argument("--output", required=True)

    revoke = commands.add_parser("revoke")
    revoke.add_argument("--key", required=True)
    platform = commands.add_parser("platform-revoke")
    platform.add_argument("--fingerprint", required=True)
    for command in (revoke, platform):
        command.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
        command.add_argument("--account", required=True)
        command.add_argument("--repository", required=True)
        command.add_argument("--reason", choices=tuple(sorted(REVOCATION_REASONS)), required=True)
        command.add_argument("--effective-at")
        command.add_argument("--output", required=True)

    assemble = commands.add_parser("assemble")
    assemble.add_argument("--binding", action="append", required=True)
    assemble.add_argument("--rotation", action="append", default=[])
    assemble.add_argument("--revocation", action="append", default=[])
    assemble.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
    assemble.add_argument("--repository", required=True)
    assemble.add_argument("--output", required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--document", required=True)
    verify.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
    verify.add_argument("--repository", required=True)

    remote = commands.add_parser("verify-provider")
    remote.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
    remote.add_argument("--repository", required=True)
    remote.add_argument("--output", required=True)

    log_events = commands.add_parser("log-events")
    log_events.add_argument("--history-evidence", required=True)
    log_events.add_argument("--document", required=True)
    log_events.add_argument(
        "--provider", choices=("huggingface", "modelscope"), required=True
    )
    log_events.add_argument("--repository", required=True)
    log_events.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        if args.command == "rotate-propose":
            value = sign_publisher_key_rotation_proposal(
                args.provider,
                args.account,
                args.repository,
                args.old_key,
                args.new_public_key,
                effective_at=args.effective_at,
            )
            _write_json_safely(args.output, value)
            print("PASS rotation_proposed")
        elif args.command == "rotate-accept":
            value = accept_publisher_key_rotation(
                _read_json_safely(args.proposal), args.new_key
            )
            _write_json_safely(args.output, value)
            print("PASS rotation_accepted")
        elif args.command == "revoke":
            value = sign_publisher_key_self_revocation(
                args.provider,
                args.account,
                args.repository,
                args.key,
                args.reason,
                effective_at=args.effective_at,
            )
            _write_json_safely(args.output, value)
            print("PASS key_self_revocation")
        elif args.command == "platform-revoke":
            value = build_platform_revocation(
                args.provider,
                args.account,
                args.repository,
                args.fingerprint,
                args.reason,
                effective_at=args.effective_at,
            )
            _write_json_safely(args.output, value)
            print("PASS platform_revocation_document")
        elif args.command == "assemble":
            value = assemble_publisher_key_history(
                [_read_json_safely(path) for path in args.binding],
                [_read_json_safely(path) for path in args.rotation],
                [_read_json_safely(path) for path in args.revocation],
                args.provider,
                args.repository,
            )
            _write_json_safely(args.output, value)
            print(f"PASS history_assembled publish_path={HISTORY_PATH}")
        elif args.command == "verify":
            verified = verify_publisher_key_history_document(
                _read_json_safely(args.document), args.provider, args.repository
            )
            print(
                "PASS publisher_key_history_supplied "
                f"current_key={verified.current_fingerprint} "
                f"history_entries={len(verified.keys)} status={verified.current_status}"
            )
        elif args.command == "verify-provider":
            adapter = (
                HuggingFaceSourceAdapter()
                if args.provider == "huggingface"
                else ModelScopeSourceAdapter()
            )
            entry = discover_publisher_key_history(
                args.provider, args.repository, adapter
            )
            evidence = build_publisher_key_history_evidence([entry])
            _write_json_safely(args.output, evidence)
            print(
                "PASS publisher_key_history_platform_observed "
                f"provider={args.provider} status={evidence['current_status']}"
            )
        else:
            evidence = _read_json_safely(args.history_evidence)
            document = _read_json_safely(args.document)
            verify_supplied_publisher_key_history_entry(
                evidence, document, args.provider, args.repository
            )
            events = build_publisher_history_log_events(
                document, args.provider, args.repository
            )
            _write_json_safely(
                args.output,
                {
                    "events": events,
                    "publisher_history_log_events_version": "1.0",
                },
            )
            print(f"PASS publisher_history_log_events count={len(events)}")
        return 0
    except (HistoryError, BindingError, ResolutionWitnessError, SourceObservationError) as exc:
        code = getattr(exc, "code", "publisher_history_invalid")
        if code in {"input_invalid", "key_invalid"}:
            code = "publisher_input_invalid" if code == "input_invalid" else "publisher_key_invalid"
        print(f"REFUSED {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
