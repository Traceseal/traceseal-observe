"""TraceSeal signing and independent witnessing for Open Registry evidence.

Open Registry constructs the deterministic evidence bundle from its real Go
resolver. This module independently re-derives that bundle's hash chain before
signing or witnessing it, while delegating every Ed25519 and receipt-envelope
operation to the public TraceSeal machinery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from traceseal_observe import (
    OperatorKey,
    Receipt,
    canonical_dumps,
    sign_execution_receipt,
    verify_receipt_signature,
)
from traceseal_observe.signed_time import (
    SIGNED_TIME_PROFILE_VERSION,
    SignedTimeProfileError,
    format_utc_seconds,
    is_signed_time_profile,
    parse_utc_seconds,
    validate_signed_time_profile,
)

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_POLICY_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_MAX_INPUT_BYTES = 2 << 20
_MAX_NATIVE_FILES = 10_000
_MAX_OBSERVATION_GAP_SECONDS = 86_400
_DEFAULT_OBSERVATION_GAP_SECONDS = 300
_SAFE_PROFILE_ERROR_CODES = frozenset(
    {
        "receipt_profile_version_invalid",
        "signed_time_invalid",
        "signed_time_order_invalid",
        "signed_time_profile_downgrade",
        "witness_method_invalid",
    }
)


class ResolutionWitnessError(ValueError):
    """Evidence or receipt validation failed; signing must not proceed."""

    def __init__(self, message: str, code: str = "resolution_evidence_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DerivedResolutionEvidence:
    bundle_hash: str
    candidate_set_hash: str
    decision_hash: str
    evidence_root: str
    evidence_strength: str
    model_identity_hash: str
    policy_hash: str
    reason_code: str
    revision_hash: str
    selected_source: str


def _fail(message: str, code: str = "resolution_evidence_invalid") -> None:
    raise ResolutionWitnessError(message, code)


def _hash_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hash_record(value: Any) -> str:
    return _hash_bytes(canonical_dumps(value))


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _require_object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("evidence object shape is invalid")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        _fail("evidence object shape is invalid")
    return value


def _require_hash(value: Any) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        _fail("evidence hash is invalid")
    return value


def _require_string(value: Any, allowed: set[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        _fail("evidence string is invalid")
    if allowed is not None and value not in allowed:
        _fail("evidence string is invalid")
    return value


def _derive_resolver(value: Any) -> str:
    resolver = _require_object(
        value, {"evidence_contract", "implementation", "version_hash"}
    )
    if resolver["evidence_contract"] != "native-first-huggingface-fallback-v1":
        _fail("resolver evidence contract is invalid")
    if resolver["implementation"] != "open-registry":
        _fail("resolver implementation is invalid")
    expected = _hash_record(
        {
            "evidence_contract": resolver["evidence_contract"],
            "implementation": resolver["implementation"],
        }
    )
    if _require_hash(resolver["version_hash"]) != expected:
        _fail("resolver version hash mismatch")
    return expected


def _derive_policy(value: Any) -> str:
    policy = _require_object(
        value,
        {
            "federated_provider",
            "native_ownership",
            "policy_version",
            "resolution_order",
        },
    )
    if policy["federated_provider"] != "huggingface":
        _fail("federated provider policy is invalid")
    if policy["native_ownership"] != "repository_wide":
        _fail("native ownership policy is invalid")
    if not isinstance(policy["policy_version"], str) or _POLICY_VERSION_RE.fullmatch(
        policy["policy_version"]
    ) is None:
        _fail("policy version is invalid")
    if policy["resolution_order"] != ["native", "huggingface"]:
        _fail("resolution order policy is invalid")
    return _hash_record(policy)


def _derive_native_content(value: Any) -> tuple[str, str, str]:
    native = _require_object(value, {"commit", "files", "revision"})
    if not isinstance(native["commit"], str) or _COMMIT_RE.fullmatch(
        native["commit"]
    ) is None:
        _fail("native commit is invalid")
    if native["revision"] != "main":
        _fail("native revision is invalid")
    files = native["files"]
    if not isinstance(files, list) or not files or len(files) > _MAX_NATIVE_FILES:
        _fail("native content set is invalid")
    previous = ""
    for file in files:
        entry = _require_object(file, {"content_digest", "path_hash", "size"})
        _require_hash(entry["content_digest"])
        path_hash = _require_hash(entry["path_hash"])
        if previous and path_hash <= previous:
            _fail("native content set ordering is invalid")
        previous = path_hash
        if isinstance(entry["size"], bool) or not isinstance(entry["size"], int):
            _fail("native file size is invalid")
        if entry["size"] < 0:
            _fail("native file size is invalid")
    return _hash_text(native["commit"]), _hash_record(files), _hash_text("main")


def _derive_remote_metadata(value: Any) -> str:
    remote = _require_object(value, {"revision"})
    if not isinstance(remote["revision"], str) or _COMMIT_RE.fullmatch(
        remote["revision"]
    ) is None:
        _fail("remote revision is invalid")
    return _hash_text(remote["revision"])


def derive_resolution_evidence(bundle: Any) -> DerivedResolutionEvidence:
    """Independently recompute and validate an Open Registry evidence bundle."""
    top = _require_object(
        bundle,
        {
            "decision",
            "event_type",
            "evidence_version",
            "observation",
            "request",
            "resolver",
            "result",
            "supporting_evidence",
        },
    )
    if top["evidence_version"] != "1.0" or top["event_type"] != "model_resolution":
        _fail("evidence discriminator is invalid")
    resolver_hash = _derive_resolver(top["resolver"])
    request = _require_object(top["request"], {"model_identity_hash"})
    model_identity_hash = _require_hash(request["model_identity_hash"])
    support = _require_object(
        top["supporting_evidence"],
        {"candidates", "policy"},
        {"native_content", "remote_metadata"},
    )
    policy_hash = _derive_policy(support["policy"])
    candidates = support["candidates"]
    if not isinstance(candidates, list):
        _fail("candidate set is invalid")

    decision = _require_object(
        top["decision"],
        {"decision_hash", "policy_hash", "reason_code", "selected_source"},
    )
    selected_source = _require_string(
        decision["selected_source"], {"native", "huggingface"}
    )
    observation = _require_object(
        top["observation"],
        {"candidate_set_hash", "native_state", "remote_state", "revision_hash"},
    )
    result = _require_object(top["result"], {"evidence_root", "evidence_strength"})

    if selected_source == "native":
        if set(support) != {"candidates", "native_content", "policy"}:
            _fail("native supporting evidence is invalid")
        commit_hash, content_set_hash, revision_hash = _derive_native_content(
            support["native_content"]
        )
        expected_candidates = [
            {
                "commit_hash": commit_hash,
                "content_set_hash": content_set_hash,
                "evidence_strength": "native_content_verified",
                "revision_hash": revision_hash,
                "source": "native",
                "state": "hit",
            }
        ]
        reason_code = "native_precedence"
        native_state, remote_state = "hit", "not_consulted"
        evidence_strength = "native_content_verified"
    else:
        if set(support) != {"candidates", "policy", "remote_metadata"}:
            _fail("remote supporting evidence is invalid")
        revision_hash = _derive_remote_metadata(support["remote_metadata"])
        expected_candidates = [
            {
                "evidence_strength": "native_repository_absence_observed",
                "source": "native",
                "state": "miss",
            },
            {
                "evidence_strength": "remote_metadata_observed",
                "revision_hash": revision_hash,
                "source": "huggingface",
                "state": "observed",
            },
        ]
        reason_code = "native_miss_federated"
        native_state, remote_state = "miss", "observed"
        evidence_strength = "remote_metadata_observed"

    if candidates != expected_candidates:
        _fail("candidate record mismatch")
    candidate_set_hash = _hash_record(candidates)
    if _require_hash(observation["candidate_set_hash"]) != candidate_set_hash:
        _fail("candidate set hash mismatch")
    if observation["native_state"] != native_state or observation["remote_state"] != remote_state:
        _fail("source observation state mismatch")
    if _require_hash(observation["revision_hash"]) != revision_hash:
        _fail("revision hash mismatch")
    if _require_hash(decision["policy_hash"]) != policy_hash:
        _fail("policy hash mismatch")
    if decision["reason_code"] != reason_code:
        _fail("decision reason mismatch")

    decision_record = {
        "policy_hash": policy_hash,
        "reason_code": reason_code,
        "selected_source": selected_source,
    }
    decision_hash = _hash_record(decision_record)
    if _require_hash(decision["decision_hash"]) != decision_hash:
        _fail("decision hash mismatch")
    if result["evidence_strength"] != evidence_strength:
        _fail("evidence strength mismatch")
    root_record = {
        "candidate_set_hash": candidate_set_hash,
        "decision_hash": decision_hash,
        "event_type": "model_resolution",
        "evidence_version": "1.0",
        "model_identity_hash": model_identity_hash,
        "policy_hash": policy_hash,
        "resolver_version_hash": resolver_hash,
        "revision_hash": revision_hash,
    }
    evidence_root = _hash_record(root_record)
    if _require_hash(result["evidence_root"]) != evidence_root:
        _fail("evidence root mismatch")

    return DerivedResolutionEvidence(
        bundle_hash=_hash_record(top),
        candidate_set_hash=candidate_set_hash,
        decision_hash=decision_hash,
        evidence_root=evidence_root,
        evidence_strength=evidence_strength,
        model_identity_hash=model_identity_hash,
        policy_hash=policy_hash,
        reason_code=reason_code,
        revision_hash=revision_hash,
        selected_source=selected_source,
    )


def _load_key_safely(path: Path | str) -> OperatorKey:
    key_path = Path(path)
    try:
        before = key_path.lstat()
    except OSError as exc:
        raise ResolutionWitnessError("signing key is unavailable", "key_invalid") from exc
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size != 32
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or mode & 0o077
    ):
        _fail("signing key is unsafe", "key_invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(key_path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                _fail("signing key changed during validation", "key_invalid")
            chunks: list[bytes] = []
            remaining = 33
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ResolutionWitnessError("signing key is unreadable", "key_invalid") from exc
    if len(raw) != 32:
        _fail("signing key is invalid", "key_invalid")
    try:
        return OperatorKey.from_raw_bytes("resolution", raw)
    except ValueError as exc:
        raise ResolutionWitnessError("signing key is invalid", "key_invalid") from exc


def _resolution_execution(derived: DerivedResolutionEvidence) -> dict[str, Any]:
    return {
        "candidate_set_hash": derived.candidate_set_hash,
        "decision_hash": derived.decision_hash,
        "evidence_bundle_hash": derived.bundle_hash,
        "evidence_root": derived.evidence_root,
        "evidence_strength": derived.evidence_strength,
        "evidence_version": "1.0",
        "event_type": "model_resolution",
        "model_identity_hash": derived.model_identity_hash,
        "policy_hash": derived.policy_hash,
        "reason_code": derived.reason_code,
        "receipt_type": "model_resolution",
        "revision_hash": derived.revision_hash,
        "selected_source": derived.selected_source,
    }


def _signed_resolution_execution(
    derived: DerivedResolutionEvidence, observed_at: str
) -> dict[str, Any]:
    execution = _resolution_execution(derived)
    execution.update(
        {
            "observed_at": observed_at,
            "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
        }
    )
    return execution


def sign_resolution_evidence(
    bundle: dict[str, Any],
    key_path: Path | str,
    *,
    observed_at: str | None = None,
) -> Receipt:
    """Re-derive and sign a deterministic model-resolution evidence bundle."""
    derived = derive_resolution_evidence(bundle)
    key = _load_key_safely(key_path)
    signed_observed_at = observed_at if observed_at is not None else format_utc_seconds()
    return sign_execution_receipt(
        _signed_resolution_execution(derived, signed_observed_at),
        {
            "attestation_scope": "operator_resolution_evidence",
            "provider_truth": "not_attested",
            "provenance_version": "1.0",
        },
        key,
    )


def _receipt_from_dict(value: Any) -> Receipt:
    receipt = _require_object(
        value, {"attestation", "execution", "provenance", "receipt_version"}
    )
    if receipt["receipt_version"] != "1.0":
        _fail("original receipt version is invalid", "receipt_invalid")
    if not isinstance(receipt["execution"], dict) or not isinstance(
        receipt["provenance"], dict
    ) or not isinstance(receipt["attestation"], dict):
        _fail("original receipt shape is invalid", "receipt_invalid")
    return Receipt(
        receipt_version=receipt["receipt_version"],
        execution=receipt["execution"],
        provenance=receipt["provenance"],
        attestation=receipt["attestation"],
    )


def _verify_original_receipt(
    value: Any, derived: DerivedResolutionEvidence
) -> Receipt:
    receipt = _receipt_from_dict(value)
    try:
        verify_receipt_signature(receipt, "model resolution receipt")
    except ValueError as exc:
        raise ResolutionWitnessError(
            "original receipt signature is invalid", "receipt_invalid"
        ) from exc
    try:
        profile_status = validate_signed_time_profile(
            receipt.execution, receipt.attestation
        )
    except SignedTimeProfileError as exc:
        raise ResolutionWitnessError(
            "original receipt signed-time profile is invalid", "receipt_invalid"
        ) from exc
    actual_execution = dict(receipt.execution)
    if profile_status == "valid":
        actual_execution.pop("observed_at")
        actual_execution.pop("receipt_profile_version")
    if actual_execution != _resolution_execution(derived):
        _fail("original receipt does not match evidence", "evidence_substitution")
    if receipt.provenance != {
        "attestation_scope": "operator_resolution_evidence",
        "provider_truth": "not_attested",
        "provenance_version": "1.0",
    }:
        _fail("original receipt provenance is invalid", "receipt_invalid")
    return receipt


def _resolver_observation_time(receipt: Receipt) -> tuple[datetime, bool]:
    """Return the freshness basis and whether it was signed by the resolver."""
    try:
        if is_signed_time_profile(receipt.execution):
            return parse_utc_seconds(receipt.execution.get("observed_at")), True
        return parse_utc_seconds(receipt.attestation.get("attested_at")), False
    except SignedTimeProfileError as exc:
        raise ResolutionWitnessError(
            "original observation time is invalid", "freshness_invalid"
        ) from exc


def witness_resolution_evidence(
    bundle: dict[str, Any],
    receipt_value: dict[str, Any],
    key_path: Path | str,
    *,
    now: datetime | None = None,
) -> Receipt:
    """Re-derive evidence, verify the original, then countersign with another key."""
    derived = derive_resolution_evidence(bundle)
    original = _verify_original_receipt(receipt_value, derived)
    key = _load_key_safely(key_path)
    original_signer = original.attestation.get("operator_fingerprint", "")
    original_public_key = original.attestation.get("operator_public_key", "")
    if key.public_key_hex == original_public_key or key.fingerprint == original_signer:
        _fail(
            "witness key is not independent from the original signer",
            "witness_key_not_independent",
        )
    execution = {
        "candidate_set_hash": derived.candidate_set_hash,
        "decision_hash": derived.decision_hash,
        "evidence_bundle_hash": derived.bundle_hash,
        "evidence_root": derived.evidence_root,
        "policy_hash": derived.policy_hash,
        "receipt_type": "model_resolution_cosignature",
        "resolution_receipt_hash": original.receipt_hash,
        "selected_source": derived.selected_source,
        "verdict": "CONFIRMED",
    }
    resolver_time, resolver_time_is_signed = _resolver_observation_time(original)
    if resolver_time_is_signed:
        execution.update(
            {
                "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
                "resolver_observed_at": format_utc_seconds(resolver_time),
                "verified_at": format_utc_seconds(now),
                "witness_method": "supplied_evidence_rederivation",
            }
        )
    return sign_execution_receipt(
        execution,
        {
            "claim": "resolution_evidence_independently_rederived_and_confirmed",
            "method": "open_registry_resolution_evidence_v1",
            "original_signer": original_signer,
            "provenance_version": "1.0",
            "role": "witness",
        },
        key,
    )


def _reobservation_time(value: Any) -> datetime:
    try:
        return parse_utc_seconds(value)
    except SignedTimeProfileError as exc:
        raise ResolutionWitnessError(
            "original attestation time is invalid", "freshness_invalid"
        ) from exc


def _format_reobservation_time(value: datetime) -> str:
    try:
        return format_utc_seconds(value)
    except SignedTimeProfileError as exc:
        raise ResolutionWitnessError(
            "re-observation time is invalid", "freshness_invalid"
        ) from exc


def witness_resolution_reobservation(
    bundle: dict[str, Any],
    receipt_value: dict[str, Any],
    model_id: str,
    key_path: Path | str,
    *,
    observer: Any = None,
    max_observation_gap_seconds: int = _DEFAULT_OBSERVATION_GAP_SECONDS,
    now: datetime | None = None,
) -> Receipt:
    """Freshly re-observe Hugging Face revision metadata before countersigning.

    This is deliberately distinct from :func:`witness_resolution_evidence`,
    whose claim is limited to re-deriving the supplied offline evidence bundle.
    """
    from traceseal_observe.source_identity import (
        HuggingFaceSourceAdapter,
        SourceObservationError,
    )

    derived = derive_resolution_evidence(bundle)
    if derived.selected_source != "huggingface":
        _fail("remote re-observation requires a Hugging Face resolution")
    original = _verify_original_receipt(receipt_value, derived)
    key = _load_key_safely(key_path)
    original_signer = original.attestation.get("operator_fingerprint", "")
    original_public_key = original.attestation.get("operator_public_key", "")
    if key.public_key_hex == original_public_key or key.fingerprint == original_signer:
        _fail(
            "witness key is not independent from the original signer",
            "witness_key_not_independent",
        )
    if _hash_text(model_id) != derived.model_identity_hash:
        _fail("source identity does not match signed evidence", "source_identity_mismatch")
    if (
        isinstance(max_observation_gap_seconds, bool)
        or not isinstance(max_observation_gap_seconds, int)
        or max_observation_gap_seconds < 1
        or max_observation_gap_seconds > _MAX_OBSERVATION_GAP_SECONDS
    ):
        _fail("freshness policy is invalid", "freshness_invalid")
    original_attested_time = _reobservation_time(
        original.attestation.get("attested_at")
    )
    resolver_time, resolver_time_is_signed = _resolver_observation_time(original)
    observer = observer or HuggingFaceSourceAdapter()
    try:
        revision = observer.observe_revision(model_id)
    except SourceObservationError as exc:
        raise ResolutionWitnessError(
            "external source re-observation failed", "source_unavailable"
        ) from exc
    signed_revision = bundle.get("supporting_evidence", {}).get(
        "remote_metadata", {}
    ).get("revision")
    if revision != signed_revision or _hash_text(revision) != derived.revision_hash:
        _fail("external source changed", "source_changed")
    try:
        reobserved_time = parse_utc_seconds(format_utc_seconds(now))
    except SignedTimeProfileError as exc:
        raise ResolutionWitnessError(
            "re-observation time is invalid", "freshness_invalid"
        ) from exc
    gap = int((reobserved_time - resolver_time).total_seconds())
    if gap < 0 or gap > max_observation_gap_seconds:
        _fail("observation freshness policy failed", "observation_stale")
    execution = {
        "candidate_set_hash": derived.candidate_set_hash,
        "decision_hash": derived.decision_hash,
        "evidence_bundle_hash": derived.bundle_hash,
        "evidence_root": derived.evidence_root,
        "max_observation_gap_seconds": max_observation_gap_seconds,
        "original_attested_at": _format_reobservation_time(
            original_attested_time
        ),
        "policy_hash": derived.policy_hash,
        "receipt_type": "model_resolution_cosignature",
        "reobserved_at": _format_reobservation_time(reobserved_time),
        "resolution_receipt_hash": original.receipt_hash,
        "revision_hash": derived.revision_hash,
        "selected_source": derived.selected_source,
        "verdict": "CONFIRMED",
        "witness_method": "remote_source_reobservation",
    }
    if resolver_time_is_signed:
        execution.update(
            {
                "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
                "resolver_observed_at": _format_reobservation_time(resolver_time),
            }
        )
    return sign_execution_receipt(
        execution,
        {
            "claim": "remote_source_revision_independently_reobserved_and_confirmed",
            "method": "huggingface_public_metadata_reobservation_v1",
            "original_signer": original_signer,
            "provider": "huggingface",
            "provenance_version": "1.0",
            "role": "witness",
        },
        key,
    )


def _read_json_safely(path: Path | str) -> dict[str, Any]:
    input_path = Path(path)
    try:
        before = input_path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 2
            or before.st_size > _MAX_INPUT_BYTES
        ):
            _fail("input file is unsafe", "input_invalid")
        fd = os.open(input_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                _fail("input file changed during validation", "input_invalid")
            chunks = []
            remaining = _MAX_INPUT_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ResolutionWitnessError("input file is unavailable", "input_invalid") from exc
    if len(payload) > _MAX_INPUT_BYTES:
        _fail("input file is too large", "input_invalid")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("input JSON contains duplicate keys", "input_invalid")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResolutionWitnessError("input JSON is invalid", "input_invalid") from exc
    if not isinstance(value, dict):
        _fail("input JSON is invalid", "input_invalid")
    return value


def _write_bytes_safely(path: Path | str, payload: bytes) -> None:
    output = Path(path)
    parent = output.parent if output.parent != Path("") else Path(".")
    try:
        parent_info = parent.lstat()
        if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
            _fail("output directory is unsafe", "output_invalid")
        directory_fd = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
    except OSError as exc:
        raise ResolutionWitnessError("output directory is unavailable", "output_invalid") from exc
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(output.name, flags, 0o600, dir_fd=directory_fd)
        created = True
        try:
            offset = 0
            while offset < len(payload):
                count = os.write(fd, payload[offset:])
                if count <= 0:
                    raise OSError("short write")
                offset += count
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        if created:
            try:
                os.unlink(output.name, dir_fd=directory_fd)
            except OSError:
                pass
        raise ResolutionWitnessError("receipt output failed", "output_invalid") from exc
    finally:
        os.close(directory_fd)


def _write_json_safely(path: Path | str, value: dict[str, Any]) -> None:
    _write_bytes_safely(path, canonical_dumps(value) + b"\n")


def _write_receipt_safely(path: Path | str, receipt: Receipt) -> None:
    _write_bytes_safely(path, (receipt.to_json() + "\n").encode("utf-8"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="traceseal-resolution")
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign", help="sign an Open Registry evidence bundle")
    sign.add_argument("--evidence", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--output", required=True)
    sign.add_argument(
        "--observed-at",
        help="claimed resolution observation time (UTC RFC3339 seconds)",
    )
    witness = commands.add_parser(
        "witness", help="independently re-derive and countersign evidence"
    )
    witness.add_argument("--evidence", required=True)
    witness.add_argument("--receipt", required=True)
    witness.add_argument("--key", required=True)
    witness.add_argument("--output", required=True)
    reobserve = commands.add_parser(
        "witness-reobserve",
        help="freshly re-observe Hugging Face and countersign a remote resolution",
    )
    reobserve.add_argument("--evidence", required=True)
    reobserve.add_argument("--receipt", required=True)
    reobserve.add_argument("--model", required=True)
    reobserve.add_argument("--key", required=True)
    reobserve.add_argument("--output", required=True)
    reobserve.add_argument(
        "--max-observation-gap-seconds",
        type=int,
        default=_DEFAULT_OBSERVATION_GAP_SECONDS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        evidence = _read_json_safely(args.evidence)
        if args.command == "sign":
            receipt = sign_resolution_evidence(
                evidence, args.key, observed_at=args.observed_at
            )
            _write_receipt_safely(args.output, receipt)
            print("PASS model_resolution receipt")
        elif args.command == "witness":
            original = _read_json_safely(args.receipt)
            receipt = witness_resolution_evidence(evidence, original, args.key)
            _write_receipt_safely(args.output, receipt)
            print("PASS model_resolution_cosignature receipt")
        else:
            original = _read_json_safely(args.receipt)
            receipt = witness_resolution_reobservation(
                evidence,
                original,
                args.model,
                args.key,
                max_observation_gap_seconds=args.max_observation_gap_seconds,
            )
            _write_receipt_safely(args.output, receipt)
            print("PASS model_resolution_cosignature reobservation receipt")
        return 0
    except ResolutionWitnessError as exc:
        print(f"REFUSED {exc.code}", file=sys.stderr)
        return 1
    except ValueError as exc:
        code = str(exc)
        if code not in _SAFE_PROFILE_ERROR_CODES:
            code = "receipt_profile_invalid"
        print(f"REFUSED {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
