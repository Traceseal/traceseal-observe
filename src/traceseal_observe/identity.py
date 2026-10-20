"""TraceSeal signing and fresh witnessing for canonical model identity evidence."""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from traceseal_observe import Receipt, sign_execution_receipt, verify_receipt_signature
from traceseal_observe.binding import (
    BindingError,
    build_publisher_binding_evidence,
    derive_publisher_binding_evidence,
    discover_publisher_binding,
)
from traceseal_observe.history import (
    HistoryError,
    build_publisher_key_history_evidence,
    derive_publisher_key_history_evidence,
    discover_publisher_key_history,
    verify_supplied_publisher_key_history,
)
from traceseal_observe.history_log import (
    HistoryLogError,
    WITNESS_METHOD_OFFLINE as HISTORY_LOG_WITNESS_METHOD_OFFLINE,
    derive_publisher_history_log_evidence,
    production_log_vkeys,
)
from traceseal_observe.resolution import (
    ResolutionWitnessError,
    _SAFE_PROFILE_ERROR_CODES,
    _load_key_safely,
    _read_json_safely,
    _receipt_from_dict,
    _write_receipt_safely,
)
from traceseal_observe.publisher import (
    PublisherAttestationError,
    derive_publisher_evidence,
)
from traceseal_observe.source_identity import (
    HuggingFaceSourceAdapter,
    ModelScopeSourceAdapter,
    SourceObservationError,
    build_canonical_identity,
    derive_canonical_identity,
    derive_source_observation,
)
from traceseal_observe.signed_time import (
    SIGNED_TIME_PROFILE_VERSION,
    SignedTimeProfileError,
    format_utc_seconds,
    is_signed_time_profile,
    validate_signed_time_profile,
)

MAX_OBSERVATION_GAP_SECONDS = 86_400
DEFAULT_OBSERVATION_GAP_SECONDS = 300


class IdentityWitnessError(ResolutionWitnessError):
    """Canonical identity evidence could not safely be signed or witnessed."""


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "traceseal-identity: invalid invocation\n")


def _fail(message: str, code: str = "identity_evidence_invalid") -> None:
    raise IdentityWitnessError(message, code)


def _hash_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _format_time(value: datetime) -> str:
    try:
        return format_utc_seconds(value)
    except SignedTimeProfileError as exc:
        raise IdentityWitnessError(
            "observation time is invalid", "freshness_invalid"
        ) from exc


def _parse_attested_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail("original attestation time is invalid", "freshness_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IdentityWitnessError(
            "original attestation time is invalid", "freshness_invalid"
        ) from exc
    if parsed.tzinfo is None or parsed.microsecond != 0:
        _fail("original attestation time is invalid", "freshness_invalid")
    return parsed.astimezone(timezone.utc)


def _check_freshness(
    original_attested_at: Any,
    reobserved_at: datetime,
    max_observation_gap_seconds: int,
) -> tuple[str, str]:
    if (
        isinstance(max_observation_gap_seconds, bool)
        or not isinstance(max_observation_gap_seconds, int)
        or max_observation_gap_seconds < 1
        or max_observation_gap_seconds > MAX_OBSERVATION_GAP_SECONDS
    ):
        _fail("freshness policy is invalid", "freshness_invalid")
    original = _parse_attested_time(original_attested_at)
    try:
        current = datetime.strptime(
            format_utc_seconds(reobserved_at), "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except (SignedTimeProfileError, ValueError) as exc:
        raise IdentityWitnessError(
            "re-observation time is invalid", "freshness_invalid"
        ) from exc
    gap = int((current - original).total_seconds())
    if gap < 0 or gap > max_observation_gap_seconds:
        _fail("observation freshness policy failed", "observation_stale")
    return _format_time(original), _format_time(current)


def _identity_execution(
    derived,
    publisher_evidence: dict[str, Any] | None = None,
    publisher_binding_evidence: dict[str, Any] | None = None,
    publisher_key_history_evidence: dict[str, Any] | None = None,
    publisher_history_log_evidence: dict[str, Any] | None = None,
    history_log_vkeys: dict[str, str] | None = None,
    history_log_witness_vkeys: dict[str, str] | None = None,
) -> dict[str, Any]:  # noqa: ANN001
    execution = {
        "canonical_id": derived.canonical_id,
        "equivalence_level": derived.equivalence_level,
        "equivalence_root": derived.evidence_root,
        "identity_evidence_hash": derived.identity_hash,
        "identity_version": "1.0",
        "profile_hash": derived.profile_hash,
        "receipt_type": "model_identity_observation",
        "selected_files": derived.selected_files,
        "source_observation_hashes": list(derived.source_observation_hashes),
    }
    if publisher_evidence is not None:
        execution.update(
            {
                "publisher_attestation_hashes": [
                    entry["attestation_hash"]
                    for entry in publisher_evidence["publisher_attestations"]
                ],
                "publisher_evidence_root": publisher_evidence[
                    "publisher_evidence_root"
                ],
                "publisher_evidence_status": publisher_evidence[
                    "publisher_status"
                ],
            }
        )
    if publisher_binding_evidence is not None:
        binding = derive_publisher_binding_evidence(publisher_binding_evidence)
        execution.update(
            {
                "publisher_binding_count": len(binding.bindings),
                "publisher_binding_root": binding.binding_root,
                "publisher_binding_status": binding.status,
            }
        )
    if publisher_key_history_evidence is not None:
        history = derive_publisher_key_history_evidence(
            publisher_key_history_evidence
        )
        execution.update(
            {
                "current_publisher_fingerprint": history.current_fingerprint,
                "publisher_key_history_root": history.publisher_key_history_root,
                "publisher_key_status": history.current_status,
            }
        )
    if publisher_history_log_evidence is not None:
        if publisher_key_history_evidence is None:
            _fail(
                "publisher history log evidence requires key history",
                "publisher_history_log_binding_invalid",
            )
        if history_log_vkeys is None or history_log_witness_vkeys is None:
            history_log_vkeys, history_log_witness_vkeys = production_log_vkeys()
        try:
            logged = derive_publisher_history_log_evidence(
                publisher_history_log_evidence,
                history_log_vkeys,
                history_log_witness_vkeys,
            )
            history = derive_publisher_key_history_evidence(
                publisher_key_history_evidence
            )
        except (HistoryLogError, HistoryError) as exc:
            raise IdentityWitnessError(
                "publisher history log evidence is invalid",
                getattr(exc, "code", "publisher_history_log_invalid"),
            ) from exc
        if (
            logged.current_fingerprint != history.current_fingerprint
            or logged.current_status != history.current_status
            or logged.publisher_key_continuity_root != history.continuity_root
            or list(logged.key_states) != list(history.key_states)
        ):
            _fail(
                "publisher history log evidence differs from key history",
                "publisher_history_log_binding_invalid",
            )
        execution.update(
            {
                "publisher_history_log_entry_hashes": list(logged.entry_hashes),
                "publisher_history_log_evidence_root": logged.publisher_history_log_evidence_root,
                "publisher_history_log_root": logged.publisher_history_log_root,
                "publisher_history_log_status": logged.status,
            }
        )
    return execution


def _signed_identity_execution(
    derived,
    observed_at: str,
    publisher_evidence: dict[str, Any] | None = None,
    publisher_binding_evidence: dict[str, Any] | None = None,
    publisher_key_history_evidence: dict[str, Any] | None = None,
    publisher_history_log_evidence: dict[str, Any] | None = None,
    history_log_vkeys: dict[str, str] | None = None,
    history_log_witness_vkeys: dict[str, str] | None = None,
) -> dict[str, Any]:  # noqa: ANN001
    execution = _identity_execution(
        derived,
        publisher_evidence,
        publisher_binding_evidence,
        publisher_key_history_evidence,
        publisher_history_log_evidence,
        history_log_vkeys,
        history_log_witness_vkeys,
    )
    execution.update(
        {
            "observed_at": observed_at,
            "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
        }
    )
    return execution


def _identity_provenance() -> dict[str, Any]:
    return {
        "attestation_scope": "operator_model_identity_evidence",
        "equivalence_scope": "selected_files_only",
        "provider_truth": "not_attested",
        "provenance_version": "1.0",
    }


def sign_identity_evidence(
    identity: dict[str, Any],
    observations: list[dict[str, Any]],
    key_path: Path | str,
    *,
    observed_at: str | None = None,
    publisher_attestations: list[dict[str, Any]] | None = None,
    platform_claims: list[dict[str, str]] | None = None,
    publisher_binding_evidence: dict[str, Any] | None = None,
    publisher_key_history_evidence: dict[str, Any] | None = None,
    publisher_history_log_evidence: dict[str, Any] | None = None,
    history_log_vkeys: dict[str, str] | None = None,
    history_log_witness_vkeys: dict[str, str] | None = None,
) -> Receipt:
    """Re-derive and sign bounded cross-registry identity evidence."""
    try:
        derived = derive_canonical_identity(identity, observations)
    except SourceObservationError as exc:
        raise IdentityWitnessError(
            "canonical identity evidence is invalid", exc.code
        ) from exc
    publisher_evidence = None
    if (
        publisher_attestations is not None
        or platform_claims is not None
        or publisher_binding_evidence is not None
        or publisher_key_history_evidence is not None
    ):
        try:
            publisher_evidence = derive_publisher_evidence(
                identity,
                observations,
                publisher_attestations or [],
                platform_claims,
                publisher_binding_evidence,
                publisher_key_history_evidence,
            )
        except (PublisherAttestationError, HistoryError) as exc:
            raise IdentityWitnessError(
                "publisher evidence is invalid", exc.code
            ) from exc
    if publisher_binding_evidence is not None:
        try:
            derive_publisher_binding_evidence(publisher_binding_evidence)
        except BindingError as exc:
            raise IdentityWitnessError(
                "publisher binding evidence is invalid", exc.code
            ) from exc
    if publisher_key_history_evidence is not None:
        try:
            derive_publisher_key_history_evidence(
                publisher_key_history_evidence
            )
        except HistoryError as exc:
            raise IdentityWitnessError(
                "publisher key history evidence is invalid", exc.code
            ) from exc
    key = _load_key_safely(key_path)
    signed_observed_at = observed_at if observed_at is not None else format_utc_seconds()
    return sign_execution_receipt(
        _signed_identity_execution(
            derived,
            signed_observed_at,
            publisher_evidence,
            publisher_binding_evidence,
            publisher_key_history_evidence,
            publisher_history_log_evidence,
            history_log_vkeys,
            history_log_witness_vkeys,
        ),
        _identity_provenance(),
        key,
    )


def _verify_original_identity_receipt(
    value: Any,
    derived,
    publisher_evidence: dict[str, Any] | None = None,
    publisher_binding_evidence: dict[str, Any] | None = None,
    publisher_key_history_evidence: dict[str, Any] | None = None,
    publisher_history_log_evidence: dict[str, Any] | None = None,
    history_log_vkeys: dict[str, str] | None = None,
    history_log_witness_vkeys: dict[str, str] | None = None,
) -> Receipt:  # noqa: ANN001
    try:
        receipt = _receipt_from_dict(value)
        verify_receipt_signature(receipt, "model identity receipt")
    except (ResolutionWitnessError, ValueError) as exc:
        raise IdentityWitnessError(
            "original identity receipt is invalid", "receipt_invalid"
        ) from exc
    try:
        profile_status = validate_signed_time_profile(
            receipt.execution, receipt.attestation
        )
    except SignedTimeProfileError as exc:
        raise IdentityWitnessError(
            "identity receipt signed-time profile is invalid", "receipt_invalid"
        ) from exc
    actual_execution = dict(receipt.execution)
    if profile_status == "valid":
        actual_execution.pop("observed_at")
        actual_execution.pop("receipt_profile_version")
    if actual_execution != _identity_execution(
        derived,
        publisher_evidence,
        publisher_binding_evidence,
        publisher_key_history_evidence,
        publisher_history_log_evidence,
        history_log_vkeys,
        history_log_witness_vkeys,
    ):
        _fail("identity receipt does not match evidence", "evidence_substitution")
    if receipt.provenance != _identity_provenance():
        _fail("identity receipt provenance is invalid", "receipt_invalid")
    return receipt


def _require_independent_key(receipt: Receipt, key_path: Path | str):  # noqa: ANN202
    key = _load_key_safely(key_path)
    original_signer = receipt.attestation.get("operator_fingerprint", "")
    original_public_key = receipt.attestation.get("operator_public_key", "")
    if key.public_key_hex == original_public_key or key.fingerprint == original_signer:
        _fail(
            "witness key is not independent from the original signer",
            "witness_key_not_independent",
        )
    return key


def witness_identity_evidence(
    identity: dict[str, Any],
    observations: list[dict[str, Any]],
    receipt_value: dict[str, Any],
    huggingface_model: str,
    modelscope_model: str,
    key_path: Path | str,
    *,
    huggingface: HuggingFaceSourceAdapter | None = None,
    modelscope: ModelScopeSourceAdapter | None = None,
    max_observation_gap_seconds: int = DEFAULT_OBSERVATION_GAP_SECONDS,
    now: datetime | None = None,
    publisher_attestations: list[dict[str, Any]] | None = None,
    platform_claims: list[dict[str, str]] | None = None,
    publisher_binding_evidence: dict[str, Any] | None = None,
    publisher_binding_repositories: dict[str, str] | None = None,
    publisher_key_history_evidence: dict[str, Any] | None = None,
    publisher_key_history_repositories: dict[str, str] | None = None,
    publisher_key_history_documents: dict[str, dict[str, Any]] | None = None,
    publisher_history_log_evidence: dict[str, Any] | None = None,
    history_log_vkeys: dict[str, str] | None = None,
    history_log_witness_vkeys: dict[str, str] | None = None,
) -> Receipt:
    """Freshly re-observe both registries before producing a countersignature."""
    try:
        derived = derive_canonical_identity(identity, observations)
        old_by_provider = {
            derive_source_observation(value).provider: value for value in observations
        }
    except SourceObservationError as exc:
        raise IdentityWitnessError(
            "canonical identity evidence is invalid", exc.code
        ) from exc
    publisher_evidence = None
    if (
        publisher_attestations is not None
        or platform_claims is not None
        or publisher_binding_evidence is not None
        or publisher_key_history_evidence is not None
    ):
        try:
            publisher_evidence = derive_publisher_evidence(
                identity,
                observations,
                publisher_attestations or [],
                platform_claims,
                publisher_binding_evidence,
                publisher_key_history_evidence,
            )
        except (PublisherAttestationError, HistoryError) as exc:
            raise IdentityWitnessError(
                "publisher evidence is invalid", exc.code
            ) from exc
    derived_binding = None
    if publisher_binding_evidence is not None:
        try:
            derived_binding = derive_publisher_binding_evidence(
                publisher_binding_evidence
            )
        except BindingError as exc:
            raise IdentityWitnessError(
                "publisher binding evidence is invalid", exc.code
            ) from exc
    derived_history = None
    if publisher_key_history_evidence is not None:
        try:
            derived_history = derive_publisher_key_history_evidence(
                publisher_key_history_evidence
            )
        except HistoryError as exc:
            raise IdentityWitnessError(
                "publisher key history evidence is invalid", exc.code
            ) from exc
    derived_history_log = None
    if publisher_history_log_evidence is not None:
        if history_log_vkeys is None or history_log_witness_vkeys is None:
            history_log_vkeys, history_log_witness_vkeys = production_log_vkeys()
        try:
            derived_history_log = derive_publisher_history_log_evidence(
                publisher_history_log_evidence,
                history_log_vkeys,
                history_log_witness_vkeys,
            )
        except HistoryLogError as exc:
            raise IdentityWitnessError(
                "publisher history log evidence is invalid", exc.code
            ) from exc
        if derived_history is None or (
            derived_history_log.current_fingerprint
            != derived_history.current_fingerprint
            or derived_history_log.current_status != derived_history.current_status
            or derived_history_log.publisher_key_continuity_root
            != derived_history.continuity_root
            or list(derived_history_log.key_states)
            != list(derived_history.key_states)
        ):
            _fail(
                "publisher history log evidence differs from key history",
                "publisher_history_log_binding_invalid",
            )
    original = _verify_original_identity_receipt(
        receipt_value,
        derived,
        publisher_evidence,
        publisher_binding_evidence,
        publisher_key_history_evidence,
        publisher_history_log_evidence,
        history_log_vkeys,
        history_log_witness_vkeys,
    )
    key = _require_independent_key(original, key_path)
    if set(old_by_provider) != {"huggingface", "modelscope"}:
        _fail("identity source set is invalid")
    if (
        _hash_text(huggingface_model)
        != old_by_provider["huggingface"]["source_identity_hash"]
        or _hash_text(modelscope_model)
        != old_by_provider["modelscope"]["source_identity_hash"]
    ):
        _fail("source identity does not match signed evidence", "source_identity_mismatch")
    resolver_time_claim = (
        original.execution.get("observed_at")
        if is_signed_time_profile(original.execution)
        else original.attestation.get("attested_at")
    )
    huggingface = huggingface or HuggingFaceSourceAdapter()
    modelscope = modelscope or ModelScopeSourceAdapter()
    try:
        fresh_hf = huggingface.observe(huggingface_model)
        fresh_ms = modelscope.observe(modelscope_model)
    except SourceObservationError as exc:
        raise IdentityWitnessError(
            "external source re-observation failed", "source_unavailable"
        ) from exc
    fresh_by_provider = {"huggingface": fresh_hf, "modelscope": fresh_ms}
    for provider in ("huggingface", "modelscope"):
        old = old_by_provider[provider]
        fresh = fresh_by_provider[provider]
        old_derived = derive_source_observation(old)
        fresh_derived = derive_source_observation(fresh)
        if old_derived.source_identity_hash != fresh_derived.source_identity_hash:
            _fail("source identity changed", "source_identity_mismatch")
        if old_derived.revision_hash != fresh_derived.revision_hash:
            _fail("external source changed", "source_changed")
        if old_derived.observation_root != fresh_derived.observation_root:
            _fail("selected file evidence changed", "selected_file_mismatch")
    try:
        fresh_identity = build_canonical_identity([fresh_hf, fresh_ms])
        fresh_derived = derive_canonical_identity(
            fresh_identity, [fresh_hf, fresh_ms]
        )
    except SourceObservationError as exc:
        code = (
            "selected_file_mismatch"
            if exc.code == "selected_file_mismatch"
            else "source_changed"
        )
        raise IdentityWitnessError("fresh identity differs", code) from exc
    if fresh_derived != derived:
        _fail("fresh identity differs", "source_changed")

    fresh_binding_evidence = None
    if derived_binding is not None:
        if (
            not isinstance(publisher_binding_repositories, dict)
            or set(publisher_binding_repositories)
            != {entry["provider"] for entry in derived_binding.bindings}
        ):
            _fail("publisher binding repositories are invalid", "binding_subject_mismatch")
        adapters = {"huggingface": huggingface, "modelscope": modelscope}
        fresh_entries = []
        for old_entry in derived_binding.bindings:
            provider = old_entry["provider"]
            repository = publisher_binding_repositories[provider]
            if _hash_text(repository) != old_entry["source_identity_hash"]:
                _fail(
                    "publisher binding repository differs",
                    "binding_subject_mismatch",
                )
            try:
                fresh_entries.append(
                    discover_publisher_binding(provider, repository, adapters[provider])
                )
            except BindingError as exc:
                raise IdentityWitnessError(
                    "publisher binding source changed", "binding_source_changed"
                ) from exc
        try:
            fresh_binding_evidence = build_publisher_binding_evidence(fresh_entries)
        except BindingError as exc:
            raise IdentityWitnessError(
                "publisher binding source changed", "binding_source_changed"
            ) from exc
        if fresh_binding_evidence != publisher_binding_evidence:
            _fail("publisher binding source changed", "binding_source_changed")
    fresh_history_evidence = None
    history_witness_method = None
    if derived_history is not None:
        expected_providers = {
            entry["provider"] for entry in derived_history.observations
        }
        if (
            not isinstance(publisher_key_history_repositories, dict)
            or set(publisher_key_history_repositories) != expected_providers
        ):
            _fail(
                "publisher key history repositories are invalid",
                "binding_subject_mismatch",
            )
        if publisher_key_history_documents is not None:
            try:
                verify_supplied_publisher_key_history(
                    publisher_key_history_evidence,
                    publisher_key_history_documents,
                    publisher_key_history_repositories,
                )
            except HistoryError as exc:
                raise IdentityWitnessError(
                    "publisher key history bundle differs", exc.code
                ) from exc
            fresh_history_evidence = publisher_key_history_evidence
            history_witness_method = "publisher_key_history_rederivation"
        else:
            adapters = {"huggingface": huggingface, "modelscope": modelscope}
            fresh_history_entries = []
            for old_entry in derived_history.observations:
                provider = old_entry["provider"]
                repository = publisher_key_history_repositories[provider]
                if _hash_text(repository) != old_entry["source_identity_hash"]:
                    _fail(
                        "publisher key history repository differs",
                        "binding_subject_mismatch",
                    )
                try:
                    fresh_history_entries.append(
                        discover_publisher_key_history(
                            provider, repository, adapters[provider]
                        )
                    )
                except (HistoryError, BindingError) as exc:
                    raise IdentityWitnessError(
                        "publisher key history source changed",
                        "publisher_history_source_changed",
                    ) from exc
            try:
                fresh_history_evidence = build_publisher_key_history_evidence(
                    fresh_history_entries
                )
            except HistoryError as exc:
                raise IdentityWitnessError(
                    "publisher key history source changed",
                    "publisher_history_source_changed",
                ) from exc
            if fresh_history_evidence != publisher_key_history_evidence:
                _fail(
                    "publisher key history source changed",
                    "publisher_history_source_changed",
                )
            history_witness_method = "platform_key_history_reobservation"
    resolver_time, witness_time = _check_freshness(
        resolver_time_claim,
        now or _now_utc(),
        max_observation_gap_seconds,
    )
    execution = {
        "canonical_id": derived.canonical_id,
        "equivalence_root": derived.evidence_root,
        "identity_receipt_hash": original.receipt_hash,
        "max_observation_gap_seconds": max_observation_gap_seconds,
        "original_attested_at": _parse_attested_time(
            original.attestation.get("attested_at")
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "receipt_type": "model_identity_cosignature",
        "reobserved_at": witness_time,
        "source_observation_hashes": list(fresh_derived.source_observation_hashes),
        "verdict": "CONFIRMED",
        "witness_method": "remote_source_reobservation",
    }
    if is_signed_time_profile(original.execution):
        execution.update(
            {
                "receipt_profile_version": SIGNED_TIME_PROFILE_VERSION,
                "resolver_observed_at": resolver_time,
            }
        )
    if publisher_evidence is not None:
        execution.update(
            {
                "publisher_attestation_hashes": [
                    entry["attestation_hash"]
                    for entry in publisher_evidence["publisher_attestations"]
                ],
                "publisher_evidence_root": publisher_evidence[
                    "publisher_evidence_root"
                ],
                "publisher_evidence_status": publisher_evidence[
                    "publisher_status"
                ],
            }
        )
    if fresh_binding_evidence is not None:
        execution.update(
            {
                "publisher_binding_count": len(fresh_binding_evidence["bindings"]),
                "publisher_binding_root": fresh_binding_evidence["binding_root"],
                "publisher_binding_status": fresh_binding_evidence["status"],
                "publisher_binding_witness_method": "platform_binding_reobservation",
            }
        )
    if fresh_history_evidence is not None:
        fresh_history = derive_publisher_key_history_evidence(
            fresh_history_evidence
        )
        execution.update(
            {
                "current_publisher_fingerprint": fresh_history.current_fingerprint,
                "publisher_key_history_root": fresh_history.publisher_key_history_root,
                "publisher_key_history_witness_method": history_witness_method,
                "publisher_key_status": fresh_history.current_status,
            }
        )
    if derived_history_log is not None:
        execution.update(
            {
                "publisher_history_log_entry_hashes": list(
                    derived_history_log.entry_hashes
                ),
                "publisher_history_log_evidence_root": derived_history_log.publisher_history_log_evidence_root,
                "publisher_history_log_root": derived_history_log.publisher_history_log_root,
                "publisher_history_log_status": derived_history_log.status,
                "publisher_history_log_witness_method": HISTORY_LOG_WITNESS_METHOD_OFFLINE,
            }
        )
    return sign_execution_receipt(
        execution,
        {
            "claim": "selected_file_evidence_independently_reobserved_and_confirmed",
            "equivalence_scope": "selected_files_only",
            "method": "huggingface_modelscope_reobservation_v1",
            "original_signer": original.attestation.get(
                "operator_fingerprint", ""
            ),
            "provenance_version": "1.0",
            "role": "witness",
        },
        key,
    )


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="traceseal-identity")
    commands = parser.add_subparsers(dest="command", required=True)
    sign = commands.add_parser("sign", help="sign canonical identity evidence")
    witness = commands.add_parser(
        "witness", help="freshly re-observe both sources and countersign"
    )
    for command in (sign, witness):
        command.add_argument("--identity", required=True)
        command.add_argument("--huggingface-observation", required=True)
        command.add_argument("--modelscope-observation", required=True)
        command.add_argument("--key", required=True)
        command.add_argument("--output", required=True)
        command.add_argument(
            "--publisher-attestation",
            action="append",
            default=None,
            help="verified publisher attestation (repeatable)",
        )
        command.add_argument(
            "--publisher-binding-evidence",
            help="validated publisher platform-binding evidence",
        )
        command.add_argument(
            "--publisher-key-history-evidence",
            help="validated publisher key-history evidence",
        )
        command.add_argument(
            "--publisher-history-log-evidence",
            help="portable witnessed publisher-history log evidence",
        )
    sign.add_argument(
        "--observed-at",
        help="claimed source observation time (UTC RFC3339 seconds)",
    )
    witness.add_argument("--receipt", required=True)
    witness.add_argument("--huggingface-model", required=True)
    witness.add_argument("--modelscope-model", required=True)
    witness.add_argument("--huggingface-binding-repository")
    witness.add_argument("--modelscope-binding-repository")
    witness.add_argument("--huggingface-key-history-repository")
    witness.add_argument("--modelscope-key-history-repository")
    witness.add_argument("--huggingface-key-history-document")
    witness.add_argument("--modelscope-key-history-document")
    witness.add_argument(
        "--max-observation-gap-seconds",
        type=int,
        default=DEFAULT_OBSERVATION_GAP_SECONDS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        identity = _read_json_safely(args.identity)
        observations = [
            _read_json_safely(args.huggingface_observation),
            _read_json_safely(args.modelscope_observation),
        ]
        publisher_attestations = (
            [_read_json_safely(path) for path in args.publisher_attestation]
            if args.publisher_attestation is not None
            else None
        )
        publisher_binding_evidence = (
            _read_json_safely(args.publisher_binding_evidence)
            if args.publisher_binding_evidence is not None
            else None
        )
        publisher_key_history_evidence = (
            _read_json_safely(args.publisher_key_history_evidence)
            if args.publisher_key_history_evidence is not None
            else None
        )
        publisher_history_log_evidence = (
            _read_json_safely(args.publisher_history_log_evidence)
            if args.publisher_history_log_evidence is not None
            else None
        )
        if args.command == "sign":
            receipt = sign_identity_evidence(
                identity,
                observations,
                args.key,
                observed_at=args.observed_at,
                publisher_attestations=publisher_attestations,
                publisher_binding_evidence=publisher_binding_evidence,
                publisher_key_history_evidence=publisher_key_history_evidence,
                publisher_history_log_evidence=publisher_history_log_evidence,
            )
            label = "model_identity_observation"
        else:
            original = _read_json_safely(args.receipt)
            binding_repositories = {
                provider: repository
                for provider, repository in (
                    ("huggingface", args.huggingface_binding_repository),
                    ("modelscope", args.modelscope_binding_repository),
                )
                if repository is not None
            }
            if binding_repositories and publisher_binding_evidence is None:
                raise IdentityWitnessError(
                    "publisher binding evidence is required",
                    "binding_subject_mismatch",
                )
            history_repositories = {
                provider: repository
                for provider, repository in (
                    ("huggingface", args.huggingface_key_history_repository),
                    ("modelscope", args.modelscope_key_history_repository),
                )
                if repository is not None
            }
            if history_repositories and publisher_key_history_evidence is None:
                raise IdentityWitnessError(
                    "publisher key history evidence is required",
                    "binding_subject_mismatch",
                )
            history_documents = {
                provider: _read_json_safely(path)
                for provider, path in (
                    ("huggingface", args.huggingface_key_history_document),
                    ("modelscope", args.modelscope_key_history_document),
                )
                if path is not None
            }
            if history_documents and set(history_documents) != set(
                history_repositories
            ):
                raise IdentityWitnessError(
                    "publisher key history documents are incomplete",
                    "publisher_history_bundle_invalid",
                )
            receipt = witness_identity_evidence(
                identity,
                observations,
                original,
                args.huggingface_model,
                args.modelscope_model,
                args.key,
                max_observation_gap_seconds=args.max_observation_gap_seconds,
                publisher_attestations=publisher_attestations,
                publisher_binding_evidence=publisher_binding_evidence,
                publisher_binding_repositories=binding_repositories or None,
                publisher_key_history_evidence=publisher_key_history_evidence,
                publisher_key_history_repositories=history_repositories or None,
                publisher_key_history_documents=history_documents or None,
                publisher_history_log_evidence=publisher_history_log_evidence,
            )
            label = "model_identity_cosignature"
        _write_receipt_safely(args.output, receipt)
        print(f"PASS {label} receipt")
        return 0
    except (
        BindingError,
        HistoryError,
        HistoryLogError,
        IdentityWitnessError,
        ResolutionWitnessError,
        SourceObservationError,
    ) as exc:
        code = getattr(exc, "code", "identity_evidence_invalid")
        print(f"REFUSED {code}", file=sys.stderr)
        return 1
    except ValueError as exc:
        code = str(exc)
        if code not in _SAFE_PROFILE_ERROR_CODES:
            code = "receipt_profile_invalid"
        print(f"REFUSED {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
