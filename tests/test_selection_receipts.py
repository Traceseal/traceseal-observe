"""Cross-language policy selection, signing, and witness re-evaluation."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from traceseal_observe import OperatorKey, verify_receipt_signature
from traceseal_observe.selection import (
    SelectionWitnessError,
    _candidate,
    derive_selection_evidence,
    main,
    sign_selection_evidence,
    witness_selection_evidence,
)
from traceseal_observe.signed_time import (
    SignedTimeProfileError,
    validate_signed_time_profile,
)


def _corpus() -> dict:
    path = Path(__file__).parent / "testdata" / "selection-conformance-vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _bundle(name: str = "eligible_selection") -> dict:
    return next(
        copy.deepcopy(vector["bundle"])
        for vector in _corpus()["vectors"]
        if vector["name"] == name
    )


def _write_key(path: Path, key: OperatorKey) -> None:
    path.write_bytes(
        key.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )
    path.chmod(0o600)


def _write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_go_python_conformance_vectors_match_every_commitment() -> None:
    corpus = _corpus()
    assert corpus["schema_version"] == 1
    assert [vector["name"] for vector in corpus["vectors"]] == [
        "eligible_selection",
        "revoked_rejection",
        "publisher_equivocation_rejection",
        "required_signature_missing",
        "provider_preference",
        "deterministic_tie",
        "no_eligible_source",
        "witnessed_history_required",
    ]
    for vector in corpus["vectors"]:
        derived = derive_selection_evidence(vector["bundle"])
        expected = vector["expected"]
        assert derived.bundle_hash == expected["bundle_hash"]
        assert derived.policy_hash == expected["policy_hash"]
        assert derived.candidate_set_hash == expected["candidate_set_hash"]
        assert derived.evaluation_root == expected["evaluation_root"]
        assert derived.decision_hash == expected["decision_hash"]
        assert derived.decision_status == expected["decision_status"]
        assert derived.selected_source == expected["selected_source"]
        assert list(derived.reason_codes) == expected["reason_codes"]
        assert vector["bundle"]["candidate_evaluations"] == expected[
            "candidate_evaluations"
        ]


def test_policy_receipt_and_independent_witness_re_evaluation(tmp_path: Path) -> None:
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    bundle = _bundle()

    receipt = sign_selection_evidence(
        bundle, signer_path, observed_at="2026-08-30T00:00:00Z"
    )
    verify_receipt_signature(receipt, "policy selection receipt")
    assert receipt.execution["policy_selection_version"] == "1.0"
    assert receipt.execution["selected_source"] == "native"
    assert receipt.execution["decision_status"] == "selected"

    cosignature = witness_selection_evidence(
        bundle,
        receipt.to_dict(),
        witness_path,
        now=datetime(2026, 8, 30, 0, 1, tzinfo=timezone.utc),
    )
    verify_receipt_signature(cosignature, "policy selection cosignature")
    assert cosignature.execution["witness_method"] == "policy_decision_rederivation"
    assert cosignature.execution["verified_at"] == "2026-08-30T00:01:00Z"
    assert cosignature.execution["decision_hash"] == receipt.execution["decision_hash"]
    assert cosignature.provenance["original_signer"] == signer.fingerprint
    assert cosignature.attestation["operator_fingerprint"] == witness.fingerprint


def test_no_eligible_source_is_a_signable_confirmable_decision(tmp_path: Path) -> None:
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    bundle = _bundle("no_eligible_source")
    receipt = sign_selection_evidence(
        bundle, signer_path, observed_at="2026-08-30T00:00:00Z"
    )
    assert receipt.execution["selected_source"] == "none"
    assert receipt.execution["reason_codes"] == ["no_eligible_source"]
    cosignature = witness_selection_evidence(
        bundle,
        receipt.to_dict(),
        witness_path,
        now=datetime(2026, 8, 30, 0, 1, tzinfo=timezone.utc),
    )
    verify_receipt_signature(cosignature)


def test_policy_profile_rejects_undeclared_execution_fields(tmp_path: Path) -> None:
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, OperatorKey.generate("resolver"))
    receipt = sign_selection_evidence(
        _bundle(), key_path, observed_at="2026-08-30T00:00:00Z"
    )
    execution = dict(receipt.execution)
    execution["undeclared_profile_field"] = "not-allowed"
    with pytest.raises(SignedTimeProfileError, match="policy_selection_profile_invalid"):
        validate_signed_time_profile(execution, receipt.attestation)


@pytest.mark.parametrize("target", ["policy", "candidate", "decision"])
def test_witness_refuses_policy_candidate_and_decision_substitution(
    target: str, tmp_path: Path
) -> None:
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, OperatorKey.generate("resolver"))
    _write_key(witness_path, OperatorKey.generate("witness"))
    original = _bundle()
    receipt = sign_selection_evidence(
        original, signer_path, observed_at="2026-08-30T00:00:00Z"
    )
    changed = copy.deepcopy(original)
    if target == "policy":
        changed["policy"]["requirements"]["require_publisher_signature"] = True
    elif target == "candidate":
        changed["candidate_set"]["candidates"][0]["availability"] = "unavailable"
    else:
        changed["decision"]["selected_source"] = "modelscope"
    with pytest.raises(SelectionWitnessError):
        witness_selection_evidence(
            changed,
            receipt.to_dict(),
            witness_path,
            now=datetime(2026, 8, 30, 0, 1, tzinfo=timezone.utc),
        )


def test_same_key_refuses_and_cli_failure_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = OperatorKey.generate("resolver")
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, key)
    bundle = _bundle()
    receipt = sign_selection_evidence(
        bundle, key_path, observed_at="2026-08-30T00:00:00Z"
    )
    with pytest.raises(SelectionWitnessError, match="witness_key_not_independent"):
        witness_selection_evidence(bundle, receipt.to_dict(), key_path)

    evidence_path = tmp_path / "evidence.json"
    receipt_path = tmp_path / "receipt.json"
    output_path = tmp_path / "must-not-exist.json"
    _write_json(evidence_path, bundle)
    _write_json(receipt_path, receipt.to_dict())
    code = main(
        [
            "witness",
            "--evidence",
            str(evidence_path),
            "--receipt",
            str(receipt_path),
            "--key",
            str(key_path),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err == "REFUSED witness_key_not_independent\n"
    assert not output_path.exists()


def test_selection_bundle_and_receipts_disclose_no_identity_or_content(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, OperatorKey.generate("resolver"))
    bundle = _bundle()
    receipt = sign_selection_evidence(
        bundle, key_path, observed_at="2026-08-30T00:00:00Z"
    )
    payload = json.dumps({"bundle": bundle, "receipt": receipt.to_dict()})
    for forbidden in (
        "/home/tim",
        "Qwen",
        "hf-internal-testing",
        "config.json",
        "Authorization",
        "Cookie",
        "?token=",
    ):
        assert forbidden not in payload


def test_python_evaluator_rejects_native_strength_on_remote_candidate() -> None:
    candidate = copy.deepcopy(_bundle()["candidate_set"]["candidates"][0])
    candidate["provider"] = "huggingface"
    with pytest.raises(SelectionWitnessError, match="source_candidate_invalid"):
        _candidate(candidate)
