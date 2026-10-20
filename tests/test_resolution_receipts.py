"""Model-resolution receipt signing and independent witness re-derivation."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from traceseal_observe import (
    OperatorKey,
    sign_execution_receipt,
    verify_receipt_signature,
)
from traceseal_observe.resolution import (
    ResolutionWitnessError,
    _resolution_execution,
    derive_resolution_evidence,
    sign_resolution_evidence,
    witness_resolution_evidence,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _hash_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _native_bundle() -> dict:
    policy = {
        "federated_provider": "huggingface",
        "native_ownership": "repository_wide",
        "policy_version": "1.0",
        "resolution_order": ["native", "huggingface"],
    }
    resolver = {
        "evidence_contract": "native-first-huggingface-fallback-v1",
        "implementation": "open-registry",
    }
    resolver["version_hash"] = _hash(resolver)
    files = [
        {
            "content_digest": "sha256:" + "a" * 64,
            "path_hash": _hash_text("config.json"),
            "size": 217,
        },
        {
            "content_digest": "sha256:" + "b" * 64,
            "path_hash": _hash_text("vocab.json"),
            "size": 180,
        },
    ]
    native_content = {
        "commit": "1" * 40,
        "files": files,
        "revision": "main",
    }
    revision_hash = _hash_text(native_content["revision"])
    candidate = {
        "commit_hash": _hash_text(native_content["commit"]),
        "content_set_hash": _hash(files),
        "evidence_strength": "native_content_verified",
        "revision_hash": revision_hash,
        "source": "native",
        "state": "hit",
    }
    candidates = [candidate]
    policy_hash = _hash(policy)
    decision_record = {
        "policy_hash": policy_hash,
        "reason_code": "native_precedence",
        "selected_source": "native",
    }
    decision_hash = _hash(decision_record)
    model_identity_hash = _hash_text("open-registry/blob-tiny-gpt2")
    candidate_set_hash = _hash(candidates)
    root_record = {
        "candidate_set_hash": candidate_set_hash,
        "decision_hash": decision_hash,
        "event_type": "model_resolution",
        "evidence_version": "1.0",
        "model_identity_hash": model_identity_hash,
        "policy_hash": policy_hash,
        "resolver_version_hash": resolver["version_hash"],
        "revision_hash": revision_hash,
    }
    return {
        "decision": {
            **decision_record,
            "decision_hash": decision_hash,
        },
        "event_type": "model_resolution",
        "evidence_version": "1.0",
        "observation": {
            "candidate_set_hash": candidate_set_hash,
            "native_state": "hit",
            "remote_state": "not_consulted",
            "revision_hash": revision_hash,
        },
        "request": {"model_identity_hash": model_identity_hash},
        "resolver": resolver,
        "result": {
            "evidence_root": _hash(root_record),
            "evidence_strength": "native_content_verified",
        },
        "supporting_evidence": {
            "candidates": candidates,
            "native_content": native_content,
            "policy": policy,
        },
    }


def _write_key(path: Path, key: OperatorKey) -> None:
    raw = key.private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    path.write_bytes(raw)
    path.chmod(0o600)


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def test_resolution_receipt_and_cosignature_verify(tmp_path: Path) -> None:
    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)

    derived = derive_resolution_evidence(bundle)
    observed_at = "2026-08-30T06:30:00Z"
    receipt = sign_resolution_evidence(
        bundle, signer_path, observed_at=observed_at
    )
    verify_receipt_signature(receipt, "model resolution receipt")
    assert receipt.execution["receipt_type"] == "model_resolution"
    assert receipt.execution["receipt_profile_version"] == "1.1"
    assert receipt.execution["observed_at"] == observed_at
    assert receipt.execution["evidence_root"] == derived.evidence_root
    assert receipt.execution["evidence_bundle_hash"] == derived.bundle_hash

    verified_at = datetime(2026, 8, 30, 6, 31, tzinfo=timezone.utc)
    cosignature = witness_resolution_evidence(
        bundle, receipt.to_dict(), witness_path, now=verified_at
    )
    verify_receipt_signature(cosignature, "model resolution cosignature")
    assert cosignature.execution["receipt_type"] == "model_resolution_cosignature"
    assert cosignature.execution["receipt_profile_version"] == "1.1"
    assert cosignature.execution["resolver_observed_at"] == observed_at
    assert cosignature.execution["verified_at"] == "2026-08-30T06:31:00Z"
    assert cosignature.execution["verdict"] == "CONFIRMED"
    assert cosignature.provenance["original_signer"] == signer.fingerprint
    assert cosignature.attestation["operator_fingerprint"] == witness.fingerprint


@pytest.mark.parametrize(
    "observed_at",
    [
        "2026-08-30T06:30:00+00:00",
        "2026-08-30 06:30:00Z",
        "2026-08-30T06:30:00.000Z",
        "2026-02-30T06:30:00Z",
        "2026-08-30T06:30:00Z\u202e",
        "2026-08-30T06:30:00Z\n",
    ],
)
def test_resolution_signed_time_rejects_noncanonical_values(
    observed_at: str, tmp_path: Path
) -> None:
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, OperatorKey.generate("resolver"))
    with pytest.raises(ValueError, match="signed_time_invalid"):
        sign_resolution_evidence(
            _native_bundle(), key_path, observed_at=observed_at
        )


def test_resolution_signed_time_is_tamper_evident_and_ordered(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, OperatorKey.generate("resolver"))
    receipt = sign_resolution_evidence(
        _native_bundle(),
        key_path,
        observed_at="2026-08-30T06:30:00Z",
    )
    assert receipt.attestation["attested_at"] >= receipt.execution["observed_at"]

    tampered = receipt.to_dict()
    tampered["execution"]["observed_at"] = "2026-08-30T06:30:01Z"
    from traceseal_observe.resolution import _receipt_from_dict

    with pytest.raises(ValueError, match="signature"):
        verify_receipt_signature(_receipt_from_dict(tampered))

    with pytest.raises(ValueError, match="signed_time_order_invalid"):
        sign_resolution_evidence(
            _native_bundle(),
            key_path,
            observed_at="2099-01-01T00:00:00Z",
        )


def test_historical_resolution_profile_remains_verifiable_and_witnessable(
    tmp_path: Path,
) -> None:
    bundle = _native_bundle()
    derived = derive_resolution_evidence(bundle)
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    legacy = sign_execution_receipt(
        _resolution_execution(derived),
        {
            "attestation_scope": "operator_resolution_evidence",
            "provider_truth": "not_attested",
            "provenance_version": "1.0",
        },
        signer,
    )
    assert "observed_at" not in legacy.execution
    assert "receipt_profile_version" not in legacy.execution
    verify_receipt_signature(legacy, "historical model resolution receipt")
    cosignature = witness_resolution_evidence(
        bundle, legacy.to_dict(), witness_path
    )
    verify_receipt_signature(cosignature, "historical resolution cosignature")
    assert "receipt_profile_version" not in cosignature.execution


def test_cli_rejects_invalid_observed_time_without_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from traceseal_observe.resolution import main

    key_path = tmp_path / "resolver.key"
    evidence_path = tmp_path / "evidence.json"
    output_path = tmp_path / "must-not-exist.json"
    _write_key(key_path, OperatorKey.generate("resolver"))
    _write_json(evidence_path, _native_bundle())

    assert main(
        [
            "sign",
            "--evidence",
            str(evidence_path),
            "--key",
            str(key_path),
            "--output",
            str(output_path),
            "--observed-at",
            "2026-08-30T06:30:00+00:00",
        ]
    ) == 1
    assert not output_path.exists()
    captured = capsys.readouterr()
    assert captured.err.strip() == "REFUSED signed_time_invalid"
    assert str(tmp_path) not in captured.err


def test_same_key_witness_refuses_without_output(tmp_path: Path) -> None:
    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, signer)
    receipt = sign_resolution_evidence(bundle, key_path)
    output = tmp_path / "must-not-exist.json"

    with pytest.raises(ResolutionWitnessError, match="independent"):
        witness_resolution_evidence(bundle, receipt.to_dict(), key_path)
    assert not output.exists()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["supporting_evidence"]["native_content"]["files"][0].update(size=218),
        lambda b: b["supporting_evidence"]["candidates"][0].update(state="miss"),
        lambda b: b["decision"].update(selected_source="huggingface"),
        lambda b: b["decision"].update(reason_code="native_miss_federated"),
        lambda b: b["supporting_evidence"]["policy"].update(policy_version="2.0"),
        lambda b: b["result"].update(evidence_root="sha256:" + "f" * 64),
    ],
)
def test_tampered_evidence_refuses(mutate, tmp_path: Path) -> None:
    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    receipt = sign_resolution_evidence(bundle, signer_path)
    mutate(bundle)

    with pytest.raises(ResolutionWitnessError):
        witness_resolution_evidence(bundle, receipt.to_dict(), witness_path)


def test_invalid_original_receipt_refuses(tmp_path: Path) -> None:
    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    receipt = sign_resolution_evidence(bundle, signer_path).to_dict()
    receipt["execution"]["selected_source"] = "huggingface"

    with pytest.raises(ResolutionWitnessError, match="signature"):
        witness_resolution_evidence(bundle, receipt, witness_path)


def test_tampered_original_fingerprint_cannot_bypass_same_key_refusal(
    tmp_path: Path,
) -> None:
    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, signer)
    receipt = sign_resolution_evidence(bundle, key_path).to_dict()
    receipt["attestation"]["operator_fingerprint"] = "ed25519:" + "0" * 32

    with pytest.raises(ResolutionWitnessError, match="signature"):
        witness_resolution_evidence(bundle, receipt, key_path)


def test_secure_key_loader_rejects_symlink_and_weak_mode(tmp_path: Path) -> None:
    bundle = _native_bundle()
    key = OperatorKey.generate("resolver")
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, key)
    symlink = tmp_path / "linked.key"
    symlink.symlink_to(key_path)

    with pytest.raises(ResolutionWitnessError, match="key"):
        sign_resolution_evidence(bundle, symlink)

    hardlink = tmp_path / "linked-hard.key"
    os.link(key_path, hardlink)
    with pytest.raises(ResolutionWitnessError, match="key"):
        sign_resolution_evidence(bundle, key_path)
    hardlink.unlink()

    key_path.chmod(0o644)
    with pytest.raises(ResolutionWitnessError, match="key"):
        sign_resolution_evidence(bundle, key_path)


def test_cli_failure_writes_nothing_and_never_uses_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from traceseal_observe.resolution import main

    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    evidence_path = tmp_path / "evidence.json"
    receipt_path = tmp_path / "receipt.json"
    output_path = tmp_path / "cosignature.json"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    _write_json(evidence_path, bundle)

    def no_network(*_args, **_kwargs):
        raise AssertionError("resolution tooling attempted network access")

    monkeypatch.setattr("socket.create_connection", no_network)
    assert main([
        "sign", "--evidence", str(evidence_path), "--key", str(signer_path),
        "--output", str(receipt_path),
    ]) == 0
    original = json.loads(receipt_path.read_text())
    bundle["decision"]["reason_code"] = "tampered"
    _write_json(evidence_path, bundle)

    assert main([
        "witness", "--evidence", str(evidence_path), "--receipt", str(receipt_path),
        "--key", str(witness_path), "--output", str(output_path),
    ]) == 1
    assert not output_path.exists()
    assert json.loads(receipt_path.read_text()) == original
    captured = capsys.readouterr()
    assert str(tmp_path) not in captured.err
    assert "tampered" not in captured.err


def test_cli_preserves_all_input_bytes_and_metadata(tmp_path: Path) -> None:
    from traceseal_observe.resolution import main

    bundle = _native_bundle()
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    evidence_path = tmp_path / "evidence.json"
    receipt_path = tmp_path / "receipt.json"
    cosignature_path = tmp_path / "cosignature.json"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    _write_json(evidence_path, bundle)

    def fingerprint(path: Path) -> tuple[int, int, int, str]:
        info = path.stat()
        return (
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )

    before_sign = {
        path: fingerprint(path)
        for path in (evidence_path, signer_path, witness_path)
    }
    assert main([
        "sign", "--evidence", str(evidence_path), "--key", str(signer_path),
        "--output", str(receipt_path),
    ]) == 0
    after_sign = {path: fingerprint(path) for path in before_sign}
    assert after_sign == before_sign

    before_witness = {
        path: fingerprint(path)
        for path in (evidence_path, receipt_path, signer_path, witness_path)
    }
    assert main([
        "witness", "--evidence", str(evidence_path), "--receipt", str(receipt_path),
        "--key", str(witness_path), "--output", str(cosignature_path),
    ]) == 0
    after_witness = {path: fingerprint(path) for path in before_witness}
    assert after_witness == before_witness


def test_sign_and_witness_inputs_are_not_mutated(tmp_path: Path) -> None:
    bundle = _native_bundle()
    before = _canonical(bundle)
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    receipt = sign_resolution_evidence(bundle, signer_path)
    witness_resolution_evidence(bundle, receipt.to_dict(), witness_path)
    assert _canonical(bundle) == before


def test_receipts_exclude_model_identity_paths_and_contents(tmp_path: Path) -> None:
    bundle = _native_bundle()
    key = OperatorKey.generate("resolver")
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, key)
    receipt = sign_resolution_evidence(bundle, key_path)
    encoded = receipt.to_json()
    for forbidden in (
        "open-registry/blob-tiny-gpt2",
        "config.json",
        str(tmp_path),
        "Bearer ",
        "Cookie",
    ):
        assert forbidden not in encoded
