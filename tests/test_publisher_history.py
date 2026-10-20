"""Phase 2A.4 publisher key rotation, revocation and witnessed history."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import traceseal_observe.history as history_module
import traceseal_observe.identity as identity_module
from test_identity_receipts import MODEL_ID, SourceFixture, _observe, _write_key
from test_publisher_bindings import _binding_document, _binding_key, _canonical
from traceseal_observe import OperatorKey, verify_receipt_signature
from traceseal_observe.binding import (
    build_publisher_binding_evidence,
    discover_publisher_binding,
)
from traceseal_observe.history import (
    HISTORY_PATH,
    HistoryError,
    accept_publisher_key_rotation,
    assemble_publisher_key_history,
    build_platform_revocation,
    build_publisher_key_history_evidence,
    canonical_publisher_key_history_bytes,
    derive_publisher_key_history_evidence,
    discover_publisher_key_history,
    main as history_main,
    sign_publisher_key_rotation_proposal,
    sign_publisher_key_self_revocation,
    verify_publisher_key_history_document,
)
from traceseal_observe.identity import (
    IdentityWitnessError,
    sign_identity_evidence,
    witness_identity_evidence,
)
from traceseal_observe.publisher import (
    derive_publisher_evidence,
    publisher_fingerprint,
    sign_publisher_attestation,
    verify_publisher_attestation,
)
from traceseal_observe.source_identity import (
    HuggingFaceSourceAdapter,
    ModelScopeSourceAdapter,
    build_canonical_identity,
)


def _history_keys(tmp_path: Path) -> tuple[OperatorKey, Path, OperatorKey, Path]:
    k1, k1_path = _binding_key(tmp_path, "publisher-k1")
    k2, k2_path = _binding_key(tmp_path, "publisher-k2")
    return k1, k1_path, k2, k2_path


def _rotation(
    old_key_path: Path,
    new_key: OperatorKey,
    new_key_path: Path,
    *,
    provider: str = "huggingface",
    repository: str = MODEL_ID,
) -> dict:
    proposal = sign_publisher_key_rotation_proposal(
        provider,
        repository.split("/", 1)[0],
        repository,
        old_key_path,
        new_key.public_key_hex,
        effective_at="2026-08-30T10:00:00Z",
    )
    return accept_publisher_key_rotation(proposal, new_key_path)


def _history_document(
    tmp_path: Path,
    provider: str = "huggingface",
    repository: str = MODEL_ID,
    *,
    revocations: list[dict] | None = None,
) -> tuple[dict, OperatorKey, OperatorKey, Path, Path]:
    k1, k1_path, k2, k2_path = _history_keys(tmp_path)
    bindings = [
        _binding_document(tmp_path, provider, repository, key_path=k1_path),
        _binding_document(tmp_path, provider, repository, key_path=k2_path),
    ]
    rotation = _rotation(
        k1_path,
        k2,
        k2_path,
        provider=provider,
        repository=repository,
    )
    document = assemble_publisher_key_history(
        bindings,
        [rotation],
        revocations or [],
        provider,
        repository,
    )
    return document, k1, k2, k1_path, k2_path


def _source_pair_with_histories(tmp_path: Path):  # noqa: ANN202
    k1, k1_path, k2, k2_path = _history_keys(tmp_path)
    hf_document = assemble_publisher_key_history(
        [
            _binding_document(tmp_path, "huggingface", key_path=k1_path),
            _binding_document(tmp_path, "huggingface", key_path=k2_path),
        ],
        [_rotation(k1_path, k2, k2_path, provider="huggingface")],
        [],
        "huggingface",
        MODEL_ID,
    )
    ms_document = assemble_publisher_key_history(
        [
            _binding_document(tmp_path, "modelscope", key_path=k1_path),
            _binding_document(tmp_path, "modelscope", key_path=k2_path),
        ],
        [_rotation(k1_path, k2, k2_path, provider="modelscope")],
        [],
        "modelscope",
        MODEL_ID,
    )
    hf, ms = SourceFixture("huggingface"), SourceFixture("modelscope")
    hf.contents[HISTORY_PATH] = _canonical(hf_document)
    ms.contents[HISTORY_PATH] = _canonical(ms_document)
    return k1, k2, k1_path, k2_path, hf, ms


def test_planned_rotation_requires_old_authorisation_and_new_acceptance(
    tmp_path: Path,
) -> None:
    document, k1, k2, _, _ = _history_document(tmp_path)
    verified = verify_publisher_key_history_document(
        document, "huggingface", MODEL_ID
    )
    assert verified.current_fingerprint == publisher_fingerprint(
        bytes.fromhex(k2.public_key_hex)
    )
    assert verified.current_status == "active"
    assert [item["status"] for item in verified.keys] == ["superseded", "active"]
    assert verified.keys[0]["fingerprint"] == publisher_fingerprint(
        bytes.fromhex(k1.public_key_hex)
    )
    assert len(verified.rotation_statement_hashes) == 1

    mutations = {
        "old-authorisation-missing": lambda value: value["rotations"][0][
            "authorisation"
        ].update(value=""),
        "new-acceptance-missing": lambda value: value["rotations"][0][
            "acceptance"
        ].update(value=""),
        "effective-time": lambda value: value["rotations"][0]["statement"].update(
            effective_at="2026-08-30T10:00:01Z"
        ),
        "provider": lambda value: value["rotations"][0]["statement"][
            "subject"
        ].update(provider="modelscope"),
        "account": lambda value: value["rotations"][0]["statement"][
            "subject"
        ].update(account="attacker"),
        "repository": lambda value: value["rotations"][0]["statement"][
            "subject"
        ].update(repository="Qwen/other"),
        "fingerprint-spoof": lambda value: value["rotations"][0][
            "acceptance"
        ].update(fingerprint="ed25519:" + "0" * 64),
    }
    for name, mutate in mutations.items():
        candidate = copy.deepcopy(document)
        mutate(candidate)
        with pytest.raises(HistoryError) as caught:
            verify_publisher_key_history_document(
                candidate, "huggingface", MODEL_ID
            )
        assert caught.value.code, name


def test_new_key_takeover_one_sided_rotation_and_cross_scope_fail(
    tmp_path: Path,
) -> None:
    document, _, k2, _, k2_path = _history_document(tmp_path)
    takeover = copy.deepcopy(document)
    statement = takeover["rotations"][0]["statement"]
    unsigned = {
        "rotation_version": takeover["rotations"][0]["rotation_version"],
        "statement": statement,
    }
    takeover["rotations"][0]["authorisation"].update(
        fingerprint=publisher_fingerprint(bytes.fromhex(k2.public_key_hex)),
        public_key=k2.public_key_hex,
        value=k2.sign(_canonical(unsigned)).hex(),
    )
    with pytest.raises(HistoryError):
        verify_publisher_key_history_document(takeover, "huggingface", MODEL_ID)

    proposal = copy.deepcopy(document)
    proposal["rotations"][0]["acceptance"]["value"] = ""
    with pytest.raises(HistoryError) as missing:
        verify_publisher_key_history_document(proposal, "huggingface", MODEL_ID)
    assert missing.value.code == "rotation_acceptance_missing"

    copied = copy.deepcopy(document)
    with pytest.raises(HistoryError) as wrong_scope:
        verify_publisher_key_history_document(
            copied, "huggingface", "attacker/model"
        )
    assert wrong_scope.value.code == "binding_subject_mismatch"

    # Acceptance must be by the exact successor key named in the signed payload.
    wrong = OperatorKey.generate("wrong-successor")
    wrong_path = tmp_path / "wrong.key"
    _write_key(wrong_path, wrong)
    with pytest.raises(HistoryError):
        accept_publisher_key_rotation(
            sign_publisher_key_rotation_proposal(
                "huggingface",
                "Qwen",
                MODEL_ID,
                k2_path,
                k2.public_key_hex,
                effective_at="2026-08-30T10:00:00Z",
            ),
            wrong_path,
        )


def test_rotation_graph_rejects_self_cycle_fork_and_limit(tmp_path: Path) -> None:
    document, _, k2, _, k2_path = _history_document(tmp_path)
    with pytest.raises(HistoryError) as self_error:
        sign_publisher_key_rotation_proposal(
            "huggingface",
            "Qwen",
            MODEL_ID,
            k2_path,
            k2.public_key_hex,
            effective_at="2026-08-30T10:00:00Z",
        )
    assert self_error.value.code == "rotation_self"

    fork = copy.deepcopy(document)
    k3, k3_path = _binding_key(tmp_path, "publisher-k3")
    fork["bindings"].append(
        _binding_document(tmp_path, "huggingface", key_path=k3_path)
    )
    first_path = tmp_path / "publisher-k1.key"
    fork["rotations"].append(_rotation(first_path, k3, k3_path))
    with pytest.raises(HistoryError) as fork_error:
        verify_publisher_key_history_document(fork, "huggingface", MODEL_ID)
    assert fork_error.value.code == "publisher_history_ambiguous"

    cycle = copy.deepcopy(document)
    first_key = OperatorKey.load_from_file(tmp_path / "publisher-k1.key")
    cycle["rotations"].append(_rotation(k2_path, first_key, tmp_path / "publisher-k1.key"))
    with pytest.raises(HistoryError) as cycle_error:
        verify_publisher_key_history_document(cycle, "huggingface", MODEL_ID)
    assert cycle_error.value.code == "publisher_history_cycle"

    over_limit = copy.deepcopy(document)
    over_limit["rotations"] = over_limit["rotations"] * 17
    with pytest.raises(HistoryError) as limit_error:
        verify_publisher_key_history_document(over_limit, "huggingface", MODEL_ID)
    assert limit_error.value.code == "publisher_history_limit"


def test_self_revocation_and_platform_revocation_are_distinct(tmp_path: Path) -> None:
    document, _, k2, _, k2_path = _history_document(tmp_path)
    self_revocation = sign_publisher_key_self_revocation(
        "huggingface",
        "Qwen",
        MODEL_ID,
        k2_path,
        "retired",
        effective_at="2026-08-30T10:05:00Z",
    )
    self_document = copy.deepcopy(document)
    self_document["revocations"] = [self_revocation]
    self_verified = verify_publisher_key_history_document(
        self_document, "huggingface", MODEL_ID
    )
    assert self_verified.current_status == "revoked"
    assert self_verified.revocations[0]["evidence_method"] == "key_self_revocation"

    platform = build_platform_revocation(
        "huggingface",
        "Qwen",
        MODEL_ID,
        publisher_fingerprint(bytes.fromhex(k2.public_key_hex)),
        "lost",
        effective_at="2026-08-30T10:05:00Z",
    )
    platform_document = copy.deepcopy(document)
    platform_document["revocations"] = [platform]
    supplied = verify_publisher_key_history_document(
        platform_document, "huggingface", MODEL_ID
    )
    observed = verify_publisher_key_history_document(
        platform_document, "huggingface", MODEL_ID, platform_observed=True
    )
    assert supplied.revocations[0]["evidence_method"] == (
        "platform_revocation_supplied"
    )
    assert observed.revocations[0]["evidence_method"] == (
        "platform_revocation_observed"
    )
    assert supplied.continuity_root != observed.continuity_root

    tampered = copy.deepcopy(self_document)
    tampered["revocations"][0]["statement"]["reason_code"] = "compromised"
    with pytest.raises(HistoryError) as invalid:
        verify_publisher_key_history_document(tampered, "huggingface", MODEL_ID)
    assert invalid.value.code == "publisher_signature_invalid"


def test_legacy_binding_and_strict_history_wrapper_are_backwards_compatible(
    tmp_path: Path,
) -> None:
    legacy = _binding_document(tmp_path, "huggingface")
    legacy_verified = verify_publisher_key_history_document(
        legacy, "huggingface", MODEL_ID
    )
    assert legacy_verified.current_status == "active"
    assert len(legacy_verified.keys) == 1

    wrapper, _, _, _, _ = _history_document(tmp_path)
    encoded = canonical_publisher_key_history_bytes(wrapper)
    assert json.loads(encoded) == wrapper
    for payload in (
        b'{"publisher_history_version":"1.0","publisher_history_version":"1.0","bindings":[],"rotations":[],"revocations":[]}',
        encoded[:-1] + b',"remote_url":"https://attacker.invalid"}',
        b'{"binding_version":"1.0","publisher_history_version":"1.0"}',
    ):
        with pytest.raises(HistoryError):
            history_module.decode_publisher_key_history_document(payload)


def test_key_history_cross_language_conformance_vector(tmp_path: Path) -> None:
    old_key = OperatorKey.from_raw_bytes("old", bytes(range(32)))
    new_key = OperatorKey.from_raw_bytes("new", bytes(range(32, 64)))
    old_path, new_path = tmp_path / "old.key", tmp_path / "new.key"
    _write_key(old_path, old_key)
    _write_key(new_path, new_key)
    bindings = [
        _binding_document(
            tmp_path, "huggingface", "example-org/model", key_path=old_path
        ),
        _binding_document(
            tmp_path, "huggingface", "example-org/model", key_path=new_path
        ),
    ]
    rotation = _rotation(
        old_path,
        new_key,
        new_path,
        provider="huggingface",
        repository="example-org/model",
    )
    document = assemble_publisher_key_history(
        bindings,
        [rotation],
        [],
        "huggingface",
        "example-org/model",
    )
    verified = verify_publisher_key_history_document(
        document, "huggingface", "example-org/model"
    )
    assert history_module.publisher_key_rotation_signing_bytes(rotation).decode() == (
        '{"rotation_version":"1.0","statement":{"effective_at":"2026-08-30T10:00:00Z",'
        '"new_publisher":{"fingerprint":"ed25519:24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28"},'
        '"old_publisher":{"fingerprint":"ed25519:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"},'
        '"statement_type":"publisher_key_rotation","subject":{"account":"example-org","provider":"huggingface",'
        '"repository":"example-org/model","scope":"repository"}}}'
    )
    assert rotation["authorisation"]["value"] == (
        "95864a5bcd787c4628e3dab8f43f26695485d867721151d1639928bd1a3a936e"
        "6a57b75011c7335ad71a6cb9038185e52d2e4bd98583a000e331a1e264748a00"
    )
    assert rotation["acceptance"]["value"] == (
        "29201dad80a8e761a9d64222177721280d8ba3dc4abb09b792a4d76d614c74f"
        "894d61522705af75ca2840da8fb34cad2aa14ac6fa714dfd941aebd1a83c66b0c"
    )
    encoded = canonical_publisher_key_history_bytes(document)
    assert "sha256:" + hashlib.sha256(encoded).hexdigest() == (
        "sha256:1cc3bf1567ae66b6a61ff6818adbe1ef80efb5fcc4182f5eba1104761c888e61"
    )
    assert verified.continuity_root == (
        "sha256:80b85aaa2c428b22b4b10ee31bc061500a17f3d0610672274a8f2417557e64cf"
    )
    assert verified.rotation_statement_hashes == (
        "sha256:8d27dfe664016a5a19eb2cd62197ab56f64321886a1fc1ec51cac75659a39a5b",
    )


def test_cross_provider_history_evidence_is_deterministic_and_pinned(
    tmp_path: Path,
) -> None:
    _, _, _, _, hf, ms = _source_pair_with_histories(tmp_path)
    try:
        hf_entry = discover_publisher_key_history(
            "huggingface", MODEL_ID, HuggingFaceSourceAdapter(base_url=hf.base_url)
        )
        ms_entry = discover_publisher_key_history(
            "modelscope", MODEL_ID, ModelScopeSourceAdapter(base_url=ms.base_url)
        )
        forward = build_publisher_key_history_evidence([hf_entry, ms_entry])
        reverse = build_publisher_key_history_evidence([ms_entry, hf_entry])
        assert forward == reverse
        assert [item["provider"] for item in forward["observations"]] == [
            "huggingface",
            "modelscope",
        ]
        derived = derive_publisher_key_history_evidence(forward)
        assert derived.current_status == "active"
        assert derived.publisher_key_history_root == forward[
            "publisher_key_history_root"
        ]
        encoded = _canonical(forward)
        for forbidden in (MODEL_ID.encode(), HISTORY_PATH.encode(), b"/home/", b"config.json"):
            assert forbidden not in encoded
        current_binding = discover_publisher_binding(
            "huggingface", MODEL_ID, HuggingFaceSourceAdapter(base_url=hf.base_url)
        )
        assert current_binding["publisher_fingerprint"] == forward[
            "current_fingerprint"
        ]
        assert current_binding["status"] == "publisher_key_platform_bound"
    finally:
        hf.close()
        ms.close()


def test_history_evidence_rejects_inconsistent_key_state_sequence(
    tmp_path: Path,
) -> None:
    _, _, _, _, hf, ms = _source_pair_with_histories(tmp_path)
    try:
        valid = discover_publisher_key_history(
            "huggingface", MODEL_ID, HuggingFaceSourceAdapter(base_url=hf.base_url)
        )

        def current_differs(entry: dict) -> None:
            entry["current_fingerprint"] = entry["key_states"][0]["fingerprint"]

        def predecessor_active(entry: dict) -> None:
            entry["key_states"][0]["status"] = "active"

        def non_adjacent_duplicate(entry: dict) -> None:
            entry["key_states"][1]["status"] = "superseded"
            entry["key_states"].append(
                {
                    "fingerprint": entry["key_states"][0]["fingerprint"],
                    "status": "active",
                }
            )
            entry["current_fingerprint"] = entry["key_states"][0]["fingerprint"]
            entry["binding_statement_hashes"].append("sha256:" + "3" * 64)
            entry["rotation_statement_hashes"].append("sha256:" + "4" * 64)

        def revocation_count_differs(entry: dict) -> None:
            entry["revocation_statement_hashes"].append("sha256:" + "5" * 64)

        for mutate in (
            current_differs,
            predecessor_active,
            non_adjacent_duplicate,
            revocation_count_differs,
        ):
            candidate = copy.deepcopy(valid)
            mutate(candidate)
            with pytest.raises(HistoryError) as invalid:
                build_publisher_key_history_evidence([candidate])
            assert invalid.value.code == "publisher_history_evidence_invalid"
    finally:
        hf.close()
        ms.close()


def test_history_attaches_to_publisher_and_traceseal_without_changing_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    k1, k2, k1_path, k2_path, hf, ms = _source_pair_with_histories(tmp_path)
    resolver = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    resolver_path, witness_path = tmp_path / "resolver.key", tmp_path / "witness.key"
    _write_key(resolver_path, resolver)
    _write_key(witness_path, witness)
    try:
        observations = _observe((hf, ms))[:2]
        identity = build_canonical_identity(list(observations))
        canonical_before = identity["canonical_id"]
        attestation = sign_publisher_attestation(
            identity,
            list(observations),
            k1_path,
            issued_at="2026-08-30T10:00:30Z",
        )
        assert verify_publisher_attestation(
            attestation, identity, list(observations)
        ).status == "publisher_signature_valid"
        adapters = {
            "huggingface": HuggingFaceSourceAdapter(base_url=hf.base_url),
            "modelscope": ModelScopeSourceAdapter(base_url=ms.base_url),
        }
        history_evidence = build_publisher_key_history_evidence(
            [
                discover_publisher_key_history(provider, MODEL_ID, adapter)
                for provider, adapter in adapters.items()
            ]
        )
        binding_evidence = build_publisher_binding_evidence(
            [
                discover_publisher_binding(provider, MODEL_ID, adapter)
                for provider, adapter in adapters.items()
            ]
        )
        original_hf_history = json.loads(hf.contents[HISTORY_PATH])
        publisher = derive_publisher_evidence(
            identity,
            list(observations),
            [attestation],
            publisher_binding_evidence=binding_evidence,
            publisher_key_history_evidence=history_evidence,
        )
        assert publisher["publisher_key_history_root"] == history_evidence[
            "publisher_key_history_root"
        ]
        assert publisher["current_publisher_fingerprint"] == publisher_fingerprint(
            bytes.fromhex(k2.public_key_hex)
        )
        assert publisher["publisher_attestations"][0]["status"] == (
            "publisher_signature_valid"
        )
        assert publisher["publisher_attestations"][0]["publisher_key_status"] == (
            "superseded"
        )
        assert publisher["publisher_attestations"][0]["publisher_fingerprint"] == (
            publisher_fingerprint(bytes.fromhex(k1.public_key_hex))
        )
        assert identity["canonical_id"] == canonical_before

        receipt = sign_identity_evidence(
            identity,
            list(observations),
            resolver_path,
            observed_at="2026-08-30T10:01:00Z",
            publisher_attestations=[attestation],
            publisher_key_history_evidence=history_evidence,
        )
        assert receipt.execution["publisher_key_history_root"] == history_evidence[
            "publisher_key_history_root"
        ]
        assert receipt.execution["publisher_key_status"] == "active"
        verify_receipt_signature(receipt, "key history receipt")

        cosignature = witness_identity_evidence(
            identity,
            list(observations),
            receipt.to_dict(),
            MODEL_ID,
            MODEL_ID,
            witness_path,
            huggingface=HuggingFaceSourceAdapter(base_url=hf.base_url),
            modelscope=ModelScopeSourceAdapter(base_url=ms.base_url),
            max_observation_gap_seconds=300,
            now=datetime(2026, 8, 30, 10, 2, tzinfo=timezone.utc),
            publisher_attestations=[attestation],
            publisher_key_history_evidence=history_evidence,
            publisher_key_history_repositories={
                "huggingface": MODEL_ID,
                "modelscope": MODEL_ID,
            },
        )
        assert cosignature.execution["publisher_key_history_witness_method"] == (
            "platform_key_history_reobservation"
        )
        verify_receipt_signature(cosignature, "key history witness")

        offline_cosignature = witness_identity_evidence(
            identity,
            list(observations),
            receipt.to_dict(),
            MODEL_ID,
            MODEL_ID,
            witness_path,
            huggingface=HuggingFaceSourceAdapter(base_url=hf.base_url),
            modelscope=ModelScopeSourceAdapter(base_url=ms.base_url),
            max_observation_gap_seconds=300,
            now=datetime(2026, 8, 30, 10, 2, tzinfo=timezone.utc),
            publisher_attestations=[attestation],
            publisher_key_history_evidence=history_evidence,
            publisher_key_history_repositories={
                "huggingface": MODEL_ID,
                "modelscope": MODEL_ID,
            },
            publisher_key_history_documents={
                "huggingface": json.loads(hf.contents[HISTORY_PATH]),
                "modelscope": json.loads(ms.contents[HISTORY_PATH]),
            },
        )
        assert offline_cosignature.execution[
            "publisher_key_history_witness_method"
        ] == "publisher_key_history_rederivation"
        verify_receipt_signature(offline_cosignature, "offline history witness")

        changed = copy.deepcopy(json.loads(hf.contents[HISTORY_PATH]))
        changed["rotations"][0]["statement"]["effective_at"] = (
            "2026-08-30T10:00:01Z"
        )
        hf.contents[HISTORY_PATH] = _canonical(changed)
        with pytest.raises(IdentityWitnessError) as refused:
            witness_identity_evidence(
                identity,
                list(observations),
                receipt.to_dict(),
                MODEL_ID,
                MODEL_ID,
                witness_path,
                huggingface=HuggingFaceSourceAdapter(base_url=hf.base_url),
                modelscope=ModelScopeSourceAdapter(base_url=ms.base_url),
                max_observation_gap_seconds=300,
                now=datetime(2026, 8, 30, 10, 2, tzinfo=timezone.utc),
                publisher_attestations=[attestation],
                publisher_key_history_evidence=history_evidence,
                publisher_key_history_repositories={
                    "huggingface": MODEL_ID,
                    "modelscope": MODEL_ID,
                },
            )
        assert refused.value.code == "publisher_history_source_changed"

        fixture_values = {
            "identity.json": identity,
            "hf.json": observations[0],
            "ms.json": observations[1],
            "receipt.json": receipt.to_dict(),
            "publisher-attestation.json": attestation,
            "history-evidence.json": history_evidence,
        }
        for name, value in fixture_values.items():
            path = tmp_path / name
            path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
            path.chmod(0o600)
        monkeypatch.setattr(
            identity_module,
            "HuggingFaceSourceAdapter",
            lambda: HuggingFaceSourceAdapter(base_url=hf.base_url),
        )
        monkeypatch.setattr(
            identity_module,
            "ModelScopeSourceAdapter",
            lambda: ModelScopeSourceAdapter(base_url=ms.base_url),
        )
        refused_output = tmp_path / "history-refusal-must-not-exist.json"
        assert identity_module.main(
            [
                "witness",
                "--identity",
                str(tmp_path / "identity.json"),
                "--huggingface-observation",
                str(tmp_path / "hf.json"),
                "--modelscope-observation",
                str(tmp_path / "ms.json"),
                "--receipt",
                str(tmp_path / "receipt.json"),
                "--huggingface-model",
                MODEL_ID,
                "--modelscope-model",
                MODEL_ID,
                "--publisher-attestation",
                str(tmp_path / "publisher-attestation.json"),
                "--publisher-key-history-evidence",
                str(tmp_path / "history-evidence.json"),
                "--huggingface-key-history-repository",
                MODEL_ID,
                "--modelscope-key-history-repository",
                MODEL_ID,
                "--max-observation-gap-seconds",
                "86400",
                "--key",
                str(witness_path),
                "--output",
                str(refused_output),
            ]
        ) == 1
        assert not refused_output.exists()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "REFUSED publisher_history_source_changed\n"
        assert MODEL_ID not in captured.err
        assert hf.base_url not in captured.err

        revoked_hf_history = copy.deepcopy(original_hf_history)
        revoked_hf_history["revocations"] = [
            sign_publisher_key_self_revocation(
                "huggingface",
                "Qwen",
                MODEL_ID,
                k2_path,
                "retired",
                effective_at="2026-08-30T10:05:00Z",
            )
        ]
        hf.contents[HISTORY_PATH] = _canonical(revoked_hf_history)
        revoked_evidence = build_publisher_key_history_evidence(
            [
                discover_publisher_key_history(
                    "huggingface",
                    MODEL_ID,
                    HuggingFaceSourceAdapter(base_url=hf.base_url),
                )
            ]
        )
        revoked_publisher = derive_publisher_evidence(
            identity,
            list(observations),
            [attestation],
            publisher_key_history_evidence=revoked_evidence,
        )
        assert revoked_publisher["canonical_id"] == canonical_before
        assert revoked_publisher["publisher_key_status"] == "revoked"
        assert identity["canonical_id"] == canonical_before
    finally:
        hf.close()
        ms.close()


def test_publisher_key_cli_is_offline_create_once_and_safe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    k1, k1_path, k2, k2_path = _history_keys(tmp_path)
    proposal = tmp_path / "proposal.json"
    rotation = tmp_path / "rotation.json"
    assert history_main(
        [
            "rotate-propose",
            "--old-key",
            str(k1_path),
            "--new-public-key",
            k2.public_key_hex,
            "--provider",
            "huggingface",
            "--account",
            "Qwen",
            "--repository",
            MODEL_ID,
            "--effective-at",
            "2026-08-30T10:00:00Z",
            "--output",
            str(proposal),
        ]
    ) == 0
    assert history_main(
        [
            "rotate-accept",
            "--proposal",
            str(proposal),
            "--new-key",
            str(k2_path),
            "--output",
            str(rotation),
        ]
    ) == 0
    assert rotation.stat().st_mode & 0o777 == 0o600
    assert "PASS" in capsys.readouterr().out

    wrong_key = tmp_path / "wrong.key"
    _write_key(wrong_key, OperatorKey.generate("wrong"))
    refused = tmp_path / "must-not-exist.json"
    assert history_main(
        [
            "rotate-accept",
            "--proposal",
            str(proposal),
            "--new-key",
            str(wrong_key),
            "--output",
            str(refused),
        ]
    ) == 1
    assert not refused.exists()
    captured = capsys.readouterr()
    assert "REFUSED" in captured.err
    assert MODEL_ID not in captured.err
    del k1
