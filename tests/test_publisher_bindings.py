"""Phase 2A.3 publisher/account binding discovery and witness contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import traceseal_observe.binding as binding_module
import traceseal_observe.identity as identity_module
from test_identity_receipts import MODEL_ID, SourceFixture, _observe, _write_key
from traceseal_observe import OperatorKey, verify_receipt_signature
from traceseal_observe.binding import (
    BINDING_PATH,
    BindingError,
    build_publisher_binding_evidence,
    canonical_publisher_binding_bytes,
    derive_publisher_binding_evidence,
    discover_publisher_binding,
    main as binding_main,
    publisher_binding_signing_bytes,
    sign_publisher_binding,
    verify_publisher_binding_document,
)
from traceseal_observe.identity import (
    IdentityWitnessError,
    sign_identity_evidence,
    witness_identity_evidence,
)
from traceseal_observe.publisher import derive_publisher_evidence
from traceseal_observe.source_identity import (
    HuggingFaceSourceAdapter,
    ModelScopeSourceAdapter,
    build_canonical_identity,
)


def _binding_key(tmp_path: Path, name: str = "demo-publisher") -> tuple[OperatorKey, Path]:
    key = OperatorKey.generate(name)
    path = tmp_path / f"{name}.key"
    _write_key(path, key)
    return key, path


def _binding_document(
    tmp_path: Path,
    provider: str,
    repository: str = MODEL_ID,
    *,
    key_path: Path | None = None,
) -> dict:
    if key_path is None:
        _, key_path = _binding_key(tmp_path)
    return sign_publisher_binding(
        provider,
        repository.split("/", 1)[0],
        repository,
        key_path,
        issued_at="2026-08-30T09:00:00Z",
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def test_binding_canonicalisation_signature_and_offline_evidence_level(tmp_path: Path) -> None:
    document = _binding_document(tmp_path, "huggingface")
    signed = publisher_binding_signing_bytes(document)
    assert signed.startswith(
        b'{"binding_version":"1.0","statement":{"issued_at":"2026-08-30T09:00:00Z"'
    )
    assert b'"provider":"huggingface"' in signed
    assert b'"repository":"Qwen/Qwen3-0.6B"' in signed
    verification = verify_publisher_binding_document(
        document, "huggingface", MODEL_ID
    )
    assert verification.status == "publisher_key_self_claimed"
    assert verification.verification_method == "binding_evidence_rederivation"
    assert verification.publisher_fingerprint == document["signature"]["fingerprint"]
    assert canonical_publisher_binding_bytes(document) == _canonical(document)


def test_binding_cross_language_conformance_vectors() -> None:
    key = OperatorKey.from_raw_bytes("vector", bytes(range(32)))
    fingerprint = (
        "ed25519:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"
    )
    document = {
        "binding_version": "1.0",
        "signature": {
            "algorithm": "ed25519",
            "fingerprint": fingerprint,
            "public_key": key.public_key_hex,
            "value": "",
        },
        "statement": {
            "issued_at": "2026-08-30T09:00:00Z",
            "publisher": {"fingerprint": fingerprint},
            "statement_type": "publisher_key_binding",
            "subject": {
                "account": "example-org",
                "provider": "huggingface",
                "repository": "example-org/model",
                "scope": "repository",
            },
        },
    }
    signing_bytes = publisher_binding_signing_bytes(document)
    expected_signing_bytes = (
        b'{"binding_version":"1.0","statement":{"issued_at":"2026-08-30T09:00:00Z",'
        b'"publisher":{"fingerprint":"ed25519:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c"},'
        b'"statement_type":"publisher_key_binding","subject":{"account":"example-org",'
        b'"provider":"huggingface","repository":"example-org/model","scope":"repository"}}}'
    )
    assert key.public_key_hex == (
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    )
    assert signing_bytes == expected_signing_bytes
    document["signature"]["value"] = key.sign(signing_bytes).hex()
    assert document["signature"]["value"] == (
        "65aa3c58848d4c6d649e17d8d896a0177c1ab8a817a6e993cd7ee50fb3449090"
        "0750b990c0d16b61eac784e7a5d83ba5c69f943f081ffdedc892bc405977180d"
    )
    encoded = canonical_publisher_binding_bytes(document)
    assert "sha256:" + hashlib.sha256(encoded).hexdigest() == (
        "sha256:3bd261f4fcab62020ce562514a7ce1bcbfebce94273d77aea6c0310ef5c75dee"
    )
    verification = verify_publisher_binding_document(
        document, "huggingface", "example-org/model"
    )
    assert verification.statement_hash == (
        "sha256:c16cfcb0b69f4eb44508c2f2fc5698ba3eca152198347e2041ddd7d5f3099a2e"
    )
    assert verification.subject_hash == (
        "sha256:dd63aca96f1efafed6bad2b05e189626f61c668f1e066de27e1673d35336d02d"
    )

    def hashed(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode()).hexdigest()

    def entry(provider: str, kind: str, reference: str, revision: str) -> dict:
        return {
            "binding_path_hash": hashed(BINDING_PATH),
            "document_hash": "sha256:3bd261f4fcab62020ce562514a7ce1bcbfebce94273d77aea6c0310ef5c75dee",
            "provider": provider,
            "publisher_fingerprint": fingerprint,
            "revision": {
                "kind": kind,
                "reference_hash": hashed(reference),
                "value_hash": hashed(revision),
            },
            "scope": "repository",
            "source_identity_hash": hashed("example-org/model"),
            "statement_hash": verification.statement_hash,
            "status": "publisher_key_platform_bound",
            "subject_hash": verification.subject_hash,
        }

    evidence = build_publisher_binding_evidence(
        [
            entry("modelscope", "file_commit_sha1", "master", "2" * 40),
            entry("huggingface", "git_commit_sha1", "main", "1" * 40),
        ]
    )
    assert evidence["binding_root"] == (
        "sha256:022d77f3b3fd5cbcbd891824f1c77edb226ff8d566e6b12777161df9d68df6e3"
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("provider", "modelscope", "publisher_signature_invalid"),
        ("account", "attacker", "publisher_signature_invalid"),
        ("repository", "Qwen/other", "publisher_signature_invalid"),
        ("issued_at", "2026-08-30T09:00:01Z", "publisher_signature_invalid"),
    ],
)
def test_binding_signed_subject_and_time_tamper_refused(
    tmp_path: Path, field: str, value: str, code: str
) -> None:
    document = _binding_document(tmp_path, "huggingface")
    if field == "issued_at":
        document["statement"][field] = value
    else:
        document["statement"]["subject"][field] = value
        if field == "account":
            document["statement"]["subject"]["repository"] = value + "/model"
    with pytest.raises(BindingError) as caught:
        verify_publisher_binding_document(
            document,
            document["statement"]["subject"]["provider"],
            document["statement"]["subject"]["repository"],
        )
    assert caught.value.code == code


def test_binding_copy_provider_fingerprint_and_key_substitution_refused(tmp_path: Path) -> None:
    document = _binding_document(tmp_path, "huggingface", "real-publisher/model")
    with pytest.raises(BindingError) as copied:
        verify_publisher_binding_document(document, "huggingface", "attacker/model")
    assert copied.value.code == "binding_subject_mismatch"
    with pytest.raises(BindingError) as cross_provider:
        verify_publisher_binding_document(document, "modelscope", "real-publisher/model")
    assert cross_provider.value.code == "binding_subject_mismatch"

    spoofed = copy.deepcopy(document)
    spoofed["signature"]["fingerprint"] = "ed25519:" + "0" * 64
    with pytest.raises(BindingError) as fingerprint:
        verify_publisher_binding_document(spoofed, "huggingface", "real-publisher/model")
    assert fingerprint.value.code == "publisher_fingerprint_mismatch"

    replacement = OperatorKey.generate("replacement")
    wrong_key = copy.deepcopy(document)
    wrong_key["signature"]["public_key"] = replacement.public_key_hex
    wrong_key["signature"]["fingerprint"] = (
        "ed25519:" + hashlib.sha256(bytes.fromhex(replacement.public_key_hex)).hexdigest()
    )
    wrong_key["statement"]["publisher"]["fingerprint"] = wrong_key["signature"][
        "fingerprint"
    ]
    with pytest.raises(BindingError) as substitution:
        verify_publisher_binding_document(
            wrong_key, "huggingface", "real-publisher/model"
        )
    assert substitution.value.code == "publisher_signature_invalid"


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda value: value["signature"].update(algorithm="ed448"), "publisher_algorithm_invalid"),
        (lambda value: value["statement"].update(issued_at="2026-08-30T09:00:00+00:00"), "publisher_issued_at_invalid"),
        (lambda value: value["statement"]["subject"].update(account="Qwen\u202e"), "binding_subject_invalid"),
        (lambda value: value["statement"]["subject"].update(repository="../model"), "binding_subject_invalid"),
        (lambda value: value["statement"]["subject"].update(scope="account"), "binding_subject_invalid"),
    ],
)
def test_binding_shape_unicode_algorithm_and_time_fail_closed(
    tmp_path: Path, mutator, code: str
) -> None:
    document = _binding_document(tmp_path, "huggingface")
    mutator(document)
    with pytest.raises(BindingError) as caught:
        verify_publisher_binding_document(document, "huggingface", MODEL_ID)
    assert caught.value.code == code


def _source_pair_with_bindings(tmp_path: Path):
    key, key_path = _binding_key(tmp_path)
    hf_document = _binding_document(
        tmp_path, "huggingface", key_path=key_path
    )
    ms_document = _binding_document(tmp_path, "modelscope", key_path=key_path)
    hf = SourceFixture("huggingface")
    ms = SourceFixture("modelscope")
    hf.contents[BINDING_PATH] = _canonical(hf_document)
    ms.contents[BINDING_PATH] = _canonical(ms_document)
    return key, key_path, hf_document, ms_document, hf, ms


def test_platform_binding_discovery_is_pinned_safe_and_cross_provider_deterministic(
    tmp_path: Path,
) -> None:
    _, _, _, _, hf, ms = _source_pair_with_bindings(tmp_path)
    try:
        hf_adapter = HuggingFaceSourceAdapter(base_url=hf.base_url)
        ms_adapter = ModelScopeSourceAdapter(base_url=ms.base_url)
        hf_entry = discover_publisher_binding("huggingface", MODEL_ID, hf_adapter)
        ms_entry = discover_publisher_binding("modelscope", MODEL_ID, ms_adapter)
        assert hf_entry["status"] == "publisher_key_platform_bound"
        assert ms_entry["status"] == "publisher_key_platform_bound"
        assert hf_entry["revision"]["kind"] == "git_commit_sha1"
        assert ms_entry["revision"]["kind"] == "file_commit_sha1"
        ms_download = [
            request for request in ms.requests if request["path"].endswith("/repo")
        ][-1]
        assert ms_download["query"]["Revision"] == [ms.ms_file_revision]
        for request in hf.requests + ms.requests:
            assert request["authorization"] == ""
            assert request["cookie"] == ""
            assert request["proxy_authorization"] == ""
            assert request["accept_encoding"] == "identity"
        forward = build_publisher_binding_evidence([hf_entry, ms_entry])
        reverse = build_publisher_binding_evidence([ms_entry, hf_entry])
        assert forward == reverse
        assert [item["provider"] for item in forward["bindings"]] == [
            "huggingface",
            "modelscope",
        ]
        assert derive_publisher_binding_evidence(forward).binding_root == forward[
            "binding_root"
        ]
        encoded = _canonical(forward)
        for forbidden in (MODEL_ID.encode(), BINDING_PATH.encode(), b"/home/", b"model_type"):
            assert forbidden not in encoded
    finally:
        hf.close()
        ms.close()


def test_different_publisher_keys_do_not_merge(tmp_path: Path) -> None:
    first_key, first_path = _binding_key(tmp_path, "first")
    second_key, second_path = _binding_key(tmp_path, "second")
    del first_key, second_key
    hf = SourceFixture("huggingface")
    ms = SourceFixture("modelscope")
    try:
        hf.contents[BINDING_PATH] = _canonical(
            _binding_document(tmp_path, "huggingface", key_path=first_path)
        )
        ms.contents[BINDING_PATH] = _canonical(
            _binding_document(tmp_path, "modelscope", key_path=second_path)
        )
        entries = [
            discover_publisher_binding(
                "huggingface", MODEL_ID, HuggingFaceSourceAdapter(base_url=hf.base_url)
            ),
            discover_publisher_binding(
                "modelscope", MODEL_ID, ModelScopeSourceAdapter(base_url=ms.base_url)
            ),
        ]
        with pytest.raises(BindingError) as caught:
            build_publisher_binding_evidence(entries)
        assert caught.value.code == "binding_publisher_mismatch"
    finally:
        hf.close()
        ms.close()


def test_binding_discovery_rejects_copy_missing_change_oversize_and_redirect(
    tmp_path: Path,
) -> None:
    _, key_path = _binding_key(tmp_path)
    valid = _binding_document(
        tmp_path, "huggingface", "real-publisher/model", key_path=key_path
    )
    hf = SourceFixture("huggingface")
    try:
        hf.contents[BINDING_PATH] = _canonical(valid)
        with pytest.raises(BindingError) as copied:
            discover_publisher_binding(
                "huggingface",
                MODEL_ID,
                HuggingFaceSourceAdapter(base_url=hf.base_url),
            )
        assert copied.value.code == "binding_subject_mismatch"
    finally:
        hf.close()

    for mode in ("unavailable", "oversized", "redirect"):
        source = SourceFixture("huggingface")
        source.mode = mode
        try:
            with pytest.raises(BindingError) as caught:
                discover_publisher_binding(
                    "huggingface",
                    MODEL_ID,
                    HuggingFaceSourceAdapter(base_url=source.base_url, timeout=0.05),
                )
            assert caught.value.code in {
                "binding_source_unavailable",
                "binding_document_too_large",
            }
        finally:
            source.close()


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (
            b'{"binding_version":"1.0","binding_version":"1.0","signature":{},"statement":{}}',
            "publisher_binding_invalid",
        ),
        (
            b'{"binding_version":"1.0","signature":{},"statement":{},"remote_url":"https://attacker.invalid"}',
            "publisher_binding_invalid",
        ),
        (b"x" * ((64 << 10) + 1), "binding_document_too_large"),
    ],
    ids=("duplicate-key", "unknown-field", "oversized"),
)
def test_fetched_binding_json_and_size_fail_closed(
    payload: bytes, code: str
) -> None:
    source = SourceFixture("huggingface")
    source.contents[BINDING_PATH] = payload
    try:
        with pytest.raises(BindingError) as caught:
            discover_publisher_binding(
                "huggingface",
                MODEL_ID,
                HuggingFaceSourceAdapter(base_url=source.base_url),
            )
        assert caught.value.code == code
        assert "attacker.invalid" not in str(caught.value)
        assert payload[:16].decode("utf-8", errors="ignore") not in str(caught.value)
    finally:
        source.close()


def test_binding_cli_generates_offline_and_does_not_accept_origin_override(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, key_path = _binding_key(tmp_path)
    output = tmp_path / "publisher-binding.json"
    assert (
        binding_main(
            [
                "generate",
                "--provider",
                "huggingface",
                "--account",
                "Qwen",
                "--repository",
                MODEL_ID,
                "--key",
                str(key_path),
                "--issued-at",
                "2026-08-30T09:00:00Z",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == (
        "PASS publisher_key_self_claimed "
        "publish_path=.well-known/open-registry/publisher.json\n"
    )
    assert output.stat().st_mode & 0o777 == 0o600
    verify_publisher_binding_document(
        json.loads(output.read_text()), "huggingface", MODEL_ID
    )
    assert binding_main(["verify", "--provider", "huggingface", "--repository", MODEL_ID, "--endpoint", "https://attacker.invalid"]) == 2
    assert "attacker.invalid" not in capsys.readouterr().err


def test_binding_cli_retrieves_from_trusted_adapter_and_writes_safe_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, key_path = _binding_key(tmp_path)
    source = SourceFixture("huggingface")
    source.contents[BINDING_PATH] = _canonical(
        _binding_document(tmp_path, "huggingface", key_path=key_path)
    )
    adapter = HuggingFaceSourceAdapter(base_url=source.base_url)
    monkeypatch.setattr(binding_module, "HuggingFaceSourceAdapter", lambda: adapter)
    output = tmp_path / "binding-evidence.json"
    try:
        assert binding_main(
            [
                "verify",
                "--provider",
                "huggingface",
                "--repository",
                MODEL_ID,
                "--output",
                str(output),
            ]
        ) == 0
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == "PASS publisher_key_platform_bound provider=huggingface\n"
        assert output.stat().st_mode & 0o777 == 0o600
        evidence = json.loads(output.read_text())
        assert derive_publisher_binding_evidence(evidence).status == (
            "publisher_key_platform_bound"
        )
        assert MODEL_ID not in output.read_text()
    finally:
        source.close()


def test_binding_cli_never_echoes_query_like_repository_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "must-not-exist.json"
    secret_input = "example-org/model?token=must-not-appear"
    assert binding_main(
        [
            "verify",
            "--provider",
            "huggingface",
            "--repository",
            secret_input,
            "--output",
            str(output),
        ]
    ) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "REFUSED binding_source_unavailable\n"
    assert secret_input not in captured.err
    assert "must-not-appear" not in captured.err
    assert not output.exists()


def test_identity_receipt_commits_binding_root_and_witness_reobserves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, _, _, _, hf, ms = _source_pair_with_bindings(tmp_path)
    resolver = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    resolver_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(resolver_path, resolver)
    _write_key(witness_path, witness)
    try:
        observations = _observe((hf, ms))[:2]
        identity = build_canonical_identity(list(observations))
        canonical_before = identity["canonical_id"]
        hf_adapter = HuggingFaceSourceAdapter(base_url=hf.base_url)
        ms_adapter = ModelScopeSourceAdapter(base_url=ms.base_url)
        binding_evidence = build_publisher_binding_evidence(
            [
                discover_publisher_binding("huggingface", MODEL_ID, hf_adapter),
                discover_publisher_binding("modelscope", MODEL_ID, ms_adapter),
            ]
        )
        receipt = sign_identity_evidence(
            identity,
            list(observations),
            resolver_path,
            observed_at="2026-08-30T09:00:00Z",
            publisher_binding_evidence=binding_evidence,
        )
        assert receipt.execution["publisher_binding_root"] == binding_evidence[
            "binding_root"
        ]
        assert receipt.execution["publisher_binding_status"] == "publisher_key_platform_bound"
        attached = derive_publisher_evidence(
            identity,
            list(observations),
            [],
            publisher_binding_evidence=binding_evidence,
        )
        assert attached["canonical_id"] == canonical_before
        assert attached["publisher_binding_root"] == binding_evidence["binding_root"]
        verify_receipt_signature(receipt, "identity binding receipt")

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
            now=datetime(2026, 8, 30, 9, 1, tzinfo=timezone.utc),
            publisher_binding_evidence=binding_evidence,
            publisher_binding_repositories={
                "huggingface": MODEL_ID,
                "modelscope": MODEL_ID,
            },
        )
        assert cosignature.execution["publisher_binding_root"] == binding_evidence[
            "binding_root"
        ]
        assert (
            cosignature.execution["publisher_binding_witness_method"]
            == "platform_binding_reobservation"
        )
        verify_receipt_signature(cosignature, "identity binding witness")
        assert identity["canonical_id"] == canonical_before

        changed = json.loads(hf.contents[BINDING_PATH])
        changed["statement"]["issued_at"] = "2026-08-30T09:00:01Z"
        hf.contents[BINDING_PATH] = _canonical(changed)
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
                now=datetime(2026, 8, 30, 9, 1, tzinfo=timezone.utc),
                publisher_binding_evidence=binding_evidence,
                publisher_binding_repositories={
                    "huggingface": MODEL_ID,
                    "modelscope": MODEL_ID,
                },
            )
        assert refused.value.code in {
            "binding_source_changed",
            "publisher_signature_invalid",
        }

        fixture_files = {
            "identity.json": identity,
            "hf.json": observations[0],
            "ms.json": observations[1],
            "receipt.json": receipt.to_dict(),
            "binding-evidence.json": binding_evidence,
        }
        for name, value in fixture_files.items():
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
        refused_output = tmp_path / "binding-refusal-must-not-exist.json"
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
                "--publisher-binding-evidence",
                str(tmp_path / "binding-evidence.json"),
                "--huggingface-binding-repository",
                MODEL_ID,
                "--modelscope-binding-repository",
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
        assert captured.err.startswith("REFUSED ")
        assert MODEL_ID not in captured.err
        assert hf.base_url not in captured.err
    finally:
        hf.close()
        ms.close()
