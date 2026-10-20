"""Phase 2A.1 external re-observation and canonical identity receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

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
from traceseal_observe.identity import (
    IdentityWitnessError,
    build_canonical_identity,
    sign_identity_evidence,
    witness_identity_evidence,
)
from traceseal_observe.resolution import (
    ResolutionWitnessError,
    sign_resolution_evidence,
    witness_resolution_evidence,
    witness_resolution_reobservation,
)
from traceseal_observe.source_identity import (
    HuggingFaceSourceAdapter,
    ModelScopeSourceAdapter,
    SourceObservationError,
    canonical_identity_bytes,
    canonical_observation_bytes,
    derive_canonical_identity,
    derive_source_observation,
)
from traceseal_observe.publisher import (
    PublisherAttestationError,
    build_platform_account_claim,
    canonical_publisher_attestation_bytes,
    derive_publisher_evidence,
    publisher_identity_from_public_key,
    publisher_signing_bytes,
    sign_publisher_attestation,
    verify_publisher_attestation,
)

MODEL_ID = "Qwen/Qwen3-0.6B"
HF_REVISION = "c1899de289a04d12100db370d81485cdf75e47ca"
MS_FILE_REVISION = "d" * 40
CONTENTS = {
    "LICENSE": b"licence\n",
    "config.json": b'{"model_type":"qwen3"}\n',
    "generation_config.json": b'{"eos_token_id":151645}\n',
    "tokenizer_config.json": b'{"tokenizer_class":"Qwen2Tokenizer"}\n',
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _hash_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _git_blob_oid(payload: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(payload) + payload).hexdigest()


class SourceFixture:
    def __init__(self, provider: str):
        self.provider = provider
        self.contents = dict(CONTENTS)
        self.hf_revision = HF_REVISION
        self.ms_file_revision = MS_FILE_REVISION
        self.mode = "ok"
        self.requests: list[dict[str, object]] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
                parsed = urlsplit(self.path)
                fixture.requests.append(
                    {
                        "path": parsed.path,
                        "query": parse_qs(parsed.query),
                        "authorization": self.headers.get("Authorization", ""),
                        "cookie": self.headers.get("Cookie", ""),
                        "proxy_authorization": self.headers.get("Proxy-Authorization", ""),
                        "accept_encoding": self.headers.get("Accept-Encoding", ""),
                    }
                )
                if fixture.mode == "unavailable":
                    self.send_error(503)
                    return
                if fixture.mode == "malformed":
                    self._reply(b"{not-json", "application/json")
                    return
                if fixture.mode == "oversized":
                    self._reply(b"x" * ((1 << 20) + 1), "application/json")
                    return
                if fixture.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "https://attacker.invalid/source")
                    self.end_headers()
                    return
                if fixture.mode == "slow":
                    time.sleep(0.25)
                if fixture.provider == "huggingface":
                    self._huggingface(parsed.path)
                else:
                    self._modelscope(parsed.path, parse_qs(parsed.query))

            def _huggingface(self, path: str) -> None:
                if path == "/api/models/" + MODEL_ID:
                    self._json({"id": MODEL_ID, "sha": fixture.hf_revision})
                    return
                if path == "/api/models/" + MODEL_ID + "/tree/" + fixture.hf_revision:
                    if fixture.mode == "traversal":
                        self._json(
                            [
                                {
                                    "path": "../escape",
                                    "type": "file",
                                    "size": 1,
                                    "oid": "a" * 40,
                                }
                            ]
                        )
                        return
                    if fixture.mode == "unicode_control":
                        self._json(
                            [
                                {
                                    "path": "\u202econtrol",
                                    "type": "file",
                                    "size": 1,
                                    "oid": "a" * 40,
                                }
                            ]
                        )
                        return
                    if fixture.mode == "percent_path":
                        self._json(
                            [
                                {
                                    "path": "%zz",
                                    "type": "file",
                                    "size": 1,
                                    "oid": "a" * 40,
                                }
                            ]
                        )
                        return
                    if fixture.mode == "duplicate":
                        payload = fixture.contents["config.json"]
                        entry = {
                            "path": "config.json",
                            "type": "file",
                            "size": len(payload),
                            "oid": _git_blob_oid(payload),
                        }
                        self._json([entry, entry])
                        return
                    self._json(
                        [
                            {
                                "path": name,
                                "type": "file",
                                "size": len(payload),
                                "oid": _git_blob_oid(payload),
                            }
                            for name, payload in sorted(fixture.contents.items())
                        ]
                    )
                    return
                prefix = "/" + MODEL_ID + "/resolve/" + fixture.hf_revision + "/"
                if path.startswith(prefix):
                    self._file(unquote(path[len(prefix) :]))
                    return
                self.send_error(404)

            def _modelscope(self, path: str, query: dict[str, list[str]]) -> None:
                root = "/api/v1/models/" + MODEL_ID
                if path == root:
                    self._json(
                        {
                            "Code": 200,
                            "Data": {
                                "Path": "Qwen",
                                "Name": "Qwen3-0.6B",
                                "Revision": "master",
                                "IsAccessible": 1,
                                "IsPublished": 1,
                            },
                        }
                    )
                    return
                if path == root + "/repo/files":
                    assert query.get("Revision") == ["master"]
                    assert query.get("Recursive") == ["true"]
                    self._json(
                        {
                            "Code": 200,
                            "Data": {
                                "Files": [
                                    {
                                        "Path": name,
                                        "Type": "blob",
                                        "Size": len(payload),
                                        "Sha256": _sha256(payload),
                                        "Revision": fixture.ms_file_revision,
                                    }
                                    for name, payload in sorted(fixture.contents.items())
                                ]
                            },
                        }
                    )
                    return
                if path == root + "/repo":
                    # Phase 2A.1 source observations intentionally retain their
                    # historical branch query. Phase 2A.3 binding discovery uses
                    # the immutable per-file commit returned by the listing.
                    assert query.get("Revision") in (["master"], [fixture.ms_file_revision])
                    self._file(query.get("FilePath", [""])[0])
                    return
                self.send_error(404)

            def _file(self, name: str) -> None:
                payload = fixture.contents.get(name)
                if payload is None:
                    self.send_error(404)
                    return
                self._reply(payload, "application/octet-stream")

            def _json(self, value: object) -> None:
                self._reply(
                    json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
                    "application/json",
                )

            def _reply(self, payload: bytes, content_type: str) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@pytest.fixture
def sources():
    hf = SourceFixture("huggingface")
    ms = SourceFixture("modelscope")
    try:
        yield hf, ms
    finally:
        hf.close()
        ms.close()


def _observe(sources):
    hf, ms = sources
    hf_adapter = HuggingFaceSourceAdapter(base_url=hf.base_url)
    ms_adapter = ModelScopeSourceAdapter(base_url=ms.base_url)
    return (
        hf_adapter.observe(MODEL_ID),
        ms_adapter.observe(MODEL_ID),
        hf_adapter,
        ms_adapter,
    )


def _write_key(path: Path, key: OperatorKey) -> None:
    path.write_bytes(
        key.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )
    path.chmod(0o600)


def _remote_resolution_bundle(revision: str = HF_REVISION) -> dict:
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
    revision_hash = _hash_text(revision)
    candidates = [
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
    policy_hash = _hash(policy)
    candidate_hash = _hash(candidates)
    decision_record = {
        "policy_hash": policy_hash,
        "reason_code": "native_miss_federated",
        "selected_source": "huggingface",
    }
    decision_hash = _hash(decision_record)
    model_hash = _hash_text(MODEL_ID)
    root = {
        "candidate_set_hash": candidate_hash,
        "decision_hash": decision_hash,
        "event_type": "model_resolution",
        "evidence_version": "1.0",
        "model_identity_hash": model_hash,
        "policy_hash": policy_hash,
        "resolver_version_hash": resolver["version_hash"],
        "revision_hash": revision_hash,
    }
    return {
        "decision": {**decision_record, "decision_hash": decision_hash},
        "event_type": "model_resolution",
        "evidence_version": "1.0",
        "observation": {
            "candidate_set_hash": candidate_hash,
            "native_state": "miss",
            "remote_state": "observed",
            "revision_hash": revision_hash,
        },
        "request": {"model_identity_hash": model_hash},
        "resolver": resolver,
        "result": {
            "evidence_root": _hash(root),
            "evidence_strength": "remote_metadata_observed",
        },
        "supporting_evidence": {
            "candidates": candidates,
            "policy": policy,
            "remote_metadata": {"revision": revision},
        },
    }


def test_source_observations_are_deterministic_and_hash_types_are_explicit(sources) -> None:
    first_hf, first_ms, _, _ = _observe(sources)
    second_hf, second_ms, _, _ = _observe(sources)
    assert canonical_observation_bytes(first_hf) == canonical_observation_bytes(second_hf)
    assert canonical_observation_bytes(first_ms) == canonical_observation_bytes(second_ms)
    assert derive_source_observation(first_hf).provider == "huggingface"
    assert derive_source_observation(first_ms).provider == "modelscope"
    assert first_hf["revision"]["kind"] == "git_commit_sha1"
    assert first_ms["revision"]["kind"] == "selected_file_commit_set"
    assert {entry["provider_hash"]["algorithm"] for entry in first_hf["files"]} == {"git_sha1"}
    assert {entry["provider_hash"]["algorithm"] for entry in first_ms["files"]} == {"sha256"}
    for observation in (first_hf, first_ms):
        assert {entry["content_hash"]["origin"] for entry in observation["files"]} == {"locally_computed"}
    for fixture in sources:
        assert all(request["authorization"] == "" for request in fixture.requests)
        assert all(request["cookie"] == "" for request in fixture.requests)
        assert all(request["proxy_authorization"] == "" for request in fixture.requests)
        assert all(request["accept_encoding"] == "identity" for request in fixture.requests)


def test_canonical_identity_is_source_order_and_registry_url_neutral(sources) -> None:
    hf, ms, _, _ = _observe(sources)
    first = build_canonical_identity([hf, ms])
    second = build_canonical_identity([ms, hf])
    assert canonical_identity_bytes(first, [hf, ms]) == canonical_identity_bytes(second, [ms, hf])
    derived = derive_canonical_identity(first, [hf, ms])
    assert derived.equivalence_level == "selected_files_equivalent"
    assert derived.selected_files == 4

    # Re-observe identical bytes through fresh origins: URLs never enter identity.
    other_hf = SourceFixture("huggingface")
    other_ms = SourceFixture("modelscope")
    try:
        other_observations = [
            HuggingFaceSourceAdapter(base_url=other_hf.base_url).observe(MODEL_ID),
            ModelScopeSourceAdapter(base_url=other_ms.base_url).observe(MODEL_ID),
        ]
        other = build_canonical_identity(other_observations)
        assert other["canonical_id"] == first["canonical_id"]
        assert other["equivalence"]["evidence_root"] == first["equivalence"]["evidence_root"]
    finally:
        other_hf.close()
        other_ms.close()


def test_metadata_agreement_and_byte_mismatch_never_become_equivalence(sources) -> None:
    hf, ms, _, _ = _observe(sources)
    metadata_only = copy.deepcopy(hf)
    metadata_only["files"] = []
    with pytest.raises(SourceObservationError):
        build_canonical_identity([metadata_only, ms])

    sources[1].contents["config.json"] = b'{"model_type":"different"}\n'
    changed_ms = ModelScopeSourceAdapter(base_url=sources[1].base_url).observe(MODEL_ID)
    with pytest.raises(SourceObservationError, match="selected file"):
        build_canonical_identity([hf, changed_ms])

    sources[0].contents["config.json"] = sources[1].contents["config.json"]
    changed_hf = HuggingFaceSourceAdapter(base_url=sources[0].base_url).observe(MODEL_ID)
    changed = build_canonical_identity([changed_hf, changed_ms])
    original = build_canonical_identity([hf, ms])
    assert changed["canonical_id"] != original["canonical_id"]
    assert changed["equivalence"]["evidence_root"] != original["equivalence"]["evidence_root"]


@pytest.mark.parametrize(
    "mode",
    [
        "malformed",
        "oversized",
        "redirect",
        "unavailable",
        "traversal",
        "unicode_control",
        "percent_path",
        "duplicate",
    ],
)
def test_source_adapters_fail_closed(mode: str) -> None:
    fixture = SourceFixture("huggingface")
    fixture.mode = mode
    try:
        with pytest.raises(SourceObservationError) as caught:
            HuggingFaceSourceAdapter(base_url=fixture.base_url, timeout=0.2).observe(MODEL_ID)
        assert fixture.base_url not in str(caught.value)
        assert "attacker" not in str(caught.value)
    finally:
        fixture.close()


def test_source_timeout_and_modelscope_redirect_fail_closed() -> None:
    slow = SourceFixture("huggingface")
    slow.mode = "slow"
    try:
        with pytest.raises(SourceObservationError) as caught:
            HuggingFaceSourceAdapter(base_url=slow.base_url, timeout=0.05).observe(
                MODEL_ID
            )
        assert caught.value.code == "source_unavailable"
    finally:
        slow.close()

    redirected = SourceFixture("modelscope")
    redirected.mode = "redirect"
    try:
        with pytest.raises(SourceObservationError) as caught:
            ModelScopeSourceAdapter(base_url=redirected.base_url).observe(MODEL_ID)
        assert caught.value.code == "source_unavailable"
    finally:
        redirected.close()


def test_identity_receipt_and_fresh_reobservation_cosignature(sources, tmp_path: Path) -> None:
    hf, ms, hf_adapter, ms_adapter = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)

    observed_at = "2026-08-30T06:30:00Z"
    receipt = sign_identity_evidence(
        identity, [hf, ms], signer_path, observed_at=observed_at
    )
    verify_receipt_signature(receipt, "identity receipt")
    assert receipt.execution["receipt_type"] == "model_identity_observation"
    assert receipt.execution["receipt_profile_version"] == "1.1"
    assert receipt.execution["observed_at"] == observed_at
    cosignature = witness_identity_evidence(
        identity,
        [hf, ms],
        receipt.to_dict(),
        MODEL_ID,
        MODEL_ID,
        witness_path,
        huggingface=hf_adapter,
        modelscope=ms_adapter,
        max_observation_gap_seconds=300,
        now=datetime(2026, 8, 30, 6, 31, tzinfo=timezone.utc),
    )
    verify_receipt_signature(cosignature, "identity cosignature")
    assert cosignature.execution["receipt_type"] == "model_identity_cosignature"
    assert cosignature.execution["receipt_profile_version"] == "1.1"
    assert cosignature.execution["resolver_observed_at"] == observed_at
    assert cosignature.execution["reobserved_at"] == "2026-08-30T06:31:00Z"
    assert cosignature.execution["witness_method"] == "remote_source_reobservation"
    assert cosignature.execution["verdict"] == "CONFIRMED"
    assert cosignature.provenance["claim"] == "selected_file_evidence_independently_reobserved_and_confirmed"


def test_canonical_identity_is_time_independent_but_receipt_hash_is_not(
    sources, tmp_path: Path
) -> None:
    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    canonical_before = canonical_identity_bytes(identity, [hf, ms])
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, OperatorKey.generate("resolver"))

    first = sign_identity_evidence(
        identity,
        [hf, ms],
        key_path,
        observed_at="2026-08-30T06:30:00Z",
    )
    second = sign_identity_evidence(
        identity,
        [hf, ms],
        key_path,
        observed_at="2026-08-30T06:30:01Z",
    )

    assert first.execution["canonical_id"] == second.execution["canonical_id"]
    assert canonical_identity_bytes(identity, [hf, ms]) == canonical_before
    assert first.receipt_hash != second.receipt_hash


def test_historical_identity_receipt_remains_witnessable(
    sources, tmp_path: Path
) -> None:
    hf, ms, hf_adapter, ms_adapter = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)

    current = sign_identity_evidence(identity, [hf, ms], signer_path)
    legacy_execution = dict(current.execution)
    legacy_execution.pop("observed_at")
    legacy_execution.pop("receipt_profile_version")
    legacy = sign_execution_receipt(
        legacy_execution, dict(current.provenance), signer
    )
    attested = datetime.fromisoformat(
        legacy.attestation["attested_at"].replace("Z", "+00:00")
    )
    cosignature = witness_identity_evidence(
        identity,
        [hf, ms],
        legacy.to_dict(),
        MODEL_ID,
        MODEL_ID,
        witness_path,
        huggingface=hf_adapter,
        modelscope=ms_adapter,
        now=attested + timedelta(seconds=1),
    )
    verify_receipt_signature(cosignature, "historical identity cosignature")
    assert "receipt_profile_version" not in cosignature.execution
    assert "resolver_observed_at" not in cosignature.execution


def test_identity_witness_refuses_same_key_source_change_and_content_change(sources, tmp_path: Path) -> None:
    hf, ms, hf_adapter, ms_adapter = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    receipt = sign_identity_evidence(identity, [hf, ms], signer_path)

    with pytest.raises(IdentityWitnessError, match="independent"):
        witness_identity_evidence(
            identity, [hf, ms], receipt.to_dict(), MODEL_ID, MODEL_ID, signer_path,
            huggingface=hf_adapter, modelscope=ms_adapter,
        )

    sources[0].hf_revision = "f" * 40
    with pytest.raises(IdentityWitnessError) as changed:
        witness_identity_evidence(
            identity, [hf, ms], receipt.to_dict(), MODEL_ID, MODEL_ID, witness_path,
            huggingface=hf_adapter, modelscope=ms_adapter,
        )
    assert changed.value.code == "source_changed"

    sources[0].hf_revision = HF_REVISION
    sources[1].contents["config.json"] = b"different\n"
    with pytest.raises(IdentityWitnessError) as mismatch:
        witness_identity_evidence(
            identity, [hf, ms], receipt.to_dict(), MODEL_ID, MODEL_ID, witness_path,
            huggingface=hf_adapter, modelscope=ms_adapter,
        )
    assert mismatch.value.code == "selected_file_mismatch"


def test_identity_witness_refuses_unavailable_source_and_stale_observation(sources, tmp_path: Path) -> None:
    hf, ms, hf_adapter, ms_adapter = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    receipt = sign_identity_evidence(identity, [hf, ms], signer_path)

    sources[1].mode = "unavailable"
    with pytest.raises(IdentityWitnessError) as unavailable:
        witness_identity_evidence(
            identity,
            [hf, ms],
            receipt.to_dict(),
            MODEL_ID,
            MODEL_ID,
            witness_path,
            huggingface=hf_adapter,
            modelscope=ms_adapter,
        )
    assert unavailable.value.code == "source_unavailable"
    sources[1].mode = "ok"

    original_time = datetime.fromisoformat(
        receipt.attestation["attested_at"].replace("Z", "+00:00")
    )
    with pytest.raises(IdentityWitnessError) as stale:
        witness_identity_evidence(
            identity,
            [hf, ms],
            receipt.to_dict(),
            MODEL_ID,
            MODEL_ID,
            witness_path,
            huggingface=hf_adapter,
            modelscope=ms_adapter,
            max_observation_gap_seconds=1,
            now=original_time.replace(tzinfo=timezone.utc) + timedelta(seconds=2),
        )
    assert stale.value.code == "observation_stale"


def test_resolution_reobservation_is_stronger_and_source_change_is_not_receipt_invalid(sources, tmp_path: Path) -> None:
    bundle = _remote_resolution_bundle()
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    observed_at = "2026-08-30T06:30:00Z"
    receipt = sign_resolution_evidence(
        bundle, signer_path, observed_at=observed_at
    )
    receipt_value = receipt.to_dict()
    # attested_at remains legacy unsigned metadata.  Freshness for profile
    # 1.1 must use the signed resolver observation instead.
    receipt_value["attestation"]["attested_at"] = "2026-08-30T06:32:00Z"

    witness_time = datetime(2026, 8, 30, 6, 31, tzinfo=timezone.utc)
    offline = witness_resolution_evidence(
        bundle, receipt_value, witness_path, now=witness_time
    )
    reobserved = witness_resolution_reobservation(
        bundle,
        receipt_value,
        MODEL_ID,
        witness_path,
        observer=HuggingFaceSourceAdapter(base_url=sources[0].base_url),
        max_observation_gap_seconds=300,
        now=witness_time,
    )
    verify_receipt_signature(reobserved, "resolution reobservation")
    assert offline.provenance["method"] != reobserved.provenance["method"]
    assert offline.execution["resolver_observed_at"] == observed_at
    assert offline.execution["verified_at"] == "2026-08-30T06:31:00Z"
    assert reobserved.execution["resolver_observed_at"] == observed_at
    assert reobserved.execution["reobserved_at"] == "2026-08-30T06:31:00Z"
    assert reobserved.execution["witness_method"] == "remote_source_reobservation"

    sources[0].hf_revision = "f" * 40
    with pytest.raises(ResolutionWitnessError) as changed:
        witness_resolution_reobservation(
            bundle,
            receipt_value,
            MODEL_ID,
            witness_path,
            observer=HuggingFaceSourceAdapter(base_url=sources[0].base_url),
            now=witness_time,
        )
    assert changed.value.code == "source_changed"
    verify_receipt_signature(receipt, "original receipt remains valid")


def test_identity_witness_failure_writes_nothing_and_cli_has_no_origin_override(
    sources, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from traceseal_observe.identity import main as identity_main

    output = tmp_path / "must-not-exist.json"
    assert identity_main([
        "witness",
        "--identity", str(tmp_path / "missing.json"),
        "--huggingface-observation", str(tmp_path / "missing-hf.json"),
        "--modelscope-observation", str(tmp_path / "missing-ms.json"),
        "--receipt", str(tmp_path / "missing-receipt.json"),
        "--huggingface-model", MODEL_ID,
        "--modelscope-model", MODEL_ID,
        "--key", str(tmp_path / "missing.key"),
        "--output", str(output),
        "--huggingface-origin", "https://attacker.invalid",
    ]) == 2
    assert not output.exists()
    captured = capsys.readouterr()
    assert "attacker" not in captured.err

    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    signer = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    signer_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    _write_key(signer_path, signer)
    _write_key(witness_path, witness)
    receipt = sign_identity_evidence(identity, [hf, ms], signer_path).to_dict()
    receipt["execution"]["canonical_id"] = "sha256:" + "f" * 64

    files = {
        "identity.json": identity,
        "hf.json": hf,
        "ms.json": ms,
        "receipt.json": receipt,
    }
    for name, value in files.items():
        path = tmp_path / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)
    output = tmp_path / "tampered-must-not-exist.json"
    assert identity_main([
        "witness",
        "--identity", str(tmp_path / "identity.json"),
        "--huggingface-observation", str(tmp_path / "hf.json"),
        "--modelscope-observation", str(tmp_path / "ms.json"),
        "--receipt", str(tmp_path / "receipt.json"),
        "--huggingface-model", MODEL_ID,
        "--modelscope-model", MODEL_ID,
        "--key", str(witness_path),
        "--output", str(output),
    ]) == 1
    assert not output.exists()


def test_canonical_signed_values_exclude_ids_paths_contents_and_origins(sources, tmp_path: Path) -> None:
    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    key = OperatorKey.generate("resolver")
    key_path = tmp_path / "resolver.key"
    _write_key(key_path, key)
    receipt = sign_identity_evidence(identity, [hf, ms], key_path)
    encoded = canonical_identity_bytes(identity, [hf, ms]) + receipt.to_json().encode()
    for forbidden in (
        MODEL_ID.encode(),
        b"config.json",
        b"model_type",
        sources[0].base_url.encode(),
        sources[1].base_url.encode(),
        str(tmp_path).encode(),
        b"Authorization",
        b"Cookie",
    ):
        assert forbidden not in encoded


def test_publisher_identity_fingerprint_is_full_derived_and_deterministic() -> None:
    key = OperatorKey.generate("demo-publisher")
    raw = bytes.fromhex(key.public_key_hex)
    first = publisher_identity_from_public_key(raw)
    second = publisher_identity_from_public_key(
        raw,
        {
            "display_name": "Demo Publisher",
            "metadata_status": "unsigned_unverified",
        },
    )
    assert first["key_algorithm"] == "ed25519"
    assert first["public_key"] == key.public_key_hex
    assert first["fingerprint"] == "ed25519:" + hashlib.sha256(raw).hexdigest()
    assert second["fingerprint"] == first["fingerprint"]
    assert second["metadata"]["metadata_status"] == "unsigned_unverified"
    assert len(first["fingerprint"]) == len("ed25519:") + 64

    for unsafe in ("Demo\u0085Publisher", "Demo\u00adPublisher", "Demo\u202ePublisher"):
        with pytest.raises(PublisherAttestationError) as caught:
            publisher_identity_from_public_key(
                raw,
                {
                    "display_name": unsafe,
                    "metadata_status": "unsigned_unverified",
                },
            )
        assert caught.value.code == "publisher_identity_invalid"


def test_publisher_signing_bytes_match_language_neutral_conformance_vector() -> None:
    fingerprint = (
        "ed25519:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )
    attestation = {
        "attestation_version": "1.0",
        "signature": {
            "algorithm": "ed25519",
            "fingerprint": fingerprint,
            "public_key": "0" * 64,
            "value": "",
        },
        "statement": {
            "artifact": {
                "artifact_type": "model",
                "canonical_id": "sha256:" + "a" * 64,
                "equivalence_root": "sha256:" + "b" * 64,
            },
            "issued_at": "2026-08-30T08:00:00Z",
            "publisher": {"fingerprint": fingerprint},
            "statement_type": "model_artifact_authorisation",
        },
    }
    expected = (
        '{"attestation_version":"1.0","statement":{"artifact":'
        '{"artifact_type":"model","canonical_id":"sha256:'
        + "a" * 64
        + '","equivalence_root":"sha256:'
        + "b" * 64
        + '"},"issued_at":"2026-08-30T08:00:00Z","publisher":'
        '{"fingerprint":"'
        + fingerprint
        + '"},"statement_type":"model_artifact_authorisation"}}'
    ).encode()
    assert publisher_signing_bytes(attestation) == expected


def test_publisher_attestation_signature_binding_and_tamper_semantics(
    sources, tmp_path: Path
) -> None:
    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    key = OperatorKey.generate("demo-publisher")
    key_path = tmp_path / "publisher.key"
    _write_key(key_path, key)
    attestation = sign_publisher_attestation(
        identity,
        [hf, ms],
        key_path,
        issued_at="2026-08-30T08:00:00Z",
    )
    verified = verify_publisher_attestation(attestation, identity, [hf, ms])
    assert verified.status == "publisher_signature_valid"
    assert verified.publisher_fingerprint == (
        "ed25519:" + hashlib.sha256(bytes.fromhex(key.public_key_hex)).hexdigest()
    )
    assert len(canonical_publisher_attestation_bytes(attestation)) < 4096

    different = copy.deepcopy(identity)
    different["canonical_id"] = "sha256:" + "f" * 64
    with pytest.raises(PublisherAttestationError) as stale:
        verify_publisher_attestation(attestation, different, [hf, ms])
    assert stale.value.code == "publisher_attestation_stale"

    for field, value, code in (
        (
            ("statement", "issued_at"),
            "2026-08-30T08:00:01Z",
            "publisher_signature_invalid",
        ),
        (
            ("statement", "artifact", "canonical_id"),
            "sha256:" + "e" * 64,
            "publisher_signature_invalid",
        ),
        (
            ("statement", "artifact", "equivalence_root"),
            "sha256:" + "d" * 64,
            "publisher_signature_invalid",
        ),
        (
            ("statement", "publisher", "fingerprint"),
            "ed25519:" + "0" * 64,
            "publisher_fingerprint_mismatch",
        ),
    ):
        tampered = copy.deepcopy(attestation)
        target = tampered
        for part in field[:-1]:
            target = target[part]
        target[field[-1]] = value
        with pytest.raises(PublisherAttestationError) as caught:
            verify_publisher_attestation(tampered, identity, [hf, ms])
        assert caught.value.code == code

    replacement = OperatorKey.generate("wrong-publisher")
    wrong_key = copy.deepcopy(attestation)
    replacement_raw = bytes.fromhex(replacement.public_key_hex)
    replacement_fingerprint = (
        "ed25519:" + hashlib.sha256(replacement_raw).hexdigest()
    )
    wrong_key["signature"]["public_key"] = replacement.public_key_hex
    wrong_key["signature"]["fingerprint"] = replacement_fingerprint
    wrong_key["statement"]["publisher"]["fingerprint"] = replacement_fingerprint
    with pytest.raises(PublisherAttestationError) as caught:
        verify_publisher_attestation(wrong_key, identity, [hf, ms])
    assert caught.value.code == "publisher_signature_invalid"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        (("signature", "algorithm"), "ed448", "publisher_algorithm_invalid"),
        (("signature", "public_key"), "00", "publisher_key_invalid"),
        (("signature", "value"), "00", "publisher_signature_invalid"),
        (("statement", "issued_at"), "2026-08-30T08:00:00+00:00", "publisher_issued_at_invalid"),
        (("statement", "issued_at"), "2026-08-30T08:00:00Z\u202e", "publisher_issued_at_invalid"),
    ],
)
def test_publisher_attestation_rejects_algorithm_key_signature_and_time_confusion(
    sources, tmp_path: Path, field: tuple[str, ...], value: str, code: str
) -> None:
    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    key_path = tmp_path / "publisher.key"
    _write_key(key_path, OperatorKey.generate("demo-publisher"))
    attestation = sign_publisher_attestation(identity, [hf, ms], key_path)
    target = attestation
    for part in field[:-1]:
        target = target[part]
    target[field[-1]] = value
    with pytest.raises(PublisherAttestationError) as caught:
        verify_publisher_attestation(attestation, identity, [hf, ms])
    assert caught.value.code == code


def test_publisher_evidence_is_additive_sorted_and_deduplicated(
    sources, tmp_path: Path
) -> None:
    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    canonical_before = canonical_identity_bytes(identity, [hf, ms])
    unsigned = derive_publisher_evidence(identity, [hf, ms], [])
    assert unsigned["publisher_status"] == "publisher_unsigned"
    assert unsigned["publisher_attestations"] == []

    attestations = []
    for index in range(2):
        key_path = tmp_path / f"publisher-{index}.key"
        _write_key(key_path, OperatorKey.generate(f"demo-publisher-{index}"))
        attestations.append(
            sign_publisher_attestation(
                identity,
                [hf, ms],
                key_path,
                issued_at=f"2026-08-30T08:00:0{index}Z",
            )
        )
    evidence = derive_publisher_evidence(
        identity, [hf, ms], [attestations[1], attestations[0], attestations[0]]
    )
    assert evidence["publisher_status"] == "publisher_signature_valid"
    assert len(evidence["publisher_attestations"]) == 2
    hashes = [item["attestation_hash"] for item in evidence["publisher_attestations"]]
    assert hashes == sorted(hashes)
    assert canonical_identity_bytes(identity, [hf, ms]) == canonical_before
    assert evidence["canonical_id"] == identity["canonical_id"]


def test_platform_account_observation_never_becomes_publisher_signature(
    sources,
) -> None:
    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    claims = [
        build_platform_account_claim(
            observation["provider"], observation["source_identity_hash"], MODEL_ID
        )
        for observation in (hf, ms)
    ]
    evidence = derive_publisher_evidence(identity, [hf, ms], [], claims)
    assert evidence["publisher_status"] == "publisher_unsigned"
    assert evidence["publisher_attestations"] == []
    assert {item["evidence"] for item in evidence["platform_claims"]} == {
        "source_metadata_observed"
    }
    encoded = _canonical(evidence)
    assert MODEL_ID.encode() not in encoded
    assert b"platform_verified" not in encoded


def test_trace_seal_identity_receipt_and_witness_commit_to_publisher_evidence(
    sources, tmp_path: Path
) -> None:
    hf, ms, hf_adapter, ms_adapter = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    resolver = OperatorKey.generate("resolver")
    witness = OperatorKey.generate("witness")
    publisher = OperatorKey.generate("demo-publisher")
    resolver_path = tmp_path / "resolver.key"
    witness_path = tmp_path / "witness.key"
    publisher_path = tmp_path / "publisher.key"
    _write_key(resolver_path, resolver)
    _write_key(witness_path, witness)
    _write_key(publisher_path, publisher)
    attestation = sign_publisher_attestation(
        identity,
        [hf, ms],
        publisher_path,
        issued_at="2026-08-30T08:00:00Z",
    )
    publisher_evidence = derive_publisher_evidence(
        identity, [hf, ms], [attestation]
    )
    receipt = sign_identity_evidence(
        identity,
        [hf, ms],
        resolver_path,
        observed_at="2026-08-30T06:30:00Z",
        publisher_attestations=[attestation],
    )
    assert receipt.execution["publisher_evidence_root"] == (
        publisher_evidence["publisher_evidence_root"]
    )
    assert receipt.execution["publisher_evidence_status"] == (
        "publisher_signature_valid"
    )
    cosignature = witness_identity_evidence(
        identity,
        [hf, ms],
        receipt.to_dict(),
        MODEL_ID,
        MODEL_ID,
        witness_path,
        huggingface=hf_adapter,
        modelscope=ms_adapter,
        now=datetime(2026, 8, 30, 6, 31, tzinfo=timezone.utc),
        publisher_attestations=[attestation],
    )
    assert cosignature.execution["publisher_evidence_root"] == (
        publisher_evidence["publisher_evidence_root"]
    )
    assert cosignature.execution["publisher_evidence_status"] == (
        "publisher_signature_valid"
    )

    tampered = copy.deepcopy(attestation)
    tampered["statement"]["issued_at"] = "2026-08-30T08:00:01Z"
    with pytest.raises(IdentityWitnessError) as caught:
        witness_identity_evidence(
            identity,
            [hf, ms],
            receipt.to_dict(),
            MODEL_ID,
            MODEL_ID,
            witness_path,
            huggingface=hf_adapter,
            modelscope=ms_adapter,
            now=datetime(2026, 8, 30, 6, 31, tzinfo=timezone.utc),
            publisher_attestations=[tampered],
        )
    assert caught.value.code == "publisher_signature_invalid"


def test_publisher_cli_is_offline_read_only_create_once_and_duplicate_safe(
    sources, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from traceseal_observe.publisher import main as publisher_main

    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    evidence_files = {
        "identity.json": canonical_identity_bytes(identity, [hf, ms]),
        "hf.json": canonical_observation_bytes(hf),
        "ms.json": canonical_observation_bytes(ms),
    }
    paths: dict[str, Path] = {}
    for name, payload in evidence_files.items():
        path = tmp_path / name
        path.write_bytes(payload + b"\n")
        path.chmod(0o600)
        paths[name] = path
    key_path = tmp_path / "publisher.key"
    _write_key(key_path, OperatorKey.generate("demo-publisher"))
    tracked = [*paths.values(), key_path]
    before = {
        path.name: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat())
        for path in tracked
    }
    request_counts = [len(source.requests) for source in sources]
    output = tmp_path / "publisher-attestation.json"
    common = [
        "--identity", str(paths["identity.json"]),
        "--huggingface-observation", str(paths["hf.json"]),
        "--modelscope-observation", str(paths["ms.json"]),
    ]
    assert publisher_main([
        "sign", *common,
        "--key", str(key_path),
        "--issued-at", "2026-08-30T08:00:00Z",
        "--output", str(output),
    ]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert publisher_main(["verify", *common, str(output)]) == 0
    assert [len(source.requests) for source in sources] == request_counts
    for path in tracked:
        old_hash, old_stat = before[path.name]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == old_hash
        current = path.stat()
        assert current.st_mode == old_stat.st_mode
        assert current.st_mtime_ns == old_stat.st_mtime_ns
    assert publisher_main([
        "sign", *common,
        "--key", str(key_path),
        "--output", str(output),
    ]) == 1

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"attestation_version":"1.0","attestation_version":"1.0"}',
        encoding="utf-8",
    )
    assert publisher_main(["verify", *common, str(duplicate)]) == 1
    captured = capsys.readouterr()
    assert "REFUSED publisher_input_invalid" in captured.err
    assert str(tmp_path) not in captured.out + captured.err
    assert MODEL_ID not in output.read_text(encoding="utf-8")
    for content in CONTENTS.values():
        assert content not in output.read_bytes()


def test_publisher_cli_rejects_unsafe_key_without_output(
    sources, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from traceseal_observe.publisher import main as publisher_main

    hf, ms, _, _ = _observe(sources)
    identity = build_canonical_identity([hf, ms])
    identity_path = tmp_path / "identity.json"
    hf_path = tmp_path / "hf.json"
    ms_path = tmp_path / "ms.json"
    identity_path.write_bytes(canonical_identity_bytes(identity, [hf, ms]))
    hf_path.write_bytes(canonical_observation_bytes(hf))
    ms_path.write_bytes(canonical_observation_bytes(ms))
    key_path = tmp_path / "publisher.key"
    _write_key(key_path, OperatorKey.generate("demo-publisher"))
    symlink = tmp_path / "publisher-link.key"
    symlink.symlink_to(key_path)
    output = tmp_path / "must-not-exist.json"
    assert publisher_main([
        "sign",
        "--identity", str(identity_path),
        "--huggingface-observation", str(hf_path),
        "--modelscope-observation", str(ms_path),
        "--key", str(symlink),
        "--output", str(output),
    ]) == 1
    assert not output.exists()
    captured = capsys.readouterr()
    assert "REFUSED publisher_key_invalid" in captured.err
    assert str(tmp_path) not in captured.err
