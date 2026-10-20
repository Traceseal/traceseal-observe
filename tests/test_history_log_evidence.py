"""Phase 2A.5 publisher-history log evidence and identity integration."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_identity_receipts import MODEL_ID, _observe, _write_key
from test_publisher_history import _source_pair_with_histories
from traceseal_observe import OperatorKey, verify_receipt_signature
from traceseal_observe.history import (
    HISTORY_PATH,
    build_publisher_history_log_events,
    build_publisher_key_history_evidence,
    discover_publisher_key_history,
)
from traceseal_observe.history_log import (
    HistoryLogError,
    build_publisher_history_log_evidence,
    derive_publisher_history_log_evidence,
)
from traceseal_observe.identity import (
    IdentityWitnessError,
    sign_identity_evidence,
    witness_identity_evidence,
)
from traceseal_observe.source_identity import (
    HuggingFaceSourceAdapter,
    ModelScopeSourceAdapter,
    build_canonical_identity,
)

# Cross-repository integration is test-only: product code independently
# implements verification and never imports the append-capable log package.
_LOG_DIR = Path(__file__).resolve().parents[2] / "traceseal-log"
sys.path.insert(0, str(_LOG_DIR))
import make_checkpoint  # noqa: E402
import publisher_history_log as publication  # noqa: E402
import tlog_note  # noqa: E402


ORIGIN = "log.publisher-history.integration.test"
PUBLISHED_AT = "2026-08-30T12:00:00Z"


def _cosign(checkpoint: bytes) -> tuple[bytes, str]:
    private = Ed25519PrivateKey.from_private_bytes(b"w" * 32)
    public = private.public_key().public_bytes_raw()
    name = "witness.publisher-history.integration.test"
    key_bytes = tlog_note.ALG_COSIGNATURE_V1 + public
    key_hash = hashlib.sha256(name.encode() + b"\n" + key_bytes).digest()[:4]
    vkey = f"{name}+{key_hash.hex()}+{base64.b64encode(key_bytes).decode()}"
    body = checkpoint[: checkpoint.index(b"\n\n") + 1].decode()
    timestamp = 1_787_999_999
    signature = private.sign(
        f"cosignature/v1\ntime {timestamp}\n{body}".encode()
    )
    line = (
        f"— {name} "
        + base64.b64encode(
            key_hash + struct.pack(">Q", timestamp) + signature
        ).decode()
        + "\n"
    ).encode()
    return checkpoint + line, vkey


def _publish_evidence(
    tmp_path: Path, events: list[dict]
) -> tuple[dict, dict[str, str], dict[str, str]]:
    inclusions, log_vkeys, witness_vkeys = _publish_inclusions(tmp_path, events)
    return (
        publication.build_witnessed_history_evidence(
            inclusions, next(iter(log_vkeys.values())), next(iter(witness_vkeys.values()))
        ),
        log_vkeys,
        witness_vkeys,
    )


def _publish_inclusions(
    tmp_path: Path, events: list[dict]
) -> tuple[list[dict], dict[str, str], dict[str, str]]:
    log = tmp_path / "publisher-history.jsonl"
    for event in events:
        publication.append_governed_event(
            log, event, published_at_claim=PUBLISHED_AT
        )
    skey, log_vkey = tlog_note.generate_key(ORIGIN)
    checkpoint = make_checkpoint.build_checkpoint(log.read_bytes(), ORIGIN, skey)
    witnessed, witness_vkey = _cosign(checkpoint)
    inclusions = [
        publication.build_inclusion_evidence(log.read_bytes(), sequence, witnessed)
        for sequence in range(1, len(events) + 1)
    ]
    log_vkeys = {ORIGIN: log_vkey}
    witness_vkeys = {ORIGIN: witness_vkey}
    return inclusions, log_vkeys, witness_vkeys


def test_witnessed_log_evidence_is_independently_derived_and_tamper_evident(
    tmp_path: Path,
) -> None:
    _k1, _k2, _k1_path, _k2_path, hf, ms = _source_pair_with_histories(
        tmp_path
    )
    try:
        document = json.loads(hf.contents[HISTORY_PATH])
        events = build_publisher_history_log_events(
            document, "huggingface", MODEL_ID
        )
        evidence, log_vkeys, witness_vkeys = _publish_evidence(tmp_path, events)
        derived = derive_publisher_history_log_evidence(
            evidence, log_vkeys, witness_vkeys
        )
        assert derived.status == "checkpoint_witnessed_unforked"
        assert derived.publisher_key_continuity_root == events[-1]["history_root"]
        assert len(derived.entry_hashes) == len(events)

        tampered = copy.deepcopy(evidence)
        tampered["inclusions"][-1]["entry"]["statement_hash"] = (
            "sha256:" + "0" * 64
        )
        with pytest.raises(HistoryLogError):
            derive_publisher_history_log_evidence(
                tampered, log_vkeys, witness_vkeys
            )
    finally:
        hf.close()
        ms.close()


def test_identity_and_witness_commit_to_verified_log_without_changing_identity(
    tmp_path: Path,
) -> None:
    _k1, _k2, _k1_path, _k2_path, hf, ms = _source_pair_with_histories(
        tmp_path
    )
    resolver, witness = OperatorKey.generate("resolver"), OperatorKey.generate(
        "witness"
    )
    resolver_path, witness_path = tmp_path / "resolver.key", tmp_path / "witness.key"
    _write_key(resolver_path, resolver)
    _write_key(witness_path, witness)
    try:
        observations = list(_observe((hf, ms))[:2])
        identity = build_canonical_identity(observations)
        canonical_id = identity["canonical_id"]
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
        events = build_publisher_history_log_events(
            json.loads(hf.contents[HISTORY_PATH]), "huggingface", MODEL_ID
        )
        log_evidence, log_vkeys, witness_vkeys = _publish_evidence(
            tmp_path, events
        )

        receipt = sign_identity_evidence(
            identity,
            observations,
            resolver_path,
            observed_at="2026-08-30T10:30:00Z",
            publisher_key_history_evidence=history_evidence,
            publisher_history_log_evidence=log_evidence,
            history_log_vkeys=log_vkeys,
            history_log_witness_vkeys=witness_vkeys,
        )
        assert receipt.execution["publisher_history_log_status"] == (
            "checkpoint_witnessed_unforked"
        )
        verify_receipt_signature(receipt, "publisher history log identity")

        cosignature = witness_identity_evidence(
            identity,
            observations,
            receipt.to_dict(),
            MODEL_ID,
            MODEL_ID,
            witness_path,
            huggingface=HuggingFaceSourceAdapter(base_url=hf.base_url),
            modelscope=ModelScopeSourceAdapter(base_url=ms.base_url),
            max_observation_gap_seconds=300,
            now=datetime(2026, 8, 30, 10, 31, tzinfo=timezone.utc),
            publisher_key_history_evidence=history_evidence,
            publisher_key_history_repositories={
                "huggingface": MODEL_ID,
                "modelscope": MODEL_ID,
            },
            publisher_key_history_documents={
                "huggingface": json.loads(hf.contents[HISTORY_PATH]),
                "modelscope": json.loads(ms.contents[HISTORY_PATH]),
            },
            publisher_history_log_evidence=log_evidence,
            history_log_vkeys=log_vkeys,
            history_log_witness_vkeys=witness_vkeys,
        )
        assert cosignature.execution["publisher_history_log_witness_method"] == (
            "log_evidence_offline_verified"
        )
        assert identity["canonical_id"] == canonical_id
        verify_receipt_signature(cosignature, "publisher history log witness")

        tampered = copy.deepcopy(log_evidence)
        tampered["inclusions"][0]["checkpoint_root"] = "sha256:" + "0" * 64
        with pytest.raises(IdentityWitnessError):
            witness_identity_evidence(
                identity,
                observations,
                receipt.to_dict(),
                MODEL_ID,
                MODEL_ID,
                witness_path,
                huggingface=HuggingFaceSourceAdapter(base_url=hf.base_url),
                modelscope=ModelScopeSourceAdapter(base_url=ms.base_url),
                now=datetime(2026, 8, 30, 10, 31, tzinfo=timezone.utc),
                publisher_key_history_evidence=history_evidence,
                publisher_key_history_repositories={
                    "huggingface": MODEL_ID,
                    "modelscope": MODEL_ID,
                },
                publisher_history_log_evidence=tampered,
                history_log_vkeys=log_vkeys,
                history_log_witness_vkeys=witness_vkeys,
            )
    finally:
        hf.close()
        ms.close()


def test_publisher_fork_is_refused_before_identity_signing(tmp_path: Path) -> None:
    _k1, _k2, _k1_path, _k2_path, hf, ms = _source_pair_with_histories(
        tmp_path
    )
    try:
        events = build_publisher_history_log_events(
            json.loads(hf.contents[HISTORY_PATH]), "huggingface", MODEL_ID
        )
        conflicting = copy.deepcopy(events[1])
        conflicting["affected_fingerprint"] = "ed25519:" + "f" * 64
        conflicting["current_fingerprint"] = "ed25519:" + "f" * 64
        conflicting["history_root"] = "sha256:" + "e" * 64
        conflicting["statement_hash"] = "sha256:" + "d" * 64
        inclusions, log_vkeys, witness_vkeys = _publish_inclusions(
            tmp_path, [events[0], events[1], conflicting]
        )
        with pytest.raises(HistoryLogError) as refused:
            build_publisher_history_log_evidence(
                inclusions, log_vkeys, witness_vkeys
            )
        assert refused.value.code == "publisher_history_equivocation"
    finally:
        hf.close()
        ms.close()
