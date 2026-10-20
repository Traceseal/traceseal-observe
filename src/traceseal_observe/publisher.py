"""Offline publisher identity and model artefact authorisation attestations.

Publisher signatures are deliberately separate from TraceSeal operator
receipts.  They authorise one canonical artefact statement; TraceSeal receipts
may subsequently commit to the independently verified publisher evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from traceseal_observe import canonical_dumps
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
    SourceObservationError,
    derive_canonical_identity,
)

PUBLISHER_IDENTITY_VERSION = "1.0"
PUBLISHER_ATTESTATION_VERSION = "1.0"
PUBLISHER_EVIDENCE_VERSION = "1.0"
PUBLISHER_ALGORITHM = "ed25519"
PUBLISHER_STATEMENT_TYPE = "model_artifact_authorisation"
PUBLISHER_UNSIGNED = "publisher_unsigned"
PUBLISHER_SIGNATURE_VALID = "publisher_signature_valid"
PLATFORM_EVIDENCE_OBSERVED = "source_metadata_observed"

_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_128_RE = re.compile(r"^[0-9a-f]{128}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$")
_MAX_ATTESTATIONS = 64


class PublisherAttestationError(ValueError):
    """Publisher evidence is malformed, invalid, or bound elsewhere."""

    def __init__(self, message: str, code: str = "publisher_attestation_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PublisherAttestationVerification:
    attestation_hash: str
    publisher_fingerprint: str
    status: str


def _fail(message: str, code: str = "publisher_attestation_invalid") -> None:
    raise PublisherAttestationError(message, code)


def _hash_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _require_object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("publisher object shape is invalid")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        _fail("publisher object shape is invalid")
    return value


def _require_sha256(value: Any) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail("publisher artefact hash is invalid")
    return value


def publisher_fingerprint(public_key: bytes) -> str:
    """Derive the full-SHA publisher fingerprint from a raw Ed25519 key."""
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        _fail("publisher public key is invalid", "publisher_key_invalid")
    return "ed25519:" + hashlib.sha256(public_key).hexdigest()


def verify_detached_publisher_signature(
    signature: Any, publisher_fingerprint_claim: Any, payload: bytes
) -> str:
    """Verify the shared Phase 2A publisher signature envelope.

    Artefact attestations and repository binding statements use the same
    Ed25519 key representation, full-SHA fingerprint derivation and detached
    signature fields. Domain modules provide their own canonical statement
    bytes but do not implement a second publisher-key format.
    """
    value = _require_object(
        signature, {"algorithm", "fingerprint", "public_key", "value"}
    )
    if value["algorithm"] != PUBLISHER_ALGORITHM:
        _fail("publisher signature algorithm is invalid", "publisher_algorithm_invalid")
    encoded_key = value["public_key"]
    if not isinstance(encoded_key, str) or _HEX_64_RE.fullmatch(encoded_key) is None:
        _fail("publisher public key is invalid", "publisher_key_invalid")
    if not isinstance(value["value"], str) or _HEX_128_RE.fullmatch(value["value"]) is None:
        _fail("publisher signature is invalid", "publisher_signature_invalid")
    fingerprint = publisher_fingerprint(bytes.fromhex(encoded_key))
    for stated in (value["fingerprint"], publisher_fingerprint_claim):
        if (
            not isinstance(stated, str)
            or _FINGERPRINT_RE.fullmatch(stated) is None
            or stated != fingerprint
        ):
            _fail(
                "publisher fingerprint does not match key",
                "publisher_fingerprint_mismatch",
            )
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(encoded_key))
        key.verify(bytes.fromhex(value["value"]), payload)
    except (InvalidSignature, ValueError) as exc:
        raise PublisherAttestationError(
            "publisher signature is invalid", "publisher_signature_invalid"
        ) from exc
    return fingerprint


def _contains_unsafe_unicode(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)


def _validate_metadata(metadata: Any) -> dict[str, Any]:
    value = _require_object(
        metadata, {"metadata_status"}, {"claims", "display_name"}
    )
    if value["metadata_status"] != "unsigned_unverified":
        _fail("publisher display metadata is invalid", "publisher_identity_invalid")
    display_name = value.get("display_name", "")
    if (
        not isinstance(display_name, str)
        or len(display_name) > 128
        or display_name != display_name.strip()
        or _contains_unsafe_unicode(display_name)
    ):
        _fail("publisher display metadata is invalid", "publisher_identity_invalid")
    claims = value.get("claims", [])
    if not isinstance(claims, list) or len(claims) > 16:
        _fail("publisher display metadata is invalid", "publisher_identity_invalid")
    normalised: list[dict[str, str]] = []
    for claim in claims:
        item = _require_object(claim, {"kind", "value"})
        if item["kind"] not in {"huggingface_org", "modelscope_org"}:
            _fail("publisher display claim is invalid", "publisher_identity_invalid")
        if not isinstance(item["value"], str) or _ACCOUNT_RE.fullmatch(item["value"]) is None:
            _fail("publisher display claim is invalid", "publisher_identity_invalid")
        normalised.append({"kind": item["kind"], "value": item["value"]})
    normalised.sort(key=lambda item: (item["kind"], item["value"]))
    if len({(item["kind"], item["value"]) for item in normalised}) != len(normalised):
        _fail("publisher display claim is duplicated", "publisher_identity_invalid")
    result: dict[str, Any] = {"metadata_status": "unsigned_unverified"}
    if normalised:
        result["claims"] = normalised
    if display_name:
        result["display_name"] = display_name
    return result


def publisher_identity_from_public_key(
    public_key: bytes, metadata: dict[str, Any] | None = None
) -> dict[str, Any]:
    fingerprint = publisher_fingerprint(public_key)
    identity: dict[str, Any] = {
        "fingerprint": fingerprint,
        "key_algorithm": PUBLISHER_ALGORITHM,
        "public_key": public_key.hex(),
        "publisher_identity_version": PUBLISHER_IDENTITY_VERSION,
    }
    if metadata is not None:
        identity["metadata"] = _validate_metadata(metadata)
    verify_publisher_identity(identity)
    return identity


def verify_publisher_identity(identity: Any) -> dict[str, Any]:
    value = _require_object(
        identity,
        {
            "fingerprint",
            "key_algorithm",
            "public_key",
            "publisher_identity_version",
        },
        {"metadata"},
    )
    if (
        value["publisher_identity_version"] != PUBLISHER_IDENTITY_VERSION
        or value["key_algorithm"] != PUBLISHER_ALGORITHM
    ):
        _fail("publisher identity is invalid", "publisher_identity_invalid")
    encoded = value["public_key"]
    if not isinstance(encoded, str) or _HEX_64_RE.fullmatch(encoded) is None:
        _fail("publisher public key is invalid", "publisher_key_invalid")
    raw = bytes.fromhex(encoded)
    derived = publisher_fingerprint(raw)
    if (
        not isinstance(value["fingerprint"], str)
        or _FINGERPRINT_RE.fullmatch(value["fingerprint"]) is None
        or value["fingerprint"] != derived
    ):
        _fail("publisher fingerprint does not match key", "publisher_fingerprint_mismatch")
    result = copy.deepcopy(value)
    if "metadata" in result:
        result["metadata"] = _validate_metadata(result["metadata"])
    return result


def _validate_issued_at(value: Any) -> str:
    if not isinstance(value, str) or _contains_unsafe_unicode(value):
        _fail("publisher issuance time is invalid", "publisher_issued_at_invalid")
    try:
        parsed = format_utc_seconds(parse_utc_seconds(value))
    except (SignedTimeProfileError, TypeError, ValueError) as exc:
        raise PublisherAttestationError(
            "publisher issuance time is invalid", "publisher_issued_at_invalid"
        ) from exc
    if parsed != value:
        _fail("publisher issuance time is invalid", "publisher_issued_at_invalid")
    return value


def _validate_attestation_shape(
    attestation: Any, *, require_signature: bool
) -> dict[str, Any]:
    value = _require_object(
        attestation, {"attestation_version", "signature", "statement"}
    )
    if value["attestation_version"] != PUBLISHER_ATTESTATION_VERSION:
        _fail("publisher attestation version is invalid")
    signature = _require_object(
        value["signature"], {"algorithm", "fingerprint", "public_key", "value"}
    )
    statement = _require_object(
        value["statement"], {"artifact", "issued_at", "publisher", "statement_type"}
    )
    artifact = _require_object(
        statement["artifact"], {"artifact_type", "canonical_id", "equivalence_root"}
    )
    publisher = _require_object(statement["publisher"], {"fingerprint"})
    if signature["algorithm"] != PUBLISHER_ALGORITHM:
        _fail("publisher signature algorithm is invalid", "publisher_algorithm_invalid")
    encoded_key = signature["public_key"]
    if not isinstance(encoded_key, str) or _HEX_64_RE.fullmatch(encoded_key) is None:
        _fail("publisher public key is invalid", "publisher_key_invalid")
    if require_signature and (
        not isinstance(signature["value"], str)
        or _HEX_128_RE.fullmatch(signature["value"]) is None
    ):
        _fail("publisher signature is invalid", "publisher_signature_invalid")
    if not require_signature and not isinstance(signature["value"], str):
        _fail("publisher signature is invalid", "publisher_signature_invalid")
    if artifact["artifact_type"] != "model":
        _fail("publisher artefact type is invalid")
    _require_sha256(artifact["canonical_id"])
    _require_sha256(artifact["equivalence_root"])
    if statement["statement_type"] != PUBLISHER_STATEMENT_TYPE:
        _fail("publisher statement type is invalid")
    _validate_issued_at(statement["issued_at"])
    raw_key = bytes.fromhex(encoded_key)
    fingerprint = publisher_fingerprint(raw_key)
    for stated in (signature["fingerprint"], publisher["fingerprint"]):
        if (
            not isinstance(stated, str)
            or _FINGERPRINT_RE.fullmatch(stated) is None
            or stated != fingerprint
        ):
            _fail(
                "publisher fingerprint does not match key",
                "publisher_fingerprint_mismatch",
            )
    return value


def publisher_signing_bytes(attestation: Any) -> bytes:
    value = _validate_attestation_shape(attestation, require_signature=False)
    return canonical_dumps(
        {
            "attestation_version": value["attestation_version"],
            "statement": value["statement"],
        }
    )


def _validate_current_identity(
    identity: dict[str, Any], observations: list[dict[str, Any]]
) -> Any:
    try:
        return derive_canonical_identity(identity, observations)
    except SourceObservationError as exc:
        raise PublisherAttestationError(
            "canonical identity evidence is invalid", "publisher_identity_invalid"
        ) from exc


def sign_publisher_attestation(
    identity: dict[str, Any],
    observations: list[dict[str, Any]],
    key_path: Path | str,
    *,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Sign an artefact authorisation offline using a hardened key descriptor."""
    derived = _validate_current_identity(identity, observations)
    try:
        key = _load_key_safely(key_path)
    except ResolutionWitnessError as exc:
        raise PublisherAttestationError(
            "publisher private key is invalid", "publisher_key_invalid"
        ) from exc
    raw_public_key = bytes.fromhex(key.public_key_hex)
    fingerprint = publisher_fingerprint(raw_public_key)
    attestation: dict[str, Any] = {
        "attestation_version": PUBLISHER_ATTESTATION_VERSION,
        "signature": {
            "algorithm": PUBLISHER_ALGORITHM,
            "fingerprint": fingerprint,
            "public_key": key.public_key_hex,
            "value": "",
        },
        "statement": {
            "artifact": {
                "artifact_type": "model",
                "canonical_id": derived.canonical_id,
                "equivalence_root": derived.evidence_root,
            },
            "issued_at": _validate_issued_at(
                issued_at if issued_at is not None else format_utc_seconds()
            ),
            "publisher": {"fingerprint": fingerprint},
            "statement_type": PUBLISHER_STATEMENT_TYPE,
        },
    }
    attestation["signature"]["value"] = key.sign(
        publisher_signing_bytes(attestation)
    ).hex()
    return attestation


def _verify_signature(attestation: Any) -> dict[str, Any]:
    value = _validate_attestation_shape(attestation, require_signature=True)
    verify_detached_publisher_signature(
        value["signature"],
        value["statement"]["publisher"]["fingerprint"],
        publisher_signing_bytes(value),
    )
    return value


def verify_publisher_attestation(
    attestation: Any,
    identity: dict[str, Any],
    observations: list[dict[str, Any]],
) -> PublisherAttestationVerification:
    """Verify signature first, then distinguish a stale artefact binding."""
    value = _verify_signature(attestation)
    current_canonical_id = (
        identity.get("canonical_id") if isinstance(identity, dict) else None
    )
    current_equivalence = identity.get("equivalence") if isinstance(identity, dict) else None
    current_equivalence_root = (
        current_equivalence.get("evidence_root")
        if isinstance(current_equivalence, dict)
        else None
    )
    artifact = value["statement"]["artifact"]
    if (
        artifact["canonical_id"] != current_canonical_id
        or artifact["equivalence_root"] != current_equivalence_root
    ):
        _fail(
            "publisher attestation binds a different artefact",
            "publisher_attestation_stale",
        )
    derived = _validate_current_identity(identity, observations)
    if (
        artifact["canonical_id"] != derived.canonical_id
        or artifact["equivalence_root"] != derived.evidence_root
    ):
        _fail(
            "publisher attestation binds a different artefact",
            "publisher_attestation_stale",
        )
    return PublisherAttestationVerification(
        attestation_hash=_hash_bytes(canonical_dumps(value)),
        publisher_fingerprint=value["signature"]["fingerprint"],
        status=PUBLISHER_SIGNATURE_VALID,
    )


def canonical_publisher_attestation_bytes(attestation: Any) -> bytes:
    return canonical_dumps(_verify_signature(attestation))


def build_platform_account_claim(
    provider: str, source_identity_hash: str, repository_id: str
) -> dict[str, str]:
    if provider not in {"huggingface", "modelscope"}:
        _fail(
            "platform account evidence is invalid",
            "platform_account_evidence_invalid",
        )
    if (
        not isinstance(source_identity_hash, str)
        or _SHA256_RE.fullmatch(source_identity_hash) is None
    ):
        _fail(
            "platform account evidence is invalid",
            "platform_account_evidence_invalid",
        )
    parts = repository_id.split("/") if isinstance(repository_id, str) else []
    if (
        len(parts) != 2
        or _ACCOUNT_RE.fullmatch(parts[0]) is None
        or _ACCOUNT_RE.fullmatch(parts[1]) is None
        or _hash_text(repository_id) != source_identity_hash
    ):
        _fail(
            "platform account evidence is invalid",
            "platform_account_evidence_invalid",
        )
    return {
        "account_identity_hash": _hash_text(parts[0]),
        "evidence": PLATFORM_EVIDENCE_OBSERVED,
        "provider": provider,
    }


def _validate_platform_claims(claims: Any) -> list[dict[str, str]]:
    if not isinstance(claims, list) or len(claims) > 2:
        _fail("platform account evidence is invalid", "platform_account_evidence_invalid")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for claim in claims:
        item = _require_object(
            claim, {"account_identity_hash", "evidence", "provider"}
        )
        if (
            item["provider"] not in {"huggingface", "modelscope"}
            or item["provider"] in seen
            or item["evidence"] != PLATFORM_EVIDENCE_OBSERVED
            or not isinstance(item["account_identity_hash"], str)
            or _SHA256_RE.fullmatch(item["account_identity_hash"]) is None
        ):
            _fail("platform account evidence is invalid", "platform_account_evidence_invalid")
        seen.add(item["provider"])
        result.append(dict(item))
    return sorted(result, key=lambda item: (item["provider"], item["account_identity_hash"]))


def derive_publisher_evidence(
    identity: dict[str, Any],
    observations: list[dict[str, Any]],
    attestations: list[dict[str, Any]],
    platform_claims: list[dict[str, str]] | None = None,
    publisher_binding_evidence: dict[str, Any] | None = None,
    publisher_key_history_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    derived = _validate_current_identity(identity, observations)
    if not isinstance(attestations, list) or len(attestations) > _MAX_ATTESTATIONS:
        _fail("publisher attestation set is invalid", "publisher_evidence_invalid")
    entries: dict[str, dict[str, str]] = {}
    for attestation in attestations:
        verified = verify_publisher_attestation(attestation, identity, observations)
        entries[verified.attestation_hash] = {
            "attestation_hash": verified.attestation_hash,
            "publisher_fingerprint": verified.publisher_fingerprint,
            "status": verified.status,
        }
    ordered = [entries[key] for key in sorted(entries)]
    evidence: dict[str, Any] = {
        "canonical_id": derived.canonical_id,
        "equivalence_root": derived.evidence_root,
        "platform_claims": _validate_platform_claims(platform_claims or []),
        "publisher_attestations": ordered,
        "publisher_evidence_version": PUBLISHER_EVIDENCE_VERSION,
        "publisher_status": (
            PUBLISHER_SIGNATURE_VALID if ordered else PUBLISHER_UNSIGNED
        ),
    }
    history = None
    if publisher_key_history_evidence is not None:
        # Imported lazily because the history profile reuses this module's
        # publisher signature and fingerprint primitives.
        from traceseal_observe.history import derive_publisher_key_history_evidence

        history = derive_publisher_key_history_evidence(
            publisher_key_history_evidence
        )
    if publisher_binding_evidence is not None:
        # Imported lazily because the binding profile reuses this module's
        # publisher signature primitive.
        from traceseal_observe.binding import derive_publisher_binding_evidence

        binding = derive_publisher_binding_evidence(publisher_binding_evidence)
        if history is not None:
            binding_matches = (
                binding.publisher_fingerprint == history.current_fingerprint
            )
        else:
            binding_matches = not ordered or any(
                entry["publisher_fingerprint"] == binding.publisher_fingerprint
                for entry in ordered
            )
        if not binding_matches:
            _fail("publisher binding key differs", "binding_publisher_mismatch")
        evidence.update(
            {
                "publisher_binding_count": len(binding.bindings),
                "publisher_binding_root": binding.binding_root,
                "publisher_binding_status": binding.status,
            }
        )
    if history is not None:
        known_fingerprints = {
            item["fingerprint"]: item["status"] for item in history.key_states
        }
        if any(
            entry["publisher_fingerprint"] not in known_fingerprints
            for entry in ordered
        ):
            _fail(
                "publisher history does not contain an artefact signer",
                "publisher_history_publisher_mismatch",
            )
        for entry in ordered:
            entry["publisher_key_status"] = known_fingerprints[
                entry["publisher_fingerprint"]
            ]
        evidence.update(
            {
                "current_publisher_fingerprint": history.current_fingerprint,
                "publisher_key_history_root": history.publisher_key_history_root,
                "publisher_key_status": history.current_status,
            }
        )
    evidence["publisher_evidence_root"] = _hash_bytes(canonical_dumps(evidence))
    return evidence


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "publisher-attest: invalid invocation\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="publisher-attest")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("sign", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--identity", required=True)
        command.add_argument("--huggingface-observation", required=True)
        command.add_argument("--modelscope-observation", required=True)
    sign = commands.choices["sign"]
    sign.add_argument("--key", required=True)
    sign.add_argument("--issued-at")
    sign.add_argument("--output", required=True)
    verify = commands.choices["verify"]
    verify.add_argument("attestation")
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
        if args.command == "sign":
            attestation = sign_publisher_attestation(
                identity,
                observations,
                args.key,
                issued_at=args.issued_at,
            )
            _write_json_safely(args.output, attestation)
            print("PASS publisher_signature_valid")
        else:
            attestation = _read_json_safely(args.attestation)
            verified = verify_publisher_attestation(
                attestation, identity, observations
            )
            print(f"PASS {verified.status}")
        return 0
    except PublisherAttestationError as exc:
        print(f"REFUSED {exc.code}", file=sys.stderr)
        return 1
    except (SourceObservationError, ValueError) as exc:
        code = getattr(exc, "code", "publisher_input_invalid")
        if code == "input_invalid":
            code = "publisher_input_invalid"
        print(f"REFUSED {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
