"""Publisher-key bindings discovered from fixed, revision-pinned registry files.

The publisher signature is the Phase 2A.2 Ed25519 signature envelope. Platform
binding is established separately by fetching that signed statement from the
exact repository named in the statement at an immutable provider revision.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traceseal_observe import canonical_dumps
from traceseal_observe.publisher import (
    PUBLISHER_ALGORITHM,
    PublisherAttestationError,
    publisher_fingerprint,
    verify_detached_publisher_signature,
)
from traceseal_observe.resolution import (
    ResolutionWitnessError,
    _load_key_safely,
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
    PinnedSourceFile,
    SourceObservationError,
)

BINDING_VERSION = "1.0"
BINDING_EVIDENCE_VERSION = "1.0"
BINDING_STATEMENT_TYPE = "publisher_key_binding"
BINDING_SCOPE = "repository"
BINDING_PATH = ".well-known/open-registry/publisher.json"
BINDING_SELF_CLAIMED = "publisher_key_self_claimed"
BINDING_PLATFORM_BOUND = "publisher_key_platform_bound"
BINDING_OFFLINE_METHOD = "binding_evidence_rederivation"
BINDING_REOBSERVATION_METHOD = "platform_binding_reobservation"

_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINGERPRINT_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")


class BindingError(ValueError):
    """A publisher binding is malformed, copied, unavailable, or inconsistent."""

    def __init__(self, message: str, code: str = "publisher_binding_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BindingVerification:
    publisher_fingerprint: str
    statement_hash: str
    status: str
    subject_hash: str
    verification_method: str


@dataclass(frozen=True)
class DerivedBindingEvidence:
    binding_root: str
    bindings: tuple[dict[str, Any], ...]
    publisher_fingerprint: str
    status: str


def _fail(message: str, code: str = "publisher_binding_invalid") -> None:
    raise BindingError(message, code)


def _hash_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _require_object(
    value: Any, required: set[str], optional: set[str] = frozenset()
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("publisher binding object shape is invalid")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        _fail("publisher binding object shape is invalid")
    return value


def _require_hash(value: Any) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        _fail("publisher binding hash is invalid", "binding_evidence_invalid")
    return value


def _contains_unsafe_unicode(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)


def _validate_issued_at(value: Any) -> str:
    if not isinstance(value, str) or _contains_unsafe_unicode(value):
        _fail("publisher binding issuance time is invalid", "publisher_issued_at_invalid")
    try:
        canonical = format_utc_seconds(parse_utc_seconds(value))
    except (SignedTimeProfileError, TypeError, ValueError) as exc:
        raise BindingError(
            "publisher binding issuance time is invalid", "publisher_issued_at_invalid"
        ) from exc
    if canonical != value:
        _fail("publisher binding issuance time is invalid", "publisher_issued_at_invalid")
    return value


def _validate_subject(value: Any) -> dict[str, str]:
    subject = _require_object(value, {"account", "provider", "repository", "scope"})
    provider, account, repository, scope = (
        subject["provider"],
        subject["account"],
        subject["repository"],
        subject["scope"],
    )
    parts = repository.split("/") if isinstance(repository, str) else []
    if (
        provider not in {"huggingface", "modelscope"}
        or scope != BINDING_SCOPE
        or not isinstance(account, str)
        or _ACCOUNT_RE.fullmatch(account) is None
        or len(parts) != 2
        or _ACCOUNT_RE.fullmatch(parts[0]) is None
        or _ACCOUNT_RE.fullmatch(parts[1]) is None
        or parts[0] != account
    ):
        _fail("publisher binding subject is invalid", "binding_subject_invalid")
    return dict(subject)


def validate_publisher_binding_subject(value: Any) -> dict[str, str]:
    """Validate the one shared provider/account/repository scope contract."""
    return _validate_subject(value)


def _validate_binding_shape(value: Any, *, require_signature: bool) -> dict[str, Any]:
    document = _require_object(value, {"binding_version", "signature", "statement"})
    if document["binding_version"] != BINDING_VERSION:
        _fail("publisher binding version is invalid")
    statement = _require_object(
        document["statement"], {"issued_at", "publisher", "statement_type", "subject"}
    )
    publisher = _require_object(statement["publisher"], {"fingerprint"})
    _validate_subject(statement["subject"])
    _validate_issued_at(statement["issued_at"])
    if statement["statement_type"] != BINDING_STATEMENT_TYPE:
        _fail("publisher binding statement type is invalid")
    signature = _require_object(
        document["signature"], {"algorithm", "fingerprint", "public_key", "value"}
    )
    if signature["algorithm"] != PUBLISHER_ALGORITHM:
        _fail("publisher signature algorithm is invalid", "publisher_algorithm_invalid")
    if not isinstance(signature["public_key"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", signature["public_key"]
    ):
        _fail("publisher public key is invalid", "publisher_key_invalid")
    if not isinstance(signature["value"], str) or (
        require_signature and not re.fullmatch(r"[0-9a-f]{128}", signature["value"])
    ):
        _fail("publisher signature is invalid", "publisher_signature_invalid")
    fingerprint = publisher_fingerprint(bytes.fromhex(signature["public_key"]))
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
    return document


def publisher_binding_signing_bytes(document: Any) -> bytes:
    value = _validate_binding_shape(document, require_signature=False)
    return canonical_dumps(
        {
            "binding_version": value["binding_version"],
            "statement": value["statement"],
        }
    )


def sign_publisher_binding(
    provider: str,
    account: str,
    repository: str,
    key_path: Path | str,
    *,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Generate one repository-scoped signed binding entirely offline."""
    _validate_subject(
        {
            "account": account,
            "provider": provider,
            "repository": repository,
            "scope": BINDING_SCOPE,
        }
    )
    try:
        key = _load_key_safely(key_path)
    except ResolutionWitnessError as exc:
        raise BindingError("publisher private key is invalid", "publisher_key_invalid") from exc
    fingerprint = publisher_fingerprint(bytes.fromhex(key.public_key_hex))
    document: dict[str, Any] = {
        "binding_version": BINDING_VERSION,
        "signature": {
            "algorithm": PUBLISHER_ALGORITHM,
            "fingerprint": fingerprint,
            "public_key": key.public_key_hex,
            "value": "",
        },
        "statement": {
            "issued_at": _validate_issued_at(
                issued_at if issued_at is not None else format_utc_seconds()
            ),
            "publisher": {"fingerprint": fingerprint},
            "statement_type": BINDING_STATEMENT_TYPE,
            "subject": {
                "account": account,
                "provider": provider,
                "repository": repository,
                "scope": BINDING_SCOPE,
            },
        },
    }
    document["signature"]["value"] = key.sign(
        publisher_binding_signing_bytes(document)
    ).hex()
    return document


def verify_publisher_binding_document(
    document: Any, expected_provider: str, expected_repository: str
) -> BindingVerification:
    value = _validate_binding_shape(document, require_signature=True)
    try:
        fingerprint = verify_detached_publisher_signature(
            value["signature"],
            value["statement"]["publisher"]["fingerprint"],
            publisher_binding_signing_bytes(value),
        )
    except PublisherAttestationError as exc:
        raise BindingError("publisher binding signature is invalid", exc.code) from exc
    subject = value["statement"]["subject"]
    parts = expected_repository.split("/") if isinstance(expected_repository, str) else []
    if (
        expected_provider not in {"huggingface", "modelscope"}
        or len(parts) != 2
        or subject["provider"] != expected_provider
        or subject["repository"] != expected_repository
        or subject["account"] != parts[0]
    ):
        _fail("publisher binding subject differs", "binding_subject_mismatch")
    return BindingVerification(
        publisher_fingerprint=fingerprint,
        statement_hash=_hash_bytes(canonical_dumps(value["statement"])),
        status=BINDING_SELF_CLAIMED,
        subject_hash=_hash_bytes(canonical_dumps(subject)),
        verification_method=BINDING_OFFLINE_METHOD,
    )


def canonical_publisher_binding_bytes(document: Any) -> bytes:
    value = _validate_binding_shape(document, require_signature=True)
    verify_publisher_binding_document(
        value,
        value["statement"]["subject"]["provider"],
        value["statement"]["subject"]["repository"],
    )
    return canonical_dumps(value)


def _decode_binding_document(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) < 2:
        _fail("publisher binding document is invalid")
    if len(payload) > MAX_SELECTED_FILE_BYTES:
        _fail("publisher binding document is too large", "binding_document_too_large")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail("publisher binding JSON has duplicate keys")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BindingError("publisher binding document is invalid") from exc
    if not isinstance(value, dict):
        _fail("publisher binding document is invalid")
    return value


def decode_publisher_binding_document(payload: bytes) -> dict[str, Any]:
    """Decode strict duplicate-safe binding JSON for shared profile loaders."""
    return _decode_binding_document(payload)


def _validate_pinned_file(
    file: PinnedSourceFile, provider: str, repository: str
) -> None:
    if (
        not isinstance(file, PinnedSourceFile)
        or file.provider != provider
        or not file.content
        or file.size != len(file.content)
        or file.size > MAX_SELECTED_FILE_BYTES
        or file.content_hash != _hash_bytes(file.content)
        or file.source_identity_hash != _hash_text(repository)
        or not isinstance(file.revision, dict)
        or set(file.revision) != {"kind", "reference_hash", "value_hash"}
        or _HASH_RE.fullmatch(file.revision.get("reference_hash", "")) is None
        or _HASH_RE.fullmatch(file.revision.get("value_hash", "")) is None
        or file.revision.get("kind")
        != ("git_commit_sha1" if provider == "huggingface" else "file_commit_sha1")
    ):
        _fail("publisher binding source is inconsistent", "binding_source_unavailable")


def validate_pinned_publisher_file(
    file: PinnedSourceFile, provider: str, repository: str
) -> None:
    """Apply the exact binding discovery descriptor and revision checks."""
    _validate_pinned_file(file, provider, repository)


def discover_publisher_binding(
    provider: str, repository: str, adapter: Any
) -> dict[str, Any]:
    """Fetch and verify the fixed binding file from one trusted source adapter."""
    if provider not in {"huggingface", "modelscope"} or adapter is None:
        _fail("publisher binding provider is invalid", "binding_source_unavailable")
    try:
        file = adapter.fetch_pinned_file(repository, BINDING_PATH)
    except SourceObservationError as exc:
        code = (
            "binding_document_too_large"
            if exc.code in {"response_too_large", "selected_file_too_large"}
            else "binding_source_unavailable"
        )
        raise BindingError("publisher binding source is unavailable", code) from exc
    _validate_pinned_file(file, provider, repository)
    document = _decode_binding_document(file.content)
    if "publisher_history_version" in document:
        # Lazy import avoids a module cycle: the history profile deliberately
        # reuses the exact v1 binding verifier defined here.
        from traceseal_observe.history import current_binding_from_publisher_document

        document = current_binding_from_publisher_document(
            document, provider, repository
        )
    verified = verify_publisher_binding_document(document, provider, repository)
    return {
        "binding_path_hash": _hash_text(BINDING_PATH),
        "document_hash": file.content_hash,
        "provider": provider,
        "publisher_fingerprint": verified.publisher_fingerprint,
        "revision": copy.deepcopy(file.revision),
        "scope": BINDING_SCOPE,
        "source_identity_hash": file.source_identity_hash,
        "statement_hash": verified.statement_hash,
        "status": BINDING_PLATFORM_BOUND,
        "subject_hash": verified.subject_hash,
    }


def _validate_binding_entry(value: Any) -> dict[str, Any]:
    entry = _require_object(
        value,
        {
            "binding_path_hash",
            "document_hash",
            "provider",
            "publisher_fingerprint",
            "revision",
            "scope",
            "source_identity_hash",
            "statement_hash",
            "status",
            "subject_hash",
        },
    )
    provider = entry["provider"]
    revision = _require_object(entry["revision"], {"kind", "reference_hash", "value_hash"})
    expected_kind = "git_commit_sha1" if provider == "huggingface" else "file_commit_sha1"
    if (
        provider not in {"huggingface", "modelscope"}
        or entry["binding_path_hash"] != _hash_text(BINDING_PATH)
        or entry["scope"] != BINDING_SCOPE
        or entry["status"] != BINDING_PLATFORM_BOUND
        or not isinstance(entry["publisher_fingerprint"], str)
        or _FINGERPRINT_RE.fullmatch(entry["publisher_fingerprint"]) is None
        or revision["kind"] != expected_kind
    ):
        _fail("publisher binding evidence entry is invalid", "binding_evidence_invalid")
    for key in (
        "document_hash",
        "source_identity_hash",
        "statement_hash",
        "subject_hash",
    ):
        _require_hash(entry[key])
    _require_hash(revision["reference_hash"])
    _require_hash(revision["value_hash"])
    return copy.deepcopy(entry)


def build_publisher_binding_evidence(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(entries, list) or not 1 <= len(entries) <= 2:
        _fail("publisher binding set is invalid", "binding_evidence_invalid")
    bindings = sorted(
        (_validate_binding_entry(entry) for entry in entries),
        key=lambda entry: (entry["provider"], entry["subject_hash"]),
    )
    fingerprint = bindings[0]["publisher_fingerprint"]
    seen: set[str] = set()
    for binding in bindings:
        if binding["publisher_fingerprint"] != fingerprint:
            _fail("publisher binding keys differ", "binding_publisher_mismatch")
        if binding["provider"] in seen:
            _fail("publisher binding provider is duplicated", "binding_evidence_invalid")
        seen.add(binding["provider"])
    evidence: dict[str, Any] = {
        "binding_evidence_version": BINDING_EVIDENCE_VERSION,
        "bindings": bindings,
        "publisher_fingerprint": fingerprint,
        "status": BINDING_PLATFORM_BOUND,
    }
    evidence["binding_root"] = _hash_bytes(canonical_dumps(evidence))
    return evidence


def derive_publisher_binding_evidence(value: Any) -> DerivedBindingEvidence:
    evidence = _require_object(
        value,
        {
            "binding_evidence_version",
            "binding_root",
            "bindings",
            "publisher_fingerprint",
            "status",
        },
    )
    if evidence["binding_evidence_version"] != BINDING_EVIDENCE_VERSION:
        _fail("publisher binding evidence version is invalid", "binding_evidence_invalid")
    root = _require_hash(evidence["binding_root"])
    expected = build_publisher_binding_evidence(evidence["bindings"])
    if canonical_dumps(expected) != canonical_dumps(evidence):
        _fail("publisher binding evidence differs", "binding_evidence_invalid")
    return DerivedBindingEvidence(
        binding_root=root,
        bindings=tuple(copy.deepcopy(expected["bindings"])),
        publisher_fingerprint=expected["publisher_fingerprint"],
        status=expected["status"],
    )


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "publisher-bind: invalid invocation\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(prog="publisher-bind")
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate", help="generate a signed binding offline")
    generate.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
    generate.add_argument("--account", required=True)
    generate.add_argument("--repository", required=True)
    generate.add_argument("--key", required=True)
    generate.add_argument("--issued-at")
    generate.add_argument("--output", required=True)
    verify = commands.add_parser("verify", help="retrieve and verify the fixed binding")
    verify.add_argument("--provider", choices=("huggingface", "modelscope"), required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    try:
        if args.command == "generate":
            document = sign_publisher_binding(
                args.provider,
                args.account,
                args.repository,
                args.key,
                issued_at=args.issued_at,
            )
            _write_json_safely(args.output, document)
            print(f"PASS {BINDING_SELF_CLAIMED} publish_path={BINDING_PATH}")
        else:
            adapter = (
                HuggingFaceSourceAdapter()
                if args.provider == "huggingface"
                else ModelScopeSourceAdapter()
            )
            entry = discover_publisher_binding(args.provider, args.repository, adapter)
            evidence = build_publisher_binding_evidence([entry])
            _write_json_safely(args.output, evidence)
            print(f"PASS {BINDING_PLATFORM_BOUND} provider={args.provider}")
        return 0
    except (BindingError, ResolutionWitnessError, SourceObservationError) as exc:
        code = getattr(exc, "code", "publisher_binding_invalid")
        if code == "input_invalid":
            code = "publisher_input_invalid"
        print(f"REFUSED {code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
