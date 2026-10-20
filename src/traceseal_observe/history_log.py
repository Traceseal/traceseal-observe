"""Independent verification of governed publisher-history log evidence.

This module intentionally does not append to the log. It independently checks
the TraceSeal log entry commitment, RFC 6962 inclusion path, log checkpoint
signature, C2SP cosignature/v1, and publisher predecessor graph before identity
receipts or witnesses accept the evidence bundle.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from traceseal_observe import canonical_dumps

ENTRY_TYPE = "publisher_identity_history"
ENTRY_VERSION = "1.0"
INCLUSION_VERSION = "1.0"
LOG_EVIDENCE_VERSION = "1.0"
LOG_HISTORY_VERSION = "1.0"

STATUS_UNFORKED = "publisher_history_unforked"
STATUS_EQUIVOCATION = "publisher_history_equivocation"
STATUS_CHECKPOINT_WITNESSED = "checkpoint_witnessed_unforked"
WITNESS_METHOD_OFFLINE = "log_evidence_offline_verified"
WITNESS_METHOD_LIVE = "live_log_checkpoint_reobserved"

# Production verification is deliberately key-pinned.  Tests inject disposable
# local keys into the public functions; neither the evidence bundle nor a CLI
# caller can select a different origin or verifier key.
TRACESEAL_LOG_ORIGIN = "log.traceseal.io"
TRACESEAL_LOG_VKEY = (
    "log.traceseal.io+bcbcecc8+AR4pimAaGABPMPkqgxneIOqI7qSXBGtEJnXFr1Wevm1B"
)
MARKOVIAN_WITNESS_VKEY = (
    "markovianprotocol.com/witness+41b8827f"
    "+BJKLl8rBYM0oUxSaWh9rjTldTprEpYj/SWVIGgacA9XC"
)

MAX_HISTORY_ENTRIES = 64
MAX_TREE_SIZE = 65_536
MAX_INCLUSION_PATH = 64
MAX_CHECKPOINT_BYTES = 16_384

_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FP_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")
_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_DESCRIPTOR_FIELDS = frozenset(
    {
        "affected_fingerprint",
        "current_fingerprint",
        "current_key_status",
        "entry_type",
        "entry_version",
        "event_time_claim",
        "event_type",
        "evidence_method",
        "history_root",
        "predecessor_history_root",
        "publisher_fingerprint",
        "scope",
        "statement_hash",
    }
)
_ENTRY_FIELDS = _DESCRIPTOR_FIELDS | frozenset(
    {"entry_hash", "event_hash", "prev_hash", "published_at_claim", "seq"}
)
_INCLUSION_FIELDS = frozenset(
    {
        "checkpoint_hash",
        "checkpoint_note",
        "checkpoint_root",
        "entry",
        "inclusion_path",
        "inclusion_version",
        "leaf_index",
        "log_origin",
        "tree_size",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "current_fingerprint",
        "current_status",
        "inclusions",
        "key_states",
        "log_origins",
        "publisher_history_log_entry_hashes",
        "publisher_history_log_evidence_root",
        "publisher_history_log_evidence_version",
        "publisher_history_log_event_hashes",
        "publisher_history_log_root",
        "publisher_history_log_status",
    }
)


class HistoryLogError(ValueError):
    def __init__(self, message: str, code: str = "publisher_history_log_invalid"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DerivedHistoryLogEvidence:
    current_fingerprint: str
    current_status: str
    entry_hashes: tuple[str, ...]
    event_hashes: tuple[str, ...]
    key_states: tuple[dict[str, str], ...]
    log_origins: tuple[str, ...]
    publisher_history_log_evidence_root: str
    publisher_history_log_root: str
    publisher_key_continuity_root: str
    status: str


def production_log_vkeys() -> tuple[dict[str, str], dict[str, str]]:
    """Return fresh key maps pinned to the deployed TraceSeal log origin."""
    return (
        {TRACESEAL_LOG_ORIGIN: TRACESEAL_LOG_VKEY},
        {TRACESEAL_LOG_ORIGIN: MARKOVIAN_WITNESS_VKEY},
    )


def _fail(message: str, code: str = "publisher_history_log_invalid") -> None:
    raise HistoryLogError(message, code)


def _hash_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _format_digest(payload: bytes) -> str:
    if len(payload) != 32:
        _fail("Merkle digest is invalid", "inclusion_path_invalid")
    return "sha256:" + payload.hex()


def _digest(value: Any, code: str = "publisher_history_log_hash_invalid") -> bytes:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail("publisher history log hash is invalid", code)
    return bytes.fromhex(value[7:])


def _object(value: Any, fields: frozenset[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail("publisher history log object shape is invalid", code)
    return value


def _fingerprint(value: Any) -> str:
    if not isinstance(value, str) or _FP_RE.fullmatch(value) is None:
        _fail("publisher history fingerprint is invalid")
    return value


def _time(value: Any) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        _fail("publisher history log time is invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise HistoryLogError("publisher history log time is invalid") from exc
    return value


def _validate_entry(value: Any) -> dict[str, Any]:
    entry = _object(value, _ENTRY_FIELDS, "publisher_history_log_entry_invalid")
    if entry["entry_type"] != ENTRY_TYPE or entry["entry_version"] != ENTRY_VERSION:
        _fail("publisher history log entry type is invalid")
    scope = _object(
        entry["scope"],
        frozenset({"account_hash", "provider", "repository_hash"}),
        "publisher_history_log_scope_invalid",
    )
    if scope["provider"] not in {"huggingface", "modelscope"}:
        _fail("publisher history log scope is invalid")
    _digest(scope["account_hash"])
    _digest(scope["repository_hash"])
    for name in (
        "affected_fingerprint",
        "current_fingerprint",
        "publisher_fingerprint",
    ):
        _fingerprint(entry[name])
    for name in ("history_root", "statement_hash"):
        _digest(entry[name])
    predecessor = entry["predecessor_history_root"]
    if predecessor != "genesis":
        _digest(predecessor)
    _time(entry["event_time_claim"])
    _time(entry["published_at_claim"])
    if (
        isinstance(entry["seq"], bool)
        or not isinstance(entry["seq"], int)
        or entry["seq"] < 1
        or entry["current_key_status"] not in {"active", "revoked"}
    ):
        _fail("publisher history log entry state is invalid")
    if entry["prev_hash"] != "genesis":
        _digest(entry["prev_hash"])
    event_type = entry["event_type"]
    method = entry["evidence_method"]
    if event_type == "binding":
        if (
            predecessor != "genesis"
            or entry["publisher_fingerprint"] != entry["current_fingerprint"]
            or entry["current_fingerprint"] != entry["affected_fingerprint"]
            or entry["current_key_status"] != "active"
            or method != "platform_binding_observed"
        ):
            _fail("publisher binding log entry is invalid")
    elif event_type == "rotation":
        if (
            predecessor == "genesis"
            or entry["current_fingerprint"] != entry["affected_fingerprint"]
            or method != "dual_signature_rotation"
        ):
            _fail("publisher rotation log entry is invalid")
    elif event_type == "revocation":
        if predecessor == "genesis" or method not in {
            "key_self_revocation",
            "platform_revocation_observed",
        }:
            _fail("publisher revocation log entry is invalid")
    else:
        _fail("publisher history log event is invalid")
    descriptor = {field: copy.deepcopy(entry[field]) for field in _DESCRIPTOR_FIELDS}
    if entry["event_hash"] != _hash_bytes(canonical_dumps(descriptor)):
        _fail("publisher history event hash differs", "log_entry_event_hash_mismatch")
    body = {key: copy.deepcopy(item) for key, item in entry.items() if key != "entry_hash"}
    if entry["entry_hash"] != _hash_bytes(canonical_dumps(body)):
        _fail("publisher history entry hash differs", "log_entry_hash_mismatch")
    return copy.deepcopy(entry)


def _parse_verifier_key(value: str) -> tuple[str, int, bytes, bytes]:
    try:
        name, stated, encoded = value.split("+", 2)
        key_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise HistoryLogError("checkpoint verifier key is invalid", "checkpoint_key_invalid") from exc
    if not name or "+" in name or "\n" in name or len(key_bytes) != 33:
        _fail("checkpoint verifier key is invalid", "checkpoint_key_invalid")
    key_hash = hashlib.sha256(name.encode() + b"\n" + key_bytes).digest()[:4]
    if stated != key_hash.hex():
        _fail("checkpoint verifier key fingerprint differs", "checkpoint_key_invalid")
    return name, key_bytes[0], key_bytes[1:], key_hash


def _parse_note(note: str) -> tuple[str, dict[str, list[bytes]]]:
    encoded = note.encode("utf-8")
    if not 1 <= len(encoded) <= MAX_CHECKPOINT_BYTES:
        _fail("checkpoint is invalid", "checkpoint_invalid")
    separator = note.find("\n\n")
    if separator < 0:
        _fail("checkpoint is invalid", "checkpoint_invalid")
    body = note[: separator + 1]
    signatures: dict[str, list[bytes]] = {}
    for line in note[separator + 2 :].splitlines():
        if not line.startswith("— "):
            _fail("checkpoint signature line is invalid", "checkpoint_invalid")
        try:
            name, encoded_signature = line[2:].split(" ", 1)
            signature = base64.b64decode(encoded_signature, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise HistoryLogError("checkpoint signature line is invalid", "checkpoint_invalid") from exc
        signatures.setdefault(name, []).append(signature)
    return body, signatures


def _matching_signature(
    signatures: dict[str, list[bytes]], name: str, key_hash: bytes, length: int
) -> bytes:
    for signature in signatures.get(name, []):
        if signature[:4] == key_hash:
            if len(signature) != length:
                _fail("checkpoint signature is malformed", "checkpoint_signature_invalid")
            return signature
    _fail("checkpoint signature is absent", "checkpoint_signature_invalid")


def _verify_checkpoint(
    note: str, log_vkey: str, witness_vkey: str
) -> tuple[str, int, bytes, int]:
    body, signatures = _parse_note(note)
    lines = body.splitlines()
    if len(lines) != 3 or not lines[0] or len(lines[0]) > 255:
        _fail("checkpoint body is invalid", "checkpoint_invalid")
    try:
        tree_size = int(lines[1])
        root = base64.b64decode(lines[2], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise HistoryLogError("checkpoint body is invalid", "checkpoint_invalid") from exc
    if not 1 <= tree_size <= MAX_TREE_SIZE or len(root) != 32:
        _fail("checkpoint body is invalid", "checkpoint_invalid")

    log_name, algorithm, public_key, key_hash = _parse_verifier_key(log_vkey)
    if algorithm != 1 or log_name != lines[0]:
        _fail("checkpoint log key is invalid", "checkpoint_key_invalid")
    signature = _matching_signature(signatures, log_name, key_hash, 68)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature[4:], body.encode("utf-8")
        )
    except InvalidSignature as exc:
        raise HistoryLogError("checkpoint signature is invalid", "checkpoint_signature_invalid") from exc

    witness_name, algorithm, witness_key, witness_hash = _parse_verifier_key(
        witness_vkey
    )
    if algorithm != 4:
        _fail("checkpoint witness key is invalid", "checkpoint_witness_invalid")
    cosignature = _matching_signature(
        signatures, witness_name, witness_hash, 76
    )
    signed_time = struct.unpack(">Q", cosignature[4:12])[0]
    try:
        Ed25519PublicKey.from_public_bytes(witness_key).verify(
            cosignature[12:],
            f"cosignature/v1\ntime {signed_time}\n{body}".encode("utf-8"),
        )
    except InvalidSignature as exc:
        raise HistoryLogError("checkpoint witness is invalid", "checkpoint_witness_invalid") from exc
    return lines[0], tree_size, root, signed_time


def _hash_leaf(payload: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + payload).digest()


def _hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _verify_inclusion(
    leaf_hash: bytes,
    index: int,
    tree_size: int,
    proof: list[bytes],
    root: bytes,
) -> bool:
    if index < 0 or index >= tree_size:
        return False
    fn, sn = index, tree_size - 1
    result = leaf_hash
    for sibling in proof:
        if fn & 1 or fn == sn:
            result = _hash_children(sibling, result)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            result = _hash_children(result, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and result == root


def _verify_inclusion_evidence(
    value: Any, log_vkeys: dict[str, str], witness_vkeys: dict[str, str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    inclusion = _object(
        value, _INCLUSION_FIELDS, "publisher_history_log_inclusion_invalid"
    )
    if inclusion["inclusion_version"] != INCLUSION_VERSION:
        _fail("publisher history inclusion version is invalid")
    entry = _validate_entry(inclusion["entry"])
    note = inclusion["checkpoint_note"]
    if not isinstance(note, str) or _hash_bytes(note.encode("utf-8")) != inclusion[
        "checkpoint_hash"
    ]:
        _fail("checkpoint commitment differs", "checkpoint_hash_mismatch")
    origin = inclusion["log_origin"]
    if origin not in log_vkeys or origin not in witness_vkeys:
        _fail("checkpoint verifier key is not pinned", "checkpoint_key_invalid")
    verified_origin, size, root, cosigned_at = _verify_checkpoint(
        note, log_vkeys[origin], witness_vkeys[origin]
    )
    if (
        verified_origin != origin
        or inclusion["tree_size"] != size
        or inclusion["checkpoint_root"] != _format_digest(root)
    ):
        _fail("checkpoint fields differ", "checkpoint_mismatch")
    index = inclusion["leaf_index"]
    if (
        isinstance(index, bool)
        or not isinstance(index, int)
        or index < 0
        or index >= size
        or entry["seq"] != index + 1
    ):
        _fail("publisher history inclusion sequence is invalid")
    path = inclusion["inclusion_path"]
    if not isinstance(path, list) or len(path) > MAX_INCLUSION_PATH:
        _fail("publisher history inclusion path is invalid")
    proof = [_digest(item, "inclusion_path_invalid") for item in path]
    if not _verify_inclusion(
        _hash_leaf(canonical_dumps(entry)), index, size, proof, root
    ):
        _fail("publisher history inclusion proof is invalid", "inclusion_proof_invalid")
    return copy.deepcopy(entry), {
        "checkpoint_hash": inclusion["checkpoint_hash"],
        "cosigned_at": cosigned_at,
        "entry_hash": entry["entry_hash"],
        "leaf_index": index,
        "log_origin": origin,
        "tree_size": size,
    }


def _analyse(entries: list[dict[str, Any]]) -> dict[str, Any]:
    if not 1 <= len(entries) <= MAX_HISTORY_ENTRIES:
        _fail("publisher history log exceeds limits", "publisher_history_log_limit")
    first = entries[0]
    for entry in entries[1:]:
        if entry["scope"] != first["scope"] or entry[
            "publisher_fingerprint"
        ] != first["publisher_fingerprint"]:
            _fail("publisher history log scope differs")
    by_event: dict[str, dict[str, Any]] = {}
    for entry in sorted(entries, key=lambda item: item["seq"]):
        by_event.setdefault(entry["event_hash"], entry)
    children: dict[str, list[dict[str, Any]]] = {}
    for entry in by_event.values():
        children.setdefault(entry["predecessor_history_root"], []).append(entry)
    for branch in children.values():
        if len({entry["event_hash"] for entry in branch}) > 1:
            _fail("publisher history contains conflicting branches", STATUS_EQUIVOCATION)
    if len(children.get("genesis", [])) != 1:
        _fail("publisher history log is disconnected")
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    current = children["genesis"][0]
    while True:
        if current["event_hash"] in seen:
            _fail("publisher history log cycles")
        seen.add(current["event_hash"])
        chain.append(current)
        following = children.get(current["history_root"], [])
        if not following:
            break
        current = following[0]
    if len(seen) != len(by_event):
        _fail("publisher history log is disconnected")

    key_order: list[str] = []
    states: dict[str, str] = {}
    current_fingerprint = ""
    for index, entry in enumerate(chain):
        if index == 0:
            current_fingerprint = entry["current_fingerprint"]
            key_order.append(current_fingerprint)
            states[current_fingerprint] = "active"
            continue
        if entry["seq"] <= chain[index - 1]["seq"]:
            _fail(
                "publisher history publication order is invalid",
                "publisher_history_log_order_invalid",
            )
        if entry["event_type"] == "rotation":
            successor = entry["affected_fingerprint"]
            if (
                successor == current_fingerprint
                or successor in states
                or successor != entry["current_fingerprint"]
            ):
                _fail("publisher history transition is invalid")
            if states[current_fingerprint] != "revoked":
                states[current_fingerprint] = "superseded"
            key_order.append(successor)
            states[successor] = entry["current_key_status"]
            current_fingerprint = successor
        elif entry["event_type"] == "revocation":
            affected = entry["affected_fingerprint"]
            if affected not in states or entry[
                "current_fingerprint"
            ] != current_fingerprint:
                _fail("publisher history transition is invalid")
            states[affected] = "revoked"
            if states[current_fingerprint] != entry["current_key_status"]:
                _fail("publisher history transition is invalid")
        else:
            _fail("publisher history transition is invalid")
    event_hashes = [entry["event_hash"] for entry in chain]
    entry_hashes = [entry["entry_hash"] for entry in chain]
    history_root = _hash_bytes(
        canonical_dumps(
            {
                "entry_hashes": entry_hashes,
                "event_hashes": event_hashes,
                "publisher_history_log_version": LOG_HISTORY_VERSION,
            }
        )
    )
    return {
        "current_fingerprint": current_fingerprint,
        "current_status": states[current_fingerprint],
        "entry_hashes": entry_hashes,
        "event_hashes": event_hashes,
        "key_states": [
            {"fingerprint": fingerprint, "status": states[fingerprint]}
            for fingerprint in key_order
        ],
        "publisher_history_log_root": history_root,
        "publisher_key_continuity_root": chain[-1]["history_root"],
    }


def build_publisher_history_log_evidence(
    inclusions: list[dict[str, Any]],
    log_vkeys: dict[str, str],
    witness_vkeys: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(inclusions, list) or not 1 <= len(inclusions) <= MAX_HISTORY_ENTRIES:
        _fail("publisher history log inclusion set is invalid")
    entries: list[dict[str, Any]] = []
    commitments: list[dict[str, Any]] = []
    for inclusion in inclusions:
        entry, commitment = _verify_inclusion_evidence(
            inclusion, log_vkeys, witness_vkeys
        )
        entries.append(entry)
        commitments.append(commitment)
    report = _analyse(entries)
    by_hash = {
        inclusion["entry"]["entry_hash"]: copy.deepcopy(inclusion)
        for inclusion in inclusions
    }
    ordered_inclusions = [by_hash[item] for item in report["entry_hashes"]]
    origins = sorted({item["log_origin"] for item in commitments})
    evidence: dict[str, Any] = {
        "current_fingerprint": report["current_fingerprint"],
        "current_status": report["current_status"],
        "inclusions": ordered_inclusions,
        "key_states": report["key_states"],
        "log_origins": origins,
        "publisher_history_log_entry_hashes": report["entry_hashes"],
        "publisher_history_log_evidence_version": LOG_EVIDENCE_VERSION,
        "publisher_history_log_event_hashes": report["event_hashes"],
        "publisher_history_log_root": report["publisher_history_log_root"],
        "publisher_history_log_status": STATUS_CHECKPOINT_WITNESSED,
    }
    evidence["publisher_history_log_evidence_root"] = _hash_bytes(
        canonical_dumps(evidence)
    )
    return evidence


def derive_publisher_history_log_evidence(
    value: Any,
    log_vkeys: dict[str, str],
    witness_vkeys: dict[str, str],
) -> DerivedHistoryLogEvidence:
    evidence = _object(
        value, _EVIDENCE_FIELDS, "publisher_history_log_evidence_invalid"
    )
    if evidence["publisher_history_log_evidence_version"] != LOG_EVIDENCE_VERSION:
        _fail("publisher history log evidence version is invalid")
    root = evidence["publisher_history_log_evidence_root"]
    _digest(root)
    expected = build_publisher_history_log_evidence(
        evidence["inclusions"], log_vkeys, witness_vkeys
    )
    if canonical_dumps(expected) != canonical_dumps(evidence):
        _fail("publisher history log evidence differs")
    return DerivedHistoryLogEvidence(
        current_fingerprint=expected["current_fingerprint"],
        current_status=expected["current_status"],
        entry_hashes=tuple(expected["publisher_history_log_entry_hashes"]),
        event_hashes=tuple(expected["publisher_history_log_event_hashes"]),
        key_states=tuple(copy.deepcopy(expected["key_states"])),
        log_origins=tuple(expected["log_origins"]),
        publisher_history_log_evidence_root=root,
        publisher_history_log_root=expected["publisher_history_log_root"],
        publisher_key_continuity_root=_continuity_root_from_evidence(expected),
        status=expected["publisher_history_log_status"],
    )


def _continuity_root_from_evidence(evidence: dict[str, Any]) -> str:
    """Return the Phase 2A.4 continuity root committed by the terminal event."""
    inclusions = evidence.get("inclusions")
    if not isinstance(inclusions, list) or not inclusions:
        _fail("publisher history log evidence is incomplete")
    entry = inclusions[-1].get("entry") if isinstance(inclusions[-1], dict) else None
    if not isinstance(entry, dict):
        _fail("publisher history log evidence is incomplete")
    _digest(entry.get("history_root"))
    return entry["history_root"]
