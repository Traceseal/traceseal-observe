"""Receipt chains: completeness evidence for operational receipts.

A signature proves a receipt is authentic. It cannot prove that no receipts
are *missing*. A ReceiptChain closes that gap for one signer stream (one
agent, one worker, one deployment):

  1. Every chained receipt carries signed fields
         chain_version, chain_id, chain_seq, chain_prev_hash, chained_at
     inside `execution`, so the existing v1 signature covers them.
     chain_prev_hash is the receipt_hash of receipt chain_seq - 1
     ("genesis" for chain_seq 1). Deleting, reordering or replacing a
     receipt breaks the links; two different receipts with the same
     chain_seq are a fork (equivocation).

  2. The receipt hashes are the leaves of an RFC 6962 Merkle tree. The
     operator signs checkpoints of that tree as C2SP signed notes
     (c2sp.org/tlog-checkpoint), the same format the TraceSeal log uses.
     A checkpoint that has left the operator's control (sent to an
     auditor, a customer, a C2SP witness) pins the chain's length: from
     then on dropping receipts from the tail is detectable too.

  3. Inclusion proofs show that one receipt (and, through its hash links,
     every receipt before it) belongs to a checkpointed chain without
     disclosing the rest. Consistency proofs show a later checkpoint
     extends an earlier one, which is what a witness checks before
     cosigning.

What this does NOT prove: that the operator chained every action (an action
signed with an unchained key is simply outside the chain), or that chained_at
is true wall-clock time. Tail truncation is only detectable relative to a
checkpoint someone else holds. These are documented in RECEIPT-CHAINS.md.

Verification reuses the signed-note, Merkle and cosignature/v1 primitives in
traceseal_observe.history_log.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import struct
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from traceseal_observe import (
    CHAINABLE_RECEIPT_TYPES,
    OperatorKey,
    canonical_dumps,
    Receipt,
    _sign_unchained,
    public_key_fingerprint,
    verify_receipt_signature,
)
from traceseal_observe.history_log import (
    HistoryLogError,
    _hash_children,
    _hash_leaf,
    _matching_signature,
    _parse_note,
    _parse_verifier_key,
    _verify_inclusion,
)

CHAIN_VERSION = "1.0"
GENESIS = "genesis"
CHAIN_FIELDS = frozenset(
    {"chain_version", "chain_id", "chain_seq", "chain_prev_hash", "chained_at"}
)
ORIGIN_PREFIX = "traceseal.io/chain"

ROTATION_TYPE = "chain_key_rotation"
ROTATION_VERSION = "1.0"
ROTATION_REASONS = frozenset({"scheduled", "compromise"})
_ACCEPTANCE_PURPOSE = "traceseal-chain-key-acceptance/1"
_VERIFIABLE_TYPES = CHAINABLE_RECEIPT_TYPES | {ROTATION_TYPE}

_CHAIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_HEADER_FILE = "chain.json"
_HASHES_FILE = "receipt-hashes.bin"
_LOCK_FILE = "chain.lock"


class ChainError(ValueError):
    """A chain could not be extended, opened or verified."""


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def _check_chain_id(chain_id: Any) -> str:
    if not isinstance(chain_id, str) or _CHAIN_ID_RE.fullmatch(chain_id) is None:
        raise ChainError(
            "chain_id must be 1-64 chars of [A-Za-z0-9._-], starting alphanumeric"
        )
    return chain_id


def _check_public_key_hex(value: Any) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ChainError("operator public key must be 64 lowercase hex chars")
    return bytes.fromhex(value)


def chain_origin(operator_public_key_hex: str, chain_id: str) -> str:
    """The checkpoint origin line: unique per (operator key, chain_id)."""
    key = _check_public_key_hex(operator_public_key_hex)
    _check_chain_id(chain_id)
    return f"{ORIGIN_PREFIX}/{hashlib.sha256(key).hexdigest()}/{chain_id}"


def checkpoint_verifier_key(operator_public_key_hex: str, chain_id: str) -> str:
    """The signed-note verifier key (name+keyhash+base64(0x01||key)).

    Standard note tooling (e.g. golang.org/x/mod/sumdb/note) and C2SP
    witnesses can verify the operator's checkpoints with this string.
    """
    name = chain_origin(operator_public_key_hex, chain_id)
    key = b"\x01" + bytes.fromhex(operator_public_key_hex)
    key_hash = hashlib.sha256(name.encode("utf-8") + b"\n" + key).digest()[:4]
    return f"{name}+{key_hash.hex()}+{base64.b64encode(key).decode('ascii')}"


# ---------------------------------------------------------------------------
# RFC 6962 Merkle tree (leaves are 32-byte receipt-hash digests)
# ---------------------------------------------------------------------------


def receipt_leaf_hash(receipt_hash: str) -> bytes:
    """Leaf hash = SHA-256(0x00 || 32-byte digest of receipt_hash)."""
    if not isinstance(receipt_hash, str) or _SHA_RE.fullmatch(receipt_hash) is None:
        raise ChainError("receipt hash must be sha256:<64 hex>")
    return _hash_leaf(bytes.fromhex(receipt_hash[7:]))


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-hashed leaves."""
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()
    level = list(leaf_hashes)
    # Bottom-up pairing of left-full subtrees gives the same root as the
    # recursive RFC 6962 definition: an unpaired last node is promoted.
    while len(level) > 1:
        nxt = [
            _hash_children(level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return _inclusion_path(index, leaves[:k]) + [merkle_root(leaves[k:])]
    return _inclusion_path(index - k, leaves[k:]) + [merkle_root(leaves[:k])]


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [merkle_root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def _decode_digests(proof: Any, label: str) -> list[bytes]:
    if not isinstance(proof, list) or len(proof) > 64:
        raise ChainError(f"{label} must be a list of at most 64 hashes")
    out = []
    for item in proof:
        if not isinstance(item, str) or _SHA_RE.fullmatch(item) is None:
            raise ChainError(f"{label} entries must be sha256:<64 hex>")
        out.append(bytes.fromhex(item[7:]))
    return out


def _fmt(digest: bytes) -> str:
    return "sha256:" + digest.hex()


def _acceptance_message(execution: dict[str, Any]) -> bytes:
    """What the incoming key signs to accept a rotation at this position."""
    return canonical_dumps(
        {
            "chain_id": execution["chain_id"],
            "chain_prev_hash": execution["chain_prev_hash"],
            "chain_seq": execution["chain_seq"],
            "next_public_key": execution["next_public_key"],
            "previous_public_key": execution["previous_public_key"],
            "purpose": _ACCEPTANCE_PURPOSE,
        }
    )


def verify_inclusion(
    receipt_hash: str, seq: int, tree_size: int, root: str, proof: list[str]
) -> bool:
    """True if receipt_hash is leaf `seq` (1-based) of the tree with `root`."""
    if (
        isinstance(seq, bool)
        or not isinstance(seq, int)
        or isinstance(tree_size, bool)
        or not isinstance(tree_size, int)
        or not 1 <= seq <= tree_size
    ):
        return False
    try:
        root_bytes = _decode_digests([root], "root")[0]
        path = _decode_digests(proof, "inclusion proof")
        leaf = receipt_leaf_hash(receipt_hash)
    except ChainError:
        return False
    return _verify_inclusion(leaf, seq - 1, tree_size, path, root_bytes)


def verify_consistency(
    old_size: int, new_size: int, old_root: str, new_root: str, proof: list[str]
) -> bool:
    """RFC 9162 §2.1.4.2: True if tree `new_root` extends tree `old_root`."""
    for value in (old_size, new_size):
        if isinstance(value, bool) or not isinstance(value, int):
            return False
    if not 1 <= old_size <= new_size:
        return False
    try:
        old_r, new_r = _decode_digests([old_root, new_root], "root")
        path = _decode_digests(proof, "consistency proof")
    except ChainError:
        return False
    if old_size == new_size:
        return not path and old_r == new_r
    if old_size & (old_size - 1) == 0:
        path = [old_r] + path
    if not path:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for node in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _hash_children(node, fr)
            sr = _hash_children(node, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _hash_children(sr, node)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_r and sr == new_r


# ---------------------------------------------------------------------------
# The signer side
# ---------------------------------------------------------------------------


@dataclass
class ChainedOperatorKey(OperatorKey):
    """An OperatorKey whose operational receipts are appended to a chain.

    Obtain one from ReceiptChain.signer and pass it anywhere an OperatorKey
    is accepted (observe_anthropic, observe_tool, WorkflowObserver, ...).
    """

    chain: "ReceiptChain | None" = field(default=None, repr=False, compare=False)

    def sign(self, message: bytes) -> bytes:
        # Delegate so remote (KMS/HSM) keys and key rotation keep working.
        return self.chain._key.sign(message)


class ReceiptChain:
    """An append-only, hash-linked sequence of receipts for one signer stream.

    In-memory:
        chain = ReceiptChain(key, "support-agent")

    Persistent (survives restarts; one process at a time):
        chain = ReceiptChain.open("/var/lib/agent/chain", key, "support-agent")

    Then sign through it:
        signer = chain.signer
        response, receipt = observe_anthropic(client, request, signer)
        checkpoint = chain.checkpoint()   # hand this to someone else

    The chain stores only 32 bytes per receipt (its hash). Storing the
    receipts themselves remains the caller's job; a receipt that is signed
    but then lost shows up to a verifier as a gap, which is the honest result.
    """

    def __init__(
        self,
        operator_key: OperatorKey,
        chain_id: str | None = None,
        *,
        directory: Path | str | None = None,
    ):
        if isinstance(operator_key, ChainedOperatorKey):
            raise ChainError("pass the base OperatorKey, not a chained signer")
        self._key = operator_key
        self._lock = threading.Lock()
        self._digests: list[bytes] = []
        self._leaves: list[bytes] = []
        self._dir: Path | None = None
        self._header_path: Path | None = None
        self._header: dict[str, Any] = {}
        self._hashes_fh: Any = None
        self._lock_fh: Any = None
        self._closed = False
        if directory is not None:
            self.chain_id = self._open_directory(Path(directory), chain_id)
        else:
            self.chain_id = _check_chain_id(chain_id or secrets.token_hex(16))
        self.signer = ChainedOperatorKey(
            name=operator_key.name,
            private_key=None,
            public_key=operator_key.public_key,
            chain=self,
        )

    @classmethod
    def open(
        cls,
        directory: Path | str,
        operator_key: OperatorKey,
        chain_id: str | None = None,
    ) -> ReceiptChain:
        """Open (or create) a persistent chain in `directory`."""
        return cls(operator_key, chain_id, directory=directory)

    # -- persistence -------------------------------------------------------

    def _open_directory(self, directory: Path, chain_id: str | None) -> str:
        directory.mkdir(parents=True, exist_ok=True)
        self._lock_fh = open(directory / _LOCK_FILE, "a+b")
        try:
            import fcntl

            fcntl.flock(self._lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:  # pragma: no cover - non-POSIX
            pass
        except OSError:
            self._lock_fh.close()
            raise ChainError(f"chain at {directory} is open in another process")

        header_path = directory / _HEADER_FILE
        self._header_path = header_path
        public_hex = self._key.public_key_hex
        hashes_path = directory / _HASHES_FILE
        existing_count = (
            hashes_path.stat().st_size // 32 if hashes_path.exists() else 0
        )
        if header_path.exists():
            try:
                header = json.loads(header_path.read_text("utf-8"))
            except (OSError, ValueError) as exc:
                self._release()
                raise ChainError(f"chain header unreadable: {exc}") from None
            if not isinstance(header, dict) or header.get("chain_version") != CHAIN_VERSION:
                self._release()
                raise ChainError("chain header is invalid")
            pending = header.get("pending_rotation")
            if isinstance(pending, dict):
                # A rotation was in flight when the process stopped. It
                # committed iff its receipt hash reached the hash file.
                if existing_count >= pending.get("seq", 0):
                    header["key_history"] = header.get("key_history", []) + [
                        header["operator_public_key"]
                    ]
                    header["operator_public_key"] = pending.get("next_public_key")
                del header["pending_rotation"]
            if header.get("operator_public_key") != public_hex:
                self._release()
                raise ChainError("chain header does not match this operator key")
            existing = _check_chain_id(header.get("chain_id"))
            if chain_id is not None and chain_id != existing:
                self._release()
                raise ChainError(
                    f"directory holds chain {existing!r}, not {chain_id!r}"
                )
            chain_id = existing
        else:
            chain_id = _check_chain_id(chain_id or secrets.token_hex(16))
            header = {
                "chain_id": chain_id,
                "chain_version": CHAIN_VERSION,
                "key_history": [],
                "operator_public_key": public_hex,
            }
        self._header = header
        self._write_header()

        self._hashes_fh = open(hashes_path, "a+b")
        self._hashes_fh.seek(0)
        data = self._hashes_fh.read()
        whole = len(data) - len(data) % 32
        if whole != len(data):
            # A crash mid-append left a partial record. That append never
            # returned a receipt to the caller, so dropping it is safe.
            self._hashes_fh.truncate(whole)
            data = data[:whole]
        self._digests = [data[i : i + 32] for i in range(0, whole, 32)]
        self._leaves = [_hash_leaf(d) for d in self._digests]
        self._dir = directory
        return chain_id

    def _write_header(self) -> None:
        if self._header_path is None:
            return
        tmp = self._header_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self._header, sort_keys=True, indent=2))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._header_path)

    def _persist(self, digest: bytes) -> None:
        if self._hashes_fh is None:
            return
        self._hashes_fh.write(digest)
        self._hashes_fh.flush()
        os.fsync(self._hashes_fh.fileno())

    def _release(self) -> None:
        for fh in (self._hashes_fh, self._lock_fh):
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass
        self._hashes_fh = None
        self._lock_fh = None

    def close(self) -> None:
        """Release the directory lock. Further signing raises ChainError."""
        with self._lock:
            self._closed = True
            self._release()

    def __enter__(self) -> ReceiptChain:
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.close()
        return False

    # -- appending ---------------------------------------------------------

    def _append(
        self,
        execution: dict[str, Any],
        provenance: dict[str, Any],
        attested_at: str,
        *,
        _next_key: OperatorKey | None = None,
    ) -> Receipt:
        receipt_type = execution.get("receipt_type")
        allowed = {ROTATION_TYPE} if _next_key is not None else CHAINABLE_RECEIPT_TYPES
        if receipt_type not in allowed:
            raise ChainError(f"receipt_type {receipt_type!r} is not chainable")
        clash = CHAIN_FIELDS.intersection(execution)
        if clash:
            raise ChainError(f"execution already has chain fields: {sorted(clash)}")
        with self._lock:
            if self._closed:
                raise ChainError("chain is closed")
            seq = len(self._digests) + 1
            body = dict(execution)
            body.update(
                {
                    "chain_version": CHAIN_VERSION,
                    "chain_id": self.chain_id,
                    "chain_seq": seq,
                    "chain_prev_hash": (
                        GENESIS if seq == 1 else _fmt(self._digests[-1])
                    ),
                    "chained_at": attested_at,
                }
            )
            if _next_key is not None:
                body["next_key_acceptance"] = _next_key.sign(
                    _acceptance_message(body)
                ).hex()
                self._header["pending_rotation"] = {
                    "next_public_key": _next_key.public_key_hex,
                    "seq": seq,
                }
                self._write_header()
            receipt = _sign_unchained(body, provenance, self._key, attested_at)
            digest = bytes.fromhex(receipt.receipt_hash[7:])
            self._persist(digest)
            self._digests.append(digest)
            self._leaves.append(_hash_leaf(digest))
            if _next_key is not None:
                self._header.pop("pending_rotation", None)
                self._header["key_history"] = self._header.get("key_history", []) + [
                    self._key.public_key_hex
                ]
                self._header["operator_public_key"] = _next_key.public_key_hex
                self._write_header()
                self._key = _next_key
                self.signer.name = _next_key.name
                self.signer.public_key = _next_key.public_key
            return receipt

    def rotate_key(
        self,
        new_key: OperatorKey,
        *,
        reason: str = "scheduled",
        compromised_after_seq: int | None = None,
    ) -> Receipt:
        """Hand the chain over to `new_key`. Returns the rotation receipt.

        The rotation is itself chained: signed by the current key, carrying
        the new public key and the new key's signature accepting this exact
        position in this chain. Every later receipt is signed by `new_key`;
        `chain.signer` switches automatically.

        reason="compromise" with compromised_after_seq=X declares that
        receipts X+1 .. (this rotation - 1), signed by the old key, must not
        be trusted. Verifiers list them in report["compromised_seqs"]. Note
        that a rotation is signed by the old key, so it is only as trustworthy
        as the checkpoints that pin the chain before the compromise.
        """
        if isinstance(new_key, ChainedOperatorKey):
            raise ChainError("pass the base OperatorKey, not a chained signer")
        if new_key.public_key_hex == self._key.public_key_hex:
            raise ChainError("new key is the current key")
        if reason not in ROTATION_REASONS:
            raise ChainError(f"reason must be one of {sorted(ROTATION_REASONS)}")
        execution: dict[str, Any] = {
            "receipt_type": ROTATION_TYPE,
            "rotation_version": ROTATION_VERSION,
            "rotation_reason": reason,
            "previous_public_key": self._key.public_key_hex,
            "next_public_key": new_key.public_key_hex,
        }
        if compromised_after_seq is not None:
            if reason != "compromise":
                raise ChainError("compromised_after_seq requires reason='compromise'")
            if (
                isinstance(compromised_after_seq, bool)
                or not isinstance(compromised_after_seq, int)
                or not 0 <= compromised_after_seq <= self.size
            ):
                raise ChainError(f"compromised_after_seq must be between 0 and {self.size}")
            execution["previous_key_compromised_after_seq"] = compromised_after_seq
        provenance = {"provenance_version": "1.0", "provider_attestation": "none"}
        from traceseal_observe import _now_iso

        return self._append(execution, provenance, _now_iso(), _next_key=new_key)

    @property
    def operator_public_key(self) -> str:
        """Hex public key currently signing this chain."""
        return self._key.public_key_hex

    # -- state and proofs --------------------------------------------------

    @property
    def size(self) -> int:
        return len(self._digests)

    @property
    def head(self) -> str:
        """receipt_hash of the latest receipt, or "genesis" if empty."""
        with self._lock:
            return _fmt(self._digests[-1]) if self._digests else GENESIS

    @property
    def origin(self) -> str:
        return chain_origin(self._key.public_key_hex, self.chain_id)

    @property
    def verifier_key(self) -> str:
        return checkpoint_verifier_key(self._key.public_key_hex, self.chain_id)

    def _leaves_upto(self, size: int | None) -> list[bytes]:
        with self._lock:
            n = len(self._leaves) if size is None else size
            if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= len(self._leaves):
                raise ChainError(f"size must be between 1 and {len(self._leaves)}")
            return self._leaves[:n]

    def root(self, size: int | None = None) -> str:
        return _fmt(merkle_root(self._leaves_upto(size)))

    def checkpoint(self, size: int | None = None) -> str:
        """Sign a C2SP checkpoint over the first `size` receipts (default all).

        Format (c2sp.org/tlog-checkpoint, signed note):
            <origin>\\n<size>\\n<base64 root>\\n\\n— <origin> <base64 sig>\\n
        """
        leaves = self._leaves_upto(size)
        origin = self.origin
        body = (
            f"{origin}\n{len(leaves)}\n"
            f"{base64.b64encode(merkle_root(leaves)).decode('ascii')}\n"
        )
        key_hash = bytes.fromhex(self.verifier_key.split("+")[1])
        signature = self._key.sign(body.encode("utf-8"))
        line = base64.b64encode(key_hash + signature).decode("ascii")
        return f"{body}\n— {origin} {line}\n"

    def inclusion_proof(self, seq: int, size: int | None = None) -> list[str]:
        """Proof that receipt `seq` is in the tree of `size` receipts."""
        leaves = self._leaves_upto(size)
        if isinstance(seq, bool) or not isinstance(seq, int) or not 1 <= seq <= len(leaves):
            raise ChainError(f"seq must be between 1 and {len(leaves)}")
        return [_fmt(d) for d in _inclusion_path(seq - 1, leaves)]

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[str]:
        """Proof that the tree of `new_size` extends the tree of `old_size`."""
        leaves = self._leaves_upto(new_size)
        if isinstance(old_size, bool) or not isinstance(old_size, int) or not 1 <= old_size <= len(leaves):
            raise ChainError(f"old_size must be between 1 and {len(leaves)}")
        return [_fmt(d) for d in _subproof(old_size, leaves, True)]


# ---------------------------------------------------------------------------
# The verifier side
# ---------------------------------------------------------------------------


def verify_chain_checkpoint(
    note: str,
    operator_public_key_hex: str,
    chain_id: str,
    *,
    witness_vkeys: Iterable[str] = (),
) -> dict[str, Any]:
    """Verify an operator checkpoint and any required witness cosignatures.

    witness_vkeys are C2SP cosignature/v1 verifier keys (algorithm 0x04).
    Every listed witness must have a valid cosignature; unlisted signatures
    are ignored. Returns {origin, tree_size, root, witnesses:[{name, time}]}.
    Raises ChainError on any failure.
    """
    if not isinstance(note, str):
        raise ChainError("checkpoint must be text")
    origin = chain_origin(operator_public_key_hex, chain_id)
    try:
        body, signatures = _parse_note(note)
        lines = body.splitlines()
        if len(lines) != 3 or lines[0] != origin:
            raise ChainError("checkpoint origin does not match this chain")
        if not re.fullmatch(r"[1-9][0-9]{0,18}", lines[1]):
            raise ChainError("checkpoint tree size is invalid")
        tree_size = int(lines[1])
        root = base64.b64decode(lines[2], validate=True)
        if len(root) != 32:
            raise ChainError("checkpoint root is invalid")
        name, _alg, public_key, key_hash = _parse_verifier_key(
            checkpoint_verifier_key(operator_public_key_hex, chain_id)
        )
        signature = _matching_signature(signatures, name, key_hash, 68)
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature[4:], body.encode("utf-8")
            )
        except InvalidSignature:
            raise ChainError("checkpoint operator signature is invalid") from None
        witnesses = []
        for vkey in witness_vkeys:
            w_name, alg, w_key, w_hash = _parse_verifier_key(vkey)
            if alg != 4:
                raise ChainError(f"witness key {w_name} is not a cosignature/v1 key")
            cosig = _matching_signature(signatures, w_name, w_hash, 76)
            signed_time = struct.unpack(">Q", cosig[4:12])[0]
            message = f"cosignature/v1\ntime {signed_time}\n{body}".encode("utf-8")
            try:
                Ed25519PublicKey.from_public_bytes(w_key).verify(cosig[12:], message)
            except InvalidSignature:
                raise ChainError(f"witness {w_name} cosignature is invalid") from None
            witnesses.append({"name": w_name, "time": signed_time})
    except HistoryLogError as exc:
        raise ChainError(f"checkpoint is invalid: {exc}") from None
    except (ValueError, base64.binascii.Error) as exc:
        if isinstance(exc, ChainError):
            raise
        raise ChainError(f"checkpoint is invalid: {exc}") from None
    return {
        "origin": origin,
        "tree_size": tree_size,
        "root": _fmt(root),
        "witnesses": witnesses,
    }


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def _chain_fields(receipt: Receipt) -> tuple[str, int, str, datetime]:
    ex = receipt.execution
    if ex.get("chain_version") != CHAIN_VERSION:
        raise ChainError("not a chained receipt (chain_version missing or unknown)")
    if ex.get("receipt_type") not in _VERIFIABLE_TYPES:
        raise ChainError("receipt_type is not chainable")
    chain_id = _check_chain_id(ex.get("chain_id"))
    seq = ex.get("chain_seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ChainError("chain_seq is invalid")
    prev = ex.get("chain_prev_hash")
    if prev != GENESIS and (not isinstance(prev, str) or _SHA_RE.fullmatch(prev) is None):
        raise ChainError("chain_prev_hash is invalid")
    if (seq == 1) != (prev == GENESIS):
        raise ChainError("only chain_seq 1 may (and must) link to genesis")
    chained_at = _parse_time(ex.get("chained_at"))
    if chained_at is None:
        raise ChainError("chained_at is invalid")
    return chain_id, seq, prev, chained_at


def _check_rotation(receipt: Receipt) -> dict[str, Any]:
    """Validate a chain_key_rotation receipt; return its key handover."""
    ex = receipt.execution
    if ex.get("rotation_version") != ROTATION_VERSION:
        raise ChainError("unsupported rotation_version")
    previous, nxt = ex.get("previous_public_key"), ex.get("next_public_key")
    _check_public_key_hex(previous)
    next_bytes = _check_public_key_hex(nxt)
    if previous != str(receipt.attestation.get("operator_public_key", "")).lower():
        raise ChainError("rotation is not signed by the key it hands over from")
    if previous == nxt:
        raise ChainError("rotation does not change the key")
    reason = ex.get("rotation_reason")
    if reason not in ROTATION_REASONS:
        raise ChainError("rotation_reason is invalid")
    acceptance = ex.get("next_key_acceptance")
    if not isinstance(acceptance, str) or re.fullmatch(r"[0-9a-f]{128}", acceptance) is None:
        raise ChainError("next_key_acceptance is malformed")
    try:
        Ed25519PublicKey.from_public_bytes(next_bytes).verify(
            bytes.fromhex(acceptance), _acceptance_message(ex)
        )
    except (InvalidSignature, KeyError):
        raise ChainError("next key did not accept this rotation") from None
    compromised = ex.get("previous_key_compromised_after_seq")
    if compromised is not None:
        if (
            reason != "compromise"
            or isinstance(compromised, bool)
            or not isinstance(compromised, int)
            or not 0 <= compromised < ex["chain_seq"]
        ):
            raise ChainError("previous_key_compromised_after_seq is invalid")
    return {
        "seq": ex["chain_seq"],
        "previous_public_key": previous,
        "next_public_key": nxt,
        "reason": reason,
        "compromised_after_seq": compromised,
    }


def _fingerprint_of(public_hex: str) -> str | None:
    try:
        return public_key_fingerprint(
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        )
    except (ValueError, TypeError):
        return None


def _verify_timestamps(tokens, note, anchors, label, errors) -> list[dict[str, Any]]:
    tokens = list(tokens or ())
    if not tokens:
        return []
    if not anchors:
        errors.append(f"{label}: timestamps supplied without tsa_trust_anchors")
        return []
    from traceseal_observe.timestamp import (
        TimestampError,
        checkpoint_body,
        verify_timestamp_token,
    )

    verified = []
    for index, token in enumerate(tokens):
        try:
            verified.append(
                verify_timestamp_token(
                    token, data=checkpoint_body(note), trust_anchors=anchors
                )
            )
        except TimestampError as exc:
            errors.append(f"{label}: timestamp[{index}]: {exc}")
    return verified


def _resolve_checkpoint(note, known_keys, chain_id, witness_vkeys):
    """Verify `note` with whichever known chain key its origin names."""
    if not isinstance(note, str) or "\n" not in note:
        raise ChainError("checkpoint must be a signed note")
    origin = note.split("\n", 1)[0]
    for public_hex in known_keys:
        if chain_origin(public_hex, chain_id) == origin:
            info = verify_chain_checkpoint(
                note, public_hex, chain_id, witness_vkeys=witness_vkeys
            )
            info["signed_by"] = public_hex
            return info
    raise ChainError("checkpoint is not signed by any key of this chain")


def verify_chain(
    receipts: list[Receipt],
    *,
    chain_id: str | None = None,
    operator_public_key: str | None = None,
    checkpoint: str | None = None,
    inclusion_proof: list[str] | None = None,
    witness_vkeys: Iterable[str] = (),
    checkpoint_timestamps: Iterable[bytes] = (),
    tsa_trust_anchors: Iterable[Any] = (),
    start_checkpoint: str | None = None,
    start_checkpoint_timestamps: Iterable[bytes] = (),
    start_consistency_proof: list[str] | None = None,
    window: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Verify a set of chained receipts. Never raises on bad input.

    Checks every signature, that all receipts belong to one chain, that hash
    links are intact, that the signing key only changes through valid
    rotation receipts, and reports gaps and forks.

      operator_public_key — the key you already trust. The first supplied
                         receipt must be signed by it; later keys are
                         accepted only through rotations.
      checkpoint       — a signed checkpoint. If the receipts are the whole
                         chain 1..N, the Merkle root is recomputed and must
                         match. Otherwise pass `inclusion_proof` for the
                         highest receipt seq <= N; its hash links anchor
                         every earlier receipt in the segment.
      witness_vkeys    — C2SP witnesses whose cosignatures every supplied
                         checkpoint must carry.
      checkpoint_timestamps, tsa_trust_anchors
                       — RFC 3161 tokens over the checkpoint body, verified
                         against these TSA roots (x509.Certificate list).
      start_checkpoint, start_checkpoint_timestamps, start_consistency_proof
                       — an earlier checkpoint with trusted time (TSA token
                         or witness cosignature) at or before the window
                         start, plus a consistency proof to `checkpoint`.
                         Proves, independent of the operator's clock, that
                         nothing created after the window opened precedes
                         the supplied segment.
      window           — (start, end) UTC "YYYY-MM-DDTHH:MM:SSZ". See
                         report["window"]["start_basis"/"end_basis"].

    Returns a report dict; report["ok"] is True only if there are no errors
    and no gaps.
    """
    report: dict[str, Any] = {
        "ok": False,
        "chain_id": None,
        "operator_public_key": None,
        "operator_fingerprint": None,
        "operator_keys": [],
        "head_public_key": None,
        "rotations": [],
        "compromised_seqs": [],
        "count": 0,
        "first_seq": None,
        "last_seq": None,
        "starts_at_genesis": False,
        "head_hash": None,
        "gaps": [],
        "forks": [],
        "errors": [],
        "warnings": [],
        "checkpoint": None,
        "start_checkpoint": None,
        "window": None,
    }
    errors: list[str] = report["errors"]
    warnings: list[str] = report["warnings"]
    if not isinstance(receipts, list) or not receipts:
        errors.append("no receipts supplied")
        return report

    # -- pass 1: each receipt on its own ----------------------------------
    by_seq: dict[int, tuple[Receipt, str, str, datetime]] = {}
    for index, receipt in enumerate(receipts):
        label = f"receipt[{index}]"
        if not isinstance(receipt, Receipt):
            errors.append(f"{label}: not a Receipt")
            continue
        try:
            verify_receipt_signature(receipt, label)
            this_chain, seq, prev, chained_at = _chain_fields(receipt)
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
            continue
        label = f"seq {seq}"
        if report["chain_id"] is None:
            report["chain_id"] = this_chain
        if this_chain != report["chain_id"]:
            errors.append(f"{label}: belongs to chain {this_chain!r}, not {report['chain_id']!r}")
            continue
        digest = receipt.receipt_hash
        if seq in by_seq:
            if by_seq[seq][1] != digest:
                report["forks"].append(seq)
                errors.append(f"{label}: two different receipts claim this position (fork)")
            else:
                warnings.append(f"{label}: duplicate copy ignored")
            continue
        by_seq[seq] = (receipt, digest, prev, chained_at)

    if chain_id is not None and report["chain_id"] not in (None, chain_id):
        errors.append(f"receipts are for chain {report['chain_id']!r}, expected {chain_id!r}")
    if not by_seq:
        return report

    # -- pass 2: order, links, keys ---------------------------------------
    seqs = sorted(by_seq)
    report["count"] = len(seqs)
    report["first_seq"], report["last_seq"] = seqs[0], seqs[-1]
    report["starts_at_genesis"] = seqs[0] == 1
    report["head_hash"] = by_seq[seqs[-1]][1]

    def signer_of(s: int) -> str:
        # Hex is case-insensitive: compare keys in one canonical form so an
        # equivalent encoding is not mistaken for a key change.
        return by_seq[s][0].attestation["operator_public_key"].lower()

    root_key = signer_of(seqs[0])
    report["operator_public_key"] = root_key
    report["operator_fingerprint"] = _fingerprint_of(root_key)
    if operator_public_key is not None and root_key != operator_public_key:
        errors.append("the first receipt is not signed by the expected operator key")

    keys: list[dict[str, Any]] = []
    known_keys: list[str] = []
    compromised_keys: dict[str, int] = {}

    def note_key(public_hex: str, s: int) -> None:
        if keys and keys[-1]["public_key"] == public_hex:
            keys[-1]["last_seq"] = s
            return
        keys.append({
            "public_key": public_hex,
            "fingerprint": _fingerprint_of(public_hex),
            "first_seq": s,
            "last_seq": s,
        })
        if public_hex not in known_keys:
            known_keys.append(public_hex)

    expected_key = root_key
    for index, s in enumerate(seqs):
        receipt = by_seq[s][0]
        signer = signer_of(s)
        if index:
            before = seqs[index - 1]
            if s != before + 1:
                report["gaps"].append([before + 1, s - 1])
                if signer != expected_key:
                    warnings.append(
                        f"seq {s}: operator key changed inside the gap before it; "
                        "the rotation cannot be checked"
                    )
            else:
                if by_seq[s][2] != by_seq[before][1]:
                    errors.append(f"seq {s}: chain_prev_hash does not match seq {before}")
                if signer != expected_key:
                    errors.append(
                        f"seq {s}: signed by {_fingerprint_of(signer)}, but the chain "
                        f"key at this point is {_fingerprint_of(expected_key)}"
                    )
                if by_seq[s][3] < by_seq[before][3]:
                    warnings.append(
                        f"seq {s}: chained_at is earlier than seq {before} (clock went backwards)"
                    )
        note_key(signer, s)
        expected_key = signer
        if receipt.execution.get("receipt_type") == ROTATION_TYPE:
            try:
                rotation = _check_rotation(receipt)
            except ChainError as exc:
                errors.append(f"seq {s}: {exc}")
                continue
            report["rotations"].append(rotation)
            expected_key = rotation["next_public_key"]
            if expected_key not in known_keys:
                known_keys.append(expected_key)
            if rotation["compromised_after_seq"] is not None:
                compromised_keys[rotation["previous_public_key"]] = rotation[
                    "compromised_after_seq"
                ]
                first_bad = rotation["compromised_after_seq"] + 1
                if first_bad <= s - 1:
                    report["compromised_seqs"].append([first_bad, s - 1])
                    warnings.append(
                        f"seq {first_bad}..{s - 1}: signed by a key the operator "
                        "declared compromised; do not rely on these receipts"
                    )
    report["operator_keys"] = keys
    report["head_public_key"] = expected_key

    # -- checkpoint ----------------------------------------------------------
    anchors = list(tsa_trust_anchors or ())
    cp_info = None
    cp_times: list[int] = []
    if checkpoint is not None:
        cp_report: dict[str, Any] = {"verified": False}
        report["checkpoint"] = cp_report
        try:
            cp_info = _resolve_checkpoint(
                checkpoint, known_keys, report["chain_id"], witness_vkeys
            )
        except ChainError as exc:
            errors.append(f"checkpoint: {exc}")
        else:
            size = cp_info["tree_size"]
            stamps = _verify_timestamps(
                checkpoint_timestamps, checkpoint, anchors, "checkpoint", errors
            )
            cp_times = [w["time"] for w in cp_info["witnesses"]] + [
                t["gen_time_unix"] for t in stamps
            ]
            cp_report.update(
                verified=True,
                tree_size=size,
                root=cp_info["root"],
                signed_by=_fingerprint_of(cp_info["signed_by"]),
                witnesses=cp_info["witnesses"],
                timestamps=stamps,
                anchored=False,
                receipts_after_segment=max(0, size - seqs[-1]),
            )
            bad_after = compromised_keys.get(cp_info["signed_by"])
            if bad_after is not None and size > bad_after:
                warnings.append(
                    "checkpoint is signed by a key declared compromised after "
                    f"seq {bad_after}"
                )
            whole = seqs[0] == 1 and seqs[-1] >= size and not report["gaps"]
            if whole:
                leaves = [receipt_leaf_hash(by_seq[s][1]) for s in range(1, size + 1)]
                if _fmt(merkle_root(leaves)) == cp_info["root"]:
                    cp_report["anchored"] = True
                    cp_report["method"] = "root_recomputed"
                else:
                    errors.append(
                        "checkpoint: root differs from these receipts "
                        "(the checkpointed chain is a different history)"
                    )
            else:
                covered = [s for s in seqs if s <= size]
                if not covered:
                    errors.append("checkpoint: no supplied receipt is within the checkpoint")
                elif inclusion_proof is None:
                    if report["gaps"]:
                        # Missing receipts already fail the report; asking
                        # for a proof would point at the wrong problem.
                        cp_report["reason"] = "receipts missing; root not recomputable"
                    else:
                        errors.append(
                            "checkpoint: receipts are a partial segment; an inclusion "
                            f"proof for seq {covered[-1]} is required"
                        )
                elif verify_inclusion(
                    by_seq[covered[-1]][1],
                    covered[-1],
                    size,
                    cp_info["root"],
                    inclusion_proof,
                ):
                    cp_report["anchored"] = True
                    cp_report["method"] = "inclusion_proof"
                    cp_report["anchor_seq"] = covered[-1]
                else:
                    errors.append(f"checkpoint: inclusion proof for seq {covered[-1]} is invalid")
            if seqs[-1] > size:
                warnings.append(
                    f"receipts after seq {size} are not covered by the checkpoint"
                )
            if cp_report["anchored"] and cp_times:
                latest_trusted = max(cp_times)
                for s in seqs:
                    if s <= size and by_seq[s][3].timestamp() > latest_trusted:
                        warnings.append(
                            f"seq {s}: chained_at is later than a trusted time that "
                            "already covers it (signer clock ahead?)"
                        )
                        break
    elif list(checkpoint_timestamps or ()):
        errors.append("checkpoint_timestamps given without a checkpoint")

    # -- start checkpoint ----------------------------------------------------
    start_info = None
    start_times: list[int] = []
    if start_checkpoint is not None:
        sc_report: dict[str, Any] = {"verified": False}
        report["start_checkpoint"] = sc_report
        try:
            start_info = _resolve_checkpoint(
                start_checkpoint, known_keys, report["chain_id"], witness_vkeys
            )
        except ChainError as exc:
            errors.append(f"start_checkpoint: {exc}")
        else:
            stamps = _verify_timestamps(
                start_checkpoint_timestamps, start_checkpoint, anchors,
                "start_checkpoint", errors,
            )
            start_times = [w["time"] for w in start_info["witnesses"]] + [
                t["gen_time_unix"] for t in stamps
            ]
            consistent = False
            if cp_info is None or not report["checkpoint"].get("anchored"):
                errors.append("start_checkpoint: needs an anchored `checkpoint` to link to")
            elif start_info["tree_size"] > cp_info["tree_size"]:
                errors.append("start_checkpoint: is larger than `checkpoint`")
            elif start_info["tree_size"] == cp_info["tree_size"]:
                consistent = start_info["root"] == cp_info["root"]
            elif start_consistency_proof is not None:
                consistent = verify_consistency(
                    start_info["tree_size"], cp_info["tree_size"],
                    start_info["root"], cp_info["root"], start_consistency_proof,
                )
            else:
                errors.append("start_checkpoint: start_consistency_proof is required")
            if not consistent and not any(e.startswith("start_checkpoint") for e in errors):
                errors.append("start_checkpoint: not consistent with `checkpoint`")
            sc_report.update(
                verified=True,
                tree_size=start_info["tree_size"],
                consistent=consistent,
                witnesses=start_info["witnesses"],
                timestamps=stamps,
            )

    # -- window --------------------------------------------------------------
    if window is not None:
        start, end = (_parse_time(window[0]), _parse_time(window[1])) if (
            isinstance(window, (tuple, list)) and len(window) == 2
        ) else (None, None)
        if start is None or end is None or start > end:
            errors.append("window must be (start, end) UTC seconds with start <= end")
        else:
            first_t = by_seq[seqs[0]][3]
            last_t = by_seq[seqs[-1]][3]
            # Start edge: everything created at/after `start` has seq >= first.
            if report["starts_at_genesis"]:
                start_basis = "genesis"
            elif (
                start_info is not None
                and report["start_checkpoint"].get("consistent")
                and start_info["tree_size"] >= seqs[0] - 1
                and any(t <= start.timestamp() for t in start_times)
            ):
                start_basis = "trusted_time"
            elif first_t < start:
                start_basis = "signer_clock"
            else:
                start_basis = None
            # End edge: everything created by `end` has seq <= last.
            if (
                cp_info is not None
                and report["checkpoint"].get("anchored")
                and seqs[-1] == cp_info["tree_size"]
                and any(t >= end.timestamp() for t in cp_times)
            ):
                end_basis = "published_checkpoint"
            elif last_t > end:
                end_basis = "signer_clock"
            else:
                end_basis = None
            report["window"] = {
                "start": window[0],
                "end": window[1],
                "complete": bool(
                    start_basis and end_basis and not report["gaps"] and not errors
                ),
                "covers_start": start_basis is not None,
                "covers_end": end_basis is not None,
                "start_basis": start_basis,
                "end_basis": end_basis,
                "receipts_in_window": sum(
                    1 for s in seqs if start <= by_seq[s][3] <= end
                ),
                "compromised_in_window": any(
                    lo <= s <= hi and start <= by_seq[s][3] <= end
                    for lo, hi in report["compromised_seqs"]
                    for s in seqs
                ),
            }

    report["ok"] = not errors and not report["gaps"]
    return report


def load_receipt(path: Path | str) -> Receipt:
    """Load a receipt JSON file into a Receipt (structure only, not verified)."""
    data = json.loads(Path(path).read_text("utf-8"))
    if not isinstance(data, dict):
        raise ChainError(f"{path}: not a JSON object")
    try:
        return Receipt(
            receipt_version=data["receipt_version"],
            execution=data["execution"],
            provenance=data["provenance"],
            attestation=data["attestation"],
        )
    except KeyError as exc:
        raise ChainError(f"{path}: missing {exc}") from None


# ---------------------------------------------------------------------------
# CLI: traceseal-chain verify
# ---------------------------------------------------------------------------


def _read_json(path: str | None) -> Any:
    return json.loads(Path(path).read_text("utf-8")) if path else None


def _read_text(path: str | None) -> str | None:
    return Path(path).read_text("utf-8") if path else None


def _read_certs(paths: list[str]) -> list[Any]:
    from traceseal_observe.timestamp import load_certificates

    certs: list[Any] = []
    for path in paths:
        certs.extend(load_certificates(Path(path).read_bytes()))
    return certs


def _print_report(report: dict[str, Any], passed: bool) -> None:
    status = "OK" if passed else "FAIL"
    print(f"[{status}] chain {report['chain_id']}  operator {report['operator_fingerprint']}")
    print(f"  receipts: {report['count']}  seq {report['first_seq']}..{report['last_seq']}"
          f"  from genesis: {report['starts_at_genesis']}")
    for rotation in report.get("rotations", []):
        print(f"  key rotation at seq {rotation['seq']} ({rotation['reason']}) -> "
              f"{_fingerprint_of(rotation['next_public_key'])}")
    for lo, hi in report.get("compromised_seqs", []):
        print(f"  COMPROMISED: seq {lo}..{hi} signed by a key declared compromised")
    for gap in report["gaps"]:
        print(f"  GAP: seq {gap[0]}..{gap[1]} missing")
    for error in report["errors"]:
        print(f"  ERROR: {error}")
    for warning in report["warnings"]:
        print(f"  warning: {warning}")
    for label in ("checkpoint", "start_checkpoint"):
        cp = report.get(label)
        if cp:
            times = [t["gen_time"] for t in cp.get("timestamps", [])]
            print(f"  {label}: verified={cp['verified']} size={cp.get('tree_size')}"
                  + (f" anchored={cp.get('anchored')}" if label == "checkpoint" else
                     f" consistent={cp.get('consistent')}")
                  + f" witnesses={len(cp.get('witnesses', []))}"
                  + (f" tsa={','.join(times)}" if times else ""))
    if report["window"]:
        w = report["window"]
        print(f"  window {w['start']}..{w['end']}: complete={w['complete']}"
              f" start={w['start_basis']} end={w['end_basis']}"
              f" receipts={w['receipts_in_window']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="traceseal-chain",
        description="Verify completeness of a chain of TraceSeal receipts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify chained receipts")
    v.add_argument("receipts", nargs="+", help="receipt JSON files")
    v.add_argument("--chain-id")
    v.add_argument("--operator-public-key", help="key you already trust (64 hex)")
    v.add_argument("--checkpoint", help="checkpoint note file")
    v.add_argument("--inclusion-proof", help="JSON list of sha256:<hex>")
    v.add_argument("--witness-vkey", action="append", default=[])
    v.add_argument("--checkpoint-timestamp", action="append", default=[],
                   help="RFC 3161 token (DER) over --checkpoint")
    v.add_argument("--tsa-root", action="append", default=[],
                   help="trusted TSA root certificate(s), PEM or DER")
    v.add_argument("--start-checkpoint", help="earlier checkpoint note file")
    v.add_argument("--start-timestamp", action="append", default=[],
                   help="RFC 3161 token (DER) over --start-checkpoint")
    v.add_argument("--start-consistency-proof", help="JSON list of sha256:<hex>")
    v.add_argument("--window-start")
    v.add_argument("--window-end")
    v.add_argument("--json", action="store_true", help="print the full report")

    t = sub.add_parser("timestamp", help="get an RFC 3161 token for a checkpoint")
    t.add_argument("--checkpoint", required=True)
    t.add_argument("--tsa-url", required=True)
    t.add_argument("--output", required=True)

    tv = sub.add_parser("timestamp-verify", help="verify an RFC 3161 token over a checkpoint")
    tv.add_argument("--checkpoint", required=True)
    tv.add_argument("--timestamp", required=True)
    tv.add_argument("--tsa-root", action="append", required=True)
    tv.add_argument("--tsa-cert", action="append", default=[],
                    help="intermediate or TSA certificate not included in the token")
    args = parser.parse_args(argv)

    if args.command in ("timestamp", "timestamp-verify"):
        from traceseal_observe.timestamp import (
            TimestampError,
            checkpoint_body,
            timestamp_checkpoint,
            verify_timestamp_token,
        )

        try:
            note = Path(args.checkpoint).read_text("utf-8")
            if args.command == "timestamp":
                token = timestamp_checkpoint(note, args.tsa_url)
                Path(args.output).write_bytes(token)
                print(f"[OK] wrote {args.output} (verify it before relying on it)")
                return 0
            info = verify_timestamp_token(
                Path(args.timestamp).read_bytes(),
                data=checkpoint_body(note),
                trust_anchors=_read_certs(args.tsa_root),
                intermediates=_read_certs(args.tsa_cert),
            )
        except (OSError, ValueError) as exc:
            label = "FAIL" if isinstance(exc, TimestampError) else "ERROR"
            print(f"[{label}] {exc}", file=sys.stderr)
            return 1
        print(f"[OK] checkpoint existed by {info['gen_time']} (TSA {info['tsa_subject']},"
              f" policy {info['policy']}, ETSI qualified statement:"
              f" {info['etsi_qualified_statement']})")
        return 0

    try:
        receipts = [load_receipt(p) for p in args.receipts]
        checkpoint = _read_text(args.checkpoint)
        start_checkpoint = _read_text(args.start_checkpoint)
        proof = _read_json(args.inclusion_proof)
        start_proof = _read_json(args.start_consistency_proof)
        cp_tokens = [Path(p).read_bytes() for p in args.checkpoint_timestamp]
        start_tokens = [Path(p).read_bytes() for p in args.start_timestamp]
        roots = _read_certs(args.tsa_root)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    window = None
    if args.window_start or args.window_end:
        window = (args.window_start or "", args.window_end or "")
    report = verify_chain(
        receipts,
        chain_id=args.chain_id,
        operator_public_key=args.operator_public_key,
        checkpoint=checkpoint,
        inclusion_proof=proof,
        witness_vkeys=args.witness_vkey,
        checkpoint_timestamps=cp_tokens,
        tsa_trust_anchors=roots,
        start_checkpoint=start_checkpoint,
        start_checkpoint_timestamps=start_tokens,
        start_consistency_proof=start_proof,
        window=window,
    )
    passed = report["ok"] and (window is None or report["window"]["complete"])
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_report(report, passed)
    return 0 if passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
