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
        self._hashes_fh: Any = None
        self._lock_fh: Any = None
        self._closed = False
        if directory is not None:
            self.chain_id = self._open_directory(Path(directory), chain_id)
        else:
            self.chain_id = _check_chain_id(chain_id or secrets.token_hex(16))
        self.signer = ChainedOperatorKey(
            name=operator_key.name,
            private_key=operator_key.private_key,
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
        public_hex = self._key.public_key_hex
        if header_path.exists():
            try:
                header = json.loads(header_path.read_text("utf-8"))
            except (OSError, ValueError) as exc:
                self._release()
                raise ChainError(f"chain header unreadable: {exc}") from None
            if (
                not isinstance(header, dict)
                or header.get("chain_version") != CHAIN_VERSION
                or header.get("operator_public_key") != public_hex
            ):
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
                "operator_public_key": public_hex,
            }
            tmp = header_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(header, sort_keys=True, indent=2), "utf-8")
            os.replace(tmp, header_path)

        hashes_path = directory / _HASHES_FILE
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
        self, execution: dict[str, Any], provenance: dict[str, Any], attested_at: str
    ) -> Receipt:
        receipt_type = execution.get("receipt_type")
        if receipt_type not in CHAINABLE_RECEIPT_TYPES:
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
            receipt = _sign_unchained(body, provenance, self._key, attested_at)
            digest = bytes.fromhex(receipt.receipt_hash[7:])
            self._persist(digest)
            self._digests.append(digest)
            self._leaves.append(_hash_leaf(digest))
            return receipt

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
    if ex.get("receipt_type") not in CHAINABLE_RECEIPT_TYPES:
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


def verify_chain(
    receipts: list[Receipt],
    *,
    chain_id: str | None = None,
    operator_public_key: str | None = None,
    checkpoint: str | None = None,
    inclusion_proof: list[str] | None = None,
    witness_vkeys: Iterable[str] = (),
    window: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Verify a set of chained receipts. Never raises on bad input.

    Checks every signature, that all receipts belong to one chain and one
    key, that hash links are intact, and reports gaps and forks. Optionally:

      checkpoint       — a signed checkpoint. If the receipts are the whole
                         chain 1..N, the Merkle root is recomputed and must
                         match. Otherwise pass `inclusion_proof` for the
                         highest receipt seq <= N; its hash links anchor
                         every earlier receipt in the segment.
      witness_vkeys    — witnesses whose cosignatures the checkpoint must carry.
      window           — (start, end) UTC "YYYY-MM-DDTHH:MM:SSZ". Reports
                         whether the segment provably covers the window: it
                         starts at genesis or before `start`, and ends after
                         `end` or at a checkpoint head cosigned at/after `end`.

    Returns a report dict; report["ok"] is True only if there are no errors
    and no gaps. Read report["errors"], ["gaps"], ["forks"], ["warnings"].
    """
    report: dict[str, Any] = {
        "ok": False,
        "chain_id": None,
        "operator_public_key": None,
        "operator_fingerprint": None,
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
        "window": None,
    }
    errors: list[str] = report["errors"]
    if not isinstance(receipts, list) or not receipts:
        errors.append("no receipts supplied")
        return report

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
        public_hex = receipt.attestation.get("operator_public_key")
        if report["chain_id"] is None:
            report["chain_id"] = this_chain
            report["operator_public_key"] = public_hex
        if this_chain != report["chain_id"]:
            errors.append(f"{label}: belongs to chain {this_chain!r}, not {report['chain_id']!r}")
            continue
        if public_hex != report["operator_public_key"]:
            errors.append(f"{label}: signed by a different operator key")
            continue
        digest = receipt.receipt_hash
        if seq in by_seq:
            if by_seq[seq][1] != digest:
                report["forks"].append(seq)
                errors.append(f"{label}: two different receipts claim this position (fork)")
            else:
                report["warnings"].append(f"{label}: duplicate copy ignored")
            continue
        by_seq[seq] = (receipt, digest, prev, chained_at)

    if chain_id is not None and report["chain_id"] not in (None, chain_id):
        errors.append(f"receipts are for chain {report['chain_id']!r}, expected {chain_id!r}")
    if operator_public_key is not None and report["operator_public_key"] not in (
        None,
        operator_public_key,
    ):
        errors.append("receipts are signed by a different operator key than expected")
    if not by_seq:
        return report

    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(report["operator_public_key"]))
        report["operator_fingerprint"] = public_key_fingerprint(pk)
    except ValueError:
        pass

    seqs = sorted(by_seq)
    report["count"] = len(seqs)
    report["first_seq"], report["last_seq"] = seqs[0], seqs[-1]
    report["starts_at_genesis"] = seqs[0] == 1
    report["head_hash"] = by_seq[seqs[-1]][1]
    for before, after in zip(seqs, seqs[1:]):
        if after != before + 1:
            report["gaps"].append([before + 1, after - 1])
            continue
        if by_seq[after][2] != by_seq[before][1]:
            errors.append(f"seq {after}: chain_prev_hash does not match seq {before}")
        if by_seq[after][3] < by_seq[before][3]:
            report["warnings"].append(
                f"seq {after}: chained_at is earlier than seq {before} (clock went backwards)"
            )

    cp_info = None
    if checkpoint is not None:
        cp_report: dict[str, Any] = {"verified": False}
        report["checkpoint"] = cp_report
        try:
            cp_info = verify_chain_checkpoint(
                checkpoint,
                report["operator_public_key"],
                report["chain_id"],
                witness_vkeys=witness_vkeys,
            )
        except ChainError as exc:
            errors.append(f"checkpoint: {exc}")
        else:
            size = cp_info["tree_size"]
            cp_report.update(
                verified=True,
                tree_size=size,
                root=cp_info["root"],
                witnesses=cp_info["witnesses"],
                anchored=False,
                receipts_after_segment=max(0, size - seqs[-1]),
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
                report["warnings"].append(
                    f"receipts after seq {size} are not covered by the checkpoint"
                )

    if window is not None:
        start, end = (_parse_time(window[0]), _parse_time(window[1])) if (
            isinstance(window, (tuple, list)) and len(window) == 2
        ) else (None, None)
        if start is None or end is None or start > end:
            errors.append("window must be (start, end) UTC seconds with start <= end")
        else:
            first_t = by_seq[seqs[0]][3]
            last_t = by_seq[seqs[-1]][3]
            left = report["starts_at_genesis"] or first_t < start
            right = last_t > end
            if (
                not right
                and cp_info is not None
                and report["checkpoint"].get("anchored")
                and seqs[-1] == cp_info["tree_size"]
            ):
                right = any(w["time"] >= end.timestamp() for w in cp_info["witnesses"])
            report["window"] = {
                "start": window[0],
                "end": window[1],
                "complete": bool(left and right and not report["gaps"] and not errors),
                "covers_start": bool(left),
                "covers_end": bool(right),
                "receipts_in_window": sum(
                    1 for s in seqs if start <= by_seq[s][3] <= end
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="traceseal-chain",
        description="Verify completeness of a chain of TraceSeal receipts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify chained receipts")
    v.add_argument("receipts", nargs="+", help="receipt JSON files")
    v.add_argument("--chain-id")
    v.add_argument("--operator-public-key", help="expected key (64 hex)")
    v.add_argument("--checkpoint", help="checkpoint note file")
    v.add_argument("--inclusion-proof", help="JSON list of sha256:<hex>")
    v.add_argument("--witness-vkey", action="append", default=[])
    v.add_argument("--window-start")
    v.add_argument("--window-end")
    v.add_argument("--json", action="store_true", help="print the full report")
    args = parser.parse_args(argv)

    try:
        receipts = [load_receipt(p) for p in args.receipts]
        checkpoint = (
            Path(args.checkpoint).read_text("utf-8") if args.checkpoint else None
        )
        proof = (
            json.loads(Path(args.inclusion_proof).read_text("utf-8"))
            if args.inclusion_proof
            else None
        )
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
        window=window,
    )
    passed = report["ok"] and (window is None or report["window"]["complete"])
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        status = "OK" if passed else "FAIL"
        print(f"[{status}] chain {report['chain_id']}  operator {report['operator_fingerprint']}")
        print(f"  receipts: {report['count']}  seq {report['first_seq']}..{report['last_seq']}"
              f"  from genesis: {report['starts_at_genesis']}")
        for gap in report["gaps"]:
            print(f"  GAP: seq {gap[0]}..{gap[1]} missing")
        for error in report["errors"]:
            print(f"  ERROR: {error}")
        for warning in report["warnings"]:
            print(f"  warning: {warning}")
        if report["checkpoint"]:
            cp = report["checkpoint"]
            print(f"  checkpoint: verified={cp['verified']} anchored={cp.get('anchored')}"
                  f" size={cp.get('tree_size')} witnesses={len(cp.get('witnesses', []))}")
        if report["window"]:
            w = report["window"]
            print(f"  window {w['start']}..{w['end']}: complete={w['complete']}"
                  f" receipts={w['receipts_in_window']}")
    return 0 if passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
