"""Evidence vault: keep the payloads behind receipt hashes, encrypted and erasable.

Receipts hold hashes, which is right for sharing and wrong for disputes:
eventually someone has to see the prompt, the tool arguments or the
response. The vault keeps those payloads so that:

  - each one is stored under the hash a receipt already commits to
    (`sha256_of(value)`), so a disclosed payload verifies against the
    receipt with no extra trust;
  - each one is encrypted (AES-256-GCM) under a data key (DEK) belonging to
    a *shred domain*: one per tenant, per user, or per retention period;
  - DEKs are wrapped by a key-encryption key (KEK) that can live in a KMS;
  - destroying a domain's DEK ("crypto-shredding") makes its payloads
    unrecoverable while every receipt and signature stays valid, and signs
    an `erasure` receipt saying exactly what was destroyed (GDPR Art. 17);
  - minimum retention (e.g. AI Act Art. 19 / 26(6): at least six months),
    maximum retention (GDPR Art. 5(1)(e)) and legal holds are enforced;
  - a payload can be disclosed to one auditor, sealed with HPKE (RFC 9180),
    optionally with a post-quantum hybrid KEM.

    vault = EvidenceVault.open("/var/lib/agent/vault", kek=LocalKEK(kek_bytes),
                               min_retention_days=183)
    vault.put_for(model_receipt, "input_hash", request, domain="tenant:acme")
    bundle = vault.disclose(model_receipt.execution["input_hash"], auditor_public_key)
    value = open_disclosure(bundle, auditor_private_key)       # auditor side
    verify_disclosure(value, model_receipt, "input_hash")      # True

Shredding caveat: deleting files is not secure erasure on SSDs, snapshots or
backups. Crypto-shredding works because the DEK is gone. A deleted *wrapped*
DEK recovered from a backup can still be unwrapped while the KEK survives,
so after shredding, call rotate_kek() and destroy the old KEK, or keep DEKs
in a KMS (see KMSKEK).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_VERSION = "1.0"
DISCLOSURE_VERSION = "1.0"
ERASURE_VERSION = "1.0"
ERASURE_REASONS = frozenset({"data_subject_request", "retention_expired", "other"})

_DOMAIN_RE = re.compile(r"^[!-~]{1,200}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class VaultError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise VaultError("times must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Encoding: the exact bytes sha256_of hashes, and how to rebuild the value
# ---------------------------------------------------------------------------


def encode_value(value: Any) -> tuple[str, bytes]:
    """(encoding, bytes) such that sha256(bytes) == sha256_of(value)."""
    from traceseal_observe import _require_strict_json, canonical_dumps

    if isinstance(value, bytes):
        return "bytes", value
    if isinstance(value, str):
        return "text", value.encode("utf-8")
    if value is None:
        raise VaultError("None hashes as empty; there is nothing to store")
    _require_strict_json(value, "vault value")
    if isinstance(value, dict):
        return "json", canonical_dumps(value)
    return "json", json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def decode_value(encoding: str, data: bytes) -> Any:
    if encoding == "bytes":
        return data
    if encoding == "text":
        return data.decode("utf-8")
    if encoding == "json":
        return json.loads(data.decode("utf-8"))
    raise VaultError(f"unknown encoding {encoding!r}")


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Key-encryption keys
# ---------------------------------------------------------------------------


class LocalKEK:
    """A 32-byte AES-256-GCM key-encryption key held by this process."""

    def __init__(self, key: bytes, key_id: str = "local"):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise VaultError("LocalKEK needs a 32-byte key")
        self._aead = AESGCM(bytes(key))
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str = "local") -> LocalKEK:
        return cls(AESGCM.generate_key(256), key_id)

    def wrap(self, dek: bytes, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self._aead.encrypt(nonce, dek, aad)

    def unwrap(self, wrapped: bytes, aad: bytes) -> bytes:
        try:
            return self._aead.decrypt(wrapped[:12], wrapped[12:], aad)
        except InvalidTag:
            raise VaultError("cannot unwrap data key (wrong KEK or tampered)") from None


class KMSKEK:
    """KEK operations delegated to a KMS: wrap_fn(dek, aad) / unwrap_fn(blob, aad).

    For example Google Cloud KMS encrypt/decrypt with additional authenticated
    data, AWS KMS Encrypt/Decrypt with an EncryptionContext built from `aad`.
    """

    def __init__(self, wrap_fn: Callable[[bytes, bytes], bytes],
                 unwrap_fn: Callable[[bytes, bytes], bytes], key_id: str = "kms"):
        self._wrap, self._unwrap, self.key_id = wrap_fn, unwrap_fn, key_id

    def wrap(self, dek: bytes, aad: bytes) -> bytes:
        return self._wrap(dek, aad)

    def unwrap(self, wrapped: bytes, aad: bytes) -> bytes:
        dek = self._unwrap(wrapped, aad)
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != 32:
            raise VaultError("KMS returned a malformed data key")
        return bytes(dek)


# ---------------------------------------------------------------------------
# The vault
# ---------------------------------------------------------------------------


@dataclass
class Domain:
    name: str
    created_at: str
    retain_until: str = ""
    delete_after: str = ""
    legal_hold: bool = False


class EvidenceVault:
    """Directory-backed encrypted payload store. One process at a time."""

    def __init__(self, directory: Path | str, kek: Any, *, min_retention_days: int = 0):
        self.dir = Path(directory)
        self._kek = kek
        self._lock = threading.RLock()
        self._deks: dict[str, bytes] = {}
        self.min_retention_days = min_retention_days
        (self.dir / "domains").mkdir(parents=True, exist_ok=True)
        (self.dir / "objects").mkdir(parents=True, exist_ok=True)
        meta = self.dir / "vault.json"
        if meta.exists():
            data = json.loads(meta.read_text("utf-8"))
            if data.get("vault_version") != VAULT_VERSION:
                raise VaultError("unsupported vault version")
            self.min_retention_days = max(min_retention_days, int(data.get("min_retention_days", 0)))
        self._write_json(meta, {"vault_version": VAULT_VERSION,
                                "min_retention_days": self.min_retention_days})

    @classmethod
    def open(cls, directory: Path | str, kek: Any, *, min_retention_days: int = 0) -> EvidenceVault:
        return cls(directory, kek, min_retention_days=min_retention_days)

    # -- files ---------------------------------------------------------------

    @staticmethod
    def _write_json(path: Path, data: dict[str, Any]) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, sort_keys=True, indent=1))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    @staticmethod
    def _domain_id(name: str) -> str:
        return hashlib.sha256(name.encode("utf-8")).hexdigest()

    def _domain_path(self, name: str) -> Path:
        return self.dir / "domains" / f"{self._domain_id(name)}.json"

    def _objects_dir(self, name: str) -> Path:
        return self.dir / "objects" / self._domain_id(name)

    def _aad(self, name: str, purpose: str, extra: str = "") -> bytes:
        return f"traceseal-vault/1|{purpose}|{self._domain_id(name)}|{extra}".encode()

    # -- domains -------------------------------------------------------------

    def create_domain(self, name: str, *, retain_until: str | None = None,
                      delete_after: str | None = None) -> Domain:
        """Create a shred domain. retain_until defaults to now +
        min_retention_days; delete_after (optional) must not precede it."""
        if not isinstance(name, str) or _DOMAIN_RE.fullmatch(name) is None:
            raise VaultError("domain names are 1-200 printable characters without spaces")
        with self._lock:
            path = self._domain_path(name)
            if path.exists():
                raise VaultError(f"domain {name!r} exists")
            now = _now()
            floor = now + timedelta(days=self.min_retention_days)
            keep = _parse(retain_until) if retain_until else floor
            if keep < floor:
                raise VaultError(f"retain_until is before the minimum retention ({_fmt(floor)})")
            if delete_after and _parse(delete_after) < keep:
                raise VaultError("delete_after is before retain_until")
            dek = AESGCM.generate_key(256)
            record = {
                "name": name,
                "created_at": _fmt(now),
                "retain_until": _fmt(keep),
                "delete_after": delete_after or "",
                "legal_hold": False,
                "kek_id": getattr(self._kek, "key_id", ""),
                "wrapped_dek": _b64(self._kek.wrap(dek, self._aad(name, "dek"))),
            }
            self._write_json(path, record)
            self._deks[name] = dek
            return self.domain(name)

    def _record(self, name: str) -> dict[str, Any]:
        path = self._domain_path(name)
        if not path.exists():
            raise VaultError(f"no live domain {name!r} (never created, or shredded)")
        return json.loads(path.read_text("utf-8"))

    def domain(self, name: str) -> Domain:
        r = self._record(name)
        return Domain(r["name"], r["created_at"], r["retain_until"], r["delete_after"], r["legal_hold"])

    def domains(self) -> list[Domain]:
        out = []
        for path in sorted((self.dir / "domains").glob("*.json")):
            r = json.loads(path.read_text("utf-8"))
            out.append(Domain(r["name"], r["created_at"], r["retain_until"], r["delete_after"], r["legal_hold"]))
        return out

    def set_legal_hold(self, name: str, hold: bool = True) -> None:
        """A legal hold blocks every shred of the domain, including expiry."""
        with self._lock:
            r = self._record(name)
            r["legal_hold"] = bool(hold)
            self._write_json(self._domain_path(name), r)

    def _dek(self, name: str) -> bytes:
        if name not in self._deks:
            r = self._record(name)
            self._deks[name] = self._kek.unwrap(_unb64(r["wrapped_dek"]), self._aad(name, "dek"))
        return self._deks[name]

    # -- payloads ------------------------------------------------------------

    def put(self, value: Any, *, domain: str) -> str:
        """Store a payload; returns sha256_of(value). Creates the domain if needed."""
        from traceseal_observe import sha256_of

        encoding, data = encode_value(value)
        digest = _hash_bytes(data)
        if digest != sha256_of(value):  # defence in depth: must match receipts
            raise VaultError("internal: encoding does not reproduce sha256_of")
        with self._lock:
            if not self._domain_path(domain).exists():
                self.create_domain(domain)
            folder = self._objects_dir(domain)
            folder.mkdir(exist_ok=True)
            path = folder / f"{digest[7:]}.json"
            if not path.exists():
                nonce = secrets.token_bytes(12)
                aead = AESGCM(self._dek(domain))
                sealed = aead.encrypt(nonce, data, self._aad(domain, "object", digest))
                self._write_json(path, {"encoding": encoding, "nonce": _b64(nonce),
                                        "ciphertext": _b64(sealed)})
        return digest

    def put_for(self, receipt: Any, field: str, value: Any, *, domain: str) -> str:
        """Store `value` only if it is what `receipt.execution[field]` commits to."""
        from traceseal_observe import sha256_of

        expected = receipt.execution.get(field)
        if not isinstance(expected, str) or _SHA_RE.fullmatch(expected) is None:
            raise VaultError(f"receipt has no {field} hash")
        if sha256_of(value) != expected:
            raise VaultError(f"value does not match the receipt's {field}")
        return self.put(value, domain=domain)

    def _find(self, digest: str, domain: str | None) -> tuple[str, Path]:
        if not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None:
            raise VaultError("hash must be sha256:<64 hex>")
        names = [domain] if domain else [d.name for d in self.domains()]
        for name in names:
            path = self._objects_dir(name) / f"{digest[7:]}.json"
            if path.exists() and self._domain_path(name).exists():
                return name, path
        raise VaultError("payload not in the vault (never stored, or shredded)")

    def get(self, digest: str, *, domain: str | None = None) -> Any:
        """Decrypt and return the payload; its hash is re-checked."""
        with self._lock:
            name, path = self._find(digest, domain)
            record = json.loads(path.read_text("utf-8"))
            try:
                data = AESGCM(self._dek(name)).decrypt(
                    _unb64(record["nonce"]), _unb64(record["ciphertext"]),
                    self._aad(name, "object", digest))
            except InvalidTag:
                raise VaultError("payload failed authentication (tampered)") from None
        if _hash_bytes(data) != digest:
            raise VaultError("payload does not match its hash")
        return decode_value(record["encoding"], data)

    def contains(self, digest: str, *, domain: str | None = None) -> bool:
        try:
            self._find(digest, domain)
            return True
        except VaultError:
            return False

    # -- disclosure ----------------------------------------------------------

    def disclose(self, digest: str, recipient_public_key: Any, *,
                 domain: str | None = None) -> dict[str, Any]:
        """Seal one payload to one recipient (HPKE, RFC 9180).

        recipient_public_key: X25519PublicKey (suite X25519/HKDF-SHA256/
        AES-256-GCM) or MLKEM768X25519PublicKey (post-quantum hybrid).
        """
        name, path = self._find(digest, domain)
        record = json.loads(path.read_text("utf-8"))
        value = self.get(digest, domain=name)
        encoding, data = encode_value(value)
        suite, suite_name = _suite_for(recipient_public_key)
        plaintext = json.dumps({"encoding": encoding, "data": _b64(data)}).encode()
        sealed = suite.encrypt(plaintext, recipient_public_key, info=_info(digest))
        assert record["encoding"] == encoding
        return {"disclosure_version": DISCLOSURE_VERSION, "hash": digest,
                "suite": suite_name, "sealed": _b64(sealed)}

    # -- erasure -------------------------------------------------------------

    def shred(self, name: str, *, operator_key: Any = None, reason: str = "data_subject_request",
              override_retention: bool = False) -> Any:
        """Destroy a domain's data key and payloads. Returns a signed
        `erasure` receipt if operator_key is given (recommended).

        Refused under legal hold. Refused before retain_until unless
        override_retention=True, which is recorded in the receipt: a legal
        retention obligation can outweigh an erasure request (GDPR Art. 17(3)(b)).
        """
        if reason not in ERASURE_REASONS:
            raise VaultError(f"reason must be one of {sorted(ERASURE_REASONS)}")
        with self._lock:
            record = self._record(name)
            if record["legal_hold"]:
                raise VaultError(f"domain {name!r} is under legal hold")
            early = _now() < _parse(record["retain_until"])
            if early and not override_retention:
                raise VaultError(f"domain {name!r} must be retained until {record['retain_until']}")
            folder = self._objects_dir(name)
            hashes = sorted("sha256:" + p.stem for p in folder.glob("*.json")) if folder.exists() else []
            # Destroy the key first: from here on the payloads are unreadable
            # even if deleting the files below fails or leaves remnants.
            path = self._domain_path(name)
            size = path.stat().st_size
            with open(path, "r+b") as fh:
                fh.write(secrets.token_bytes(size))
                fh.flush()
                os.fsync(fh.fileno())
            path.unlink()
            self._deks.pop(name, None)
            for p in folder.glob("*.json") if folder.exists() else []:
                p.unlink()
            if folder.exists():
                folder.rmdir()
        if operator_key is None:
            return None
        return sign_erasure(domain=name, object_hashes=hashes, reason=reason,
                            retention_overridden=early, operator_key=operator_key)

    def enforce_retention(self, *, operator_key: Any = None, now: str | None = None) -> list[Any]:
        """Shred every domain past delete_after and not under legal hold."""
        moment = _parse(now) if now else _now()
        done = []
        for d in self.domains():
            if d.delete_after and _parse(d.delete_after) <= moment and not d.legal_hold:
                done.append(self.shred(d.name, operator_key=operator_key, reason="retention_expired"))
        return done

    def rotate_kek(self, new_kek: Any) -> int:
        """Re-wrap every live data key under new_kek. Destroy the old KEK
        afterwards so wrapped keys of shredded domains in old backups can no
        longer be unwrapped. Returns the number of domains re-wrapped."""
        with self._lock:
            count = 0
            for d in self.domains():
                dek = self._dek(d.name)
                record = self._record(d.name)
                record["wrapped_dek"] = _b64(new_kek.wrap(dek, self._aad(d.name, "dek")))
                record["kek_id"] = getattr(new_kek, "key_id", "")
                self._write_json(self._domain_path(d.name), record)
                count += 1
            self._kek = new_kek
            return count


# ---------------------------------------------------------------------------
# Erasure receipts
# ---------------------------------------------------------------------------


def objects_root(object_hashes: list[str]) -> str:
    """Commitment to the set of destroyed payload hashes."""
    from traceseal_observe import sha256_of

    return sha256_of(sorted(object_hashes))


def sign_erasure(*, domain: str, object_hashes: list[str], reason: str,
                 retention_overridden: bool, operator_key: Any) -> Any:
    """Sign an `erasure` receipt. Records a hash of the domain name, never
    the name, and a commitment to the destroyed payload hashes, so anyone
    holding a receipt can later show its payload was in the erased set."""
    from traceseal_observe import sign_execution_receipt

    if reason not in ERASURE_REASONS:
        raise VaultError(f"reason must be one of {sorted(ERASURE_REASONS)}")
    execution = {
        "receipt_type": "erasure",
        "erasure_version": ERASURE_VERSION,
        "domain_hash": "sha256:" + hashlib.sha256(domain.encode("utf-8")).hexdigest(),
        "object_count": len(object_hashes),
        "objects_root": objects_root(object_hashes),
        "reason": reason,
        "retention_overridden": "true" if retention_overridden else "false",
    }
    provenance = {"provenance_version": "1.0", "provider_attestation": "none"}
    return sign_execution_receipt(execution, provenance, operator_key)


def erasure_covers(erasure_receipt: Any, object_hashes: list[str], payload_hash: str) -> bool:
    """True if `payload_hash` is in `object_hashes` and that list is exactly
    the set the erasure receipt commits to."""
    return (
        payload_hash in object_hashes
        and erasure_receipt.execution.get("objects_root") == objects_root(object_hashes)
        and erasure_receipt.execution.get("object_count") == len(set(object_hashes))
    )


# ---------------------------------------------------------------------------
# Disclosure (auditor side)
# ---------------------------------------------------------------------------


def _info(digest: str) -> bytes:
    return f"traceseal-disclosure/1|{digest}".encode()


def _suite_for(key: Any):
    try:
        from cryptography.hazmat.primitives import hpke
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError:  # pragma: no cover
        raise VaultError("sealed disclosure needs a cryptography release with HPKE") from None
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM), \
            "DHKEM(X25519)-HKDF-SHA256-AES-256-GCM"
    if isinstance(key, (hpke.MLKEM768X25519PublicKey, hpke.MLKEM768X25519PrivateKey)):
        return hpke.Suite(hpke.KEM.MLKEM768_X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM), \
            "MLKEM768-X25519-HKDF-SHA256-AES-256-GCM"
    raise VaultError("recipient key must be X25519 or ML-KEM-768+X25519")


def open_disclosure(bundle: dict[str, Any], recipient_private_key: Any) -> Any:
    """Decrypt a sealed disclosure and check the payload matches its hash."""
    if not isinstance(bundle, dict) or bundle.get("disclosure_version") != DISCLOSURE_VERSION:
        raise VaultError("not a disclosure bundle")
    digest = bundle.get("hash")
    if not isinstance(digest, str) or _SHA_RE.fullmatch(digest) is None:
        raise VaultError("disclosure hash is malformed")
    suite, name = _suite_for(recipient_private_key)
    if bundle.get("suite") != name:
        raise VaultError("disclosure was sealed for a different key type")
    try:
        plaintext = suite.decrypt(_unb64(bundle["sealed"]), recipient_private_key, info=_info(digest))
    except Exception:
        raise VaultError("cannot open disclosure (wrong key or tampered)") from None
    inner = json.loads(plaintext)
    data = _unb64(inner["data"])
    if _hash_bytes(data) != digest:
        raise VaultError("disclosed payload does not match its hash")
    return decode_value(inner["encoding"], data)


def verify_disclosure(value: Any, receipt: Any, field: str) -> bool:
    """True if `value` is what the receipt's `field` hash commits to.

    Check the receipt's signature separately (traceseal-verify)."""
    from traceseal_observe import sha256_of

    expected = receipt.execution.get(field)
    return isinstance(expected, str) and sha256_of(value) == expected
