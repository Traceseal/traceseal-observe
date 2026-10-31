"""Operator key directory: which signing keys does an organisation stand behind?

A receipt carries the public key that signed it, so a verifier can always
check the signature. What a verifier cannot tell from the receipt is
whether that key belongs to the organisation it claims to come from. The
directory answers that:

    https://<domain>/.well-known/traceseal/operator-keys.json

    {
      "directory_version": "1.0",
      "domain": "example.com",
      "issued_at": "2026-10-01T00:00:00Z",
      "keys": [
        {"public_key": "<hex>", "status": "active",  "valid_from": "...", "chain_ids": ["support-agent"]},
        {"public_key": "<hex>", "status": "retired", "valid_from": "...", "valid_until": "..."},
        {"public_key": "<hex>", "status": "revoked", "valid_from": "...", "revoked_at": "...",
         "compromised_after": "..."}
      ],
      "signatures": [{"public_key": "<hex>", "signature": "<hex>"}]
    }

- Domain binding comes from where the document is served: HTTPS on the
  organisation's own domain. The signed `domain` field stops it being
  copied to another domain.
- Every *active* key listed must sign the document (canonical JSON of
  everything except `signatures`). This proves the listed keys are held by
  whoever published it, so a key can't be listed without its holder's
  consent.
- `key_status_at(report, public_key, when)` tells a verifier whether a key
  was valid for the organisation at a given time.

This is a TraceSeal convention, not an external standard. For a legal
identity binding, sign the directory additionally with an eIDAS
qualified electronic seal; that is out of scope here.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DIRECTORY_VERSION = "1.0"
WELL_KNOWN_PATH = "/.well-known/traceseal/operator-keys.json"
KEY_STATUSES = frozenset({"active", "retired", "revoked"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_MAX_KEYS = 256
_MAX_BYTES = 1 << 20


class DirectoryError(ValueError):
    pass


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise DirectoryError(f"{label} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _body(document: dict[str, Any]) -> bytes:
    from traceseal_observe import canonical_dumps

    return canonical_dumps({k: v for k, v in document.items() if k != "signatures"})


def build_directory(
    domain: str,
    keys: list[dict[str, Any]],
    signing_keys: Iterable[Any],
    *,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Build and sign a directory. `signing_keys` must include every key
    listed as active (OperatorKey or RemoteOperatorKey)."""
    from traceseal_observe import _now_iso

    document = {
        "directory_version": DIRECTORY_VERSION,
        "domain": domain.lower(),
        "issued_at": issued_at or _now_iso(),
        "keys": [dict(k) for k in keys],
    }
    _validate(document, require_signatures=False)
    signers = {k.public_key_hex: k for k in signing_keys}
    active = [k["public_key"] for k in document["keys"] if k["status"] == "active"]
    missing = [pk for pk in active if pk not in signers]
    if missing:
        raise DirectoryError(f"active keys must sign the directory; missing {missing}")
    body = _body(document)
    document["signatures"] = [
        {"public_key": pk, "signature": signers[pk].sign(body).hex()}
        for pk in sorted(signers)
    ]
    return document


def _validate(document: Any, *, require_signatures: bool = True) -> None:
    if not isinstance(document, dict) or document.get("directory_version") != DIRECTORY_VERSION:
        raise DirectoryError("not a TraceSeal operator key directory (version 1.0)")
    if not isinstance(document.get("domain"), str) or not _DOMAIN_RE.fullmatch(document["domain"]):
        raise DirectoryError("domain is malformed")
    _utc(document.get("issued_at"), "issued_at")
    keys = document.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= _MAX_KEYS:
        raise DirectoryError("keys must list 1-256 keys")
    seen = set()
    for entry in keys:
        if not isinstance(entry, dict):
            raise DirectoryError("key entries must be objects")
        pk = entry.get("public_key")
        if not isinstance(pk, str) or not _HEX64.fullmatch(pk) or pk in seen:
            raise DirectoryError("key public_key must be unique 64-hex")
        seen.add(pk)
        if entry.get("status") not in KEY_STATUSES:
            raise DirectoryError("key status must be active, retired or revoked")
        start = _utc(entry.get("valid_from"), "valid_from")
        for field in ("valid_until", "revoked_at", "compromised_after"):
            if field in entry and _utc(entry[field], field) < start:
                raise DirectoryError(f"{field} is before valid_from")
        if entry["status"] == "revoked" and "revoked_at" not in entry:
            raise DirectoryError("revoked keys need revoked_at")
        if entry["status"] != "revoked" and ("revoked_at" in entry or "compromised_after" in entry):
            raise DirectoryError("only revoked keys carry revoked_at / compromised_after")
        if "chain_ids" in entry and (not isinstance(entry["chain_ids"], list) or any(
                not isinstance(c, str) for c in entry["chain_ids"])):
            raise DirectoryError("chain_ids must be a list of strings")
        unknown = set(entry) - {"public_key", "status", "valid_from", "valid_until",
                                "revoked_at", "compromised_after", "chain_ids", "label"}
        if unknown:
            raise DirectoryError(f"unknown key fields {sorted(unknown)}")
    if require_signatures and not isinstance(document.get("signatures"), list):
        raise DirectoryError("directory is unsigned")


def verify_directory(document: Any, *, domain: str | None = None) -> dict[str, Any]:
    """Verify a directory's structure and signatures. Raises DirectoryError.

    `domain` is the domain you fetched it from; it must match the signed
    domain field.
    """
    _validate(document)
    if domain is not None and document["domain"] != domain.lower():
        raise DirectoryError(f"directory is for {document['domain']}, fetched from {domain}")
    body = _body(document)
    listed = {k["public_key"] for k in document["keys"]}
    valid_signers = set()
    for sig in document["signatures"]:
        pk = sig.get("public_key") if isinstance(sig, dict) else None
        if pk not in listed:
            raise DirectoryError("directory is signed by a key it does not list")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
                bytes.fromhex(sig.get("signature", "")), body)
        except (ValueError, InvalidSignature):
            raise DirectoryError(f"signature by {pk[:16]}… is invalid") from None
        valid_signers.add(pk)
    unsigned = [k["public_key"] for k in document["keys"]
                if k["status"] == "active" and k["public_key"] not in valid_signers]
    if unsigned:
        raise DirectoryError(f"active keys did not sign the directory: {unsigned}")
    return {"domain": document["domain"], "issued_at": document["issued_at"],
            "keys": {k["public_key"]: k for k in document["keys"]}}


def key_status_at(report: dict[str, Any], public_key: str, when: str) -> str:
    """'valid', 'not_listed', 'not_yet_valid', 'expired', 'revoked' or
    'compromised' for a key at a time, per a verified directory."""
    entry = report["keys"].get(public_key)
    if entry is None:
        return "not_listed"
    moment = _utc(when, "when")
    if moment < _utc(entry["valid_from"], "valid_from"):
        return "not_yet_valid"
    if "compromised_after" in entry and moment > _utc(entry["compromised_after"], "compromised_after"):
        return "compromised"
    if entry["status"] == "revoked" and moment >= _utc(entry["revoked_at"], "revoked_at"):
        return "revoked"
    if "valid_until" in entry and moment > _utc(entry["valid_until"], "valid_until"):
        return "expired"
    return "valid"


def fetch_directory(domain: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch and verify https://<domain>/.well-known/traceseal/operator-keys.json
    (TLS certificate verified by the platform's default trust store)."""
    if not _DOMAIN_RE.fullmatch(domain.lower()):
        raise DirectoryError("domain is malformed")
    url = f"https://{domain.lower()}{WELL_KNOWN_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read(_MAX_BYTES + 1)
    except OSError as exc:
        raise DirectoryError(f"cannot fetch {url}: {type(exc).__name__}") from None
    if len(data) > _MAX_BYTES:
        raise DirectoryError("directory is too large")
    document = json.loads(data)
    return verify_directory(document, domain=domain)


def check_receipts(receipts: list[Any], report: dict[str, Any]) -> list[dict[str, Any]]:
    """Status of each receipt's signing key at its signing time."""
    out = []
    for r in receipts:
        when = r.execution.get("chained_at") or r.attestation.get("attested_at")
        pk = r.attestation.get("operator_public_key", "")
        status = key_status_at(report, pk, when) if isinstance(when, str) else "unknown_time"
        out.append({"receipt": r.receipt_hash, "public_key": pk, "status": status})
    return out


def main(argv: list[str] | None = None) -> int:
    from traceseal_observe import OperatorKey
    from traceseal_observe.chain import load_receipt

    parser = argparse.ArgumentParser(prog="traceseal-keys",
                                     description="Publish or verify an operator key directory.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("publish", help="sign a directory from a JSON list of key entries")
    p.add_argument("--domain", required=True)
    p.add_argument("--keys", required=True, help="JSON file: list of key entries")
    p.add_argument("--signing-key", action="append", required=True, help="raw Ed25519 key file")
    p.add_argument("--output", required=True)
    v = sub.add_parser("verify", help="verify a directory file or fetch it from a domain")
    v.add_argument("--domain", required=True)
    v.add_argument("--file", help="local copy (default: fetch over HTTPS)")
    v.add_argument("receipts", nargs="*", help="receipts whose keys to check")
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            document = build_directory(
                args.domain, json.loads(Path(args.keys).read_text("utf-8")),
                [OperatorKey.load_from_file(k) for k in args.signing_key])
            Path(args.output).write_text(json.dumps(document, indent=2, sort_keys=True))
            print(f"[OK] wrote {args.output}; serve it at https://{args.domain}{WELL_KNOWN_PATH}")
            return 0
        if args.file:
            report = verify_directory(json.loads(Path(args.file).read_text("utf-8")), domain=args.domain)
        else:
            report = fetch_directory(args.domain)
    except (OSError, ValueError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(f"[OK] {report['domain']} lists {len(report['keys'])} key(s), issued {report['issued_at']}")
    bad = 0
    for item in check_receipts([load_receipt(r) for r in args.receipts], report):
        print(f"  {item['receipt'][:23]}  key {item['public_key'][:16]}…  {item['status']}")
        bad += item["status"] != "valid"
    return 1 if bad else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
