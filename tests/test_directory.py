"""Operator key directory."""

from __future__ import annotations

import json

import pytest

from traceseal_observe import OperatorKey, observe_tool
from traceseal_observe import directory as dir_mod
from traceseal_observe.directory import (
    DirectoryError,
    build_directory,
    check_receipts,
    key_status_at,
    verify_directory,
)


@pytest.fixture
def keys():
    return OperatorKey.generate("k1"), OperatorKey.generate("k2"), OperatorKey.generate("old")


def _doc(keys):
    k1, k2, old = keys
    entries = [
        {"public_key": k1.public_key_hex, "status": "active", "valid_from": "2026-01-01T00:00:00Z",
         "chain_ids": ["support-agent"]},
        {"public_key": k2.public_key_hex, "status": "active", "valid_from": "2026-06-01T00:00:00Z"},
        {"public_key": old.public_key_hex, "status": "revoked", "valid_from": "2025-01-01T00:00:00Z",
         "revoked_at": "2026-02-01T00:00:00Z", "compromised_after": "2026-01-20T00:00:00Z"},
    ]
    return build_directory("Example.com", entries, [k1, k2], issued_at="2026-10-01T00:00:00Z")


class TestDirectory:
    def test_build_verify_and_statuses(self, keys):
        k1, k2, old = keys
        report = verify_directory(_doc(keys), domain="example.com")
        assert report["domain"] == "example.com"
        assert key_status_at(report, k1.public_key_hex, "2026-03-01T00:00:00Z") == "valid"
        assert key_status_at(report, k2.public_key_hex, "2026-03-01T00:00:00Z") == "not_yet_valid"
        assert key_status_at(report, old.public_key_hex, "2026-01-10T00:00:00Z") == "valid"
        assert key_status_at(report, old.public_key_hex, "2026-01-25T00:00:00Z") == "compromised"
        assert key_status_at(report, "ab" * 32, "2026-03-01T00:00:00Z") == "not_listed"

    def test_active_keys_must_sign(self, keys):
        k1, k2, _ = keys
        entries = [{"public_key": k.public_key_hex, "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z"} for k in (k1, k2)]
        with pytest.raises(DirectoryError, match="must sign"):
            build_directory("example.com", entries, [k1])
        doc = build_directory("example.com", entries, [k1, k2])
        doc["signatures"] = doc["signatures"][:1]
        with pytest.raises(DirectoryError, match="did not sign"):
            verify_directory(doc)

    def test_tampering_and_domain_copy(self, keys):
        doc = _doc(keys)
        with pytest.raises(DirectoryError, match="fetched from"):
            verify_directory(doc, domain="evil.example")
        doc["keys"][2]["status"] = "active"
        doc["keys"][2].pop("revoked_at")
        doc["keys"][2].pop("compromised_after")
        with pytest.raises(DirectoryError):
            verify_directory(doc)

    def test_unlisted_signer_and_validation(self, keys):
        doc = _doc(keys)
        stranger = OperatorKey.generate()
        doc["signatures"].append({"public_key": stranger.public_key_hex, "signature": "00" * 64})
        with pytest.raises(DirectoryError, match="does not list"):
            verify_directory(doc)
        k1 = keys[0]
        for bad in ({"status": "revoked"}, {"status": "weird"}, {"valid_until": "2020-01-01T00:00:00Z"},
                    {"revoked_at": "2026-05-01T00:00:00Z"}, {"extra": 1}):
            entry = {"public_key": k1.public_key_hex, "status": "active",
                     "valid_from": "2026-01-01T00:00:00Z", **bad}
            with pytest.raises(DirectoryError):
                build_directory("example.com", [entry], [k1])
        with pytest.raises(DirectoryError):
            build_directory("not a domain", [], [k1])

    def test_check_receipts_and_cli(self, keys, tmp_path, capsys):
        k1, k2, old = keys
        doc = _doc(keys)
        r = observe_tool("t", k1, lambda: 1)[1]
        stranger = observe_tool("t", OperatorKey.generate(), lambda: 1)[1]
        report = verify_directory(doc)
        statuses = [c["status"] for c in check_receipts([r, stranger], report)]
        assert statuses == ["valid", "not_listed"]
        (tmp_path / "dir.json").write_text(json.dumps(doc))
        (tmp_path / "r.json").write_text(r.to_json())
        assert dir_mod.main(["verify", "--domain", "example.com", "--file", str(tmp_path / "dir.json"),
                             str(tmp_path / "r.json")]) == 0
        (tmp_path / "s.json").write_text(stranger.to_json())
        assert dir_mod.main(["verify", "--domain", "example.com", "--file", str(tmp_path / "dir.json"),
                             str(tmp_path / "s.json")]) == 1

    def test_key_status_uses_signed_time_only(self, keys):
        """attestation.attested_at is outside the signature, so editing it must
        not change a key's status (review finding)."""
        k1, k2, old = keys
        report = verify_directory(_doc(keys))
        r = observe_tool("t", old, lambda: 1)[1]  # signed now, after revocation
        assert check_receipts([r], report)[0]["status"] == "compromised"
        r.attestation["attested_at"] = "2025-06-01T00:00:00Z"  # holder back-dates it
        assert check_receipts([r], report)[0]["status"] == "compromised"  # not "valid"
        from traceseal_observe import sign_execution_receipt

        untimed = sign_execution_receipt({"receipt_type": "tool"}, {}, old)
        assert check_receipts([untimed], report)[0]["status"] == "unknown_time"

    def test_fetch_uses_https_well_known(self, keys, monkeypatch):
        seen = {}

        class Resp:
            def __init__(self, body):
                self.body = body

            def read(self, n):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake(url, timeout):
            seen["url"] = url
            return Resp(json.dumps(_doc(keys)).encode())

        monkeypatch.setattr("urllib.request.urlopen", fake)
        assert dir_mod.fetch_directory("example.com")["domain"] == "example.com"
        assert seen["url"] == "https://example.com/.well-known/traceseal/operator-keys.json"
