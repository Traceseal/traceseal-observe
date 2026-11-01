"""Evidence vault: storage, retention, crypto-shredding, disclosure."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from traceseal_observe import (
    OperatorKey,
    ReceiptChain,
    observe_model_call,
    observe_tool,
    sha256_of,
    verify_chain,
    verify_receipt_signature,
)
from traceseal_observe.vault import (
    EvidenceVault,
    KMSKEK,
    LocalKEK,
    VaultError,
    erasure_covers,
    open_disclosure,
    verify_disclosure,
)


@pytest.fixture
def kek():
    return LocalKEK.generate()


@pytest.fixture
def vault(tmp_path, kek):
    return EvidenceVault.open(tmp_path / "v", kek)


VALUES = [{"messages": [{"role": "user", "content": "Héllo"}], "temperature": 0.5},
          ["a", 1, True], "plain text", b"\x00\x01raw", 42, 1.5, True]


class TestStorage:
    @pytest.mark.parametrize("value", VALUES)
    def test_hash_matches_sha256_of_and_round_trips(self, vault, value):
        digest = vault.put(value, domain="tenant:acme")
        assert digest == sha256_of(value)
        assert vault.get(digest) == value

    def test_put_for_receipt_and_verify(self, vault):
        key = OperatorKey.generate()
        request = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        _, receipt = observe_model_call("p", "m", "https://e", key, lambda: {"ok": 1},
                                        serialize_request=lambda: request)
        vault.put_for(receipt, "input_hash", request, domain="tenant:acme")
        with pytest.raises(VaultError, match="does not match"):
            vault.put_for(receipt, "input_hash", {"something": "else"}, domain="tenant:acme")
        assert verify_disclosure(vault.get(receipt.execution["input_hash"]), receipt, "input_hash")

    def test_encrypted_at_rest_and_tamper_evident(self, vault, tmp_path):
        digest = vault.put({"secret": "sk-live-123"}, domain="d")
        files = list((tmp_path / "v").rglob("*.json"))
        assert not any("sk-live-123" in f.read_text() for f in files)
        obj = next((tmp_path / "v" / "objects").rglob("*.json"))
        record = json.loads(obj.read_text())
        ct = bytearray(__import__("base64").b64decode(record["ciphertext"]))
        ct[0] ^= 1
        record["ciphertext"] = __import__("base64").b64encode(bytes(ct)).decode()
        obj.write_text(json.dumps(record))
        with pytest.raises(VaultError, match="tampered"):
            vault.get(digest)

    def test_reopen_and_wrong_kek(self, tmp_path, kek):
        v = EvidenceVault.open(tmp_path / "v", kek)
        digest = v.put("x", domain="d")
        assert EvidenceVault.open(tmp_path / "v", kek).get(digest) == "x"
        with pytest.raises(VaultError, match="unwrap"):
            EvidenceVault.open(tmp_path / "v", LocalKEK.generate()).get(digest)

    def test_rejects_non_json_and_none(self, vault):
        with pytest.raises(ValueError):
            vault.put({"x": float("nan")}, domain="d")
        with pytest.raises(VaultError):
            vault.put(None, domain="d")
        with pytest.raises(VaultError):
            vault.put("x", domain="has space")

    def test_kms_kek(self, tmp_path):
        inner = LocalKEK.generate()
        calls = []

        def wrap(dek, aad):
            calls.append("wrap")
            return inner.wrap(dek, aad)

        def unwrap(blob, aad):
            calls.append("unwrap")
            return inner.unwrap(blob, aad)

        v = EvidenceVault.open(tmp_path / "v", KMSKEK(wrap, unwrap))
        d = v.put("x", domain="d")
        assert EvidenceVault.open(tmp_path / "v", KMSKEK(wrap, unwrap)).get(d) == "x"
        assert calls == ["wrap", "unwrap"]


class TestRetentionAndShredding:
    def test_shred_makes_payloads_unrecoverable_and_signs_erasure(self, vault):
        key = OperatorKey.generate()
        a = vault.put("user data 1", domain="principal:u1")
        b = vault.put("user data 2", domain="principal:u1")
        keep = vault.put("other user", domain="principal:u2")
        erasure = vault.shred("principal:u1", operator_key=key)
        verify_receipt_signature(erasure)
        ex = erasure.execution
        assert ex["receipt_type"] == "erasure" and ex["object_count"] == 2
        assert "principal:u1" not in json.dumps(erasure.to_dict())
        assert erasure_covers(erasure, sorted([a, b]), a)
        assert not erasure_covers(erasure, [a], a)  # not the committed set
        for digest in (a, b):
            with pytest.raises(VaultError):
                vault.get(digest)
        assert vault.get(keep) == "other user"
        with pytest.raises(VaultError):
            vault.shred("principal:u1")

    def test_minimum_retention_and_override(self, tmp_path, kek):
        v = EvidenceVault.open(tmp_path / "v", kek, min_retention_days=183)
        v.put("log", domain="period:2026-10")
        with pytest.raises(VaultError, match="retained until"):
            v.shred("period:2026-10")
        erasure = v.shred("period:2026-10", operator_key=OperatorKey.generate(),
                          override_retention=True)
        assert erasure.execution["retention_overridden"] == "true"
        with pytest.raises(VaultError, match="minimum retention"):
            v.create_domain("x", retain_until="2020-01-01T00:00:00Z")
        # A reopened vault can't lower the configured floor.
        assert EvidenceVault.open(tmp_path / "v", kek).min_retention_days == 183

    def test_legal_hold_blocks_everything(self, vault):
        vault.put("x", domain="d")
        vault.set_legal_hold("d")
        with pytest.raises(VaultError, match="legal hold"):
            vault.shred("d", operator_key=OperatorKey.generate(), override_retention=True)
        vault.set_legal_hold("d", False)
        vault.shred("d")

    def test_enforce_retention(self, vault):
        key = OperatorKey.generate()
        vault.create_domain("expiring", delete_after="2099-01-01T00:00:00Z")
        vault.create_domain("held", delete_after="2099-01-01T00:00:00Z")
        vault.set_legal_hold("held")
        vault.put("a", domain="expiring")
        done = vault.enforce_retention(operator_key=key, now="2099-01-02T00:00:00Z")
        assert len(done) == 1 and done[0].execution["reason"] == "retention_expired"
        assert [d.name for d in vault.domains()] == ["held"]

    def test_erasure_is_chainable(self, vault):
        chain = ReceiptChain(OperatorKey.generate(), "c")
        r = observe_tool("t", chain.signer, lambda: 1)[1]
        vault.put("x", domain="d")
        erasure = vault.shred("d", operator_key=chain.signer)
        assert erasure.execution["chain_seq"] == 2
        assert verify_chain([r, erasure])["ok"]

    def test_rotate_kek(self, tmp_path, kek):
        v = EvidenceVault.open(tmp_path / "v", kek)
        d = v.put("x", domain="a")
        v.put("y", domain="b")
        new = LocalKEK.generate("kek-2")
        assert v.rotate_kek(new) == 2
        assert EvidenceVault.open(tmp_path / "v", new).get(d) == "x"
        with pytest.raises(VaultError):
            EvidenceVault.open(tmp_path / "v", kek).get(d)


class TestDisclosure:
    @pytest.fixture(autouse=True)
    def _needs_hpke(self):
        pytest.importorskip("cryptography.hazmat.primitives.hpke")
    def test_x25519_disclosure(self, vault):
        auditor = X25519PrivateKey.generate()
        digest = vault.put({"prompt": "refund order o-1"}, domain="d")
        bundle = vault.disclose(digest, auditor.public_key())
        assert "refund" not in json.dumps(bundle)
        assert open_disclosure(bundle, auditor) == {"prompt": "refund order o-1"}
        with pytest.raises(VaultError):
            open_disclosure(bundle, X25519PrivateKey.generate())

    def test_post_quantum_hybrid_disclosure(self, vault):
        from cryptography.hazmat.primitives import hpke
        from cryptography.hazmat.primitives.asymmetric import mlkem

        auditor = hpke.MLKEM768X25519PrivateKey(mlkem.MLKEM768PrivateKey.generate(),
                                                X25519PrivateKey.generate())
        digest = vault.put(b"binary evidence", domain="d")
        bundle = vault.disclose(digest, auditor.public_key())
        assert bundle["suite"].startswith("MLKEM768")
        assert open_disclosure(bundle, auditor) == b"binary evidence"

    def test_swapped_hash_rejected(self, vault):
        auditor = X25519PrivateKey.generate()
        bundle = vault.disclose(vault.put("a", domain="d"), auditor.public_key())
        bundle["hash"] = sha256_of("b")
        with pytest.raises(VaultError):
            open_disclosure(bundle, auditor)
