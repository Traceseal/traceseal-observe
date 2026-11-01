"""Receipt chains: hash links, gaps, forks, checkpoints, proofs, persistence."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from traceseal_observe import (
    ChainError,
    OperatorKey,
    ReceiptChain,
    WorkflowObserver,
    observe_data_flow,
    observe_model_call,
    observe_tool,
    sign_execution_receipt,
    sign_outcome,
    verify_chain,
    verify_chain_checkpoint,
    verify_outcome,
    verify_receipt_signature,
)
from traceseal_observe import chain as chain_mod
from traceseal_observe.chain import (
    _inclusion_path,
    _subproof,
    checkpoint_verifier_key,
    merkle_root,
    receipt_leaf_hash,
    verify_consistency,
    verify_inclusion,
)


@pytest.fixture
def key():
    return OperatorKey.generate("chain-test")


def _tool(signer, i):
    return observe_tool("t", signer, lambda: {"i": i}, args={"i": i})[1]


def _make(key, n, chain_id="agent-1", offset=0):
    chain = ReceiptChain(key, chain_id)
    return chain, [_tool(chain.signer, i + offset) for i in range(n)]


# ---------------------------------------------------------------------------
# RFC 6962 Merkle primitives against a direct transcription of the RFC
# ---------------------------------------------------------------------------


def _ref_mth(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + _ref_mth(leaves[:k]) + _ref_mth(leaves[k:])).digest()


def _leaves(n):
    return [hashlib.sha256(b"\x00" + bytes([i % 256, i // 256])).digest() for i in range(n)]


def _hex(d):
    return "sha256:" + d.hex()


class TestMerkle:
    @pytest.mark.parametrize("n", list(range(1, 34)) + [64, 65, 100])
    def test_root_matches_rfc_definition(self, n):
        assert merkle_root(_leaves(n)) == _ref_mth(_leaves(n))

    @pytest.mark.parametrize("n", range(1, 22))
    def test_inclusion_proofs(self, n):
        leaves = _leaves(n)
        root = _hex(merkle_root(leaves))
        for i in range(n):
            proof = [_hex(p) for p in _inclusion_path(i, leaves)]
            from traceseal_observe.history_log import _verify_inclusion

            assert _verify_inclusion(leaves[i], i, n, [bytes.fromhex(p[7:]) for p in proof],
                                     bytes.fromhex(root[7:]))
            if proof:
                bad = list(proof)
                bad[0] = _hex(b"\x00" * 32)
                assert not _verify_inclusion(leaves[i], i, n, [bytes.fromhex(p[7:]) for p in bad],
                                             bytes.fromhex(root[7:]))

    def test_consistency_proofs_all_pairs(self):
        for n in range(1, 21):
            leaves = _leaves(n)
            new_root = _hex(merkle_root(leaves))
            for m in range(1, n + 1):
                old_root = _hex(merkle_root(leaves[:m]))
                proof = [_hex(p) for p in _subproof(m, leaves, True)]
                assert verify_consistency(m, n, old_root, new_root, proof), (m, n)
                if m < n:
                    other = _hex(merkle_root(_leaves(n + 1)[1 : m + 1]))
                    assert not verify_consistency(m, n, other, new_root, proof)
                    assert not verify_consistency(m, n, old_root, _hex(b"\x01" * 32), proof)

    def test_consistency_rejects_bad_sizes(self):
        r = _hex(merkle_root(_leaves(2)))
        assert not verify_consistency(0, 2, r, r, [])
        assert not verify_consistency(3, 2, r, r, [])
        assert not verify_consistency(True, 2, r, r, [])


# ---------------------------------------------------------------------------
# Chaining
# ---------------------------------------------------------------------------


class TestChaining:
    def test_fields_are_signed_and_linked(self, key):
        chain, rs = _make(key, 3)
        for i, r in enumerate(rs, start=1):
            verify_receipt_signature(r)
            ex = r.execution
            assert ex["chain_seq"] == i
            assert ex["chain_id"] == "agent-1"
            assert ex["chain_version"] == "1.0"
            assert ex["chained_at"] == r.attestation["attested_at"]
        assert rs[0].execution["chain_prev_hash"] == "genesis"
        assert rs[1].execution["chain_prev_hash"] == rs[0].receipt_hash
        assert rs[2].execution["chain_prev_hash"] == rs[1].receipt_hash
        assert chain.size == 3 and chain.head == rs[2].receipt_hash

    def test_all_operational_types_chain(self, key):
        chain = ReceiptChain(key, "mixed")
        s = chain.signer
        _, m = observe_model_call("p", "m", "https://e", s, lambda: {"ok": 1})
        _, t = observe_tool("t", s, lambda: 1)
        _, d = observe_data_flow("https://api.example.com/x", "POST", s, lambda: None)
        with WorkflowObserver("wf", "1", s) as wf:
            wf.add_step("m", m)
        o = sign_outcome(t, status="succeeded", outcome={"x": 1}, operator_key=s)
        verify_outcome(o, t)
        rs = [m, t, d, wf.receipt, o]
        assert [r.execution["chain_seq"] for r in rs] == [1, 2, 3, 4, 5]
        assert verify_chain(rs)["ok"]

    def test_plain_keys_are_unchanged(self, key):
        r = _tool(key, 0)
        assert not chain_mod.CHAIN_FIELDS.intersection(r.execution)

    def test_domain_receipts_refuse_chained_signer(self, key):
        chain = ReceiptChain(key, "x")
        with pytest.raises(ValueError, match="not chainable"):
            sign_execution_receipt({"receipt_type": "model_resolution"}, {}, chain.signer)
        assert chain.size == 0

    def test_concurrent_signing_produces_one_linear_chain(self, key):
        chain = ReceiptChain(key, "threads")
        out, lock = [], threading.Lock()

        def work(n):
            for i in range(25):
                r = _tool(chain.signer, (n, i))
                with lock:
                    out.append(r)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        report = verify_chain(out, checkpoint=chain.checkpoint())
        assert report["ok"] and report["count"] == 200
        assert report["checkpoint"]["method"] == "root_recomputed"

    def test_invalid_chain_id(self, key):
        with pytest.raises(ChainError):
            ReceiptChain(key, "bad id with spaces")
        with pytest.raises(ChainError):
            ReceiptChain(key, "x" * 65)

    def test_random_chain_id_by_default(self, key):
        assert ReceiptChain(key).chain_id != ReceiptChain(key).chain_id


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_complete_chain(self, key):
        _, rs = _make(key, 5)
        report = verify_chain(list(reversed(rs)))  # order of input is irrelevant
        assert report["ok"]
        assert report["starts_at_genesis"]
        assert (report["first_seq"], report["last_seq"], report["count"]) == (1, 5, 5)
        assert report["operator_fingerprint"] == key.fingerprint

    def test_deleted_receipt_is_a_gap(self, key):
        _, rs = _make(key, 6)
        report = verify_chain(rs[:2] + rs[4:])
        assert not report["ok"]
        assert report["gaps"] == [[3, 4]]

    def test_tampered_receipt_fails_signature(self, key):
        _, rs = _make(key, 3)
        rs[1].execution["output_hash"] = "sha256:" + "0" * 64
        report = verify_chain(rs)
        assert not report["ok"]
        assert any("signature" in e for e in report["errors"])

    def test_resigned_replacement_breaks_link(self, key):
        """An operator who re-signs a replacement for seq 2 can't fix seq 3's link."""
        _, rs = _make(key, 3)
        # Same key and chain_id, same seq 1, then a different seq 2.
        other = ReceiptChain(key, "agent-1")
        _tool(other.signer, 0)
        replacement = _tool(other.signer, 99)
        assert replacement.execution["chain_seq"] == 2
        assert replacement.receipt_hash != rs[1].receipt_hash
        report = verify_chain([rs[0], replacement, rs[2]])
        assert not report["ok"]
        assert any("chain_prev_hash does not match" in e for e in report["errors"])

    def test_two_receipts_same_seq_is_a_fork(self, key):
        _, rs_a = _make(key, 2)
        _, rs_b = _make(key, 2, offset=10)  # same key and chain_id, other history
        report = verify_chain(rs_a + [rs_b[1]])
        assert 2 in report["forks"] and not report["ok"]

    def test_duplicate_copy_is_only_a_warning(self, key):
        _, rs = _make(key, 2)
        copy = type(rs[1])(**json.loads(json.dumps(rs[1].to_dict())))
        report = verify_chain(rs + [copy])
        assert report["ok"] and report["warnings"]

    def test_mixed_chains_and_keys_rejected(self, key):
        _, a = _make(key, 1, "a")
        _, b = _make(key, 1, "b")
        _, c = _make(OperatorKey.generate(), 1, "a")
        assert not verify_chain(a + b)["ok"]
        assert not verify_chain(a + c)["ok"]
        assert not verify_chain(a, chain_id="other")["ok"]
        assert not verify_chain(a, operator_public_key="00" * 32)["ok"]

    def test_key_hex_case_is_not_a_key_change(self, key):
        _, rs = _make(key, 2)
        rs[1].attestation["operator_public_key"] = rs[1].attestation["operator_public_key"].upper()
        assert verify_chain(rs)["ok"]

    def test_unchained_receipt_rejected(self, key):
        report = verify_chain([_tool(key, 0)])
        assert not report["ok"] and "not a chained receipt" in report["errors"][0]

    def test_empty_and_garbage_input(self):
        assert not verify_chain([])["ok"]
        assert not verify_chain([{"not": "a receipt"}])["ok"]

    def test_partial_segment_without_checkpoint_is_ok_but_not_from_genesis(self, key):
        _, rs = _make(key, 5)
        report = verify_chain(rs[2:])
        assert report["ok"] and not report["starts_at_genesis"]


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------


def _witness():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    name = "witness.example.com"
    key = b"\x04" + pub
    key_hash = hashlib.sha256(name.encode() + b"\n" + key).digest()[:4]
    vkey = f"{name}+{key_hash.hex()}+{base64.b64encode(key).decode()}"

    def cosign(note, t):
        body = note[: note.index("\n\n") + 1]
        sig = sk.sign(f"cosignature/v1\ntime {t}\n{body}".encode())
        line = base64.b64encode(key_hash + struct.pack(">Q", t) + sig).decode()
        return note + f"— {name} {line}\n"

    return vkey, cosign


class TestCheckpoints:
    def test_checkpoint_format(self, key):
        chain, _ = _make(key, 3)
        note = chain.checkpoint()
        lines = note.split("\n")
        assert lines[0] == chain.origin
        assert lines[1] == "3"
        assert base64.b64decode(lines[2]) == merkle_root(chain._leaves)
        assert lines[3] == ""
        assert lines[4].startswith("— " + chain.origin + " ")
        info = verify_chain_checkpoint(note, key.public_key_hex, "agent-1")
        assert info["tree_size"] == 3 and info["root"] == chain.root()
        assert chain.verifier_key == checkpoint_verifier_key(key.public_key_hex, "agent-1")

    def test_tail_truncation_detected_against_checkpoint(self, key):
        chain, rs = _make(key, 5)
        note = chain.checkpoint()
        report = verify_chain(rs[:3], checkpoint=note)
        assert not report["ok"]
        assert any("inclusion proof for seq 3 is required" in e for e in report["errors"])

        proof = chain.inclusion_proof(3)
        report = verify_chain(rs[:3], checkpoint=note, inclusion_proof=proof)
        assert report["ok"]
        assert report["checkpoint"]["anchored"]
        assert report["checkpoint"]["receipts_after_segment"] == 2

    def test_middle_segment_with_proof(self, key):
        chain, rs = _make(key, 8)
        note = chain.checkpoint(6)
        report = verify_chain(rs[2:5], checkpoint=note, inclusion_proof=chain.inclusion_proof(5, 6))
        assert report["ok"] and report["checkpoint"]["anchor_seq"] == 5

    def test_wrong_proof_rejected(self, key):
        chain, rs = _make(key, 5)
        report = verify_chain(rs[:3], checkpoint=chain.checkpoint(),
                              inclusion_proof=chain.inclusion_proof(2))
        assert not report["ok"]

    def test_checkpoint_of_a_different_history_rejected(self, key):
        chain_a, rs_a = _make(key, 3)
        chain_b, _ = _make(key, 3, offset=10)  # same key and id, other receipts
        report = verify_chain(rs_a, checkpoint=chain_b.checkpoint())
        assert not report["ok"]
        assert any("root differs" in e for e in report["errors"])

    def test_receipts_beyond_checkpoint_warned(self, key):
        chain, rs = _make(key, 4)
        report = verify_chain(rs, checkpoint=chain.checkpoint(2))
        assert report["ok"]
        assert any("not covered" in w for w in report["warnings"])

    def test_tampered_or_foreign_checkpoint(self, key):
        chain, rs = _make(key, 3)
        note = chain.checkpoint()
        bad = note.replace("\n3\n", "\n4\n", 1)
        assert not verify_chain(rs, checkpoint=bad)["ok"]
        other = ReceiptChain(OperatorKey.generate(), "agent-1")
        _tool(other.signer, 0)
        assert not verify_chain(rs, checkpoint=other.checkpoint())["ok"]
        with pytest.raises(ChainError):
            verify_chain_checkpoint(note, key.public_key_hex, "agent-2")
        with pytest.raises(ChainError):
            verify_chain_checkpoint("garbage", key.public_key_hex, "agent-1")

    def test_witness_cosignature(self, key):
        chain, rs = _make(key, 3)
        vkey, cosign = _witness()
        note = cosign(chain.checkpoint(), 1_900_000_000)
        info = verify_chain_checkpoint(note, key.public_key_hex, "agent-1", witness_vkeys=[vkey])
        assert info["witnesses"] == [{"name": "witness.example.com", "time": 1_900_000_000}]
        assert verify_chain(rs, checkpoint=note, witness_vkeys=[vkey])["ok"]

        # A required witness that did not cosign fails.
        other_vkey, _ = _witness()
        assert not verify_chain(rs, checkpoint=chain.checkpoint(), witness_vkeys=[vkey])["ok"]
        with pytest.raises(ChainError):
            verify_chain_checkpoint(note, key.public_key_hex, "agent-1", witness_vkeys=[other_vkey])

    def test_consistency_between_checkpoints(self, key):
        chain, _ = _make(key, 7)
        old, new = chain.root(3), chain.root()
        assert verify_consistency(3, 7, old, new, chain.consistency_proof(3))
        assert not verify_consistency(3, 7, chain.root(4), new, chain.consistency_proof(3))

    def test_inclusion_api(self, key):
        chain, rs = _make(key, 5)
        for i, r in enumerate(rs, start=1):
            assert verify_inclusion(r.receipt_hash, i, 5, chain.root(), chain.inclusion_proof(i))
        assert not verify_inclusion(rs[0].receipt_hash, 2, 5, chain.root(), chain.inclusion_proof(2))
        assert receipt_leaf_hash(rs[0].receipt_hash) == chain._leaves[0]
        with pytest.raises(ChainError):
            chain.inclusion_proof(6)
        with pytest.raises(ChainError):
            chain.checkpoint(0)


# ---------------------------------------------------------------------------
# Windows ("did you send user data to X between 2pm and 4pm?")
# ---------------------------------------------------------------------------


class TestWindow:
    def _chain_with_times(self, key, times):
        chain = ReceiptChain(key, "w")
        out = []
        for t in times:
            original = chain_mod._sign_unchained

            def at_time(execution, provenance, k, attested_at, _t=t):
                execution["chained_at"] = _t
                return original(execution, provenance, k, _t)

            chain_mod._sign_unchained = at_time
            try:
                out.append(_tool(chain.signer, t))
            finally:
                chain_mod._sign_unchained = original
        return chain, out

    def test_window_bounded_on_both_sides(self, key):
        times = ["2026-10-01T13:00:00Z", "2026-10-01T14:30:00Z",
                 "2026-10-01T15:00:00Z", "2026-10-01T16:30:00Z"]
        _, rs = self._chain_with_times(key, times)
        w = ("2026-10-01T14:00:00Z", "2026-10-01T16:00:00Z")
        report = verify_chain(rs[1:], window=w)
        assert report["ok"]
        assert report["window"]["covers_start"] is False  # seq 2 is inside the window
        assert not report["window"]["complete"]
        report = verify_chain(rs, window=w)
        assert report["window"]["complete"] and report["window"]["receipts_in_window"] == 2
        report = verify_chain(rs[:3], window=w)  # last receipt is inside: tail unproven
        assert not report["window"]["complete"]

    def test_window_end_proven_by_witnessed_checkpoint(self, key):
        times = ["2026-10-01T13:00:00Z", "2026-10-01T15:00:00Z"]
        chain, rs = self._chain_with_times(key, times)
        vkey, cosign = _witness()
        end = "2026-10-01T16:00:00Z"
        late = 1790870400  # 2026-10-01T16:00:00Z
        note = cosign(chain.checkpoint(), late)
        report = verify_chain(rs, checkpoint=note, witness_vkeys=[vkey],
                              window=("2026-10-01T14:00:00Z", end))
        assert report["window"]["complete"]
        early = cosign(chain.checkpoint(), late - 1)
        report = verify_chain(rs, checkpoint=early, witness_vkeys=[vkey],
                              window=("2026-10-01T14:00:00Z", end))
        assert not report["window"]["complete"]

    def test_bad_window(self, key):
        _, rs = _make(key, 1)
        assert not verify_chain(rs, window=("nope", "2026-10-01T16:00:00Z"))["ok"]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_reopen_continues_chain(self, key, tmp_path):
        with ReceiptChain.open(tmp_path / "c", key, "agent-1") as chain:
            first = [_tool(chain.signer, i) for i in range(3)]
            root3 = chain.root()
        with ReceiptChain.open(tmp_path / "c", key) as chain:
            assert chain.chain_id == "agent-1" and chain.size == 3
            assert chain.root() == root3
            more = [_tool(chain.signer, i) for i in range(3, 5)]
            note = chain.checkpoint()
        assert more[0].execution["chain_prev_hash"] == first[-1].receipt_hash
        assert verify_chain(first + more, checkpoint=note)["ok"]

    def test_second_process_is_locked_out(self, key, tmp_path):
        chain = ReceiptChain.open(tmp_path / "c", key, "a")
        with pytest.raises(ChainError, match="another process"):
            ReceiptChain.open(tmp_path / "c", key, "a")
        chain.close()
        ReceiptChain.open(tmp_path / "c", key, "a").close()

    def test_closed_chain_refuses_to_sign(self, key, tmp_path):
        chain = ReceiptChain.open(tmp_path / "c", key, "a")
        chain.close()
        with pytest.raises(ChainError):
            _tool(chain.signer, 0)

    def test_wrong_key_or_id_refused(self, key, tmp_path):
        ReceiptChain.open(tmp_path / "c", key, "a").close()
        with pytest.raises(ChainError, match="operator key"):
            ReceiptChain.open(tmp_path / "c", OperatorKey.generate(), "a")
        with pytest.raises(ChainError, match="not 'b'"):
            ReceiptChain.open(tmp_path / "c", key, "b")
        # a failed open must not leave the lock held
        ReceiptChain.open(tmp_path / "c", key, "a").close()

    def test_partial_trailing_record_is_dropped(self, key, tmp_path):
        with ReceiptChain.open(tmp_path / "c", key, "a") as chain:
            rs = [_tool(chain.signer, i) for i in range(2)]
        with open(tmp_path / "c" / "receipt-hashes.bin", "ab") as fh:
            fh.write(b"\x01" * 7)
        with ReceiptChain.open(tmp_path / "c", key) as chain:
            assert chain.size == 2
            nxt = _tool(chain.signer, 2)
        assert verify_chain(rs + [nxt])["ok"]
        assert (tmp_path / "c" / "receipt-hashes.bin").stat().st_size == 96

    def test_chained_signer_cannot_seed_a_chain(self, key):
        chain = ReceiptChain(key, "a")
        with pytest.raises(ChainError):
            ReceiptChain(chain.signer, "b")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_verify_ok_and_gap(self, key, tmp_path, capsys):
        chain, rs = _make(key, 4)
        paths = []
        for r in rs:
            p = tmp_path / f"{r.execution['chain_seq']}.json"
            p.write_text(r.to_json())
            paths.append(str(p))
        cp = tmp_path / "cp.txt"
        cp.write_text(chain.checkpoint())
        assert chain_mod.main(["verify", *paths, "--checkpoint", str(cp)]) == 0
        assert "[OK]" in capsys.readouterr().out
        assert chain_mod.main(["verify", paths[0], paths[3]]) == 1
        assert "GAP: seq 2..3" in capsys.readouterr().out
        assert chain_mod.main(["verify", *paths, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["count"] == 4
        assert chain_mod.main(["verify", str(tmp_path / "missing.json")]) == 2
