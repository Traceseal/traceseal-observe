"""Regression tests for the 2026-11 cryptographic red-team findings
(observe 1.6.0): key change across a gap (F4), small-order and
non-canonical Ed25519 keys (F8), fork framing through unsigned bytes (F3),
compromise declarations (F6), duplicate JSON keys (F9) and crashes (F7).
The re-timestamped stale checkpoint (F5) is covered in
test_trusted_time_and_keys.py and test_receipt_chain.py."""

from __future__ import annotations

import copy
import json
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from traceseal_observe import (
    OperatorKey,
    Receipt,
    RemoteOperatorKey,
    _sign_unchained,
    is_weak_ed25519_public_key,
    load_ed25519_public_key,
    loads_receipt_json,
    observe_tool,
    public_key_fingerprint,
    verify_receipt_signature,
)
from traceseal_observe.chain import (
    ChainError,
    ReceiptChain,
    _acceptance_message,
    load_receipt,
    verify_chain,
    verify_chain_checkpoint,
)

P = 2**255 - 19
IDENTITY = "01" + "00" * 31
# (R = basepoint, S = 1): valid for every message under the identity key.
UNIVERSAL_SIG = "58" + "66" * 31 + "01" + "00" * 31


def _enc(y: int, sign: int = 0) -> bytes:
    return (y | (sign << 255)).to_bytes(32, "little")


# Canonical encodings of all 8 points of the torsion subgroup (order | 8).
SMALL_ORDER_CANONICAL = [
    "0100000000000000000000000000000000000000000000000000000000000000",  # identity
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
    "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
]


def _key_obj(hex_key: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))


def _forged(execution: dict, key_hex: str = IDENTITY) -> Receipt:
    return Receipt("1.0", execution, {"provenance_version": "1.0", "provider_attestation": "none"}, {
        "operator_public_key": key_hex,
        "operator_fingerprint": public_key_fingerprint(_key_obj(key_hex)),
        "attested_at": "2026-10-01T00:00:00Z",
        "signature": UNIVERSAL_SIG,
    })


class TestWeakKeys:
    def test_all_small_order_points_rejected(self):
        for hex_key in SMALL_ORDER_CANONICAL:
            assert is_weak_ed25519_public_key(hex_key), hex_key
            assert is_weak_ed25519_public_key(bytes.fromhex(hex_key))
            assert is_weak_ed25519_public_key(_key_obj(hex_key))

    def test_list_is_the_whole_torsion_subgroup(self):
        # 8 distinct encodings, closed under the group law: the full E[8].
        from traceseal_observe import _ed25519_add, _ed25519_decode_point

        points = {_ed25519_decode_point(bytes.fromhex(h)) for h in SMALL_ORDER_CANONICAL}
        assert None not in points and len(points) == 8
        assert all(_ed25519_add(a, b) in points for a in points for b in points)

    def test_non_canonical_encodings_rejected(self):
        # y >= p (19 values fit in 255 bits), both sign bits
        for y in range(P, 2**255):
            for sign in (0, 1):
                assert is_weak_ed25519_public_key(_enc(y, sign))
        # x = 0 with the sign bit set ("-0")
        assert is_weak_ed25519_public_key(_enc(1, 1))
        assert is_weak_ed25519_public_key(_enc(P - 1, 1))

    def test_off_curve_and_malformed_rejected(self):
        assert is_weak_ed25519_public_key(_enc(2))  # y = 2 is not on the curve
        for bad in (b"", b"\x01" * 31, "zz" * 32, "01" * 31, 7, None):
            assert is_weak_ed25519_public_key(bad)

    def test_real_and_mixed_order_keys_accepted(self):
        from traceseal_observe import _ed25519_add, _ed25519_decode_point

        for _ in range(20):
            k = OperatorKey.generate()
            assert not is_weak_ed25519_public_key(k.public_key_hex)
        # A + T (T of order 8) is not small-order: 8(A+T) = 8A != identity.
        a = _ed25519_decode_point(bytes.fromhex(OperatorKey.generate().public_key_hex))
        t = _ed25519_decode_point(bytes.fromhex(SMALL_ORDER_CANONICAL[4]))
        x, y = _ed25519_add(a, t)
        assert not is_weak_ed25519_public_key(_enc(y, x & 1))

    def test_identity_key_universal_forgery_rejected(self):
        a = _forged({"receipt_type": "tool", "tool_name": "refund", "amount": "10"})
        with pytest.raises(ValueError, match="small-order"):
            verify_receipt_signature(a)
        for hex_key in SMALL_ORDER_CANONICAL:
            with pytest.raises(ValueError):
                verify_receipt_signature(_forged({"receipt_type": "tool"}, hex_key))

    def test_operator_key_objects_reject_weak_keys(self):
        for hex_key in SMALL_ORDER_CANONICAL:
            with pytest.raises(ValueError):
                OperatorKey(name="w", private_key=None, public_key=_key_obj(hex_key))
            with pytest.raises(ValueError):
                RemoteOperatorKey("w", public_key=hex_key, sign_fn=lambda m: b"\x00" * 64)
            with pytest.raises(ValueError):
                RemoteOperatorKey("w", public_key=bytes.fromhex(hex_key), sign_fn=lambda m: b"")
            with pytest.raises(ValueError):
                load_ed25519_public_key(hex_key)
        good = OperatorKey.generate()
        assert RemoteOperatorKey("ok", public_key=good.public_key_hex, sign_fn=good.sign)

    def test_rotation_to_small_order_key_rejected(self):
        k1 = OperatorKey.generate()
        chain = ReceiptChain(k1, "agent")
        rs = [observe_tool("t", chain.signer, lambda: 1)[1]]
        ex = {
            "receipt_type": "chain_key_rotation", "rotation_version": "1.0",
            "rotation_reason": "scheduled", "previous_public_key": k1.public_key_hex,
            "next_public_key": IDENTITY, "chain_version": "1.0", "chain_id": "agent",
            "chain_seq": 2, "chain_prev_hash": rs[0].receipt_hash,
            "chained_at": "2026-10-01T00:00:00Z",
        }
        ex["next_key_acceptance"] = UNIVERSAL_SIG
        _acceptance_message(ex)  # well-formed message; the key is the problem
        rot = _sign_unchained(ex, {"provenance_version": "1.0", "provider_attestation": "none"},
                              k1, "2026-10-01T00:00:00Z")
        rs.append(rot)
        rs.append(_forged({"receipt_type": "tool", "tool_name": "anything",
                           "chain_version": "1.0", "chain_id": "agent", "chain_seq": 3,
                           "chain_prev_hash": rot.receipt_hash,
                           "chained_at": "2026-10-01T00:00:00Z"}))
        report = verify_chain(rs, operator_public_key=k1.public_key_hex)
        assert not report["ok"]
        assert any("small-order" in e for e in report["errors"])
        assert report["head_public_key"] == k1.public_key_hex

    def test_rotate_key_refuses_weak_key(self):
        chain = ReceiptChain(OperatorKey.generate(), "agent")
        weak = object.__new__(OperatorKey)
        weak.name, weak.private_key, weak.public_key = "w", None, _key_obj(IDENTITY)
        with pytest.raises(ChainError, match="small-order"):
            chain.rotate_key(weak)

    def test_weak_witness_key_rejected(self):
        import base64
        import hashlib

        key = OperatorKey.generate()
        chain = ReceiptChain(key, "agent")
        observe_tool("t", chain.signer, lambda: 1)
        name = "witness.example.com"
        raw = b"\x04" + bytes.fromhex(IDENTITY)
        kh = hashlib.sha256(name.encode() + b"\n" + raw).digest()[:4]
        vkey = f"{name}+{kh.hex()}+{base64.b64encode(raw).decode()}"
        with pytest.raises(ChainError, match="small-order"):
            verify_chain_checkpoint(chain.checkpoint(), key.public_key_hex, "agent",
                                    witness_vkeys=[vkey])
        with pytest.raises(ChainError):
            verify_chain_checkpoint(chain.checkpoint(), IDENTITY, "agent")


class TestGapKeySwitch:
    def _forged_after_gap(self):
        victim, attacker = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(victim, "payments")
        honest = [observe_tool("lookup", chain.signer, lambda: 1)[1] for _ in range(3)]
        forged, prev = [], "sha256:" + "ab" * 32
        for seq in (5, 6):
            body = {"receipt_type": "tool", "tool_name": "wire", "chain_version": "1.0",
                    "chain_id": "payments", "chain_seq": seq, "chain_prev_hash": prev,
                    "chained_at": "2026-10-01T12:00:00Z"}
            r = _sign_unchained(body, {"provenance_version": "1.0"}, attacker,
                                "2026-10-01T12:00:00Z")
            forged.append(r)
            prev = r.receipt_hash
        return victim, attacker, honest, forged

    def test_key_change_across_gap_is_an_error(self):
        victim, attacker, honest, forged = self._forged_after_gap()
        report = verify_chain(honest + forged, operator_public_key=victim.public_key_hex)
        assert not report["ok"]
        assert any("across a gap" in e for e in report["errors"])
        assert report["head_public_key"] == victim.public_key_hex  # never adopted

    def test_unrotated_key_cannot_sign_checkpoints(self):
        victim, attacker, honest, forged = self._forged_after_gap()
        evil = ReceiptChain(attacker, "payments")
        for _ in range(6):
            observe_tool("x", evil.signer, lambda: 1)
        report = verify_chain(honest + forged, checkpoint=evil.checkpoint())
        assert any("not signed by any key of this chain" in e for e in report["errors"])

    def test_same_key_across_gap_is_only_a_gap(self):
        chain = ReceiptChain(OperatorKey.generate(), "a")
        rs = [observe_tool("t", chain.signer, lambda: 1)[1] for _ in range(4)]
        report = verify_chain([rs[0], rs[3]])
        assert report["gaps"] == [[2, 3]] and not report["errors"]


class TestForkFraming:
    def _chain(self, n=3):
        key = OperatorKey.generate()
        chain = ReceiptChain(key, "support")
        return key, chain, [observe_tool(f"t{i}", chain.signer, lambda: 1)[1] for i in range(n)]

    def _twin(self, r):
        twin = Receipt(**copy.deepcopy(r.to_dict()))
        twin.attestation["attested_at"] = "1999-01-01T00:00:00Z"  # unsigned
        verify_receipt_signature(twin)
        assert twin.receipt_hash != r.receipt_hash
        return twin

    def test_unsigned_attestation_difference_is_not_a_fork(self):
        key, chain, rs = self._chain()
        cp = chain.checkpoint()
        for order in (rs + [self._twin(rs[1])], [self._twin(rs[1])] + rs):
            report = verify_chain(order, operator_public_key=key.public_key_hex, checkpoint=cp)
            assert report["ok"], report["errors"]
            assert report["forks"] == []
            assert any("outside the signed payload" in w for w in report["warnings"])

    def test_head_twin_resolved_by_checkpoint(self):
        key, chain, rs = self._chain()
        cp = chain.checkpoint()
        twin = self._twin(rs[2])
        report = verify_chain([twin] + rs, checkpoint=cp)
        assert report["ok"], report["errors"]
        assert report["head_hash"] == rs[2].receipt_hash
        # partial segment + inclusion proof
        report = verify_chain([twin, rs[1], rs[2]], checkpoint=cp,
                              inclusion_proof=chain.inclusion_proof(3))
        assert report["ok"], report["errors"]

    def test_copy_resigned_by_another_key_is_not_a_fork(self):
        key, chain, rs = self._chain()
        outsider = OperatorKey.generate()
        resigned = _sign_unchained(rs[1].execution, rs[1].provenance, outsider,
                                   rs[1].attestation["attested_at"])
        report = verify_chain([resigned] + rs, operator_public_key=key.public_key_hex)
        assert report["ok"], report["errors"]
        assert report["forks"] == []

    def test_different_signed_content_is_still_a_fork(self):
        key, chain, rs = self._chain()
        other = ReceiptChain(key, "support")
        alt = [observe_tool(f"other{i}", other.signer, lambda: 1)[1] for i in range(2)]
        report = verify_chain(rs + [alt[1]])
        assert report["forks"] == [2] and not report["ok"]


class TestCompromise:
    def test_compromised_receipts_fail_by_default(self):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "agent")
        rs = [observe_tool("t", chain.signer, lambda: 1)[1] for _ in range(3)]
        rs.append(chain.rotate_key(k2, reason="compromise", compromised_after_seq=1))
        rs.append(observe_tool("t", chain.signer, lambda: 1)[1])
        report = verify_chain(rs, operator_public_key=k1.public_key_hex)
        assert not report["ok"] and report["compromised_seqs"] == [[2, 3]]
        assert verify_chain(rs, operator_public_key=k1.public_key_hex,
                            allow_compromised=True)["ok"]

    def test_cli_flag(self, tmp_path, capsys):
        from traceseal_observe.chain import main

        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "agent")
        rs = [observe_tool("t", chain.signer, lambda: 1)[1] for _ in range(2)]
        rs.append(chain.rotate_key(k2, reason="compromise", compromised_after_seq=1))
        files = []
        for i, r in enumerate(rs):
            p = tmp_path / f"{i}.json"
            p.write_text(r.to_json())
            files.append(str(p))
        assert main(["verify", *files]) == 1
        assert main(["verify", "--allow-compromised", *files]) == 0


class TestStrictJson:
    def test_duplicate_keys_rejected(self, tmp_path):
        r = observe_tool("lookup_balance", OperatorKey.generate(), lambda: 1)[1]
        raw = json.dumps(r.to_dict()).replace(
            '"tool_name": "lookup_balance"',
            '"tool_name": "wire_transfer_1M", "tool_name": "lookup_balance"')
        p = tmp_path / "dup.json"
        p.write_text(raw)
        with pytest.raises(ChainError, match="duplicate JSON key"):
            load_receipt(p)
        with pytest.raises(ValueError):
            loads_receipt_json('{"a": NaN}')
        assert load_receipt(_write(tmp_path / "ok.json", r)).receipt_hash == r.receipt_hash

    def test_bool_and_null_in_signed_payload_rejected(self):
        key = OperatorKey.generate()
        for value in (True, None):
            r = _sign_unchained({"receipt_type": "tool", "flag": value}, {}, key,
                                "2026-10-01T00:00:00Z")
            with pytest.raises(ValueError, match="RECEIPT-SPEC"):
                verify_receipt_signature(r)
        # floats are not forbidden by §3; still verify
        r = _sign_unchained({"receipt_type": "tool", "x": 1.5}, {}, key, "2026-10-01T00:00:00Z")
        verify_receipt_signature(r)


def _write(path, receipt):
    path.write_text(receipt.to_json())
    return path


class TestNeverRaises:
    def test_hostile_shapes(self):
        key = OperatorKey.generate()
        chain = ReceiptChain(key, "c")
        good = observe_tool("t", chain.signer, lambda: 1)[1]
        cp = chain.checkpoint()

        def mutate(fn):
            r = Receipt(**copy.deepcopy(good.to_dict()))
            fn(r)
            return r

        hostile = [
            mutate(lambda r: r.attestation.__setitem__("operator_public_key", 7)),
            mutate(lambda r: r.attestation.__setitem__("signature", ["x"])),
            mutate(lambda r: r.attestation.__setitem__("attested_at", "\ud800")),
            mutate(lambda r: r.execution.__setitem__("tool_name", "\ud800")),
            mutate(lambda r: setattr(r, "attestation", None)),
            mutate(lambda r: setattr(r, "execution", ["x"])),
            mutate(lambda r: r.execution.__setitem__("chain_seq", 10**30)),
            mutate(lambda r: r.execution.__setitem__(1, "x")),
            mutate(lambda r: r.attestation.pop("signature")),
        ]
        for h in hostile:
            for receipts in ([h], [good, h], [h, good]):
                report = verify_chain(receipts, checkpoint=cp)
                assert isinstance(report, dict)
            assert not verify_chain([h])["ok"]
        for kwargs in (
            {"operator_public_key": 7},
            {"checkpoint": 42},
            {"checkpoint": cp, "witness_vkeys": [None]},
            {"checkpoint": cp, "consistency_witness_vkeys": ["a+b+c"]},
            {"window": ("a",)},
            {"window": 5},
            {"checkpoint": cp, "checkpoint_timestamps": [b"\x30\x00", "str", None]},
            {"start_checkpoint": cp, "start_consistency_proof": {"x": 1}},
        ):
            report = verify_chain([good], **kwargs)
            assert isinstance(report, dict) and not report["ok"], kwargs
        assert isinstance(verify_chain([good], checkpoint=cp, inclusion_proof="nope"), dict)
        assert not verify_chain("nope")["ok"]
        assert not verify_chain([None, 1, "x"])["ok"]

    def test_random_byte_flips_never_raise(self):
        key = OperatorKey.generate()
        chain = ReceiptChain(key, "c")
        rs = [observe_tool("t", chain.signer, lambda: 1)[1] for _ in range(2)]
        rng = random.Random(7)
        text = json.dumps([r.to_dict() for r in rs])
        for _ in range(200):
            i = rng.randrange(len(text))
            mutated = text[:i] + rng.choice('0aZ"{}[],:\\') + text[i + 1:]
            try:
                data = loads_receipt_json(mutated)
                receipts = [Receipt(**d) for d in data]
            except (ValueError, TypeError, KeyError, AttributeError):
                continue
            verify_chain(receipts)


def test_private_key_roundtrip_unaffected():
    sk = Ed25519PrivateKey.generate()
    key = OperatorKey(name="x", private_key=sk, public_key=sk.public_key())
    r = observe_tool("t", key, lambda: 1)[1]
    verify_receipt_signature(r)
