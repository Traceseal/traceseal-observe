"""Regression tests for the 1.6.0 red-team findings on evidence packs,
analyse() / map_controls() and the operator key directory."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from traceseal_observe import (
    OperatorKey,
    Receipt,
    ReceiptChain,
    sha256_of,
    sign_execution_receipt,
    sign_incident,
    verify_receipt_signature,
)
from traceseal_observe import directory as dir_mod
from traceseal_observe import report as report_mod
from traceseal_observe.directory import (
    build_directory,
    check_receipts,
    verify_directory,
)
from traceseal_observe.report import (
    _sha256_file,
    analyse,
    build_pack,
    render_markdown,
    verify_pack,
)

PROV = {"provenance_version": "1.0", "provider_attestation": "none"}
PEPPER = b"0123456789abcdef-pepper"


def _model(key, calls, t="2026-10-01T12:00:00Z"):
    return sign_execution_receipt(
        {"receipt_type": "model", "provider": "anthropic", "model": "m", "started_at": t,
         "input_hash": "sha256:" + "0" * 64, "output_hash": "sha256:" + "1" * 64,
         "requested_tool_calls": [{"id": i, "name": n, "input_hash": sha256_of(a)} for i, n, a in calls]},
        PROV, key)


def _tool(key, name, args, t="2026-10-01T12:05:00Z", **ctx):
    ex = {"receipt_type": "tool", "tool_name": name, "started_at": t,
          "input_hash": sha256_of(args), "output_hash": "sha256:" + "2" * 64}
    if ctx:
        ex["context"] = {"context_version": "1.0", **ctx}
    return sign_execution_receipt(ex, PROV, key)


def _write(tmp_path, receipts):
    d = tmp_path / "in"
    d.mkdir(exist_ok=True)
    paths = []
    for i, r in enumerate(receipts):
        p = d / f"r{i}.json"
        p.write_text(r.to_json() if isinstance(r, Receipt) else r)
        paths.append(p)
    return paths


def _failing_pack(tmp_path, key):
    """A pack whose own analysis fails: a refund without the required approval."""
    m = _model(key, [("toolu_A", "issue_refund", {"amount": 20})])
    t = _tool(key, "issue_refund", {"amount": 9999}, caused_by=[m.receipt_hash], tool_call_id="toolu_A")
    pack = tmp_path / "pack"
    s = build_pack(pack, _write(tmp_path, [m, t]), operator_key=key, require_approval=["issue_refund"])
    assert not s["ok"]
    return pack


def _remanifest(pack):
    files = sorted(p for p in pack.rglob("*") if p.is_file()
                   and p.name not in ("manifest.json", "pack.receipt.json"))
    (pack / "manifest.json").write_text(json.dumps(
        {"pack_version": "1.1", "files": {p.relative_to(pack).as_posix(): _sha256_file(p) for p in files}}))
    return files


def _resign(pack, key, **overrides):
    old = json.loads((pack / "pack.receipt.json").read_text())["execution"]
    ex = dict(old, manifest_hash=_sha256_file(pack / "manifest.json"),
              file_count=len(json.loads((pack / "manifest.json").read_text())["files"]), **overrides)
    (pack / "pack.receipt.json").write_text(sign_execution_receipt(ex, PROV, key).to_json())


def _forge_pass(pack):
    rep = json.loads((pack / "report.json").read_text())
    rep["ok"] = True
    rep["trace"]["errors"], rep["trace"]["ok"] = [], True
    for c in rep["controls"]:
        if c["status"] == "issues":
            c["status"], c["problems"] = "evidence", []
    (pack / "report.json").write_text(json.dumps(rep))
    (pack / "report.md").write_text(render_markdown(rep))


# ---------------------------------------------------------------------------
# 1. verify-pack: mandatory signature, pinned signer, re-derived findings
# ---------------------------------------------------------------------------


class TestVerifyPackTrust:
    def test_expected_keys_required(self, tmp_path):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        with pytest.raises(TypeError):
            verify_pack(pack)  # type: ignore[call-arg]  (required argument)
        with pytest.raises(ValueError, match="expected_keys"):
            verify_pack(pack, None)
        with pytest.raises(ValueError, match="64-hex"):
            verify_pack(pack, ["not-a-key"])

    def test_honest_failing_pack_is_intact_but_reports_issues(self, tmp_path, capsys):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        result = verify_pack(pack, [key.public_key_hex])
        assert result["ok"] and result["pinned"] and result["signed"]
        assert result["pack_result"] == "ISSUES FOUND"
        assert report_mod.main(["verify-pack", str(pack), "--operator-pubkey", key.public_key_hex]) == 3
        assert "auditor result (your clock and requirements): ISSUES FOUND" in capsys.readouterr().out

    def test_unsigned_pack_fails(self, tmp_path):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        (pack / "pack.receipt.json").unlink()
        result = verify_pack(pack, [key.public_key_hex])
        assert not result["ok"] and not result["signed"]
        assert any("not signed" in p for p in result["problems"])

    def test_unsigned_build_fails_verification(self, tmp_path):
        key = OperatorKey.generate()
        pack = tmp_path / "pack"
        build_pack(pack, _write(tmp_path, [_tool(key, "t", {})]))
        assert not verify_pack(pack, None, trust_signer_in_pack=True)["ok"]

    def test_invalid_pack_receipt_fails(self, tmp_path):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        data = json.loads((pack / "pack.receipt.json").read_text())
        data["execution"]["verification_ok"] = "true"
        (pack / "pack.receipt.json").write_text(json.dumps(data))
        result = verify_pack(pack, [key.public_key_hex])
        assert not result["ok"] and any("signature verification failed" in p for p in result["problems"])

    def test_forged_report_resigned_by_stranger(self, tmp_path):
        key, mallory = OperatorKey.generate(), OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        _forge_pass(pack)
        _remanifest(pack)
        _resign(pack, mallory, verification_ok="true")
        pinned = verify_pack(pack, [key.public_key_hex])
        assert not pinned["ok"] and not pinned["pinned"]
        assert any("not an expected operator key" in p for p in pinned["problems"])
        # Without a pin the signature is accepted, but the findings are re-derived.
        trusting = verify_pack(pack, None, trust_signer_in_pack=True)
        assert trusting["pinned"] is False and trusting["signed"]
        assert any("SIGNER NOT PINNED" in w for w in trusting["warnings"])
        problems = trusting["problems"]
        assert not trusting["ok"]
        assert any("report.json says ok=True, re-derived ok=False" in p for p in problems)
        assert any("Art. 14 / 26(2)" in p and "re-derived 'issues'" in p for p in problems)
        assert any("verification_ok='true'" in p for p in problems)
        assert trusting["pack_result"] == "ISSUES FOUND"

    def test_forged_report_signed_by_operator_still_caught(self, tmp_path):
        """Even the operator's own key cannot make report.json disagree with the receipts."""
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        _forge_pass(pack)
        _remanifest(pack)
        _resign(pack, key, verification_ok="true")
        result = verify_pack(pack, [key.public_key_hex])
        assert result["pinned"] and not result["ok"]
        assert any("re-derived ok=False" in p for p in result["problems"])

    def test_removed_receipt_with_manifest_entry(self, tmp_path):
        key, mallory = OperatorKey.generate(), OperatorKey.generate()
        m = _model(key, [("toolu_A", "lookup", {"q": 1})])
        t = _tool(key, "lookup", {"q": 1}, caused_by=[m.receipt_hash], tool_call_id="toolu_A")
        pack = tmp_path / "pack"
        build_pack(pack, _write(tmp_path, [m, t]), operator_key=key)
        victim = sorted((pack / "receipts").iterdir())[1]
        victim.unlink()
        _remanifest(pack)
        _resign(pack, mallory)  # forger keeps the original receipt_count
        result = verify_pack(pack, None, trust_signer_in_pack=True)
        assert not result["ok"]
        assert any("records 2 receipts, pack holds 1" in p for p in result["problems"])
        assert any("receipts=2, re-derived 1" in p for p in result["problems"])
        _resign(pack, mallory, receipt_count=1)  # ... or updates it: re-derivation still catches it
        result = verify_pack(pack, None, trust_signer_in_pack=True)
        assert not result["ok"] and any("re-derived 1" in p for p in result["problems"])

    def test_pack_without_analysis_options_fails_closed(self, tmp_path):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        rep = json.loads((pack / "report.json").read_text())
        del rep["analysis_options"]
        (pack / "report.json").write_text(json.dumps(rep))
        _remanifest(pack)
        _resign(pack, key)
        result = verify_pack(pack, [key.public_key_hex])
        assert not result["ok"] and any("analysis_options" in p for p in result["problems"])

    def test_cli_requires_pin(self, tmp_path, capsys):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        assert report_mod.main(["verify-pack", str(pack)]) == 2
        err = capsys.readouterr().err
        assert "--operator-pubkey" in err and "--trust-signer-in-pack" in err
        assert report_mod.main(["verify-pack", str(pack), "--operator-pubkey", "zz"]) == 2
        assert report_mod.main(["verify-pack", str(pack), "--trust-signer-in-pack"]) == 3
        assert "NOT PINNED" in capsys.readouterr().out


def test_rederivation_with_checkpoint_and_pin(tmp_path):
    """Checkpoints, approvals, the key pin and `now` recorded at build time are reused."""
    from test_incident_and_report import _scenario

    key, _, paths, cp = _scenario(tmp_path)
    pack = tmp_path / "pack"
    s = build_pack(pack, paths, operator_key=key, checkpoint_paths=[cp],
                   require_approval={"issue_refund"}, operator_keys=[key.public_key_hex],
                   now="2026-12-01T00:00:00Z")
    assert s["ok"], (s["chains"], s["trace"]["errors"])
    opts = json.loads((pack / "report.json").read_text())["analysis_options"]
    assert opts["now"] == "2026-12-01T00:00:00Z" and opts["operator_keys"] == [key.public_key_hex]
    assert opts["require_approval"] == ["issue_refund"] and opts["checkpoints"][0]["file"].startswith("checkpoints/")
    result = verify_pack(pack, [key.public_key_hex])
    assert result["ok"] and result["pack_result"] == "passed", result["problems"]
    assert report_mod.main(["verify-pack", str(pack), "--operator-pubkey", key.public_key_hex]) == 0


# ---------------------------------------------------------------------------
# 2. path safety
# ---------------------------------------------------------------------------


def _bare(tmp_path, files, name="p"):
    d = tmp_path / name
    (d / "receipts").mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({"pack_version": "1.1", "files": files}))
    return d


class TestPackPaths:
    def test_absolute_and_parent_paths_refused(self, tmp_path):
        secret = tmp_path / "victim.txt"
        secret.write_text("auditor-local secret\n")
        d = _bare(tmp_path, {str(secret): _sha256_file(secret),
                             "../victim.txt": _sha256_file(secret),
                             "receipts/../../victim.txt": _sha256_file(secret)})
        result = verify_pack(d, None, trust_signer_in_pack=True)
        assert not result["ok"]
        assert any("absolute path refused" in p for p in result["problems"])
        assert sum("'..'" in p for p in result["problems"]) == 2

    def test_symlinked_manifest_entry_refused(self, tmp_path):
        target = tmp_path / "outside.json"
        target.write_text("{}")
        d = _bare(tmp_path, {})
        os.symlink(target, d / "receipts" / "x.json")
        d.joinpath("manifest.json").write_text(json.dumps(
            {"files": {"receipts/x.json": _sha256_file(target)}}))
        result = verify_pack(d, None, trust_signer_in_pack=True)
        assert "symlink refused: receipts/x.json" in result["problems"] and not result["ok"]

    def test_symlinked_directory_refused(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "r.json").write_text("{}")
        d = _bare(tmp_path, {"sub/r.json": _sha256_file(outside / "r.json")})
        os.symlink(outside, d / "sub")
        result = verify_pack(d, None, trust_signer_in_pack=True)
        assert "symlink refused: sub/r.json" in result["problems"]
        assert "symlink refused: sub" in result["problems"]

    def test_unlisted_symlink_under_receipts_not_followed(self, tmp_path):
        key = OperatorKey.generate()
        pack = _failing_pack(tmp_path, key)
        os.symlink("/etc/passwd", pack / "receipts" / "zz.json")
        result = verify_pack(pack, [key.public_key_hex])
        assert not result["ok"] and "symlink refused: receipts/zz.json" in result["problems"]
        assert not any("Expecting value" in p for p in result["problems"])


# ---------------------------------------------------------------------------
# 3. hostile JSON never crashes verify_pack / build / analyse
# ---------------------------------------------------------------------------


class TestHostileJson:
    @pytest.mark.parametrize("manifest", ["[]", json.dumps({"files": ["a"]}), "{", json.dumps({"files": {"a": 1}})])
    def test_malformed_manifest(self, tmp_path, manifest):
        d = tmp_path / "p"
        d.mkdir()
        (d / "manifest.json").write_text(manifest)
        result = verify_pack(d, None, trust_signer_in_pack=True)
        assert not result["ok"] and result["problems"]

    def test_pack_receipt_not_json(self, tmp_path):
        d = _bare(tmp_path, {})
        (d / "pack.receipt.json").write_text("{")
        result = verify_pack(d, None, trust_signer_in_pack=True)
        assert any(p.startswith("pack receipt: not valid JSON") for p in result["problems"])

    @pytest.mark.parametrize("body", [
        {"receipt_version": "1.0", "execution": {}, "provenance": {}, "attestation": []},
        {"receipt_version": "1.0", "execution": [], "provenance": {}, "attestation": {}},
        {"receipt_version": "1.0", "execution": {}, "provenance": {},
         "attestation": {"operator_public_key": 5, "signature": ["x"]}},
        [1, 2],
    ])
    def test_hostile_receipt_in_pack(self, tmp_path, body):
        raw = json.dumps(body)
        d = _bare(tmp_path, {"receipts/r.json": "sha256:" + hashlib.sha256(raw.encode()).hexdigest()})
        (d / "receipts" / "r.json").write_text(raw)
        result = verify_pack(d, None, trust_signer_in_pack=True)
        assert not result["ok"] and any(p.startswith("receipts/r.json") for p in result["problems"])

    def test_analyse_hostile_receipts(self):
        key = OperatorKey.generate()
        hostile = [
            Receipt("1.0", {}, {}, []),
            Receipt("1.0", [], {}, {}),
            Receipt(None, None, None, None),
            Receipt("1.0", {"receipt_type": "tool"}, {}, {"operator_public_key": 1, "signature": 2}),
            sign_execution_receipt({"receipt_type": "outcome", "observed_at": "not-a-timestamp-20ch"}, PROV, key),
            sign_execution_receipt({"receipt_type": "tool", "tool_name": {"x": 1},
                                    "started_at": "2026-13-45T99:99:99Z"}, PROV, key),
            sign_execution_receipt({"receipt_type": "model", "served_model": ["a"], "provider": {}}, PROV, key),
            sign_execution_receipt({"receipt_type": "tool", "chain_id": {"x": 1}, "chain_seq": 1}, PROV, key),
        ]
        s = analyse(hostile, now="2026-11-01T00:00:00Z")
        assert not s["ok"] and len(s["signature_failures"]) == 5
        assert s["period"]["first"] is None  # malformed times are unknown, not a crash

    @pytest.mark.parametrize("patch", [{"reported_at": "yesterday"}, {"supersedes": {"x": 1}},
                                       {"deadlines": [{"regime": "x"}]}])
    def test_hostile_incident(self, patch):
        key = OperatorKey.generate()
        root = sign_incident(category="serious_incident", severity="critical", status="detected",
                             aware_at="2026-01-01T00:00:00Z", operator_key=key)
        ex = dict(root.execution, **patch)
        s = analyse([sign_execution_receipt(ex, PROV, key)], now="2026-10-01T00:00:00Z")
        # incident.py reports hostile values as problems (or analysis fails): never ok
        assert not s["ok"]
        assert s["analysis_failures"] or any(i.get("problems") for i in s["incidents"])
        assert {c["ref"]: c["status"] for c in s["controls"]}["Art. 73"] == "issues"

    def test_build_with_unparsable_receipt_file(self, tmp_path):
        key = OperatorKey.generate()
        paths = _write(tmp_path, [_tool(key, "t", {}), "{not json", json.dumps([1])])
        pack = tmp_path / "pack"
        s = build_pack(pack, paths, operator_key=key)
        assert not s["ok"] and len(s["signature_failures"]) == 2
        result = verify_pack(pack, [key.public_key_hex])
        # the pack is consistent (its findings re-derive), but the bad files are reported
        assert not any("re-derived" in p for p in result["problems"])
        assert any("not valid JSON" in p for p in result["problems"])


# ---------------------------------------------------------------------------
# 4. analyse(): signed time only; operator-key pin; multi-key warning
# ---------------------------------------------------------------------------


class TestAnalyseTimeAndKeys:
    def test_attested_at_never_used(self):
        from traceseal_observe.oversight import sign_policy_decision

        key = OperatorKey.generate()
        m = _model(key, [], t="2026-10-01T12:00:00Z")
        p = sign_policy_decision(policy_id="pii", decision="allow", stage="output",
                                 decided_at="2026-10-01T12:00:00Z", operator_key=key)
        p.attestation["attested_at"] = "2025-01-01T00:00:00Z"
        verify_receipt_signature(p)
        s = analyse([m, p], now="2026-11-01T00:00:00Z")
        assert s["period"]["first"] == s["period"]["last"] == "2026-10-01T12:00:00Z"
        assert s["period"]["days"] == 0
        assert {c["ref"]: c["status"] for c in s["controls"]}["Art. 19 / 26(6)"] == "partial"

    def test_operator_key_pin(self):
        key, stranger = OperatorKey.generate(), OperatorKey.generate()
        m = _model(key, [], t="2026-10-01T12:00:00Z")
        old = _model(stranger, [], t="2024-01-01T00:00:00Z")
        s = analyse([m, old], operator_keys=[key.public_key_hex.upper()])
        assert not s["ok"]
        assert s["foreign_key_receipts"] == [{"receipt": old.receipt_hash, "public_key": stranger.public_key_hex}]
        assert s["period"]["first"] == "2026-10-01T12:00:00Z"
        controls = {c["ref"]: c for c in s["controls"]}
        assert controls["Art. 12"]["status"] == "issues"
        assert any("pinned operator keys" in p for p in controls["Art. 12"]["problems"])
        assert analyse([m], operator_keys=[key.public_key_hex])["ok"]

    def test_unpinned_multi_key_warning(self):
        key, stranger = OperatorKey.generate(), OperatorKey.generate()
        s = analyse([_model(key, []), _model(stranger, [])])
        assert any("not all linked by a verified chain rotation" in w for w in s["warnings"])
        assert not any("rotation" in w for w in analyse([_model(key, [])])["warnings"])

    def test_rotation_linked_keys_no_warning(self):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "agent")
        r1 = _tool(chain.signer, "t", {})
        rot = chain.rotate_key(k2)
        r2 = _tool(chain.signer, "t", {})
        s = analyse([r1, rot, r2])
        assert len(s["signer_keys"]) == 2
        assert not any("rotation" in w for w in s["warnings"]), s["warnings"]

    def test_build_cli_operator_pubkey(self, tmp_path, capsys):
        from cryptography.hazmat.primitives.serialization import (
            NoEncryption,
            PrivateFormat,
        )

        key, stranger = OperatorKey.generate(), OperatorKey.generate()
        _write(tmp_path, [_tool(key, "t", {}), _tool(stranger, "t", {})])
        keyfile = tmp_path / "ops.key"
        keyfile.write_bytes(key.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        rc = report_mod.main(["build", str(tmp_path / "in"), "--output", str(tmp_path / "pack"),
                              "--operator-key", str(keyfile), "--operator-pubkey", key.public_key_hex])
        assert rc == 1
        rep = json.loads((tmp_path / "pack" / "report.json").read_text())
        assert len(rep["foreign_key_receipts"]) == 1
        assert verify_pack(tmp_path / "pack", [key.public_key_hex])["ok"]


# ---------------------------------------------------------------------------
# 5. control mapping
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
        return note + f"— {name} {base64.b64encode(key_hash + struct.pack('>Q', t) + sig).decode()}\n"

    return vkey, cosign


def _long_chain(key, days_apart):
    chain = ReceiptChain(key, "long")
    ex = lambda: {"receipt_type": "tool", "tool_name": "t", "input_hash": "sha256:" + "0" * 64,
                  "output_hash": "sha256:" + "1" * 64}
    receipts = [chain._append(ex(), PROV, "2026-01-01T00:00:00Z")]
    later = "2026-01-01T00:00:00Z" if days_apart == 0 else f"2026-{1 + days_apart // 30:02d}-15T00:00:00Z"
    receipts.append(chain._append(ex(), PROV, later))
    return chain, receipts


class TestControls:
    def test_every_trace_error_surfaces(self):
        key = OperatorKey.generate()
        m = _model(key, [("toolu_1", "lookup", {"q": 1})])
        t = _tool(key, "wire_money", {"to": "mallory"}, caused_by=[m.receipt_hash], tool_call_id="toolu_EVIL")
        bad = sign_execution_receipt({"receipt_type": "outcome", "observed_at": "2026-10-01T12:06:00Z",
                                      "context": {"context_version": "1.0", "tenant": "\n"}}, PROV, key)
        s = analyse([m, t, bad], now="2026-11-01T00:00:00Z")
        assert not s["ok"] and len(s["trace"]["errors"]) == 2
        controls = {c["ref"]: c for c in s["controls"]}
        for ref in ("Art. 12", "Art. 26(5)", "MEASURE / MANAGE", "Annex A"):
            assert controls[ref]["status"] == "issues", ref
            for e in s["trace"]["errors"]:
                assert e in controls[ref]["problems"], (ref, e)

    def test_claimed_errors_still_on_26_5_and_nist(self):
        key = OperatorKey.generate()
        m = _model(key, [("toolu_A", "issue_refund", {"amount": 20})])
        t = _tool(key, "issue_refund", {"amount": 20}, caused_by=[m.receipt_hash], tool_call_id="toolu_A")
        s = analyse([m, t], require_approval=["issue_refund"])
        controls = {c["ref"]: c for c in s["controls"]}
        err = s["trace"]["errors"][0]
        assert err in controls["Art. 14 / 26(2)"]["problems"]
        assert err in controls["Art. 26(5)"]["problems"] and err in controls["MEASURE / MANAGE"]["problems"]

    def test_art12_partial_when_unchained(self):
        key = OperatorKey.generate()
        s = analyse([_tool(key, "t", {})])
        assert {c["ref"]: c["status"] for c in s["controls"]}["Art. 12"] == "partial"

    def test_art19_needs_trusted_time(self):
        key = OperatorKey.generate()
        chain, receipts = _long_chain(key, 200)
        note = chain.checkpoint()
        s = analyse(receipts, checkpoints=[note])
        assert s["period"]["days"] >= 183 and s["chains"]["long"]["checkpoint"]["anchored"]
        assert {c["ref"]: c["status"] for c in s["controls"]}["Art. 19 / 26(6)"] == "partial"
        vkey, cosign = _witness()
        witnessed = cosign(note, 1_790_000_000)
        s = analyse(receipts, checkpoints=[witnessed], witness_vkeys=[vkey])
        assert s["chains"]["long"]["trusted_time"], s["chains"]
        assert {c["ref"]: c["status"] for c in s["controls"]}["Art. 19 / 26(6)"] == "evidence"

    def test_art19_long_period_without_chain_is_partial(self):
        key = OperatorKey.generate()
        s = analyse([_model(key, [], t="2025-01-01T00:00:00Z"), _model(key, [], t="2026-10-01T00:00:00Z")])
        assert s["period"]["days"] > 183
        assert {c["ref"]: c["status"] for c in s["controls"]}["Art. 19 / 26(6)"] == "partial"

    def test_wording(self, tmp_path):
        assert report_mod.__doc__.startswith("Evidence packs")
        assert "Compliance evidence pack" not in report_mod.__doc__
        key = OperatorKey.generate()
        build_pack(tmp_path / "pack", _write(tmp_path, [_tool(key, "t", {})]), operator_key=key)
        md = (tmp_path / "pack" / "report.md").read_text()
        assert md.startswith("# TraceSeal evidence pack") and "ompliance evidence" not in md
        assert f"--operator-pubkey {key.public_key_hex}" in md


# ---------------------------------------------------------------------------
# 6. directory.check_receipts / traceseal-keys verify
# ---------------------------------------------------------------------------


class TestDirectoryRedTeam:
    def _report(self, key, **entry):
        doc = build_directory("example.com", [{"public_key": key.public_key_hex, "status": "active",
                                               "valid_from": "2026-01-01T00:00:00Z", **entry}],
                              [key], issued_at="2026-10-01T00:00:00Z")
        return doc, verify_directory(doc, domain="example.com")

    def test_forged_receipt_is_invalid_signature(self, tmp_path):
        victim = OperatorKey.generate()
        doc, rep = self._report(victim)
        forged = Receipt("1.0", {"receipt_type": "tool", "tool_name": "wire_transfer",
                                 "started_at": "2026-10-15T12:00:00Z"}, PROV,
                         {"operator_public_key": victim.public_key_hex,
                          "operator_fingerprint": victim.fingerprint,
                          "attested_at": "2026-10-15T12:00:00Z", "signature": "00" * 64})
        assert check_receipts([forged], rep)[0]["status"] == "invalid_signature"
        (tmp_path / "dir.json").write_text(json.dumps(doc))
        (tmp_path / "r.json").write_text(forged.to_json())
        assert dir_mod.main(["verify", "--domain", "example.com", "--file", str(tmp_path / "dir.json"),
                             str(tmp_path / "r.json")]) == 1

    def test_hostile_receipts_do_not_raise(self, tmp_path):
        key = OperatorKey.generate()
        doc, rep = self._report(key)
        hostile = [Receipt("1.0", {}, {}, []), Receipt("1.0", [], {}, {}),
                   Receipt("1.0", {}, {}, {"operator_public_key": {"x": 1}, "signature": 7}),
                   Receipt(None, None, None, None), "not a receipt"]
        assert {c["status"] for c in check_receipts(hostile, rep)} == {"invalid_signature"}
        (tmp_path / "dir.json").write_text(json.dumps(doc))
        (tmp_path / "bad.json").write_text("[1]")
        assert dir_mod.main(["verify", "--domain", "example.com", "--file", str(tmp_path / "dir.json"),
                             str(tmp_path / "bad.json")]) == 1

    def test_non_string_directory_signature(self):
        key = OperatorKey.generate()
        doc, _ = self._report(key)
        for bad in (123, None, ["00"], "zz" * 64):
            d = json.loads(json.dumps(doc))
            d["signatures"][0]["signature"] = bad
            with pytest.raises(dir_mod.DirectoryError):
                verify_directory(d)
        d = json.loads(json.dumps(doc))
        d["signatures"][0]["public_key"] = {"x": 1}
        with pytest.raises(dir_mod.DirectoryError):
            verify_directory(d)

    def test_revoked_without_compromised_after(self):
        stolen, current = OperatorKey.generate(), OperatorKey.generate()
        doc = build_directory("example.com", [
            {"public_key": stolen.public_key_hex, "status": "revoked", "valid_from": "2026-01-01T00:00:00Z",
             "revoked_at": "2026-10-01T00:00:00Z"},
            {"public_key": current.public_key_hex, "status": "active", "valid_from": "2026-10-01T00:00:00Z"}],
            [current])
        rep = verify_directory(doc, domain="example.com")
        r = sign_execution_receipt({"receipt_type": "tool", "tool_name": "wire_transfer",
                                    "started_at": "2026-09-30T23:59:59Z"}, PROV, stolen)
        assert check_receipts([r], rep)[0]["status"] == "revoked_time_unproven"
        # a trusted (TSA/witness) time before revocation makes it decidable
        assert check_receipts([r], rep, trusted_times={r.receipt_hash: "2026-09-30T23:59:59Z"})[0]["status"] == "valid"
        assert check_receipts([r], rep, trusted_times={r.receipt_hash: "2026-10-02T00:00:00Z"})[0]["status"] == "revoked"
        r.attestation["attested_at"] = "2026-01-02T00:00:00Z"  # unsigned: ignored
        assert check_receipts([r], rep)[0]["status"] == "revoked_time_unproven"


def test_pack_reviewer_key_registry_is_recorded_and_rederived(tmp_path):
    """Packs can verify reviewer countersignatures against a registry, and
    verify-pack re-derives with the same registry."""
    from traceseal_observe.report import build_pack, verify_pack

    key = OperatorKey.generate()
    s = build_pack(tmp_path / "pack", [], operator_key=key, reviewer_keys={})
    assert s["analysis_options"]["reviewer_keys"] == {}
    assert verify_pack(tmp_path / "pack", [key.public_key_hex])["ok"]


def test_normalized_reviewer_registry_round_trips(tmp_path):
    from traceseal_observe.oversight import normalize_reviewer_keys
    from traceseal_observe.report import build_pack, verify_pack

    key, rev = OperatorKey.generate(), OperatorKey.generate()
    reg = normalize_reviewer_keys({"id:alice": [rev.public_key_hex]})
    build_pack(tmp_path / "pack", [], operator_key=key, reviewer_keys=reg)
    stored = json.loads((tmp_path / "pack" / "report.json").read_text())["analysis_options"]
    assert stored["reviewer_keys"] == {"id:alice": [rev.public_key_hex]}
    assert verify_pack(tmp_path / "pack", [key.public_key_hex])["ok"]


class TestAuditorControlsTheAnalysis:
    """Pass 2: the pack author must not choose the clock or drop requirements,
    and nothing in report.json / report.md may be edited."""

    def _incident_pack(self, tmp_path, **build):
        from traceseal_observe import sign_incident
        from traceseal_observe.report import build_pack

        key = OperatorKey.generate()
        inc = sign_incident(category="serious_incident", severity="critical", status="detected",
                            aware_at="2026-01-01T00:00:00Z", operator_key=key)
        paths = _write(tmp_path, [inc])
        build_pack(tmp_path / "pack", paths, operator_key=key,
                   operator_keys=[key.public_key_hex], **build)
        return key

    def test_backdated_now_is_a_problem_and_auditor_clock_rules(self, tmp_path):
        from traceseal_observe.report import verify_pack

        key = self._incident_pack(tmp_path, now="2026-01-01T01:00:00Z")
        r = verify_pack(tmp_path / "pack", [key.public_key_hex])
        assert r["pack_result"] == "passed"           # what the author computed
        assert r["auditor_result"] == "ISSUES FOUND"  # today the Art. 73 deadline has passed
        assert any("MISSED" in f for f in r["auditor_findings"])

    def test_back_dated_before_own_receipts_fails(self, tmp_path):
        from traceseal_observe.report import verify_pack

        key = self._incident_pack(tmp_path, now="2025-06-01T00:00:00Z")
        r = verify_pack(tmp_path / "pack", [key.public_key_hex])
        assert not r["ok"] and any("back-dated analysis" in p for p in r["problems"])

    def test_auditor_adds_requirements(self, tmp_path):
        from traceseal_observe.report import build_pack, verify_pack

        key = OperatorKey.generate()
        paths = _write(tmp_path, [_tool(key, "issue_refund", {})])
        build_pack(tmp_path / "pack", paths, operator_key=key, operator_keys=[key.public_key_hex])
        plain = verify_pack(tmp_path / "pack", [key.public_key_hex])
        strict = verify_pack(tmp_path / "pack", [key.public_key_hex], require_approval=["issue_refund"])
        assert plain["auditor_result"] == "passed" and strict["auditor_result"] == "ISSUES FOUND"

    def test_any_edit_to_report_files_is_caught(self, tmp_path):
        from traceseal_observe.report import verify_pack

        key = self._incident_pack(tmp_path)
        pack = tmp_path / "pack"
        rj = json.loads((pack / "report.json").read_text())
        rj["incidents"] = []
        (pack / "report.json").write_text(json.dumps(rj, indent=2, sort_keys=True))
        md = pack / "report.md"
        md.write_text(md.read_text() + "\nNo incidents. All controls satisfied.\n")
        _remanifest(pack)
        _resign(pack, key)
        r = verify_pack(pack, [key.public_key_hex])
        assert not r["ok"]
        assert any("report.json does not match" in p for p in r["problems"])
        assert any("report.md does not match" in p for p in r["problems"])


def test_auditor_scope_requirement_adds_to_recorded_one(tmp_path):
    from traceseal_observe.report import _union_scopes, build_pack, verify_pack

    assert _union_scopes({"refund": "refunds:write"}, {"refund": "audit:read"}) == \
        {"refund": ["audit:read", "refunds:write"]}
    key = OperatorKey.generate()
    paths = _write(tmp_path, [_tool(key, "refund", {})])
    build_pack(tmp_path / "pack", paths, operator_key=key, operator_keys=[key.public_key_hex],
               required_scopes={"refund": "refunds:write"})
    r = verify_pack(tmp_path / "pack", [key.public_key_hex],
                    required_scopes={"refund": "audit:read"})
    assert r["auditor_result"] == "ISSUES FOUND"


def test_auditor_policy_requirement_cannot_erase_recorded_failure(tmp_path):
    from traceseal_observe.oversight import sign_policy_decision
    from traceseal_observe.report import build_pack, verify_pack

    key = OperatorKey.generate()
    audit = sign_policy_decision(policy_id="audit", decision="allow", stage="input",
                                 decided_at="2026-10-01T11:59:00Z", operator_key=key)
    tool = _tool(key, "refund", {}, caused_by=[audit.receipt_hash])
    paths = _write(tmp_path, [audit, tool])
    build_pack(tmp_path / "pack", paths, operator_key=key, operator_keys=[key.public_key_hex],
               require_policy={"refund": "fraud"})
    # sanity: the cited audit decision alone satisfies an "audit" requirement
    from traceseal_observe.report import analyse
    from traceseal_observe.trace import verify_trace
    assert verify_trace([audit, tool], require_policy={"refund": "audit"})["ok"]
    r = verify_pack(tmp_path / "pack", [key.public_key_hex], require_policy={"refund": "audit"})
    assert r["pack_result"] == "ISSUES FOUND"
    assert r["auditor_result"] == "ISSUES FOUND"


def test_pack_built_with_platform_newline_translation_still_verifies(tmp_path, monkeypatch):
    """Windows text mode writes CRLF; report files must be written as bytes."""
    from pathlib import Path as _P
    from traceseal_observe.report import build_pack, verify_pack

    real = _P.write_text

    def crlf(self, data, *a, **k):
        return real(self, data.replace("\n", "\r\n"), *a, **k)

    monkeypatch.setattr(_P, "write_text", crlf)
    key = OperatorKey.generate()
    paths = _write(tmp_path, [_tool(key, "t", {})])
    build_pack(tmp_path / "pack", paths, operator_key=key, operator_keys=[key.public_key_hex])
    monkeypatch.setattr(_P, "write_text", real)
    assert b"\r" not in (tmp_path / "pack" / "report.md").read_bytes()
    assert verify_pack(tmp_path / "pack", [key.public_key_hex])["ok"]


def test_crlf_checkpoint_build_and_verify_agree(tmp_path):
    from test_incident_and_report import _scenario

    key, _, paths, cp = _scenario(tmp_path)
    crlf = tmp_path / "cp-crlf.txt"
    crlf.write_bytes(cp.read_bytes().replace(b"\n", b"\r\n"))
    pack = tmp_path / "pack"
    s = build_pack(pack, paths, operator_key=key, checkpoint_paths=[crlf],
                   require_approval=["issue_refund"], operator_keys=[key.public_key_hex])
    assert s["ok"] and any(rep.get("checkpoint", {}).get("anchored") for rep in s["chains"].values())
    r = verify_pack(pack, [key.public_key_hex])
    assert r["ok"] and r["pack_result"] == "passed", r["problems"]


def test_single_string_approval_enforced_at_build_and_verify(tmp_path):
    key = OperatorKey.generate()
    paths = _write(tmp_path, [_tool(key, "refund", {})])
    s = build_pack(tmp_path / "pack", paths, operator_key=key,
                   operator_keys=[key.public_key_hex], require_approval="refund")
    assert not s["ok"]  # 'refund' requires approval and cites none
    r = verify_pack(tmp_path / "pack", [key.public_key_hex])
    assert r["ok"] and r["pack_result"] == "ISSUES FOUND", r["problems"]
