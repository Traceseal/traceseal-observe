"""Incident receipts, deadlines, and compliance evidence packs."""

from __future__ import annotations

import json

import pytest

from traceseal_observe import (
    OperatorKey,
    Principal,
    ReceiptChain,
    agent_context,
    caused_by,
    observe_data_flow,
    observe_tool,
    reporting_deadlines,
    sign_incident,
    sign_oversight,
    verify_receipt_signature,
)
from traceseal_observe import report as report_mod
from traceseal_observe.incident import incident_status
from traceseal_observe.report import analyse, build_pack, verify_pack

PEPPER = b"0123456789abcdef-pepper"


class TestDeadlines:
    def test_ai_act_art_73(self):
        aware = "2026-10-01T09:00:00Z"
        assert reporting_deadlines("serious_incident", aware)[0]["due"] == "2026-10-16T09:00:00Z"
        assert reporting_deadlines("serious_incident", aware, death=True)[0]["due"] == "2026-10-11T09:00:00Z"
        assert reporting_deadlines("serious_incident", aware, widespread=True,
                                   death=True)[0]["due"] == "2026-10-03T09:00:00Z"

    def test_gdpr_and_nis2(self):
        aware = "2026-10-01T09:00:00Z"
        assert reporting_deadlines("personal_data_breach", aware)[0]["due"] == "2026-10-04T09:00:00Z"
        nis2 = reporting_deadlines("significant_incident", aware)
        assert [d["due"] for d in nis2] == ["2026-10-02T09:00:00Z", "2026-10-04T09:00:00Z"]
        dora = reporting_deadlines("major_ict_incident", aware)
        assert [d["due"] for d in dora] == ["2026-10-02T09:00:00Z"]
        assert "4 hours of classifying" in dora[0]["qualifier"]
        assert reporting_deadlines("malfunction", aware) == []
        with pytest.raises(ValueError):
            reporting_deadlines("bad", aware)

    def test_every_deadline_carries_its_legal_qualifier(self):
        aware = "2026-10-01T09:00:00Z"
        for cat in ("serious_incident", "personal_data_breach", "significant_incident",
                    "major_ict_incident"):
            for d in reporting_deadlines(cat, aware):
                assert d["qualifier"]
        ai = reporting_deadlines("serious_incident", aware)[0]["qualifier"]
        assert "immediately" in ai and "2026/1744" in ai and "high-risk" in ai
        assert "undue delay" in reporting_deadlines("personal_data_breach", aware)[0]["qualifier"]

    def test_dora_classification(self):
        aware = "2026-10-01T09:00:00Z"
        # classified quickly: 4 hours from classification
        d = reporting_deadlines("major_ict_incident", aware, classified_at="2026-10-01T10:00:00Z")[0]
        assert d["due"] == "2026-10-01T14:00:00Z" and "definitive" not in d
        # classified at hour 22: capped by the 24-hour limit
        d = reporting_deadlines("major_ict_incident", aware, classified_at="2026-10-02T07:00:00Z")[0]
        assert d["due"] == "2026-10-02T09:00:00Z"
        # classified at hour 26 (Art. 5(2)): 4 hours from classification
        d = reporting_deadlines("major_ict_incident", aware, classified_at="2026-10-02T11:00:00Z")[0]
        assert d["due"] == "2026-10-02T15:00:00Z"
        with pytest.raises(ValueError):
            reporting_deadlines("major_ict_incident", aware, classified_at="2026-09-30T00:00:00Z")
        with pytest.raises(ValueError):
            reporting_deadlines("personal_data_breach", aware, classified_at=aware)
        key = OperatorKey.generate()
        # late classification, notified at hour 27: on time, not missed
        late_class = sign_incident(category="major_ict_incident", severity="high", status="reported",
                                   aware_at=aware, classified_at="2026-10-02T11:00:00Z",
                                   reported_at="2026-10-02T12:00:00Z", operator_key=key)
        st = incident_status([late_class])[0]
        assert st["missed_deadlines"] == [] and st["unconfirmed_deadlines"] == []
        # no classification time recorded: unconfirmed, never missed
        unknown = sign_incident(category="major_ict_incident", severity="high", status="reported",
                                aware_at=aware, reported_at="2026-10-02T12:00:00Z", operator_key=key)
        st = incident_status([unknown])[0]
        assert st["missed_deadlines"] == [] and len(st["unconfirmed_deadlines"]) == 1
        # a later stage that omits classified_at must not loosen the deadline
        early = sign_incident(category="major_ict_incident", severity="high", status="reported",
                              aware_at=aware, classified_at="2026-10-01T10:00:00Z",
                              reported_at="2026-10-01T16:00:00Z", operator_key=key)
        closed = sign_incident(category="major_ict_incident", severity="high", status="closed",
                               aware_at=aware, supersedes=early, operator_key=key)
        st = incident_status([early, closed])[0]
        assert [d["due"] for d in st["missed_deadlines"]] == ["2026-10-01T14:00:00Z"]
        assert st["unconfirmed_deadlines"] == []
        # same for AI Act death flag set only on the first stage
        first = sign_incident(category="serious_incident", severity="critical", status="detected",
                              aware_at=aware, death=True, operator_key=key)
        later = sign_incident(category="serious_incident", severity="critical", status="mitigated",
                              aware_at=aware, supersedes=first, operator_key=key)
        st = incident_status([first, later], now="2026-10-12T00:00:00Z")[0]
        assert [d["due"] for d in st["missed_deadlines"]] == ["2026-10-11T09:00:00Z"]
        # a 1.5.1-style record (24-hour due, no flag) is never reported as missed
        from traceseal_observe import sign_execution_receipt
        legacy = sign_execution_receipt(
            {"receipt_type": "incident", "incident_version": "1.0", "category": "major_ict_incident",
             "severity": "high", "status": "detected", "aware_at": aware,
             "recorded_at": aware, "deadlines": [{"regime": "DORA", "step": "initial notification",
                                                  "basis": "x", "due": "2026-10-02T09:00:00Z"}]},
            {"provenance_version": "1.0", "provider_attestation": "none"}, key)
        st = incident_status([legacy], now="2026-10-05T00:00:00Z")[0]
        assert st["missed_deadlines"] == [] and len(st["unconfirmed_deadlines"]) == 1

    def test_related_obligations(self):
        aware = "2026-10-01T09:00:00Z"
        from traceseal_observe import related_obligations
        bases = {o["basis"] for o in related_obligations("personal_data_breach")}
        assert "GDPR Art. 34" in bases
        assert any(o["step"] == "final report" for o in related_obligations("significant_incident"))
        assert any(o["step"] == "final report" for o in related_obligations("major_ict_incident"))
        assert any("26(5)" in o["basis"] for o in related_obligations("serious_incident"))
        assert related_obligations("other") == []
        r = sign_incident(category="personal_data_breach", severity="high", status="detected",
                          aware_at=aware, operator_key=OperatorKey.generate())
        assert r.execution["related_obligations"][0]["basis"] == "GDPR Art. 34"
        assert incident_status([r])[0]["related_obligations"]


class TestIncidents:
    def test_lifecycle_and_missed_deadline(self):
        key = OperatorKey.generate()
        tool = observe_tool("issue_refund", key, lambda: 1)[1]
        detected = sign_incident(category="personal_data_breach", severity="high",
                                 status="detected", aware_at="2026-10-01T09:00:00Z",
                                 title="refund export leaked emails", affected_receipts=[tool],
                                 description={"writeup": "..."}, operator_key=key)
        verify_receipt_signature(detected)
        assert detected.execution["deadlines"][0]["basis"] == "GDPR Art. 33(1)"
        status = incident_status([detected], now="2026-10-05T00:00:00Z")
        assert status[0]["missed_deadlines"][0]["unreported"]
        late = sign_incident(category="personal_data_breach", severity="high", status="reported",
                             aware_at="2026-10-01T09:00:00Z", reported_at="2026-10-04T10:00:00Z",
                             supersedes=detected, regulator="ICO", report_reference="ref-123",
                             operator_key=key)
        status = incident_status([detected, late], now="2026-10-05T00:00:00Z")
        assert len(status) == 1 and status[0]["stages"] == 2
        assert status[0]["missed_deadlines"][0]["reported_late"] == "2026-10-04T10:00:00Z"
        on_time = sign_incident(category="personal_data_breach", severity="high", status="reported",
                                aware_at="2026-10-01T09:00:00Z", reported_at="2026-10-02T10:00:00Z",
                                supersedes=detected, operator_key=key)
        assert incident_status([detected, on_time])[0]["missed_deadlines"] == []

    def test_validation(self):
        key = OperatorKey.generate()
        base = dict(category="other", severity="low", status="detected",
                    aware_at="2026-10-01T09:00:00Z", operator_key=key)
        with pytest.raises(ValueError):
            sign_incident(**{**base, "severity": "apocalyptic"})
        with pytest.raises(ValueError):
            sign_incident(**base, detected_at="2026-10-02T00:00:00Z")
        with pytest.raises(ValueError):
            sign_incident(**base, reported_at="2026-09-01T00:00:00Z")
        with pytest.raises(ValueError):
            sign_incident(**base, title="line\nbreak")

    def test_chainable(self):
        chain = ReceiptChain(OperatorKey.generate(), "c")
        r = sign_incident(category="malfunction", severity="low", status="detected",
                          aware_at="2026-10-01T09:00:00Z", operator_key=chain.signer)
        assert r.execution["chain_seq"] == 1


def _scenario(tmp_path, *, gap=False, rejected=False):
    key = OperatorKey.generate("ops")
    chain = ReceiptChain(key, "support-agent")
    s = chain.signer
    receipts = []
    with agent_context(agent_id="bot", principal=Principal.user("u", pepper=PEPPER)):
        receipts.append(observe_tool("lookup", s, lambda: 1)[1])
        receipts.append(observe_data_flow("https://api.example.com/v1", "POST", s, lambda: None,
                                          request_body={"email": "a@b.com"})[1])
        decision = "rejected" if rejected else "approved"
        approval = sign_oversight(decision=decision, operator_key=s,
                                  reviewer=Principal.user("rev", pepper=PEPPER))
        receipts.append(approval)
        with caused_by(approval):
            receipts.append(observe_tool("issue_refund", s, lambda: 1)[1])
    cp = chain.checkpoint()
    paths = []
    for i, r in enumerate(receipts):
        if gap and i == 1:
            continue
        p = tmp_path / "in" / f"{i}.json"
        p.parent.mkdir(exist_ok=True)
        p.write_text(r.to_json())
        paths.append(p)
    cp_path = tmp_path / "in" / "cp.txt"
    cp_path.write_text(cp)
    return key, receipts, paths, cp_path


class TestEvidencePack:
    def test_analysis_and_controls(self, tmp_path):
        key, receipts, _, cp = _scenario(tmp_path)
        s = analyse(receipts, checkpoints=[cp.read_text()], require_approval={"issue_refund"})
        assert s["ok"], (s["chains"], s["trace"]["errors"])
        assert s["chains"]["support-agent"]["checkpoint"]["anchored"]
        controls = {c["ref"]: c for c in s["controls"]}
        assert controls["Art. 12"]["status"] == "evidence"
        assert controls["Art. 14 / 26(2)"]["status"] == "evidence"
        assert controls["Art. 73"]["status"] == "no evidence"
        assert "Art. 12(3)" not in controls
        assert all(c["applies_to"] for c in s["controls"])
        assert "2 December 2027" in controls["Art. 12"]["applies_to"]
        assert "not legal advice" in s["legal_notice"]
        assert "pseudonymised" in controls["Art. 5(1)(c), 25"]["evidence"]
        assert "email" in controls["Art. 5(1)(c), 25"]["evidence"]

    def test_gap_and_oversight_issues_surface(self, tmp_path):
        _, receipts, _, cp = _scenario(tmp_path, rejected=True)
        receipts = receipts[:1] + receipts[2:]
        s = analyse(receipts, checkpoints=[cp.read_text()])
        controls = {c["ref"]: c for c in s["controls"]}
        assert not s["ok"]
        assert controls["Art. 12"]["status"] == "issues"
        assert controls["Art. 14 / 26(2)"]["status"] == "issues"

    def test_build_and_verify_pack(self, tmp_path):
        key, _, paths, cp = _scenario(tmp_path)
        summary = build_pack(tmp_path / "pack", paths, operator_key=key, checkpoint_paths=[cp],
                             require_approval={"issue_refund"})
        assert summary["ok"]
        md = (tmp_path / "pack" / "report.md").read_text()
        assert "all checks passed" in md and "| EU AI Act | Art. 14 / 26(2) |" in md and "Legal notice" in md
        assert json.loads((tmp_path / "pack" / "report.json").read_text())["ok"]
        pk = key.public_key_hex
        result = verify_pack(tmp_path / "pack", [pk])
        assert result["ok"] and result["signed"] and result["pinned"], result["problems"]
        assert result["pack_result"] == "passed"

        (tmp_path / "pack" / "report.md").write_text(md.replace("all checks passed", "fine"))
        assert "file changed: report.md" in verify_pack(tmp_path / "pack", [pk])["problems"]
        (tmp_path / "pack" / "report.md").write_text(md)
        (tmp_path / "pack" / "receipts" / "extra.json").write_text("{}")
        assert any("not in manifest" in p for p in verify_pack(tmp_path / "pack", [pk])["problems"])

    def test_pack_refuses_non_empty_output(self, tmp_path):
        _, _, paths, _ = _scenario(tmp_path)
        (tmp_path / "out").mkdir()
        (tmp_path / "out" / "x").write_text("x")
        with pytest.raises(ValueError):
            build_pack(tmp_path / "out", paths)

    def test_cli(self, tmp_path, capsys):
        key, _, _, cp = _scenario(tmp_path, gap=True)
        keyfile = tmp_path / "ops.key"
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        keyfile.write_bytes(key.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        rc = report_mod.main(["build", str(tmp_path / "in"), "--output", str(tmp_path / "pack"),
                              "--checkpoint", str(cp), "--operator-key", str(keyfile)])
        out = capsys.readouterr().out
        assert rc == 1 and "EU AI Act Art. 12: issues" in out  # the gap is reported
        # no pinned signer: refused
        assert report_mod.main(["verify-pack", str(tmp_path / "pack")]) == 2
        assert "--operator-pubkey" in capsys.readouterr().err
        # intact pack, but the pack's own findings show issues: exit 3, shown as such
        assert report_mod.main(["verify-pack", str(tmp_path / "pack"),
                                "--operator-pubkey", key.public_key_hex]) == 3
        out = capsys.readouterr().out
        assert "[OK]" in out and "pack result: ISSUES FOUND" in out and "(pinned)" in out
        assert report_mod.main(["verify-pack", str(tmp_path / "pack"), "--trust-signer-in-pack"]) == 3
        out = capsys.readouterr().out
        assert "NOT PINNED" in out and "pack result: ISSUES FOUND" in out
