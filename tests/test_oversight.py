"""Human oversight and policy-decision receipts, and their trace checks."""

from __future__ import annotations

import json

import pytest

from traceseal_observe import (
    OperatorKey,
    Principal,
    ReceiptChain,
    agent_context,
    caused_by,
    observe_anthropic,
    observe_policy,
    observe_tool,
    sha256_of,
    sign_oversight,
    sign_policy_decision,
    verify_chain,
    verify_receipt_signature,
)
from traceseal_observe import trace as trace_mod
from traceseal_observe.trace import verify_trace

PEPPER = b"0123456789abcdef-pepper"
REVIEWER = Principal.user("reviewer-7", pepper=PEPPER)
ARGS = {"order": "o-1", "amount": 20}


class Obj:
    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return json.loads(json.dumps(self._data))


class FakeAnthropic:
    def __init__(self, response):
        class Messages:
            def create(self, **kw):
                return response

        self.messages = Messages()


RESPONSE = {"id": "msg_1", "model": "claude-x-1", "stop_reason": "tool_use", "content": [
    {"type": "tool_use", "id": "toolu_A", "name": "issue_refund", "input": ARGS}]}


@pytest.fixture
def key():
    return OperatorKey.generate("ops")


def _model(key):
    return observe_anthropic(FakeAnthropic(Obj(RESPONSE)), {"model": "m"}, key)[1]


def _run(key, model, *extra_causes, args=ARGS, tool="issue_refund"):
    with caused_by(model, *extra_causes, tool_call_id="toolu_A"):
        return observe_tool(tool, key, lambda: {"ok": True}, args=args)[1]


class TestOversightReceipts:
    def test_fields_and_reviewer_countersignature(self, key):
        model = _model(key)
        reviewer_key = OperatorKey.generate("reviewer-personal")
        r = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                           subjects=[model], tool_call_ids=["toolu_A"], reviewer_role="claims",
                           presented={"amount": 20}, rationale="verified by phone",
                           review_started_at="2026-10-01T12:00:00Z",
                           decided_at="2026-10-01T12:00:45Z", reviewer_key=reviewer_key)
        verify_receipt_signature(r)
        ex = r.execution
        assert ex["receipt_type"] == "oversight" and ex["review_seconds"] == 45
        assert ex["presented_hash"] == sha256_of({"amount": 20})
        assert "verified by phone" not in json.dumps(r.to_dict())
        report = verify_trace([model, r])
        assert report["ok"] and report["oversight"][0]["reviewer_signed"]

    def test_forged_reviewer_signature(self, key):
        model = _model(key)
        r = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                           subjects=[model], tool_call_ids=["toolu_A"],
                           reviewer_key=OperatorKey.generate())
        # The operator re-signs with a different decision but keeps the
        # reviewer's signature: the countersignature no longer matches.
        from traceseal_observe import sign_execution_receipt

        ex = {k: v for k, v in r.execution.items()}
        ex["decision"] = "rejected"
        forged = sign_execution_receipt(ex, r.provenance, key)
        assert any("countersignature" in e for e in verify_trace([forged])["errors"])

    def test_argument_validation(self, key):
        with pytest.raises(ValueError):
            sign_oversight(decision="maybe", operator_key=key, reviewer=REVIEWER)
        with pytest.raises(ValueError):
            sign_oversight(decision="modified", operator_key=key, reviewer=REVIEWER)
        with pytest.raises(ValueError):
            sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                           modified_input={"x": 1})
        with pytest.raises(ValueError):
            sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                           tool_call_ids=["t"])  # no subject
        with pytest.raises(ValueError):
            sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                           review_started_at="2026-10-01T12:01:00Z",
                           decided_at="2026-10-01T12:00:00Z")
        with pytest.raises(ValueError):
            sign_oversight(decision="approved", operator_key=key, reviewer="alice")

    def test_chained_with_context(self, key):
        chain = ReceiptChain(key, "oversight")
        with agent_context(agent_id="bot", session_id="s1"):
            model = _model(chain.signer)
            approval = sign_oversight(decision="approved", operator_key=chain.signer,
                                      reviewer=REVIEWER, subjects=[model], tool_call_ids=["toolu_A"])
            tool = _run(chain.signer, model, approval)
        assert approval.execution["chain_seq"] == 2
        assert approval.execution["context"]["session_id"] == "s1"
        assert verify_chain([model, approval, tool])["ok"]


class TestOversightChecks:
    def test_required_approval_present(self, key):
        model = _model(key)
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_A"])
        tool = _run(key, model, approval)
        report = verify_trace([model, approval, tool], require_approval={"issue_refund"})
        assert report["ok"], report["errors"]
        assert report["tool_calls"][0]["approved_by"] == [approval.receipt_hash]

    def test_required_approval_missing(self, key):
        model = _model(key)
        tool = _run(key, model)
        report = verify_trace([model, tool], require_approval={"issue_refund"})
        assert any("requires human approval" in e for e in report["errors"])

    def test_approval_is_bound_to_its_subject_model_receipt(self, key):
        """An approval for one model response must not cover another response
        that happens to reuse the same tool_call_id (review finding)."""
        approved_model = _model(key)
        other_model = observe_anthropic(FakeAnthropic(Obj(RESPONSE)), {"model": "other"}, key)[1]
        assert other_model.receipt_hash != approved_model.receipt_hash
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[approved_model], tool_call_ids=["toolu_A"])
        tool = _run(key, other_model, approval)
        report = verify_trace([approved_model, other_model, approval, tool],
                              require_approval={"issue_refund"})
        assert any("requires human approval" in e for e in report["errors"])
        ok = _run(key, approved_model, approval)
        assert verify_trace([approved_model, approval, ok], require_approval={"issue_refund"})["ok"]

    def test_approval_for_another_call_does_not_count(self, key):
        model = _model(key)
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_OTHER"])
        tool = _run(key, model, approval)
        assert not verify_trace([model, approval, tool], require_approval={"issue_refund"})["ok"]

    def test_executed_after_rejection_even_if_not_cited(self, key):
        model = _model(key)
        rejection = sign_oversight(decision="rejected", operator_key=key, reviewer=REVIEWER,
                                   subjects=[model], tool_call_ids=["toolu_A"])
        tool = _run(key, model)  # agent ignores the rejection and doesn't cite it
        report = verify_trace([model, rejection, tool])
        assert any("which a human rejected" in e for e in report["errors"])

    def test_human_modified_arguments(self, key):
        model = _model(key)
        new_args = {"order": "o-1", "amount": 15}
        approval = sign_oversight(decision="modified", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_A"],
                                  modified_input=new_args)
        ok = _run(key, model, approval, args=new_args)
        report = verify_trace([model, approval, ok])
        assert report["ok"] and report["tool_calls"][0]["status"] == "human_modified"
        bad = _run(key, model, approval, args={"order": "o-1", "amount": 99})
        assert any("arguments the reviewer approved" in e
                   for e in verify_trace([model, approval, bad])["errors"])

    def test_approved_but_arguments_changed_is_an_error(self, key):
        model = _model(key)
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_A"])
        tool = _run(key, model, approval, args={"order": "o-1", "amount": 5000})
        assert any("did not approve" in e for e in verify_trace([model, approval, tool])["errors"])

    def test_stop_and_resume(self, key):
        with agent_context(session_id="s-9"):
            stop = sign_oversight(decision="stopped", operator_key=key, reviewer=REVIEWER,
                                  decided_at="2020-01-01T00:00:00Z")
            after = observe_tool("t", key, lambda: 1)[1]
        assert any("after a human stopped it" in e for e in verify_trace([stop, after])["errors"])
        with agent_context(session_id="s-9"):
            resume = sign_oversight(decision="resumed", operator_key=key, reviewer=REVIEWER,
                                    decided_at="2020-01-01T00:05:00Z")
        assert verify_trace([stop, resume, after])["ok"]
        with agent_context(session_id="other"):
            elsewhere = observe_tool("t", key, lambda: 1)[1]
        assert verify_trace([stop, elsewhere])["ok"]

    def test_rubber_stamp_warning(self, key):
        model = _model(key)
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_A"],
                                  review_started_at="2026-10-01T12:00:00Z",
                                  decided_at="2026-10-01T12:00:01Z")
        report = verify_trace([model, approval], min_review_seconds=10)
        assert report["ok"] and any("rubber-stamping" in w for w in report["warnings"])

    def test_tampered_review_seconds(self, key):
        from traceseal_observe import sign_execution_receipt

        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  review_started_at="2026-10-01T12:00:00Z",
                                  decided_at="2026-10-01T12:00:01Z")
        ex = dict(approval.execution, review_seconds=600)
        forged = sign_execution_receipt(ex, approval.provenance, key)
        assert not verify_trace([forged])["ok"]


class TestPolicyDecisions:
    def test_observe_policy_and_required_policy(self, key):
        def pii_filter(text):
            return {"decision": "allow", "categories": ["none"], "rule_ids": ["r1"]}

        model = _model(key)
        _, decision = observe_policy("pii-filter", pii_filter, "hello", key, stage="tool_call",
                                     policy_definition={"threshold": 3}, engine="regex-v1")
        ex = decision.execution
        assert ex["policy_hash"] == sha256_of({"threshold": 3})
        assert ex["subject_hash"] == sha256_of("hello")
        tool = _run(key, model, decision)
        report = verify_trace([model, decision, tool], require_policy={"issue_refund": "pii-filter"})
        assert report["ok"], report["errors"]
        missing = _run(key, model)
        assert not verify_trace([model, missing], require_policy={"issue_refund": "pii-filter"})["ok"]

    def test_executed_despite_deny(self, key):
        model = _model(key)
        deny = sign_policy_decision(policy_id="spend-limit", decision="deny", stage="tool_call",
                                    operator_key=key, subject=ARGS)
        tool = _run(key, model, deny)
        report = verify_trace([model, deny, tool], require_policy={"issue_refund": "spend-limit"})
        assert any("denied it" in e for e in report["errors"])

    def test_modify_needs_output_and_evaluator_errors_propagate(self, key):
        with pytest.raises(ValueError):
            sign_policy_decision(policy_id="p", decision="modify", stage="output", operator_key=key)
        r = sign_policy_decision(policy_id="p", decision="modify", stage="output",
                                 operator_key=key, subject="a@b.com", output="[email]")
        assert r.execution["output_hash"] == sha256_of("[email]")

        def broken(_):
            raise RuntimeError("model unavailable")

        with pytest.raises(RuntimeError):
            observe_policy("p", broken, "x", key, stage="input")
        with pytest.raises(ValueError):
            observe_policy("p", lambda _: 42, "x", key, stage="input")
        with pytest.raises(ValueError):
            sign_policy_decision(policy_id="p", decision="allow", stage="nowhere", operator_key=key)


def test_cli(key, tmp_path, capsys):
    model = _model(key)
    approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                              subjects=[model], tool_call_ids=["toolu_A"],
                              review_started_at="2026-10-01T12:00:00Z",
                              decided_at="2026-10-01T12:00:30Z")
    tool = _run(key, model, approval)
    paths = []
    for i, r in enumerate([model, approval, tool]):
        p = tmp_path / f"{i}.json"
        p.write_text(r.to_json())
        paths.append(str(p))
    assert trace_mod.main(["verify", *paths, "--require-approval", "issue_refund"]) == 0
    assert "human approved (operator-attested, 30s review)" in capsys.readouterr().out
    assert trace_mod.main(["verify", paths[0], paths[2], "--require-approval", "issue_refund"]) == 1
