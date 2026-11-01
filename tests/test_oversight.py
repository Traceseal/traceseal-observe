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


def _at(receipt, seconds=0):
    """A UTC time `seconds` after a receipt's signed started_at/decided_at."""
    from datetime import datetime, timedelta, timezone

    ex = receipt.execution
    base = datetime.strptime(ex.get("started_at") or ex["decided_at"], "%Y-%m-%dT%H:%M:%SZ")
    return (base.replace(tzinfo=timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _past_model(key, ago=600, call_id="toolu_A", args=ARGS, **context):
    """A model receipt that requested issue_refund `ago` seconds ago."""
    from datetime import datetime, timedelta, timezone

    from traceseal_observe import sign_execution_receipt

    t = (datetime.now(timezone.utc) - timedelta(seconds=ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ex = {"receipt_type": "model", "provider": "anthropic", "model": "m", "started_at": t,
          "input_hash": sha256_of("in"), "output_hash": sha256_of("out"),
          "requested_tool_calls": [{"id": call_id, "name": "issue_refund", "input_hash": sha256_of(args)}]}
    if context:
        ex["context"] = {"context_version": "1.0", **context}
    return sign_execution_receipt(ex, {"provenance_version": "1.0", "provider_attestation": "none"}, key)


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
                           review_started_at=_at(model), decided_at=_at(model, 45),
                           reviewer_key=reviewer_key)
        verify_receipt_signature(r)
        ex = r.execution
        assert ex["receipt_type"] == "oversight" and ex["review_seconds"] == 45
        assert ex["presented_hash"] == sha256_of({"amount": 20})
        assert "verified by phone" not in json.dumps(r.to_dict())
        # Without a reviewer key registry the countersignature is valid but
        # unverified: anyone can make a key.
        report = verify_trace([model, r])
        assert report["ok"] and report["oversight"][0]["reviewer_signed"] == "unverified"
        assert any("registry" in w for w in report["warnings"])
        report = verify_trace([model, r], reviewer_keys={REVIEWER.ref: reviewer_key.public_key_hex})
        assert report["ok"] and report["oversight"][0]["reviewer_signed"] is True

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
                                    subjects=[stop], decided_at="2020-01-01T00:05:00Z")
        report = verify_trace([stop, resume, after])
        assert report["ok"]
        # unchained: the order rests on signed times, and the report says so
        assert any("operator's signed times" in w for w in report["warnings"])
        with agent_context(session_id="other"):
            elsewhere = observe_tool("t", key, lambda: 1)[1]
        assert verify_trace([stop, elsewhere])["ok"]

    def test_rubber_stamp_warning(self, key):
        model = _model(key)
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_A"],
                                  review_started_at=_at(model), decided_at=_at(model, 1))
        report = verify_trace([model, approval], min_review_seconds=10)
        assert report["ok"] and any("rubber-stamping" in w for w in report["warnings"])

    def test_tampered_review_seconds(self, key):
        from traceseal_observe import sign_execution_receipt

        model = _model(key)
        approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                                  subjects=[model], tool_call_ids=["toolu_A"],
                                  review_started_at=_at(model), decided_at=_at(model, 1))
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
    model = _past_model(key)
    approval = sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                              subjects=[model], tool_call_ids=["toolu_A"],
                              review_started_at=_at(model), decided_at=_at(model, 30))
    tool = _run(key, model, approval)
    paths = []
    for i, r in enumerate([model, approval, tool]):
        p = tmp_path / f"{i}.json"
        p.write_text(r.to_json())
        paths.append(str(p))
    assert trace_mod.main(["verify", *paths, "--require-approval", "issue_refund"]) == 0
    assert "human approved (operator-attested, 30s review)" in capsys.readouterr().out
    # --reviewer-keys: a malformed registry is a usage error
    bad = tmp_path / "keys.json"
    bad.write_text('{"id:x": ["nothex"]}')
    assert trace_mod.main(["verify", *paths, "--reviewer-keys", str(bad)]) == 2
    assert trace_mod.main(["verify", paths[0], paths[2], "--require-approval", "issue_refund"]) == 1


# ---------------------------------------------------------------------------
# 1.6.0 red-team regressions
# ---------------------------------------------------------------------------

from traceseal_observe import sign_execution_receipt

PROV = {"provenance_version": "1.0", "provider_attestation": "none"}
T0 = "2026-10-01T12:00:00Z"


def _ctx(**kw):
    return {"context_version": "1.0", **kw}


def _rmodel(key, calls, t=T0, **ctx):
    ex = {"receipt_type": "model", "provider": "anthropic", "model": "m", "started_at": t,
          "input_hash": sha256_of("in"), "output_hash": sha256_of("out"),
          "requested_tool_calls": [{"id": i, "name": n, "input_hash": sha256_of(a)} for i, n, a in calls]}
    if ctx:
        ex["context"] = _ctx(**ctx)
    return sign_execution_receipt(ex, PROV, key)


def _rtool(key, name, args, t="2026-10-01T12:05:00Z", **ctx):
    ex = {"receipt_type": "tool", "tool_name": name, "started_at": t,
          "input_hash": sha256_of(args), "output_hash": sha256_of("r")}
    if ctx:
        ex["context"] = _ctx(**ctx)
    return sign_execution_receipt(ex, PROV, key)


def _raw(key, receipt, **changes):
    ex = dict(receipt.execution, **changes)
    for k in [k for k, v in changes.items() if v is None]:
        ex.pop(k)
    return sign_execution_receipt(ex, PROV, key)


def _approve(key, model, call_id="toolu_A", decided=None, started=None, **kw):
    return sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                          subjects=[model], tool_call_ids=[call_id],
                          decided_at=decided or _at(model, 60), review_started_at=started, **kw)


class TestReviewerKeyRegistry:
    """Item 1: a countersignature is bound to the reviewer only via a registry."""

    def _setup(self, key, reviewer_key):
        model = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        appr = _approve(key, model, started=_at(model, 1), reviewer_key=reviewer_key)
        tool = _rtool(key, "issue_refund", ARGS, caused_by=[model.receipt_hash, appr.receipt_hash],
                      tool_call_id="toolu_A")
        return [model, appr, tool]

    def test_operator_key_as_reviewer_key_is_refused_and_an_error(self, key):
        model = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        with pytest.raises(ValueError, match="operator key"):
            _approve(key, model, reviewer_key=key)
        # Forged on the wire: operator countersigns with its own key.
        other = OperatorKey.generate()
        appr = _approve(key, model, reviewer_key=other)
        from traceseal_observe.oversight import reviewer_statement

        ex = dict(appr.execution, reviewer_public_key=key.public_key_hex)
        ex["reviewer_signature"] = key.sign(reviewer_statement(ex)).hex()
        forged = sign_execution_receipt(ex, PROV, key)
        report = verify_trace([model, forged])
        assert any("operator's own key" in e for e in report["errors"])
        # Same with any other operator key present in the trace.
        ex = dict(appr.execution, reviewer_public_key=other.public_key_hex)
        ex["reviewer_signature"] = other.sign(reviewer_statement(ex)).hex()
        forged = sign_execution_receipt(ex, PROV, key)
        side = _rtool(other, "lookup", {})
        assert any("operator's own key" in e for e in verify_trace([model, forged, side])["errors"])

    def test_without_registry_unverified_never_true(self, key):
        receipts = self._setup(key, OperatorKey.generate())
        report = verify_trace(receipts, require_approval=["issue_refund"])
        assert report["ok"], report["errors"]
        assert report["oversight"][0]["reviewer_signed"] == "unverified"
        assert any("unverified" in w for w in report["warnings"])

    def test_registry_binds_key_to_reviewer_ref(self, key):
        alice_key, mallory_key = OperatorKey.generate(), OperatorKey.generate()
        receipts = self._setup(key, mallory_key)
        registry = {REVIEWER.ref: [alice_key.public_key_hex]}
        report = verify_trace(receipts, require_approval=["issue_refund"], reviewer_keys=registry)
        assert any("not registered" in e for e in report["errors"])
        assert any("requires human approval" in e for e in report["errors"])
        # Registered for someone else: still not this reviewer.
        other_ref = Principal.user("someone-else", pepper=PEPPER).ref
        report = verify_trace(receipts, reviewer_keys={other_ref: mallory_key.public_key_hex,
                                                       REVIEWER.ref: alice_key.public_key_hex})
        assert not report["ok"]
        good = self._setup(key, alice_key)
        report = verify_trace(good, require_approval=["issue_refund"], reviewer_keys=registry)
        assert report["ok"], report["errors"]
        assert report["oversight"][0]["reviewer_signed"] is True
        # A malformed registry fails closed.
        assert not verify_trace(good, reviewer_keys={REVIEWER.ref: "zz"})["ok"]

    def test_cli_reviewer_keys(self, key, tmp_path, capsys):
        alice_key = OperatorKey.generate()
        paths = []
        for i, r in enumerate(self._setup(key, alice_key)):
            p = tmp_path / f"{i}.json"
            p.write_text(r.to_json())
            paths.append(str(p))
        assert trace_mod.main(["verify", *paths]) == 0
        assert "key unverified" in capsys.readouterr().out
        reg = tmp_path / "reviewers.json"
        reg.write_text(json.dumps({REVIEWER.ref: [alice_key.public_key_hex]}))
        assert trace_mod.main(["verify", *paths, "--reviewer-keys", str(reg)]) == 0
        assert "(reviewer-signed" in capsys.readouterr().out
        reg.write_text(json.dumps({REVIEWER.ref: [OperatorKey.generate().public_key_hex]}))
        assert trace_mod.main(["verify", *paths, "--reviewer-keys", str(reg)]) == 1


class TestApprovalBinding:
    """Item 2: approvals name their model response and tool_call_ids."""

    def test_sign_refuses_unbound_approvals(self, key):
        model = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        for kw in ({}, {"subjects": [model]}, {"tool_call_ids": ["toolu_A"]}):
            with pytest.raises(ValueError):
                sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER, **kw)
        with pytest.raises(ValueError):
            sign_oversight(decision="modified", operator_key=key, reviewer=REVIEWER,
                           subjects=[model], modified_input={"x": 1})
        tool = _rtool(key, "issue_refund", ARGS)
        with pytest.raises(ValueError, match="model receipts"):
            sign_oversight(decision="approved", operator_key=key, reviewer=REVIEWER,
                           subjects=[tool], tool_call_ids=["toolu_A"])

    def test_blanket_approval_does_not_satisfy_require_approval(self, key):
        model = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        ok = _approve(key, model)
        blanket = _raw(key, ok, subject_receipt_hashes=None, tool_call_ids=None,
                       decided_at="2026-01-01T00:00:00Z")
        receipts = [blanket]
        for n in range(3):
            m = _rmodel(key, [(f"toolu_{n}", "issue_refund", {"n": n})], t=f"2026-10-0{n + 1}T12:00:00Z")
            receipts += [m, _rtool(key, "issue_refund", {"n": n}, t=f"2026-10-0{n + 1}T12:05:00Z",
                                   caused_by=[m.receipt_hash, blanket.receipt_hash],
                                   tool_call_id=f"toolu_{n}")]
        report = verify_trace(receipts, require_approval=["issue_refund"])
        assert any("approves nothing" in e for e in report["errors"])
        assert sum("requires human approval" in e for e in report["errors"]) == 3

    def test_id_only_approval_is_not_replayable(self, key):
        m1 = _rmodel(key, [("toolu_A", "issue_refund", {"amount": 5})])
        a = _approve(key, m1)
        id_only = _raw(key, a, subject_receipt_hashes=None)
        m2 = _rmodel(key, [("toolu_A", "issue_refund", {"amount": 50000})], t="2026-10-02T12:00:00Z")
        t2 = _rtool(key, "issue_refund", {"amount": 50000}, t="2026-10-02T12:05:00Z",
                    caused_by=[m2.receipt_hash, id_only.receipt_hash], tool_call_id="toolu_A")
        report = verify_trace([m1, id_only, m2, t2], require_approval=["issue_refund"])
        assert any("tool_call_ids without the model receipt" in e for e in report["errors"])
        assert any("requires human approval" in e for e in report["errors"])
        # The genuine approval for m1 does not carry over to m2 either.
        t3 = _rtool(key, "issue_refund", {"amount": 50000}, t="2026-10-02T12:05:00Z",
                    caused_by=[m2.receipt_hash, a.receipt_hash], tool_call_id="toolu_A")
        assert any("requires human approval" in e
                   for e in verify_trace([m1, a, m2, t3], require_approval=["issue_refund"])["errors"])

    def test_approval_subject_must_be_a_model_receipt(self, key):
        model = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        other = _rtool(key, "lookup", {}, t=T0)
        a = _approve(key, model)
        wrong = _raw(key, a, subject_receipt_hashes=[other.receipt_hash])
        t = _rtool(key, "issue_refund", ARGS, caused_by=[model.receipt_hash, other.receipt_hash,
                                                         wrong.receipt_hash], tool_call_id="toolu_A")
        report = verify_trace([model, other, wrong, t], require_approval=["issue_refund"])
        assert any("not a model receipt" in e for e in report["errors"])
        assert any("requires human approval" in e for e in report["errors"])


class TestRejectionsAndStops:
    """Item 3."""

    def test_subject_level_rejection_applies_to_every_call(self, key):
        model = _rmodel(key, [("toolu_R", "delete_account", {"u": 1}), ("toolu_S", "email", {})])
        rej = sign_oversight(decision="rejected", operator_key=key, reviewer=REVIEWER,
                             subjects=[model], decided_at=_at(model, 30))
        t1 = _rtool(key, "delete_account", {"u": 1}, caused_by=[model.receipt_hash], tool_call_id="toolu_R")
        t2 = _rtool(key, "email", {}, caused_by=[model.receipt_hash], tool_call_id="toolu_S")
        report = verify_trace([model, rej, t1, t2])
        assert sum("which a human rejected" in e for e in report["errors"]) == 2
        # Even if the model receipt itself isn't supplied.
        assert not verify_trace([rej, t1])["ok"]

    def _stop(self, key, decision, at, subjects=(), **ctx):
        with agent_context(**ctx):
            return sign_oversight(decision=decision, operator_key=key, reviewer=REVIEWER,
                                  decided_at=at, subjects=subjects)

    def test_sessionless_tool_after_stop_in_scope(self, key):
        stop = self._stop(key, "stopped", T0, agent_id="bot", session_id="s1")
        act = _rtool(key, "wire_money", {}, t="2026-10-01T13:00:00Z")
        assert any("no session_id" in e for e in verify_trace([stop, act])["errors"])
        same_agent = _rtool(key, "wire_money", {}, t="2026-10-01T13:00:00Z", agent={"id": "bot"})
        assert not verify_trace([stop, same_agent])["ok"]
        other_agent = _rtool(key, "wire_money", {}, t="2026-10-01T13:00:00Z", agent={"id": "other"})
        assert verify_trace([stop, other_agent])["ok"]
        other_session = _rtool(key, "wire_money", {}, t="2026-10-01T13:00:00Z", session_id="s2")
        assert verify_trace([stop, other_session])["ok"]
        before = _rtool(key, "wire_money", {}, t="2026-10-01T11:00:00Z")
        assert verify_trace([stop, before])["ok"]

    def test_resume_must_cite_the_stop_and_be_strictly_later(self, key):
        stop = self._stop(key, "stopped", T0, session_id="s1")
        act = _rtool(key, "wire_money", {}, t="2026-10-01T13:00:00Z", session_id="s1")
        with pytest.raises(ValueError):
            self._stop(key, "resumed", "2026-10-01T12:10:00Z", session_id="s1")
        # Back-dated to the stop's second: the stop wins the tie.
        tie = self._stop(key, "resumed", T0, subjects=[stop], session_id="s1")
        assert any("after a human stopped it" in e for e in verify_trace([stop, tie, act])["errors"])
        # A resume that cites nothing (raw) lifts nothing.
        later = self._stop(key, "resumed", "2026-10-01T12:10:00Z", subjects=[stop], session_id="s1")
        uncited = _raw(key, later, subject_receipt_hashes=None)
        report = verify_trace([stop, uncited, act])
        assert not report["ok"] and any("lifts nothing" in w for w in report["warnings"])
        # Citing and strictly later: lifted, for actions after the resume only.
        assert verify_trace([stop, later, act])["ok"]
        between = _rtool(key, "wire_money", {}, t="2026-10-01T12:05:00Z", session_id="s1")
        assert not verify_trace([stop, later, between])["ok"]

    def test_chained_resume_same_second_uses_chain_order(self, key):
        chain = ReceiptChain(key, "stops")
        with agent_context(session_id="s1"):
            stop = sign_oversight(decision="stopped", operator_key=chain.signer, reviewer=REVIEWER,
                                  decided_at=T0)
            resume = sign_oversight(decision="resumed", operator_key=chain.signer, reviewer=REVIEWER,
                                    decided_at=T0, subjects=[stop])
            act = observe_tool("t", chain.signer, lambda: 1)[1]
        assert verify_trace([stop, resume, act])["ok"]


class TestApprovalTiming:
    """Item 4: model time <= review_started_at <= decided_at <= tool started_at."""

    def test_approval_decided_after_the_tool_ran(self, key):
        m = _rmodel(key, [("toolu_C", "issue_refund", {"a": 1})], t="2026-10-01T11:59:00Z")
        a = _approve(key, m, call_id="toolu_C", decided="2026-10-01T12:30:00Z")
        t = _rtool(key, "issue_refund", {"a": 1}, t="2026-10-01T12:00:00Z",
                   caused_by=[m.receipt_hash, a.receipt_hash], tool_call_id="toolu_C")
        report = verify_trace([m, a, t], require_approval=["issue_refund"])
        assert any("before the human approval it cites was decided" in e for e in report["errors"])

    def test_review_started_before_the_model_response(self, key):
        m = _rmodel(key, [("toolu_D", "issue_refund", {"a": 7})], t=T0)
        with pytest.raises(ValueError, match="before the subject model receipt"):
            _approve(key, m, call_id="toolu_D", started="2026-10-01T11:00:00Z",
                     decided="2026-10-01T12:00:01Z")
        good = _approve(key, m, call_id="toolu_D", started=T0, decided="2026-10-01T12:00:01Z")
        early = _raw(key, good, review_started_at="2026-10-01T11:00:00Z", review_seconds=3601)
        t = _rtool(key, "issue_refund", {"a": 7}, t="2026-10-01T12:00:02Z",
                   caused_by=[m.receipt_hash, early.receipt_hash], tool_call_id="toolu_D")
        report = verify_trace([m, early, t], require_approval=["issue_refund"], min_review_seconds=30)
        assert any("before the model response it reviews existed" in e for e in report["errors"])
        assert report["oversight"][0]["effective_review_seconds"] == 1
        assert any("approved after 1s" in w for w in report["warnings"])
        decided_early = _raw(key, good, review_started_at=None, review_seconds=None,
                             decided_at="2026-10-01T11:00:00Z")
        assert any("decided before the model response" in e
                   for e in verify_trace([m, decided_early])["errors"])

    def test_rubber_stamp_without_review_started_uses_model_time(self, key):
        m = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        a = _approve(key, m, decided=_at(m, 2))
        report = verify_trace([m, a], min_review_seconds=30)
        assert any("approved after 2s" in w for w in report["warnings"])
        report = verify_trace([a], min_review_seconds=30)
        assert any("rubber-stamp check not performed" in w for w in report["warnings"])

    def test_approved_model_not_supplied(self, key):
        m = _rmodel(key, [("toolu_A", "issue_refund", ARGS)])
        a = _approve(key, m)
        t = _rtool(key, "issue_refund", ARGS, caused_by=[m.receipt_hash, a.receipt_hash],
                   tool_call_id="toolu_A")
        report = verify_trace([a, t], require_approval=["issue_refund"])
        assert any("model receipt was not supplied" in e for e in report["errors"])


class TestSignedTimeOnly:
    """Item 5: never the unsigned attested_at; strict format; never silently pass."""

    def test_offset_time_and_edited_attested_at(self, key):
        with agent_context(session_id="s1"):
            stop = sign_oversight(decision="stopped", operator_key=key, reviewer=REVIEWER, decided_at=T0)
        t = _rtool(key, "wire_money", {}, t="2026-10-01T15:00:00+00:00", session_id="s1",
                   authorization={"scopes": ["pay"], "expires_at": "2026-10-01T12:30:00Z"})
        t.attestation["attested_at"] = "2026-10-01T11:00:00Z"  # unsigned
        verify_receipt_signature(t)
        report = verify_trace([stop, t])
        assert any("expiry not checked" in e for e in report["errors"])
        assert any("after-stop check not performed" in e for e in report["errors"])

    def test_policy_decision_time_is_signed(self, key):
        import copy

        from traceseal_observe import Receipt

        with agent_context(agent_id="agent-1", session_id="S1"):
            stop = sign_oversight(decision="stopped", operator_key=key, reviewer=REVIEWER,
                                  decided_at=T0)
            pd = sign_policy_decision(policy_id="egress", decision="allow", stage="data_flow",
                                      operator_key=key, subject="x",
                                      decided_at="2026-10-01T12:30:00Z")
        assert pd.execution["decided_at"] == "2026-10-01T12:30:00Z"
        forged = Receipt(**copy.deepcopy(pd.to_dict()))
        forged.attestation["attested_at"] = "2026-10-01T11:59:00Z"
        for r in (pd, forged):
            assert any("after a human stopped it" in e for e in verify_trace([stop, r])["errors"])

    def test_no_signed_time_is_never_a_pass(self, key):
        with agent_context(session_id="s1"):
            stop = sign_oversight(decision="stopped", operator_key=key, reviewer=REVIEWER, decided_at=T0)
        bare = sign_execution_receipt({"receipt_type": "tool", "tool_name": "x",
                                       "context": _ctx(session_id="s1")}, PROV, key)
        report = verify_trace([stop, bare])
        assert any("no signed time" in e for e in report["errors"])
        assert trace_mod._when(bare) is None
