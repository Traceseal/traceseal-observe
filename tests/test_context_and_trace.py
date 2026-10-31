"""Agent/principal/authorisation context, tool-call causality, verify_trace."""

from __future__ import annotations

import asyncio
import json
import threading

import pytest

from traceseal_observe import (
    Authorization,
    OperatorKey,
    Principal,
    ReceiptChain,
    WorkflowObserver,
    agent_context,
    caused_by,
    observe_anthropic,
    observe_anthropic_stream,
    observe_model_call,
    observe_openai,
    observe_tool,
    requested_tool_calls,
    sha256_of,
    sign_execution_receipt,
    sign_outcome,
    verify_chain,
    verify_receipt_signature,
)
from traceseal_observe import context as ctx_mod
from traceseal_observe import trace as trace_mod
from traceseal_observe.context import (
    ToolCallAccumulator,
    current_context,
    extract_tool_calls,
    principal_ref,
)
from traceseal_observe.trace import find_receipts_for_principal, verify_trace

PEPPER = b"0123456789abcdef-pepper"


@pytest.fixture
def key():
    return OperatorKey.generate("ctx")


class Obj:
    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return json.loads(json.dumps(self._data))


class FakeAnthropic:
    def __init__(self, response):
        outer = self

        class Messages:
            def create(self, **kw):
                return response() if callable(response) else response

        self.messages = Messages()


class FakeOpenAI:
    def __init__(self, response):
        class Completions:
            def create(self, **kw):
                return response

        class Chat:
            completions = Completions()

        self.chat = Chat()


TOOL_USE_RESPONSE = {
    "id": "msg_1", "model": "claude-x-1", "stop_reason": "tool_use",
    "content": [
        {"type": "text", "text": "Refunding."},
        {"type": "tool_use", "id": "toolu_A", "name": "issue_refund",
         "input": {"order": "o-1", "amount": 20}},
        {"type": "tool_use", "id": "toolu_B", "name": "send_email",
         "input": {"to": "u@example.com"}},
    ],
}


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


class TestContext:
    def test_no_context_means_no_field(self, key):
        assert "context" not in observe_tool("t", key, lambda: 1)[1].execution
        assert current_context() is None

    def test_fields_are_signed(self, key):
        auth = Authorization(scopes=["refunds:write", "email:send"], grant={"jti": "abc"},
                             granted_by=Principal.public("organisation", "acme-ops"),
                             expires_at="2030-01-01T00:00:00Z")
        with agent_context(agent_id="support-bot", agent_version="2.3.1", deployment="prod-eu",
                           tenant="acme", session_id="s-42",
                           principal=Principal.user("user-123", pepper=PEPPER),
                           trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
                           span_id="00f067aa0ba902b7", authorization=auth):
            r = observe_tool("t", key, lambda: 1)[1]
        verify_receipt_signature(r)
        c = r.execution["context"]
        assert c["context_version"] == "1.0"
        assert c["agent"] == {"id": "support-bot", "version": "2.3.1", "deployment": "prod-eu"}
        assert c["principal"] == {"kind": "user", "ref": principal_ref("user", "user-123", PEPPER)}
        assert "user-123" not in json.dumps(r.to_dict())
        assert c["authorization"]["scopes"] == ["email:send", "refunds:write"]
        assert c["authorization"]["grant_hash"] == sha256_of({"jti": "abc"})
        assert c["authorization"]["granted_by"] == {"kind": "organisation", "ref": "id:acme-ops"}
        assert c["trace"]["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        r.execution["context"]["tenant"] = "evil"
        with pytest.raises(ValueError):
            verify_receipt_signature(r)

    def test_nesting_overrides_and_restores(self, key):
        with agent_context(agent_id="a", agent_version="1", tenant="t1"):
            with agent_context(agent_version="2", tenant="t2"):
                inner = observe_tool("t", key, lambda: 1)[1].execution["context"]
            outer = observe_tool("t", key, lambda: 1)[1].execution["context"]
        assert inner["agent"] == {"id": "a", "version": "2"} and inner["tenant"] == "t2"
        assert outer["agent"] == {"id": "a", "version": "1"} and outer["tenant"] == "t1"

    def test_applies_to_every_operational_type_and_chains(self, key):
        chain = ReceiptChain(key, "c")
        with agent_context(agent_id="bot"):
            _, m = observe_model_call("p", "m", "https://e", chain.signer, lambda: {"x": 1})
            _, t = observe_tool("t", chain.signer, lambda: 1)
            with WorkflowObserver("wf", "1", chain.signer) as wf:
                wf.add_step("t", t)
            o = sign_outcome(t, status="succeeded", outcome=None, operator_key=chain.signer)
        rs = [m, t, wf.receipt, o]
        assert all(r.execution["context"]["agent"]["id"] == "bot" for r in rs)
        assert verify_chain(rs)["ok"]

    def test_domain_receipts_never_get_context(self, key):
        from traceseal_observe import _sign_receipt_body

        with agent_context(agent_id="bot"):
            r = _sign_receipt_body({"receipt_type": "model_resolution"}, {}, key)
        assert "context" not in r.execution

    def test_explicit_context_wins(self, key):
        with agent_context(agent_id="bot"):
            r = sign_execution_receipt({"receipt_type": "tool", "context": {"mine": "1"}}, {}, key)
        assert r.execution["context"] == {"mine": "1"}

    def test_threads_and_tasks_are_isolated(self, key):
        seen = {}

        def worker(name):
            with agent_context(agent_id=name):
                seen[name] = observe_tool("t", key, lambda: 1)[1].execution["context"]["agent"]["id"]

        threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert seen == {f"w{i}": f"w{i}" for i in range(5)}

        async def task(name):
            with agent_context(agent_id=name):
                await asyncio.sleep(0)
                return observe_tool("t", key, lambda: 1)[1].execution["context"]["agent"]["id"]

        async def run():
            return await asyncio.gather(*(task(f"a{i}") for i in range(5)))

        assert asyncio.run(run()) == [f"a{i}" for i in range(5)]

    def test_validation(self):
        bad = [
            dict(trace_id="XYZ"), dict(trace_id="0" * 32), dict(span_id="1" * 15),
            dict(agent_id=""), dict(agent_id="x" * 129), dict(tenant="a\nb"),
            dict(principal="user-1"), dict(caused_by=["not-a-hash"]),
            dict(authorization=Authorization()),
            dict(authorization=Authorization(scopes=["has space"])),
            dict(authorization=Authorization(expires_at="tomorrow")),
            dict(authorization=Authorization(grant={1, 2})),
        ]
        for fields in bad:
            with pytest.raises(ValueError):
                with agent_context(**fields):
                    pass
        with pytest.raises(TypeError):
            with agent_context(nonsense=1):
                pass
        with pytest.raises(ValueError):
            Principal.public("user", "alice")
        with pytest.raises(ValueError):
            Principal.user("u", pepper=b"short")

    def test_opentelemetry_span_is_picked_up(self, key, monkeypatch):
        monkeypatch.setattr(ctx_mod, "_otel_trace",
                            lambda: {"trace_id": "a" * 32, "span_id": "b" * 16})
        r = observe_tool("t", key, lambda: 1)[1]
        assert r.execution["context"]["trace"] == {"trace_id": "a" * 32, "span_id": "b" * 16}
        with agent_context(trace_id="c" * 32):
            r = observe_tool("t", key, lambda: 1)[1]
        assert r.execution["context"]["trace"] == {"trace_id": "c" * 32}


# ---------------------------------------------------------------------------
# Requested tool calls
# ---------------------------------------------------------------------------


class TestRequestedToolCalls:
    def test_anthropic_tool_use(self, key):
        _, r = observe_anthropic(FakeAnthropic(Obj(TOOL_USE_RESPONSE)), {"model": "m"}, key)
        calls = requested_tool_calls(r)
        assert calls == [
            {"id": "toolu_A", "name": "issue_refund",
             "input_hash": sha256_of({"order": "o-1", "amount": 20})},
            {"id": "toolu_B", "name": "send_email", "input_hash": sha256_of({"to": "u@example.com"})},
        ]

    def test_openai_tool_calls_hash_parsed_arguments(self, key):
        resp = {"id": "c", "model": "g", "choices": [{"finish_reason": "tool_calls", "message": {
            "tool_calls": [{"id": "call_1", "type": "function", "function": {
                "name": "lookup", "arguments": '{"b": 2, "a": 1}'}}]}}]}
        _, r = observe_openai(FakeOpenAI(Obj(resp)), {"model": "g"}, key)
        assert requested_tool_calls(r) == [
            {"id": "call_1", "name": "lookup", "input_hash": sha256_of({"a": 1, "b": 2})}]

    def test_responses_api_and_bad_arguments(self):
        calls = extract_tool_calls({"output": [
            {"type": "function_call", "call_id": "fc_1", "name": "f", "arguments": "not json"},
            {"type": "message"},
        ]})
        assert calls == [{"id": "fc_1", "name": "f", "input_hash": sha256_of("not json")}]

    def test_streamed_anthropic_tool_use(self, key):
        events = [
            {"type": "message_start", "message": {"id": "msg_s", "model": "claude-x-1",
                                                  "usage": {"input_tokens": 3}}},
            {"type": "content_block_start", "index": 0,
             "content_block": {"type": "tool_use", "id": "toolu_S", "name": "issue_refund", "input": {}}},
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "input_json_delta", "partial_json": '{"order": "o-1", '}},
            {"type": "content_block_delta", "index": 0,
             "delta": {"type": "input_json_delta", "partial_json": '"amount": 20}'}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}},
        ]
        stream = observe_anthropic_stream(FakeAnthropic(lambda: iter([Obj(e) for e in events])),
                                          {"model": "m"}, key)
        list(stream)
        assert requested_tool_calls(stream.receipt) == [
            {"id": "toolu_S", "name": "issue_refund",
             "input_hash": sha256_of({"order": "o-1", "amount": 20})}]

    def test_streamed_openai_tool_calls(self):
        acc = ToolCallAccumulator()
        for chunk in [
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_9", "function": {"name": "f", "arguments": '{"x"'}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": ': 1}'}}]}}]},
        ]:
            acc.feed(chunk)
        assert acc.result() == [{"id": "call_9", "name": "f", "input_hash": sha256_of({"x": 1})}]

    def test_stream_signs_under_context_at_start(self, key):
        with agent_context(agent_id="starter"):
            stream = observe_anthropic_stream(FakeAnthropic(lambda: iter([])), {"model": "m"}, key)
        with agent_context(agent_id="other"):
            list(stream)
        assert stream.receipt.execution["context"]["agent"]["id"] == "starter"


# ---------------------------------------------------------------------------
# verify_trace
# ---------------------------------------------------------------------------


def _agent_run(key, *, refund_args=None, call_id="toolu_A", expires="2030-01-01T00:00:00Z",
               scopes=("refunds:write",)):
    auth = Authorization(scopes=list(scopes), expires_at=expires)
    with agent_context(agent_id="support-bot", principal=Principal.user("u-1", pepper=PEPPER),
                       authorization=auth):
        _, model = observe_anthropic(FakeAnthropic(Obj(TOOL_USE_RESPONSE)), {"model": "m"}, key)
        args = refund_args or {"order": "o-1", "amount": 20}
        with caused_by(model, tool_call_id=call_id):
            _, tool = observe_tool("issue_refund", key, lambda: {"ok": True}, args=args)
    return model, tool


class TestVerifyTrace:
    def test_matched_call_and_findings(self, key):
        model, tool = _agent_run(key)
        report = verify_trace([model, tool], required_scopes={"issue_refund": "refunds:write"})
        assert report["ok"], report["errors"]
        assert report["edges"] == [{"from": model.receipt_hash, "to": tool.receipt_hash}]
        assert report["tool_calls"][0]["status"] == "matched"
        assert report["unexecuted_tool_calls"] == [
            {"model_receipt": model.receipt_hash, "id": "toolu_B", "name": "send_email"}]
        assert report["agents"] == {"support-bot": 2}

    def test_arguments_changed_by_agent(self, key):
        model, tool = _agent_run(key, refund_args={"order": "o-1", "amount": 2000})
        report = verify_trace([model, tool])
        assert report["ok"]
        assert report["tool_calls"][0]["status"] == "arguments_differ"

    def test_not_requested_is_an_error(self, key):
        model, tool = _agent_run(key, call_id="toolu_FAKE")
        report = verify_trace([model, tool])
        assert not report["ok"]
        assert report["tool_calls"][0]["status"] == "not_requested"

    def test_name_differs(self, key):
        with agent_context():
            _, model = observe_anthropic(FakeAnthropic(Obj(TOOL_USE_RESPONSE)), {"model": "m"}, key)
            with caused_by(model, tool_call_id="toolu_A"):
                _, tool = observe_tool("wire_money", key, lambda: 1,
                                       args={"order": "o-1", "amount": 20})
        assert verify_trace([model, tool])["tool_calls"][0]["status"] == "name_differs"

    def test_expired_and_missing_scope(self, key):
        model, tool = _agent_run(key, expires="2020-01-01T00:00:00Z")
        assert any("expired" in e for e in verify_trace([model, tool])["errors"])
        model, tool = _agent_run(key, scopes=("email:send",))
        report = verify_trace([model, tool], required_scopes={"issue_refund": ["refunds:write"]})
        assert any("missing required scope" in e for e in report["errors"])

    def test_unprompted_and_unresolved(self, key):
        _, lone = observe_tool("cron_cleanup", key, lambda: 1)
        model, tool = _agent_run(key)
        report = verify_trace([lone, tool])  # model receipt withheld
        assert report["unprompted_tool_receipts"] == [lone.receipt_hash]
        assert report["unresolved_causes"] == [{"receipt": tool.receipt_hash,
                                                "cause": model.receipt_hash}]

    def test_tampering_and_malformed_context(self, key):
        model, tool = _agent_run(key)
        tool.execution["context"]["tool_call_id"] = "toolu_B"
        assert not verify_trace([model, tool])["ok"]
        bad = sign_execution_receipt({"receipt_type": "tool", "context": {"context_version": "9"}},
                                     {}, key)
        assert any("context_version" in e for e in verify_trace([bad])["errors"])

    def test_cross_operator_causality(self, key):
        """Agent A's tool call causes agent B's (different operator) action."""
        other = OperatorKey.generate("partner")
        model, tool = _agent_run(key)
        with caused_by(tool):
            _, downstream = observe_tool("ship_parcel", other, lambda: 1)
        report = verify_trace([model, tool, downstream])
        assert report["ok"]
        assert {"from": tool.receipt_hash, "to": downstream.receipt_hash} in report["edges"]

    def test_find_receipts_for_principal(self, key):
        model, tool = _agent_run(key)
        _, other = observe_tool("t", key, lambda: 1)
        found = find_receipts_for_principal([model, tool, other], "user", "u-1", PEPPER)
        assert found == [model, tool]
        assert find_receipts_for_principal([model, tool], "user", "u-1", b"x" * 16) == []

    def test_cli(self, key, tmp_path, capsys):
        model, tool = _agent_run(key)
        paths = []
        for i, r in enumerate([model, tool]):
            p = tmp_path / f"{i}.json"
            p.write_text(r.to_json())
            paths.append(str(p))
        assert trace_mod.main(["verify", *paths, "--require-scope", "issue_refund=refunds:write"]) == 0
        out = capsys.readouterr().out
        assert "matched" in out and "requested, not executed: send_email" in out
        assert trace_mod.main(["verify", *paths, "--require-scope", "issue_refund=admin"]) == 1
        capsys.readouterr()
        (tmp_path / "pepper").write_bytes(PEPPER)
        assert trace_mod.main(["find-principal", *paths, "--id", "u-1",
                               "--pepper-file", str(tmp_path / "pepper")]) == 0
        assert capsys.readouterr().out.split() == paths
