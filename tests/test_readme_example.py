"""The README's 'complete agent turn' example, run against the real SDK."""

from __future__ import annotations

import pytest

httpx = pytest.importorskip("httpx2")
anthropic = pytest.importorskip("anthropic")

from test_capture_async_otel import REQ, handler  # noqa: E402

from traceseal_observe import (  # noqa: E402
    Authorization,
    OperatorKey,
    Principal,
    ReceiptChain,
    agent_context,
    caused_by,
    observe_anthropic,
    observe_policy,
    observe_tool,
    sign_oversight,
    verify_chain,
)
from traceseal_observe import trace as trace_mod  # noqa: E402
from traceseal_observe.vault import EvidenceVault, LocalKEK  # noqa: E402

PEPPER = b"0123456789abcdef-pepper"


def test_complete_agent_turn(tmp_path, capsys):
    client = anthropic.Anthropic(api_key="k", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    chain = ReceiptChain(OperatorKey.generate(), "support-agent")
    signer = chain.signer
    vault = EvidenceVault.open(tmp_path / "vault", LocalKEK.generate())
    request, session_id, user_id, reviewer_id, tenant = REQ, "s-1", "u-1", "r-1", "acme"
    receipts = []

    def check_limit(args):
        return "allow"

    def run(call):
        return {"refunded": True}

    with agent_context(agent_id="support-bot", agent_version="2.3.1", session_id=session_id,
                       principal=Principal.user(user_id, pepper=PEPPER),
                       authorization=Authorization(scopes=["refunds:write"], grant={"jti": "x"})):
        response, model_receipt = observe_anthropic(client, request, signer)
        receipts.append(model_receipt)
        for call in response.content:
            if call.type != "tool_use":
                continue
            _, policy = observe_policy("spend-limit", check_limit, call.input, signer, stage="tool_call")
            approval = sign_oversight(decision="approved", operator_key=signer,
                                      reviewer=Principal.user(reviewer_id, pepper=PEPPER),
                                      subjects=[model_receipt], tool_call_ids=[call.id],
                                      presented={"call": call.name},
                                      review_started_at=model_receipt.execution["started_at"])
            with caused_by(model_receipt, policy, approval, tool_call_id=call.id):
                result, tool_receipt = observe_tool(call.name, signer, lambda: run(call), args=call.input)
            receipts += [policy, approval, tool_receipt]
        vault.put_for(model_receipt, "input_hash", request, domain=f"tenant:{tenant}")

    assert verify_chain(receipts, checkpoint=chain.checkpoint())["ok"]
    paths = []
    for i, r in enumerate(receipts):
        p = tmp_path / f"{i}.json"
        p.write_text(r.to_json())
        paths.append(str(p))
    tool = "refund"  # the tool name the mock model requested
    rc = trace_mod.main(["verify", *paths, "--require-approval", tool,
                         "--require-policy", f"{tool}=spend-limit",
                         "--require-scope", f"{tool}=refunds:write"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "[toolu_1] matched" in out
