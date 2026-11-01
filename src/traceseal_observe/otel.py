"""Put receipts into your existing OpenTelemetry traces.

Observability tools already show what agents do; receipts make it
verifiable. This module annotates spans with the OpenTelemetry GenAI
semantic-convention attributes plus `traceseal.*` attributes (receipt hash,
type, chain position, operator), so a trace in your observability backend
links to the exact signed receipt an auditor can verify.

    from traceseal_observe.otel import record_receipt, OTelSink

    response, receipt = observe_anthropic(client, request, key)
    record_receipt(receipt)                 # annotate the current span

    sink = OTelSink()                       # or: a receipt_sink / on_receipt callback
    ReceiptTransport(..., on_receipt=sink)

When a span is active, agent_context picks up its trace and span ids
automatically (context.py), so the receipt points back to the trace too.
Requires opentelemetry-api (pip install opentelemetry-api).
"""

from __future__ import annotations

from typing import Any

_OPERATION = {"model": "chat", "tool": "execute_tool"}


def receipt_attributes(receipt: Any) -> dict[str, Any]:
    """OpenTelemetry attributes for a receipt (GenAI semconv + traceseal.*)."""
    ex = receipt.execution
    att = receipt.attestation
    rtype = ex.get("receipt_type", "skill")
    attrs: dict[str, Any] = {
        "traceseal.receipt.hash": receipt.receipt_hash,
        "traceseal.receipt.type": rtype,
        "traceseal.operator.fingerprint": att.get("operator_fingerprint", ""),
    }
    if "ok" in ex:
        attrs["traceseal.receipt.ok"] = ex["ok"] == "true"
    if "chain_id" in ex:
        attrs["traceseal.chain.id"] = ex["chain_id"]
        attrs["traceseal.chain.seq"] = ex["chain_seq"]
    if rtype in _OPERATION:
        attrs["gen_ai.operation.name"] = _OPERATION[rtype]
    if rtype == "model":
        attrs["gen_ai.provider.name"] = ex.get("provider", "")
        attrs["gen_ai.request.model"] = ex.get("model", "")
        if ex.get("served_model"):
            attrs["gen_ai.response.model"] = ex["served_model"]
        if ex.get("response_id"):
            attrs["gen_ai.response.id"] = ex["response_id"]
        if ex.get("stop_reason"):
            attrs["gen_ai.response.finish_reasons"] = [ex["stop_reason"]]
        if "input_tokens" in ex:
            attrs["gen_ai.usage.input_tokens"] = ex["input_tokens"]
        if "output_tokens" in ex:
            attrs["gen_ai.usage.output_tokens"] = ex["output_tokens"]
    elif rtype == "tool":
        attrs["gen_ai.tool.name"] = ex.get("tool_name", "")
    elif rtype == "data_flow":
        attrs["server.address"] = ex.get("destination_host", "")
        attrs["http.request.method"] = ex.get("method", "")
        if ex.get("status_code"):
            attrs["http.response.status_code"] = ex["status_code"]
    ctx = ex.get("context") if isinstance(ex.get("context"), dict) else {}
    if ctx.get("tool_call_id"):
        attrs["gen_ai.tool.call.id"] = ctx["tool_call_id"]
    agent = ctx.get("agent") or {}
    if agent.get("id"):
        attrs["gen_ai.agent.id"] = agent["id"]
    if ctx.get("session_id"):
        attrs["gen_ai.conversation.id"] = ctx["session_id"]
    return attrs


def record_receipt(receipt: Any, span: Any = None, *, as_event: bool = True) -> None:
    """Annotate `span` (default: the current span) with the receipt."""
    from opentelemetry import trace

    target = span if span is not None else trace.get_current_span()
    attrs = receipt_attributes(receipt)
    if as_event:
        target.add_event("traceseal.receipt", attributes=attrs)
    else:
        target.set_attributes(attrs)


class OTelSink:
    """A receipt callback that records each receipt on the current span,
    or on a new span named `traceseal.<type>` when none is active."""

    def __init__(self, tracer_name: str = "traceseal-observe"):
        from opentelemetry import trace

        self._trace = trace
        self._tracer = trace.get_tracer(tracer_name)

    def __call__(self, receipt: Any) -> None:
        span = self._trace.get_current_span()
        if span.get_span_context().is_valid:
            record_receipt(receipt, span)
            return
        kind = receipt.execution.get("receipt_type", "receipt")
        with self._tracer.start_as_current_span(f"traceseal.{kind}") as new_span:
            new_span.set_attributes(receipt_attributes(receipt))
