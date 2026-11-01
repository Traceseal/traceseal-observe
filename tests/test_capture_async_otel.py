"""Real-SDK integration (Anthropic/OpenAI over a mock HTTP transport):
endpoints, async observers and streams, the capture transport, OpenTelemetry."""

from __future__ import annotations

import asyncio
import json

import pytest

httpx = pytest.importorskip("httpx2")
anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")

from traceseal_observe import (  # noqa: E402
    OperatorKey,
    ReceiptChain,
    agent_context,
    aobserve_anthropic,
    aobserve_anthropic_stream,
    aobserve_openai,
    aobserve_openai_stream,
    aobserve_tool,
    observe_anthropic,
    observe_anthropic_stream,
    observe_openai,
    sha256_of,
    verify_chain,
    verify_receipt_signature,
)
from traceseal_observe.capture import (  # noqa: E402
    AsyncReceiptTransport,
    ReceiptTransport,
    UndeclaredDestination,
)

MSG = {"id": "msg_01", "type": "message", "role": "assistant",
       "model": "claude-sonnet-4-5-20250929",
       "content": [{"type": "tool_use", "id": "toolu_1", "name": "refund", "input": {"a": 1}}],
       "stop_reason": "tool_use", "stop_sequence": None,
       "usage": {"input_tokens": 10, "output_tokens": 5}}
EVENTS = [
    ("message_start", {"type": "message_start", "message": {**MSG, "content": [], "stop_reason": None,
                                                            "usage": {"input_tokens": 10, "output_tokens": 1}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "tool_use", "id": "toolu_1", "name": "refund", "input": {}}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "input_json_delta", "partial_json": "{\"a\": 1}"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                       "usage": {"output_tokens": 5}}),
    ("message_stop", {"type": "message_stop"}),
]
SSE = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in EVENTS).encode()
CHAT = {"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-x-2026-01-01",
        "system_fingerprint": "fp_1",
        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": "{\"q\": \"x\"}"}}]}}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}}
CHAT_CHUNKS = [
    {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x-2026-01-01",
     "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
         {"index": 0, "id": "call_9", "type": "function", "function": {"name": "f", "arguments": "{\"x\""}}]},
         "finish_reason": None}]},
    {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x-2026-01-01",
     "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": ": 1}"}}]},
                  "finish_reason": "tool_calls"}]},
]
OPENAI_SSE = ("".join(f"data: {json.dumps(c)}\n\n" for c in CHAT_CHUNKS) + "data: [DONE]\n\n").encode()
REQ = {"model": "claude-sonnet-5-5", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}
OREQ = {"model": "gpt-x", "messages": [{"role": "user", "content": "hi"}]}


def handler(request):
    body = json.loads(request.content)
    if request.url.path.endswith("/messages"):
        if body.get("stream"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=SSE)
        return httpx.Response(200, json=MSG)
    if body.get("stream"):
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=OPENAI_SSE)
    return httpx.Response(200, json=CHAT)


@pytest.fixture
def key():
    return OperatorKey.generate("sdk")


def _anthropic(transport=None, base_url=None):
    return anthropic.Anthropic(api_key="sk-test", base_url=base_url,
                               http_client=httpx.Client(transport=transport or httpx.MockTransport(handler)))


def _openai(transport=None):
    return openai.OpenAI(api_key="sk-test", http_client=httpx.Client(transport=transport or httpx.MockTransport(handler)))


class TestRealSDKs:
    def test_anthropic_sync_and_stream(self, key):
        resp, r = observe_anthropic(_anthropic(), REQ, key)
        ex = r.execution
        assert type(resp).__name__ == "Message" and ex["ok"] == "true"
        assert ex["api_endpoint"] == "https://api.anthropic.com/v1/messages"
        assert ex["served_model"] == "claude-sonnet-4-5-20250929"
        assert ex["requested_tool_calls"][0]["input_hash"] == sha256_of({"a": 1})
        assert (ex["input_tokens"], ex["output_tokens"]) == (10, 5)
        with observe_anthropic_stream(_anthropic(), REQ, key) as stream:
            events = [e.type for e in stream]
        assert events[0] == "message_start" and stream.receipt.execution["stream_complete"] == "true"
        assert stream.receipt.execution["requested_tool_calls"] == ex["requested_tool_calls"]

    def test_custom_base_url_is_recorded_without_credentials(self, key):
        client = _anthropic(base_url="https://user:secret@gateway.example:8443/anthropic/?k=v")
        _, r = observe_anthropic(client, REQ, key)
        assert r.execution["api_endpoint"] == "https://gateway.example:8443/anthropic/v1/messages"

    def test_openai_sync(self, key):
        _, r = observe_openai(_openai(), OREQ, key)
        ex = r.execution
        assert ex["api_endpoint"] == "https://api.openai.com/v1/chat/completions"
        assert ex["system_fingerprint"] == "fp_1" and ex["stop_reason"] == "tool_calls"
        assert ex["requested_tool_calls"] == [{"id": "call_1", "name": "lookup",
                                               "input_hash": sha256_of({"q": "x"})}]


class TestAsync:
    def test_async_anthropic_openai_and_streams(self, key):
        async def run():
            a = anthropic.AsyncAnthropic(api_key="k", http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(handler)))
            o = openai.AsyncOpenAI(api_key="k", http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(handler)))
            with agent_context(agent_id="async-bot"):
                _, r1 = await aobserve_anthropic(a, REQ, key)
                _, r2 = await aobserve_openai(o, OREQ, key)
                s1 = await aobserve_anthropic_stream(a, REQ, key)
                async with s1:
                    async for _ in s1:
                        pass
                s2 = await aobserve_openai_stream(o, OREQ, key)
                async for _ in s2:
                    pass
                result, r3 = await aobserve_tool("lookup", key, lambda: asyncio.sleep(0, "done"),
                                                 args={"q": "x"})
            return r1, r2, s1.receipt, s2.receipt, result, r3

        r1, r2, s1, s2, result, r3 = asyncio.run(run())
        assert r1.execution["served_model"] == "claude-sonnet-4-5-20250929"
        assert r2.execution["input_tokens"] == 7
        assert s1.execution["stream_complete"] == "true"
        assert s1.execution["requested_tool_calls"][0]["id"] == "toolu_1"
        assert s2.execution["requested_tool_calls"] == [
            {"id": "call_9", "name": "f", "input_hash": sha256_of({"x": 1})}]
        assert result == "done" and r3.execution["output_hash"] == sha256_of("done")
        assert all(r.execution["context"]["agent"]["id"] == "async-bot" for r in (r1, r2, s1, s2, r3))

    def test_async_failure_contract(self, key):
        async def boom():
            raise ConnectionError("down")

        async def run():
            from traceseal_observe import aobserve_model_call

            return await aobserve_model_call("p", "m", "https://e", key, boom)

        resp, r = asyncio.run(run())
        assert resp is None and r.execution["ok"] == "false"


class TestCaptureTransport:
    def test_every_request_is_receipted(self, key):
        receipts = []
        transport = ReceiptTransport(httpx.MockTransport(handler), operator_key=key,
                                     on_receipt=receipts.append, allow_hosts=["api.anthropic.com"])
        client = _anthropic(transport)
        client.messages.create(**REQ)                       # not wrapped by observe_*
        with client.messages.stream(**REQ) as stream:      # SDK helper, streamed
            stream.get_final_message()
        assert len(receipts) == 2
        for r in receipts:
            verify_receipt_signature(r)
            ex = r.execution
            assert ex["receipt_type"] == "data_flow" and ex["destination_host"] == "api.anthropic.com"
            assert ex["destination_declared"] == "true" and ex["status_code"] == 200
        assert receipts[0].execution["response_payload_hash"] == sha256_of(httpx.Response(200, json=MSG).content)
        assert receipts[1].execution["response_payload_hash"] == sha256_of(SSE)
        assert "sk-test" not in json.dumps([r.to_dict() for r in receipts])

    def test_pii_and_undeclared(self, key):
        receipts = []
        transport = ReceiptTransport(httpx.MockTransport(handler), operator_key=key,
                                     on_receipt=receipts.append, allow_hosts=["api.anthropic.com"])
        client = _openai(transport)
        client.chat.completions.create(model="gpt-x", messages=[
            {"role": "user", "content": "email jane@example.com"}])
        ex = receipts[0].execution
        assert ex["destination_declared"] == "false" and ex["pii_fingerprint"] == {"email": 1}

    def test_block_undeclared(self, key):
        receipts, sent = [], []

        def recording(request):
            sent.append(request)
            return handler(request)

        transport = ReceiptTransport(httpx.MockTransport(recording), operator_key=key,
                                     on_receipt=receipts.append, allow_hosts=["api.anthropic.com"],
                                     block_undeclared=True)
        client = openai.OpenAI(api_key="k", max_retries=0, http_client=httpx.Client(transport=transport))
        with pytest.raises(Exception):
            client.chat.completions.create(**OREQ)
        assert sent == []
        assert receipts and receipts[0].execution["ok"] == "false"
        assert "blocked" in receipts[0].execution["error_message"]
        with pytest.raises(ValueError):
            ReceiptTransport(httpx.MockTransport(handler), operator_key=key,
                             on_receipt=print, block_undeclared=True)

    def test_transport_error_is_receipted(self, key):
        receipts = []

        def failing(request):
            raise httpx.ConnectError("refused", request=request)

        transport = ReceiptTransport(httpx.MockTransport(failing), operator_key=key,
                                     on_receipt=receipts.append)
        client = anthropic.Anthropic(api_key="k", max_retries=1, http_client=httpx.Client(transport=transport))
        with pytest.raises(Exception):
            client.messages.create(**REQ)
        assert len(receipts) == 2  # the retry is receipted too
        assert all(r.execution["status_code"] == 0 for r in receipts)

    def test_async_transport_and_chain(self, key):
        chain = ReceiptChain(key, "capture")
        receipts = []

        async def run():
            transport = AsyncReceiptTransport(httpx.MockTransport(handler), operator_key=chain.signer,
                                              on_receipt=receipts.append)
            client = anthropic.AsyncAnthropic(api_key="k", http_client=httpx.AsyncClient(transport=transport))
            await client.messages.create(**REQ)
            stream = await client.messages.create(**REQ, stream=True)
            async for _ in stream:
                pass

        asyncio.run(run())
        assert [r.execution["chain_seq"] for r in receipts] == [1, 2]
        assert verify_chain(receipts, checkpoint=chain.checkpoint())["ok"]


class TestOpenTelemetry:
    def test_attributes_and_sink(self, key):
        pytest.importorskip("opentelemetry.sdk")
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

        from traceseal_observe.otel import OTelSink, receipt_attributes, record_receipt

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("agent-step") as span:
            with agent_context(agent_id="bot", session_id="s1"):
                _, r = observe_anthropic(_anthropic(), REQ, key)
            record_receipt(r)
            ctx = r.execution["context"]["trace"]
            assert ctx["trace_id"] == format(span.get_span_context().trace_id, "032x")
        attrs = receipt_attributes(r)
        assert attrs["gen_ai.request.model"] == "claude-sonnet-5-5"
        assert attrs["gen_ai.response.model"] == "claude-sonnet-4-5-20250929"
        assert attrs["gen_ai.usage.input_tokens"] == 10
        assert attrs["gen_ai.agent.id"] == "bot" and attrs["gen_ai.conversation.id"] == "s1"
        finished = exporter.get_finished_spans()
        event = finished[0].events[0]
        assert event.name == "traceseal.receipt"
        assert event.attributes["traceseal.receipt.hash"] == r.receipt_hash

        sink = OTelSink()
        sink._tracer = tracer
        sink(r)  # no active span: creates one
        assert exporter.get_finished_spans()[-1].name == "traceseal.model"
