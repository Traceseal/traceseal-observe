"""Streaming model receipts and served-model / response metadata."""

from __future__ import annotations

import pytest

from traceseal_observe import (
    OperatorKey,
    observe_anthropic,
    observe_anthropic_stream,
    observe_model_call,
    observe_model_stream,
    observe_openai,
    observe_openai_stream,
    sha256_of,
    verify_receipt_signature,
)


@pytest.fixture
def key():
    return OperatorKey.generate("stream-test")


class Obj:
    """SDK-like object: model_dump() plus pydantic-style field iteration."""

    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return dict(self._data)

    def __iter__(self):
        return iter(self._data.items())


ANTHROPIC_EVENTS = [
    {"type": "message_start", "message": {"id": "msg_01", "model": "claude-x-20260101",
                                          "usage": {"input_tokens": 12, "output_tokens": 1}}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 7}},
    {"type": "message_stop"},
]

OPENAI_CHUNKS = [
    {"id": "chatcmpl-1", "model": "gpt-x-2026", "system_fingerprint": "fp_1",
     "choices": [{"index": 0, "delta": {"content": "Hi"}, "finish_reason": None}]},
    {"id": "chatcmpl-1", "model": "gpt-x-2026", "system_fingerprint": "fp_1",
     "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    {"id": "chatcmpl-1", "model": "gpt-x-2026", "system_fingerprint": "fp_1", "choices": [],
     "usage": {"prompt_tokens": 5, "completion_tokens": 3}},
]


def _stream(**kw):
    defaults = dict(provider="anthropic", model="claude-x", api_endpoint="https://e/v1",
                    serialize_request=lambda: {"p": 1})
    defaults.update(kw)
    return defaults


class TestStreamNotSilentlyMisHashed:
    def test_generator_response_is_returned_unconsumed_with_honest_receipt(self, key):
        def gen():
            yield {"a": 1}
            yield {"a": 2}

        response, receipt = observe_model_call(
            "x", "m", "https://e", key, lambda: gen(), serialize_request=lambda: {"p": 1}
        )
        assert list(response) == [{"a": 1}, {"a": 2}]  # untouched
        ex = receipt.execution
        assert ex["ok"] == "false"
        assert ex["output_hash"] == "sha256:empty"
        assert ex["response_mode"] == "stream"
        assert "observe_model_stream" in ex["error_message"]
        verify_receipt_signature(receipt)

    def test_model_dump_objects_are_not_streams(self, key):
        response, receipt = observe_model_call(
            "x", "m", "https://e", key, lambda: Obj({"id": "r1", "model": "m-1"})
        )
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["output_hash"] == sha256_of({"id": "r1", "model": "m-1"})

    def test_explicit_serializer_is_respected_for_iterators(self, key):
        _, receipt = observe_model_call(
            "x", "m", "https://e", key, lambda: iter([1, 2]),
            serialize_response=lambda r: "custom",
        )
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["output_hash"] == sha256_of("custom")


class TestObserveModelStream:
    def test_full_stream(self, key):
        stream = observe_model_stream(operator_key=key, call=lambda: iter(ANTHROPIC_EVENTS), **_stream())
        assert list(stream) == ANTHROPIC_EVENTS
        r = stream.receipt
        verify_receipt_signature(r)
        ex = r.execution
        assert ex["output_hash"] == sha256_of(ANTHROPIC_EVENTS)
        assert ex["input_hash"] == sha256_of({"p": 1})
        assert ex["response_mode"] == "stream"
        assert ex["stream_complete"] == "true"
        assert ex["stream_chunk_count"] == 4
        assert ex["ok"] == "true"
        assert ex["served_model"] == "claude-x-20260101"
        assert ex["model"] == "claude-x"
        assert ex["response_id"] == "msg_01"
        assert ex["stop_reason"] == "end_turn"
        assert ex["input_tokens"] == 12
        assert ex["output_tokens"] == 7

    def test_sdk_objects_hash_like_their_model_dump(self, key):
        objs = [Obj(e) for e in ANTHROPIC_EVENTS]
        stream = observe_model_stream(operator_key=key, call=lambda: iter(objs), **_stream())
        assert list(stream) == objs  # same objects passed through
        assert stream.receipt.execution["output_hash"] == sha256_of(ANTHROPIC_EVENTS)

    def test_openai_chunk_metadata(self, key):
        stream = observe_model_stream(operator_key=key, call=lambda: iter(OPENAI_CHUNKS),
                                      **_stream(provider="openai"))
        for _ in stream:
            pass
        ex = stream.receipt.execution
        assert ex["served_model"] == "gpt-x-2026"
        assert ex["system_fingerprint"] == "fp_1"
        assert ex["stop_reason"] == "stop"
        assert ex["input_tokens"] == 5 and ex["output_tokens"] == 3

    def test_empty_stream(self, key):
        stream = observe_model_stream(operator_key=key, call=lambda: iter([]), **_stream())
        assert list(stream) == []
        assert stream.receipt.execution["output_hash"] == sha256_of([])
        assert stream.receipt.execution["stream_chunk_count"] == 0

    def test_early_break_in_context_manager(self, key):
        closed = []

        class SDKStream:
            def __init__(self):
                self._it = iter(ANTHROPIC_EVENTS)

            def __iter__(self):
                return self

            def __next__(self):
                return next(self._it)

            def close(self):
                closed.append(True)

        with observe_model_stream(operator_key=key, call=SDKStream, **_stream()) as stream:
            for i, _ in enumerate(stream):
                if i == 1:
                    break
        ex = stream.receipt.execution
        assert closed == [True]
        assert ex["stream_complete"] == "false"
        assert ex["ok"] == "true"
        assert ex["stream_chunk_count"] == 2
        assert ex["output_hash"] == sha256_of(ANTHROPIC_EVENTS[:2])

    def test_mid_stream_failure_is_reraised_and_receipted(self, key):
        def gen():
            yield ANTHROPIC_EVENTS[0]
            raise ConnectionError("reset https://x/?api_key=SECRET")

        stream = observe_model_stream(operator_key=key, call=gen, **_stream())
        with pytest.raises(ConnectionError):
            for _ in stream:
                pass
        ex = stream.receipt.execution
        assert ex["ok"] == "false"
        assert ex["stream_complete"] == "false"
        assert ex["stream_chunk_count"] == 1
        assert "SECRET" not in ex["error_message"]
        assert isinstance(stream.error, ConnectionError)

    def test_call_failure_does_not_raise(self, key):
        def boom():
            raise RuntimeError("no connection")

        stream = observe_model_stream(operator_key=key, call=boom, **_stream())
        assert stream.finished and list(stream) == []
        assert stream.receipt.execution["ok"] == "false"
        assert stream.receipt.execution["output_hash"] == "sha256:empty"
        assert isinstance(stream.error, RuntimeError)

    def test_receipt_before_finish_raises(self, key):
        stream = observe_model_stream(operator_key=key, call=lambda: iter(ANTHROPIC_EVENTS), **_stream())
        next(stream)
        with pytest.raises(RuntimeError, match="not finished"):
            stream.receipt
        stream.close()
        assert stream.receipt.execution["stream_chunk_count"] == 1

    def test_receipt_signed_once(self, key):
        stream = observe_model_stream(operator_key=key, call=lambda: iter([{"a": 1}]), **_stream())
        list(stream)
        first = stream.receipt
        stream.close()
        assert list(stream) == []
        assert stream.receipt is first

    def test_custom_chunk_metadata(self, key):
        stream = observe_model_stream(
            operator_key=key, call=lambda: iter([{"m": "served-1"}]),
            chunk_metadata=lambda c: {"served_model": c["m"], "output_tokens": True},
            **_stream(),
        )
        list(stream)
        ex = stream.receipt.execution
        assert ex["served_model"] == "served-1"
        assert "output_tokens" not in ex  # bools rejected as counts


class FakeAnthropic:
    def __init__(self, response):
        self.calls = []
        outer = self

        class Messages:
            def create(self, **kw):
                outer.calls.append(kw)
                return response() if callable(response) else response

        self.messages = Messages()


class FakeOpenAI:
    def __init__(self, response):
        self.calls = []
        outer = self

        class Completions:
            def create(self, **kw):
                outer.calls.append(kw)
                return response() if callable(response) else response

        class Chat:
            completions = Completions()

        self.chat = Chat()


class TestProviderWrappers:
    def test_anthropic_records_served_model(self, key):
        client = FakeAnthropic(Obj({"id": "msg_9", "model": "claude-x-20260101",
                                    "stop_reason": "tool_use", "content": []}))
        _, receipt = observe_anthropic(client, {"model": "claude-x", "messages": []}, key)
        ex = receipt.execution
        assert ex["model"] == "claude-x"
        assert ex["served_model"] == "claude-x-20260101"
        assert ex["response_id"] == "msg_9"
        assert ex["stop_reason"] == "tool_use"

    def test_openai_records_fingerprint_and_finish_reason(self, key):
        client = FakeOpenAI(Obj({"id": "c1", "model": "gpt-x-2026", "system_fingerprint": "fp_9",
                                 "choices": [{"finish_reason": "length"}]}))
        _, receipt = observe_openai(client, {"model": "gpt-x", "messages": []}, key)
        ex = receipt.execution
        assert ex["served_model"] == "gpt-x-2026"
        assert ex["system_fingerprint"] == "fp_9"
        assert ex["stop_reason"] == "length"

    def test_stream_flag_on_non_stream_wrapper_is_refused_before_calling(self, key):
        client = FakeAnthropic(None)
        with pytest.raises(ValueError, match="observe_anthropic_stream"):
            observe_anthropic(client, {"model": "m", "stream": True}, key)
        oclient = FakeOpenAI(None)
        with pytest.raises(ValueError, match="observe_openai_stream"):
            observe_openai(oclient, {"model": "m", "stream": True}, key)
        assert client.calls == [] and oclient.calls == []

    def test_anthropic_stream_wrapper(self, key):
        client = FakeAnthropic(lambda: iter([Obj(e) for e in ANTHROPIC_EVENTS]))
        request = {"model": "claude-x", "messages": []}
        with observe_anthropic_stream(client, request, key) as stream:
            for _ in stream:
                pass
        assert client.calls == [{"model": "claude-x", "messages": [], "stream": True}]
        assert "stream" not in request  # caller's dict untouched
        ex = stream.receipt.execution
        assert ex["input_hash"] == sha256_of({**request, "stream": True})
        assert ex["served_model"] == "claude-x-20260101"
        assert ex["stream_complete"] == "true"

    def test_openai_stream_wrapper(self, key):
        client = FakeOpenAI(lambda: iter(OPENAI_CHUNKS))
        stream = observe_openai_stream(client, {"model": "gpt-x", "messages": []}, key)
        list(stream)
        assert client.calls[0]["stream"] is True
        assert stream.receipt.execution["served_model"] == "gpt-x-2026"


class TestMetadataHygiene:
    def test_overlong_and_non_string_values_are_dropped(self, key):
        _, receipt = observe_model_call(
            "x", "m", "https://e", key,
            lambda: {"model": "m" * 300, "id": 42, "stop_reason": "end"},
        )
        ex = receipt.execution
        assert "served_model" not in ex and "response_id" not in ex
        assert ex["stop_reason"] == "end"

    def test_custom_extractor_and_failing_extractor(self, key):
        _, r1 = observe_model_call("x", "m", "https://e", key, lambda: "plain",
                                   extract_response_metadata=lambda r: {"served_model": "s1"})
        assert r1.execution["served_model"] == "s1"

        def bad(_):
            raise KeyError("x")

        _, r2 = observe_model_call("x", "m", "https://e", key, lambda: {"model": "s2"},
                                   extract_response_metadata=bad)
        assert r2.execution["ok"] == "true"
        assert "served_model" not in r2.execution

    def test_responses_without_metadata_are_unchanged(self, key):
        _, receipt = observe_model_call("x", "m", "https://e", key, lambda: {"text": "hi"})
        for name in ("served_model", "response_id", "stop_reason", "system_fingerprint",
                     "response_mode", "stream_complete", "stream_chunk_count"):
            assert name not in receipt.execution
