"""Async variants of the observers, for asyncio agents.

    response, receipt = await aobserve_anthropic(async_client, request, key)

    async with await aobserve_anthropic_stream(async_client, request, key) as stream:
        async for event in stream:
            ...
    receipt = stream.receipt

Same receipts, same fields and the same no-raise contract as the sync
observers, which they share their hashing and signing code with. The
signed agent_context is whatever is active in the awaiting task.
"""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

from traceseal_observe import (
    ObservedModelStream,
    OperatorKey,
    Receipt,
    _client_endpoint,
    _default_chunk_metadata,
    _default_serialize_chunk,
    _fail_model_call,
    _fail_tool_call,
    _finish_model_call,
    _finish_tool_call,
    _now_iso,
    _start_model_call,
    _start_tool_call,
    sha256_of,
    tool_definitions_hash,
)


async def aobserve_model_call(
    provider: str,
    model: str,
    api_endpoint: str,
    operator_key: OperatorKey,
    call: Callable[[], Awaitable[Any]],
    *,
    serialize_request: Callable[[], Any] | None = None,
    serialize_response: Callable[[Any], Any] | None = None,
    extract_input_tokens: Callable[[Any], int | None] | None = None,
    extract_output_tokens: Callable[[Any], int | None] | None = None,
    extract_status_code: Callable[[Any], int | None] | None = None,
    extract_response_metadata: Callable[[Any], dict] | None = None,
    tools: list[dict] | None = None,
) -> tuple[Any, Receipt]:
    """Async observe_model_call: `call` returns an awaitable."""
    state = _start_model_call(provider, model, api_endpoint, serialize_request, tools)
    try:
        response = await call()
        return _finish_model_call(
            state, response, operator_key,
            serialize_response=serialize_response,
            extract_input_tokens=extract_input_tokens,
            extract_output_tokens=extract_output_tokens,
            extract_status_code=extract_status_code,
            extract_response_metadata=extract_response_metadata,
        )
    except Exception as exc:
        return None, _fail_model_call(state, exc, operator_key)


async def aobserve_tool(
    tool_name: str,
    operator_key: OperatorKey,
    call: Callable[[], Awaitable[Any]],
    *,
    transport: str = "python",
    args: Any = None,
    tool_version: str = "",
    endpoint: str = "",
    serialize_input: Callable[[], Any] | None = None,
    serialize_output: Callable[[Any], Any] | None = None,
    tool_definition: dict | None = None,
) -> tuple[Any, Receipt]:
    """Async observe_tool: `call` returns an awaitable."""
    state = _start_tool_call(tool_name, transport, args, tool_version, endpoint,
                             serialize_input, tool_definition)
    try:
        result = await call()
        return result, _finish_tool_call(state, result, operator_key, serialize_output)
    except Exception as exc:
        return None, _fail_tool_call(state, exc, operator_key)


class AsyncObservedModelStream(ObservedModelStream):
    """Async pass-through over a streamed response (`async for`)."""

    async def _astart(self, call: Callable[[], Awaitable[Any]]) -> None:
        try:
            self._raw = await call()
            self._iterator = self._raw.__aiter__()
        except Exception as exc:
            self.error = exc
            self._sign(complete=False, ok=False, error=exc, output_observed=False)

    def __iter__(self):  # pragma: no cover - guard against misuse
        raise TypeError("use `async for` with an async stream")

    def __aiter__(self) -> AsyncObservedModelStream:
        return self

    async def __anext__(self) -> Any:
        if self._receipt is not None or self._iterator is None:
            raise StopAsyncIteration
        try:
            chunk = await self._iterator.__anext__()
        except StopAsyncIteration:
            self._sign(complete=True, ok=True)
            raise
        except Exception as exc:
            self.error = exc
            self._sign(complete=False, ok=False, error=exc)
            raise
        self._observe(chunk)
        return chunk

    async def aclose(self) -> None:
        if self._receipt is not None:
            return
        closer = getattr(self._raw, "close", None) or getattr(self._raw, "aclose", None)
        if callable(closer):
            try:
                result = closer()
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                pass
        self._sign(complete=False, ok=True)

    async def __aenter__(self) -> AsyncObservedModelStream:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self._receipt is None:
            if exc_type is not None:
                self.error = exc_val
                self._sign(complete=False, ok=False, error=exc_val)
            else:
                await self.aclose()
        return False


async def aobserve_model_stream(
    provider: str,
    model: str,
    api_endpoint: str,
    operator_key: OperatorKey,
    call: Callable[[], Awaitable[Any]],
    *,
    serialize_request: Callable[[], Any] | None = None,
    serialize_chunk: Callable[[Any], Any] | None = None,
    chunk_metadata: Callable[[Any], dict] | None = None,
    tools: list[dict] | None = None,
) -> AsyncObservedModelStream:
    """Async observe_model_stream: `call` returns an awaitable async iterable."""
    stream = AsyncObservedModelStream(
        provider=provider,
        model=model,
        api_endpoint=api_endpoint,
        operator_key=operator_key,
        input_hash=sha256_of(serialize_request()) if serialize_request else "sha256:empty",
        started_at=_now_iso(),
        t_start=time.monotonic(),
        tools_offered_hash=tool_definitions_hash(tools) if tools is not None else "",
        tools_offered_count=len(tools) if tools is not None else None,
        serialize_chunk=serialize_chunk or _default_serialize_chunk,
        chunk_metadata=chunk_metadata or _default_chunk_metadata,
    )
    await stream._astart(call)
    return stream


def _dump(r: Any) -> Any:
    return r.model_dump() if hasattr(r, "model_dump") else dict(r)


async def aobserve_anthropic(client: Any, request: dict, operator_key: OperatorKey) -> tuple[Any, Receipt]:
    """Async wrapper for anthropic.AsyncAnthropic (messages.create)."""
    if request.get("stream"):
        raise ValueError("request has stream=True; use aobserve_anthropic_stream()")
    return await aobserve_model_call(
        "anthropic", request.get("model", "unknown"),
        _client_endpoint(client, "https://api.anthropic.com", "v1/messages"), operator_key,
        lambda: client.messages.create(**request),
        serialize_request=lambda: request, serialize_response=_dump,
        extract_input_tokens=lambda r: getattr(getattr(r, "usage", None), "input_tokens", None),
        extract_output_tokens=lambda r: getattr(getattr(r, "usage", None), "output_tokens", None),
        tools=request.get("tools"),
    )


async def aobserve_openai(client: Any, request: dict, operator_key: OperatorKey) -> tuple[Any, Receipt]:
    """Async wrapper for openai.AsyncOpenAI (chat.completions.create)."""
    if request.get("stream"):
        raise ValueError("request has stream=True; use aobserve_openai_stream()")
    return await aobserve_model_call(
        "openai", request.get("model", "unknown"),
        _client_endpoint(client, "https://api.openai.com/v1", "chat/completions"), operator_key,
        lambda: client.chat.completions.create(**request),
        serialize_request=lambda: request, serialize_response=_dump,
        extract_input_tokens=lambda r: getattr(getattr(r, "usage", None), "prompt_tokens", None),
        extract_output_tokens=lambda r: getattr(getattr(r, "usage", None), "completion_tokens", None),
        tools=request.get("tools"),
    )


async def aobserve_anthropic_stream(client: Any, request: dict, operator_key: OperatorKey) -> AsyncObservedModelStream:
    sent = {**request, "stream": True}
    return await aobserve_model_stream(
        "anthropic", request.get("model", "unknown"),
        _client_endpoint(client, "https://api.anthropic.com", "v1/messages"), operator_key,
        lambda: client.messages.create(**sent), serialize_request=lambda: sent,
        tools=request.get("tools"),
    )


async def aobserve_openai_stream(client: Any, request: dict, operator_key: OperatorKey) -> AsyncObservedModelStream:
    sent = {**request, "stream": True}
    return await aobserve_model_stream(
        "openai", request.get("model", "unknown"),
        _client_endpoint(client, "https://api.openai.com/v1", "chat/completions"), operator_key,
        lambda: client.chat.completions.create(**sent), serialize_request=lambda: sent,
        tools=request.get("tools"),
    )
