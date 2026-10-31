"""Zero-code capture: sign a data_flow receipt for every HTTP request an SDK makes.

Wrapping each call site misses calls: retries, background requests, a new
code path someone forgot to wrap. Model SDKs (Anthropic, OpenAI and most
others) take an `http_client`; give them one whose transport receipts
everything:

    import httpx2  # or httpx, whichever your SDK uses
    receipts = []
    transport = ReceiptTransport(httpx2.HTTPTransport(), operator_key=chain.signer,
                                 on_receipt=receipts.append,
                                 allow_hosts=["api.anthropic.com"], block_undeclared=True)
    client = anthropic.Anthropic(http_client=httpx2.Client(transport=transport))

Each request gets a data_flow receipt: destination host and URL (query
string removed), method, SHA-256 and size of the request body and of the
response body as received (before content decoding), status, latency, the
PII-pattern fingerprint of the request, and whether the host was on the
allow-list. Headers (API keys) are never hashed or recorded. With
`block_undeclared=True`, a request to an unlisted host is refused before
anything is sent, and the refusal is itself receipted.

Response bodies are hashed as they stream, so server-sent-event streams are
covered. The receipt is signed when the response is closed, which SDKs do
when they finish reading.

Combine with observe_anthropic / observe_tool for semantic receipts; the
transport is the safety net that proves nothing left the system unrecorded.
"""

from __future__ import annotations

import hashlib
import sys
import time
from typing import Any, Callable, Iterable

from traceseal_observe import (
    DataFlowRecord,
    OperatorKey,
    _now_iso,
    _redact_error,
    _strip_query,
    fingerprint_pii,
    sign_data_flow,
)

_MAX_PII_SCAN = 1 << 20


class UndeclaredDestination(Exception):
    """Raised (after receipting) when block_undeclared refuses a request."""


def _lib(obj: Any):
    """The httpx-compatible module (httpx or httpx2) an object comes from."""
    return sys.modules[type(obj).__module__.split(".")[0]]


class _Capture:
    def __init__(self, operator_key: OperatorKey, on_receipt: Callable[[Any], None],
                 allow_hosts: Iterable[str] | None, block_undeclared: bool, scan_pii: bool):
        self.operator_key = operator_key
        self.on_receipt = on_receipt
        self.allow_hosts = sorted({h.lower() for h in allow_hosts}) if allow_hosts else []
        self.block_undeclared = block_undeclared
        self.scan_pii = scan_pii
        if block_undeclared and not self.allow_hosts:
            raise ValueError("block_undeclared needs allow_hosts")

    def begin(self, request: Any, body: bytes) -> dict[str, Any]:
        url = str(request.url)
        host = (request.url.host or "").lower()
        declared = not self.allow_hosts or host in self.allow_hosts
        return {
            "host": host,
            "url": _strip_query(url),
            "method": request.method,
            "request_hash": "sha256:" + hashlib.sha256(body).hexdigest() if body else "sha256:empty",
            "request_bytes": len(body),
            "pii": fingerprint_pii(body[:_MAX_PII_SCAN]) if self.scan_pii and body else {},
            "declared": declared,
            "started_at": _now_iso(),
            "t0": time.monotonic(),
        }

    def finish(self, state: dict[str, Any], *, status: int, response_hash: str,
               response_bytes: int, error: str = "") -> None:
        record = DataFlowRecord(
            destination_host=state["host"],
            destination_url=state["url"],
            method=state["method"],
            request_payload_hash=state["request_hash"],
            response_payload_hash=response_hash,
            payload_bytes=state["request_bytes"],
            response_bytes=response_bytes,
            started_at=state["started_at"],
            wall_time_ms=int((time.monotonic() - state["t0"]) * 1000),
            status_code=status,
            ok=200 <= status < 300 and not error,
            pii_fingerprint=state["pii"],
            destination_declared=state["declared"],
            declared_allow_list=list(self.allow_hosts),
            error_message=error,
        )
        self.on_receipt(sign_data_flow(record, self.operator_key))

    def refuse(self, state: dict[str, Any]) -> None:
        self.finish(state, status=0, response_hash="sha256:empty", response_bytes=0,
                    error=f"blocked: {state['host']} is not an allowed destination")
        raise UndeclaredDestination(f"{state['host']} is not in allow_hosts")


def _hashing_stream(lib: Any, inner: Any, capture: _Capture, state: dict[str, Any],
                    status: int, is_async: bool):
    base = lib.AsyncByteStream if is_async else lib.SyncByteStream

    class HashingStream(base):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            self._hash = hashlib.sha256()
            self._size = 0
            self._done = False
            self._error = ""

        def _seal(self) -> None:
            if not self._done:
                self._done = True
                capture.finish(state, status=status,
                               response_hash=("sha256:" + self._hash.hexdigest()) if self._size else "sha256:empty",
                               response_bytes=self._size, error=self._error)

        if not is_async:
            def __iter__(self):
                try:
                    for chunk in inner:
                        self._hash.update(chunk)
                        self._size += len(chunk)
                        yield chunk
                except Exception as exc:
                    self._error = _redact_error(f"{type(exc).__name__}: {exc}")
                    raise

            def close(self) -> None:
                try:
                    if hasattr(inner, "close"):
                        inner.close()
                finally:
                    self._seal()
        else:
            async def __aiter__(self):
                try:
                    async for chunk in inner:
                        self._hash.update(chunk)
                        self._size += len(chunk)
                        yield chunk
                except Exception as exc:
                    self._error = _redact_error(f"{type(exc).__name__}: {exc}")
                    raise

            async def aclose(self) -> None:
                try:
                    if hasattr(inner, "aclose"):
                        await inner.aclose()
                finally:
                    self._seal()

    return HashingStream()


class ReceiptTransport:
    """Wraps an httpx/httpx2 sync transport. Pass to Client(transport=...)."""

    def __init__(self, inner: Any, *, operator_key: OperatorKey,
                 on_receipt: Callable[[Any], None], allow_hosts: Iterable[str] | None = None,
                 block_undeclared: bool = False, scan_pii: bool = True):
        self._inner = inner
        self._capture = _Capture(operator_key, on_receipt, allow_hosts, block_undeclared, scan_pii)

    def handle_request(self, request: Any) -> Any:
        body = request.read()
        state = self._capture.begin(request, body)
        if self._capture.block_undeclared and not state["declared"]:
            self._capture.refuse(state)
        try:
            response = self._inner.handle_request(request)
        except Exception as exc:
            self._capture.finish(state, status=0, response_hash="sha256:empty", response_bytes=0,
                                 error=_redact_error(f"{type(exc).__name__}: {exc}"))
            raise
        lib = _lib(response)
        return lib.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_hashing_stream(lib, response.stream, self._capture, state,
                                   response.status_code, is_async=False),
            request=request,
            extensions=response.extensions,
        )

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> ReceiptTransport:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class AsyncReceiptTransport:
    """Wraps an httpx/httpx2 async transport. Pass to AsyncClient(transport=...)."""

    def __init__(self, inner: Any, *, operator_key: OperatorKey,
                 on_receipt: Callable[[Any], None], allow_hosts: Iterable[str] | None = None,
                 block_undeclared: bool = False, scan_pii: bool = True):
        self._inner = inner
        self._capture = _Capture(operator_key, on_receipt, allow_hosts, block_undeclared, scan_pii)

    async def handle_async_request(self, request: Any) -> Any:
        body = await request.aread()
        state = self._capture.begin(request, body)
        if self._capture.block_undeclared and not state["declared"]:
            self._capture.refuse(state)
        try:
            response = await self._inner.handle_async_request(request)
        except Exception as exc:
            self._capture.finish(state, status=0, response_hash="sha256:empty", response_bytes=0,
                                 error=_redact_error(f"{type(exc).__name__}: {exc}"))
            raise
        lib = _lib(response)
        return lib.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_hashing_stream(lib, response.stream, self._capture, state,
                                   response.status_code, is_async=True),
            request=request,
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()
