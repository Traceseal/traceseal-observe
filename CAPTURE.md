# Capture: Transports, Async and OpenTelemetry

## Zero-code capture with an HTTP transport

Wrapping call sites by hand misses calls: retries, SDK helpers, code paths
someone forgot. Model SDKs take an `http_client`. Give them one whose
transport signs a `data_flow` receipt for **every** request:

```python
import httpx2   # current Anthropic and OpenAI SDKs use httpx2; older ones use httpx
from traceseal_observe.capture import ReceiptTransport

receipts = []
transport = ReceiptTransport(
    httpx2.HTTPTransport(), operator_key=chain.signer, on_receipt=receipts.append,
    allow_hosts=["api.anthropic.com"], block_undeclared=True,
)
client = anthropic.Anthropic(http_client=httpx2.Client(transport=transport))
```

Each request's receipt records:
- the destination host and URL, with the query string removed;
- the method;
- the SHA-256 and size of the request body, and of the response body as
  received (before content decoding);
- status and latency;
- the request's PII-pattern fingerprint;
- whether the host was on the allow-list.

Headers, and so API keys, are never hashed or recorded.

- **Streaming responses** (server-sent events) are hashed as they stream.
  The receipt is signed when the SDK closes the response.
- **`block_undeclared=True`** refuses a request to an unlisted host *before
  anything is sent*, and receipts the refusal.
- **Transport errors** are receipted too, and each SDK retry gets its own
  receipt.
- **`AsyncReceiptTransport`** does the same for `AsyncClient`.
- The transport is duck-typed: it works with `httpx` and `httpx2`
  transports alike.

The transport is the safety net: every request sent through a client
configured with it is recorded. It cannot see traffic sent through other
clients, processes or channels, so it does not prove that nothing else
left the system. The `observe_*` wrappers add the semantic receipts on top:
model, served model, tool calls and causality.

## Async

```python
response, receipt = await aobserve_anthropic(async_client, request, key)
_, receipt = await aobserve_openai(async_openai, request, key)
result, receipt = await aobserve_tool("lookup", key, lambda: lookup(q), args={"q": q})

stream = await aobserve_anthropic_stream(async_client, request, key)
async with stream:
    async for event in stream:
        ...
receipt = stream.receipt
```

The async observers share their hashing and signing code with the sync
ones, so receipts are identical. `agent_context` follows the awaiting
asyncio task.

## Gateways and custom endpoints

`observe_anthropic` / `observe_openai` (and the async and stream variants)
record the client's real `base_url`, for gateways and compatible proxies.
Credentials and query strings in the URL are removed. Clients without a
`base_url` keep the provider default.

## OpenTelemetry

```python
from traceseal_observe.otel import record_receipt, OTelSink, receipt_attributes

record_receipt(receipt)                    # add a traceseal.receipt event to the current span
transport = ReceiptTransport(..., on_receipt=OTelSink())
```

| Attribute | From |
|---|---|
| `gen_ai.operation.name` | `chat` (model) / `execute_tool` (tool) |
| `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model` | provider, requested model, served model |
| `gen_ai.response.id`, `gen_ai.response.finish_reasons` | response id, stop reason |
| `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | token counts |
| `gen_ai.tool.name`, `gen_ai.tool.call.id` | tool receipts and `tool_call_id` |
| `gen_ai.agent.id`, `gen_ai.conversation.id` | `agent_context` agent id and session |
| `server.address`, `http.request.method`, `http.response.status_code` | data-flow receipts |
| `traceseal.receipt.hash`, `traceseal.receipt.type`, `traceseal.receipt.ok` | the receipt |
| `traceseal.chain.id`, `traceseal.chain.seq`, `traceseal.operator.fingerprint` | chain position and signer |

The link works both ways. When a span is active, `agent_context` records
its W3C trace and span ids in the signed receipt, and the span carries the
receipt hash. Install `opentelemetry-api` (`pip install
"traceseal-observe[otel]"`).
