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
- the destination host and URL, sanitised (see below);
- the method;
- the SHA-256 and size of the request body, and of the response body as
  received (before content decoding);
- status and latency;
- the request's PII-pattern fingerprint;
- whether the host was on the allow-list.

Headers, and so API keys, are never hashed or recorded.

**What is sanitised.** Every URL written into a receipt (the transport's
`destination_url`, `observe_data_flow`, the `endpoint` of
`observe_http_tool` and of `observe_tool` when it is a URL, and the
`api_endpoint` of model receipts) goes through `sanitize_url()`. It
rebuilds the URL from scheme, host, port and path only:

- userinfo (`user:password@`), query string, fragment and `;params` are
  dropped;
- path segments that look like secrets are replaced with `{redacted}`:
  long high-entropy tokens, API-key shapes (`sk-…`, `ghp_…`, JWTs, AWS
  keys), UUIDs, segments matching the PII patterns (emails, card numbers),
  segments after `key/`, `token/`, `secret/`…, everything after a
  `hooks`/`webhooks` segment, and the whole path of known webhook hosts
  (`hooks.slack.com/services/…`, Discord webhooks, Zapier, IFTTT, Office
  365 connectors, Telegram bot tokens…);
- `host_only=True` (on `ReceiptTransport`, `AsyncReceiptTransport`,
  `observe_data_flow` and `observe_http_tool`) records just
  `scheme://host[:port]`.

Secret detection in paths is heuristic. If your URLs carry identifiers in
other shapes, use `host_only=True`.

**Error messages.** Failure receipts record the exception type and a short
hash of its message, e.g. `ConnectError (sha256:4a01c1bff5b8)`, never the
text. `set_error_text("scrubbed")` (process-wide) or `with
error_text("scrubbed"):` opts in to recording the message with URL
userinfo, queries and fragments, `Bearer`/`Basic` tokens,
`Authorization:`-style headers, `api_key=`/`token=`/`password=` pairs,
pydantic `input_value=…` and PII-pattern matches removed. That scrubbing
is heuristic too.

**PII fingerprint.** JSON bodies are decoded and each string value is
scanned separately, so escaped `\n` or `\t` can't hide a value. Only the
first 1 MiB of a body is scanned; a larger body's receipt carries
`pii_scan_truncated: "true"` and `pii_scan_bytes`.

**Allow-list.** `allow_hosts` entries match scheme, host and port. A bare
host (`"api.anthropic.com"`) means `https` on port 443. Write
`"http://localhost:8080"` or `"https://gw.example.com:8443"` to allow
another scheme or port. Plain `http://` to a bare-host entry is not
declared, and with `block_undeclared=True` it is refused.

- **Streaming responses** (server-sent events) are hashed as they stream.
  The receipt is signed when the SDK closes the response.
- **`block_undeclared=True`** refuses a request to an unlisted host *before
  anything is sent*, and receipts the refusal.
- **Transport errors** are receipted too, and each SDK retry gets its own
  receipt.
- **`AsyncReceiptTransport`** does the same for `AsyncClient`.
- The transport is duck-typed: it works with `httpx` and `httpx2`
  transports alike.

**Routes that bypass the transport are not recorded.** httpx sends a
request through a `mounts=` entry, or through `proxy=` (which httpx
installs as a mount), *instead of* the client's `transport=`. Those
requests are neither receipted nor blocked. Build clients with
`receipted_client(httpx2.Client, httpx2.HTTPTransport(), operator_key=…,
on_receipt=…, allow_hosts=…)`, or call `check_client(client)` on one you
built: both emit an `UnreceiptedRouteWarning` listing the routes that
bypass it. Put a `ReceiptTransport` in each mount if you need mounts.

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
The base URL goes through `sanitize_url()`: credentials, query strings,
fragments, `;params` and secret-looking path segments are removed. Clients without a
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
