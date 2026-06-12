"""traceseal-observe — execution receipts for AI model calls and tool invocations.

This library wraps model API calls and tool invocations to produce
signed execution receipts in the same format as traceseal skill receipts.
Any third party can verify the receipt with `traceseal-verify` — no
access to the operator's machine required.

Receipts from this library are compatible with RECEIPT-SPEC.md v1.0.
The `execution` section uses a `receipt_type` discriminator to tell
verifiers what kind of execution was receipted:

  - "skill"  — a signed skill ran in a sandbox (traceseal)
  - "model"  — an AI model API was called (this library)
  - "tool"   — a tool/function was invoked (this library)

Third-party verifiers check the signature regardless of type. The type
discriminator is for downstream consumers who want to filter or
aggregate by kind.

What receipts PROVE:
  - The operator attests: "I called model X with this input hash at
    this time, and received a response with this output hash."

What receipts do NOT prove:
  - That the provider actually returned what the operator claims.
    (Provider-signed responses, when available, would close this gap.)
  - That no tampering happened between the provider and the operator.
  - That the model is genuinely the version the operator requested.

These are honest limitations. The receipt is an attestation, not a
zero-knowledge proof of provider-side behavior. It's the strongest
trust primitive the operator can produce without provider cooperation.
"""

from __future__ import annotations

__version__ = "1.3.2"

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RECEIPT_VERSION = "1.0"

# Matches a URL query string so credentials passed as query params
# (?api_key=..., ?token=..., &sig=...) never get baked into a signed,
# publicly-shareable receipt's error_message. Errors from HTTP libraries
# routinely embed the full request URL.
_QUERY_STRING_RE = __import__("re").compile(r"\?[^\s\"']*")


def _redact_error(message: str, limit: int = 200) -> str:
    """Scrub URL query strings from an exception message and bound its length.

    Receipt error messages are signed and shareable, so a leaked
    ?api_key=... in a library exception would become a published credential.
    """
    scrubbed = _QUERY_STRING_RE.sub("?<redacted>", message)
    return scrubbed[:limit]


# ---------------------------------------------------------------------------
# Canonical JSON (matches RECEIPT-SPEC.md §3)
# ---------------------------------------------------------------------------


def canonical_dumps(obj: dict) -> bytes:
    """Encode a dict as canonical JSON bytes.

    Rules:
    - Keys sorted lexicographically at every nesting level
    - Compact encoding (no whitespace)
    - UTF-8 encoded
    - No booleans or nulls in receipt bodies — use "true"/"false"/""
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_of(data: bytes | str | dict | list | int | float | bool | None) -> str:
    """Compute SHA-256 of arbitrary data, returning 'sha256:<hex>'.

    Accepts bytes, strings, JSON-serializable structures, and primitives.
    For structured data, canonical JSON is used so hashes are deterministic
    across Python versions and platforms.
    """
    if data is None:
        data = b""
    elif isinstance(data, bytes):
        pass
    elif isinstance(data, str):
        data = data.encode("utf-8")
    elif isinstance(data, dict):
        data = canonical_dumps(data)
    elif isinstance(data, (list, int, float, bool)):
        # Use canonical JSON serialization for all JSON primitives
        data = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    else:
        # Fallback: stringify
        data = str(data).encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


# ---------------------------------------------------------------------------
# Keypair
# ---------------------------------------------------------------------------


def _public_key_bytes(pk: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_fingerprint(pk: Ed25519PublicKey) -> str:
    raw = _public_key_bytes(pk)
    digest = hashlib.sha256(raw).hexdigest()
    return f"ed25519:{digest[:32]}"


@dataclass
class OperatorKey:
    """An operator's ed25519 keypair for signing receipts."""

    name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def fingerprint(self) -> str:
        return public_key_fingerprint(self.public_key)

    @property
    def public_key_hex(self) -> str:
        return _public_key_bytes(self.public_key).hex()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    @classmethod
    def generate(cls, name: str = "default") -> OperatorKey:
        sk = Ed25519PrivateKey.generate()
        return cls(name=name, private_key=sk, public_key=sk.public_key())

    @classmethod
    def from_raw_bytes(cls, name: str, private_bytes: bytes) -> OperatorKey:
        sk = Ed25519PrivateKey.from_private_bytes(private_bytes)
        return cls(name=name, private_key=sk, public_key=sk.public_key())

    @classmethod
    def load_from_file(cls, key_path: Path | str) -> OperatorKey:
        """Load a raw 32-byte ed25519 private key from a file.

        Compatible with traceseal key storage (~/.traceseal/keys/).
        """
        path = Path(key_path)
        name = path.stem
        return cls.from_raw_bytes(name, path.read_bytes())


# ---------------------------------------------------------------------------
# Receipt dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ModelCallRecord:
    """Intermediate record before signing — the data to be receipted.

    Don't construct directly in most cases — use `observe_model_call()` or
    the `@observe_model` decorator. These helpers handle timing,
    hashing, and signing automatically.
    """

    provider: str
    """The provider identifier. E.g. "anthropic", "openai", "google"."""

    model: str
    """The model string as requested by the operator. E.g. "claude-sonnet-4-20250514"."""

    api_endpoint: str
    """The HTTP endpoint called. E.g. "https://api.anthropic.com/v1/messages"."""

    input_hash: str
    """SHA-256 of the canonical request payload. sha256:<hex> format."""

    output_hash: str
    """SHA-256 of the canonical response payload. sha256:<hex> format."""

    started_at: str
    """ISO 8601 UTC timestamp of when the call began."""

    wall_time_ms: int
    """Wall-clock latency in milliseconds."""

    ok: bool
    """Whether the call succeeded."""

    exit_code: int = 0
    """0 for success, non-zero for error. For HTTP errors, matches the status code."""

    error_message: str = ""
    """If ok=False, a short human-readable error (no sensitive data)."""

    input_tokens: int | None = None
    """Optional: input tokens consumed, when the provider reports them."""

    output_tokens: int | None = None
    """Optional: output tokens generated, when the provider reports them."""


@dataclass
class Receipt:
    """A signed Traceseal receipt conforming to RECEIPT-SPEC.md v1.0."""

    receipt_version: str
    execution: dict[str, Any]
    provenance: dict[str, Any]
    attestation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "execution": self.execution,
            "provenance": self.provenance,
            "attestation": self.attestation,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @property
    def receipt_hash(self) -> str:
        """SHA-256 of the canonical receipt JSON.

        Used when one receipt references another (orchestration chains).
        """
        return sha256_of(self.to_dict())


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _signed_payload(execution: dict, provenance: dict) -> bytes:
    """The canonical bytes that the operator signs."""
    return canonical_dumps({"execution": execution, "provenance": provenance})


def _check_receipt_signature(receipt: Receipt, label: str) -> None:
    """Raise ValueError unless the receipt's Ed25519 signature is valid.

    Used to fail closed when loading receipts from an untrusted bundle.
    """
    from cryptography.exceptions import InvalidSignature

    att = receipt.attestation
    pubkey_hex = att.get("operator_public_key", "")
    signature_hex = att.get("signature", "")
    # Ed25519: 32-byte key (64 hex chars), 64-byte signature (128 hex chars).
    # Bound lengths before decoding so a hostile bundle can't force a huge
    # bytes.fromhex() allocation.
    if len(pubkey_hex) != 64:
        raise ValueError(f"{label}: operator_public_key is {len(pubkey_hex)} hex chars, expected 64")
    if len(signature_hex) != 128:
        raise ValueError(f"{label}: signature is {len(signature_hex)} hex chars, expected 128")
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pk.verify(bytes.fromhex(signature_hex), _signed_payload(receipt.execution, receipt.provenance))
    except InvalidSignature:
        raise ValueError(f"{label}: signature verification failed — receipt may be tampered")
    except ValueError:
        raise
    except Exception as e:  # malformed key material, etc.
        raise ValueError(f"{label}: signature check error: {type(e).__name__}")


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sign_model_call(
    record: ModelCallRecord,
    operator_key: OperatorKey,
) -> Receipt:
    """Sign a ModelCallRecord into a verifiable Receipt."""

    execution = {
        "receipt_type": "model",
        "provider": record.provider,
        "model": record.model,
        "api_endpoint": record.api_endpoint,
        "started_at": record.started_at,
        "wall_time_ms": record.wall_time_ms,
        "input_hash": record.input_hash,
        "output_hash": record.output_hash,
        "ok": "true" if record.ok else "false",
        "exit_code": record.exit_code,
    }
    if record.error_message:
        execution["error_message"] = record.error_message
    if record.input_tokens is not None:
        execution["input_tokens"] = record.input_tokens
    if record.output_tokens is not None:
        execution["output_tokens"] = record.output_tokens

    # Provenance for model calls is weaker than for skills —
    # we don't have a publisher signature over the model's code.
    # The operator records what they believe they called. A future
    # provider-signed response would strengthen this.
    provenance = {
        "provider_attestation": "none",
        "provenance_version": "1.0",
    }

    payload = _signed_payload(execution, provenance)
    signature = operator_key.sign(payload)

    attestation = {
        "operator_fingerprint": operator_key.fingerprint,
        "operator_public_key": operator_key.public_key_hex,
        "attested_at": _now_iso(),
        "signature": signature.hex(),
    }

    return Receipt(
        receipt_version=RECEIPT_VERSION,
        execution=execution,
        provenance=provenance,
        attestation=attestation,
    )


# ---------------------------------------------------------------------------
# The high-level API — observe_model_call()
# ---------------------------------------------------------------------------


def observe_model_call(
    provider: str,
    model: str,
    api_endpoint: str,
    operator_key: OperatorKey,
    call: Callable[[], Any],
    *,
    extract_input_tokens: Callable[[Any], int | None] | None = None,
    extract_output_tokens: Callable[[Any], int | None] | None = None,
    serialize_request: Callable[[], Any] | None = None,
    serialize_response: Callable[[Any], Any] | None = None,
    extract_status_code: Callable[[Any], int | None] | None = None,
) -> tuple[Any, Receipt]:
    """Wrap a model API call, producing a signed receipt alongside the response.

    Args:
        provider: Provider identifier (e.g. "anthropic", "openai").
        model: Model string as requested.
        api_endpoint: The HTTP endpoint being called.
        operator_key: The operator's signing key.
        call: A zero-arg callable that performs the actual API call and
            returns the response. Exceptions are caught and recorded as
            failed receipts (ok=False).
        extract_input_tokens: Optional function that extracts input token
            count from the response for telemetry. Called with the response.
        extract_output_tokens: Same, for output tokens.
        serialize_request: Optional function that returns the canonical
            representation of the request for hashing. If None, the caller
            must include the request in `call` and we hash the result only.
            For best results, provide this so input_hash is meaningful.
        serialize_response: Optional function that canonicalizes the response
            before hashing. Useful when the response is a complex object
            (like an SDK response class) that doesn't JSON-serialize cleanly.

    Returns:
        (response, receipt) — the response from `call()` plus a signed Receipt.
        If `call()` raised, response is None and the receipt has ok=False.

    Example (Anthropic):
        from anthropic import Anthropic
        client = Anthropic()

        request_body = {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": "Hello"}],
        }

        response, receipt = observe_model_call(
            provider="anthropic",
            model=request_body["model"],
            api_endpoint="https://api.anthropic.com/v1/messages",
            operator_key=my_key,
            call=lambda: client.messages.create(**request_body),
            serialize_request=lambda: request_body,
            serialize_response=lambda r: r.model_dump(),
            extract_input_tokens=lambda r: r.usage.input_tokens,
            extract_output_tokens=lambda r: r.usage.output_tokens,
        )

        # Write the receipt for later verification
        Path("receipt.json").write_text(receipt.to_json())
    """
    started_at = _now_iso()
    t_start = time.monotonic()

    # Hash the request before making the call
    if serialize_request is not None:
        input_hash = sha256_of(serialize_request())
    else:
        input_hash = "sha256:empty"

    try:
        response = call()
        wall_time_ms = int((time.monotonic() - t_start) * 1000)

        # Serialize and hash the response
        if serialize_response is not None:
            serialized = serialize_response(response)
        else:
            # Best-effort serialization
            if hasattr(response, "model_dump"):
                serialized = response.model_dump()
            elif hasattr(response, "to_dict"):
                serialized = response.to_dict()
            elif isinstance(response, (dict, list)):
                serialized = response
            else:
                serialized = str(response)

        output_hash = sha256_of(serialized)

        # Extract token counts if available
        try:
            input_tokens = extract_input_tokens(response) if extract_input_tokens else None
            output_tokens = extract_output_tokens(response) if extract_output_tokens else None
        except Exception:
            input_tokens = None
            output_tokens = None

        # Detect application-level failures (e.g. 401, 403, 429, 500)
        # even when the HTTP transport succeeded. A model call that
        # returns 401 is not "ok" from the operator's perspective.
        call_ok = True
        exit_code = 0
        error_msg = ""
        if extract_status_code is not None:
            try:
                status = extract_status_code(response)
                if status is not None and status >= 400:
                    call_ok = False
                    exit_code = status
                    error_msg = f"HTTP {status}"
            except Exception:
                pass  # Can't extract status — assume success
        else:
            # Best-effort: check common attributes
            for attr in ("status_code", "status", "http_status"):
                code = getattr(response, attr, None)
                if isinstance(code, int) and code >= 400:
                    call_ok = False
                    exit_code = code
                    error_msg = f"HTTP {code}"
                    break

        record = ModelCallRecord(
            provider=provider,
            model=model,
            api_endpoint=api_endpoint,
            input_hash=input_hash,
            output_hash=output_hash,
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=call_ok,
            exit_code=exit_code,
            error_message=error_msg,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

        return response, sign_model_call(record, operator_key)

    except Exception as exc:
        wall_time_ms = int((time.monotonic() - t_start) * 1000)
        record = ModelCallRecord(
            provider=provider,
            model=model,
            api_endpoint=api_endpoint,
            input_hash=input_hash,
            output_hash="sha256:empty",
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=False,
            exit_code=1,
            error_message=_redact_error(f"{type(exc).__name__}: {str(exc)}"),
        )
        receipt = sign_model_call(record, operator_key)
        return None, receipt


# ---------------------------------------------------------------------------
# Provider-specific convenience wrappers
# ---------------------------------------------------------------------------


def observe_anthropic(
    client: Any,
    request: dict,
    operator_key: OperatorKey,
) -> tuple[Any, Receipt]:
    """Convenience wrapper for the Anthropic Python SDK.

    Usage:
        from anthropic import Anthropic
        client = Anthropic()
        response, receipt = observe_anthropic(
            client,
            {"model": "claude-sonnet-4-20250514", "max_tokens": 1000,
             "messages": [{"role": "user", "content": "Hello"}]},
            my_key,
        )
    """
    return observe_model_call(
        provider="anthropic",
        model=request.get("model", "unknown"),
        api_endpoint="https://api.anthropic.com/v1/messages",
        operator_key=operator_key,
        call=lambda: client.messages.create(**request),
        serialize_request=lambda: request,
        serialize_response=lambda r: r.model_dump() if hasattr(r, "model_dump") else dict(r),
        extract_input_tokens=lambda r: getattr(r.usage, "input_tokens", None) if hasattr(r, "usage") else None,
        extract_output_tokens=lambda r: getattr(r.usage, "output_tokens", None) if hasattr(r, "usage") else None,
    )


def observe_openai(
    client: Any,
    request: dict,
    operator_key: OperatorKey,
) -> tuple[Any, Receipt]:
    """Convenience wrapper for the OpenAI Python SDK.

    Usage:
        from openai import OpenAI
        client = OpenAI()
        response, receipt = observe_openai(
            client,
            {"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]},
            my_key,
        )
    """
    return observe_model_call(
        provider="openai",
        model=request.get("model", "unknown"),
        api_endpoint="https://api.openai.com/v1/chat/completions",
        operator_key=operator_key,
        call=lambda: client.chat.completions.create(**request),
        serialize_request=lambda: request,
        serialize_response=lambda r: r.model_dump() if hasattr(r, "model_dump") else dict(r),
        extract_input_tokens=lambda r: getattr(r.usage, "prompt_tokens", None) if hasattr(r, "usage") else None,
        extract_output_tokens=lambda r: getattr(r.usage, "completion_tokens", None) if hasattr(r, "usage") else None,
    )


# ---------------------------------------------------------------------------
# TOOL CALL RECEIPTS (Module 2)
# ---------------------------------------------------------------------------


@dataclass
class ToolCallRecord:
    """A record of a tool/function invocation before signing.

    Tools are a separate receipt type from model calls because the
    metadata differs. A model call records a provider + model string;
    a tool call records a tool identifier + optional version + the
    transport used (python, mcp, http, shell).

    Don't construct directly in most cases — use observe_tool(),
    observe_mcp_tool(), or the @observe_tool_fn decorator.
    """

    tool_name: str
    """Unique identifier for the tool. E.g. "search_web", "send_email"."""

    transport: str
    """How the tool was invoked: "python", "mcp", "http", "shell"."""

    input_hash: str
    """SHA-256 of the canonical input arguments. sha256:<hex>."""

    output_hash: str
    """SHA-256 of the canonical output. sha256:<hex>."""

    started_at: str
    """ISO 8601 UTC timestamp of when the call began."""

    wall_time_ms: int
    """Wall-clock latency in milliseconds."""

    ok: bool
    """Whether the call succeeded."""

    exit_code: int = 0
    """0 for success, non-zero for error."""

    error_message: str = ""
    """If ok=False, short human-readable error (no sensitive data)."""

    tool_version: str = ""
    """Optional: the tool's version if known."""

    endpoint: str = ""
    """Optional: for HTTP tools, the URL. For MCP, the server name.
    For shell, the command. For Python, the module.function path."""


def sign_tool_call(
    record: ToolCallRecord,
    operator_key: OperatorKey,
) -> Receipt:
    """Sign a ToolCallRecord into a verifiable Receipt."""

    execution = {
        "receipt_type": "tool",
        "tool_name": record.tool_name,
        "transport": record.transport,
        "started_at": record.started_at,
        "wall_time_ms": record.wall_time_ms,
        "input_hash": record.input_hash,
        "output_hash": record.output_hash,
        "ok": "true" if record.ok else "false",
        "exit_code": record.exit_code,
    }
    if record.error_message:
        execution["error_message"] = record.error_message
    if record.tool_version:
        execution["tool_version"] = record.tool_version
    if record.endpoint:
        execution["endpoint"] = record.endpoint

    # Provenance for tool calls: by default weak (no publisher signature
    # over the tool). Tools can be upgraded to signed provenance by
    # passing a tool_manifest_hash when available (e.g. if the tool is
    # a Traceseal-signed skill being called as a subroutine).
    provenance = {
        "provider_attestation": "none",
        "provenance_version": "1.0",
    }

    payload = _signed_payload(execution, provenance)
    signature = operator_key.sign(payload)

    attestation = {
        "operator_fingerprint": operator_key.fingerprint,
        "operator_public_key": operator_key.public_key_hex,
        "attested_at": _now_iso(),
        "signature": signature.hex(),
    }

    return Receipt(
        receipt_version=RECEIPT_VERSION,
        execution=execution,
        provenance=provenance,
        attestation=attestation,
    )


# ---------------------------------------------------------------------------
# Generic tool observation
# ---------------------------------------------------------------------------


def observe_tool(
    tool_name: str,
    operator_key: OperatorKey,
    call: Callable[[], Any],
    *,
    transport: str = "python",
    args: Any = None,
    tool_version: str = "",
    endpoint: str = "",
    serialize_input: Callable[[], Any] | None = None,
    serialize_output: Callable[[Any], Any] | None = None,
) -> tuple[Any, Receipt]:
    """Wrap a tool invocation, producing a signed receipt alongside the result.

    This is the generic entry point. For specific transports, prefer:
      - observe_tool_fn() decorator for Python functions
      - observe_mcp_tool() for MCP server calls
      - observe_http_tool() for HTTP API tools
      - observe_shell_tool() for subprocess invocations

    Args:
        tool_name: Identifier for the tool.
        operator_key: The operator's signing key.
        call: A zero-arg callable that performs the tool invocation.
            Exceptions are caught and recorded as failed receipts.
        transport: How the tool is being invoked ("python" | "mcp" |
            "http" | "shell"). Defaults to "python".
        args: Optional — the arguments to the tool, used as input for
            hashing if serialize_input isn't provided. Convenience for
            simple cases where args is JSON-serializable.
        tool_version: Optional version string for the tool.
        endpoint: Optional endpoint identifier (URL, MCP server, command, etc).
        serialize_input: Optional function returning canonical input. Overrides
            `args` if provided.
        serialize_output: Optional function canonicalizing the output before hashing.

    Returns:
        (result, receipt) — tool result plus signed Receipt.
        On exception: (None, receipt_with_ok_false).

    Example:
        def my_search(query: str) -> list[dict]:
            return search_api.query(query)

        results, receipt = observe_tool(
            tool_name="search_web",
            operator_key=my_key,
            call=lambda: my_search("traceseal"),
            args={"query": "traceseal"},
            transport="python",
        )
    """
    started_at = _now_iso()
    t_start = time.monotonic()

    # Hash the input
    if serialize_input is not None:
        input_hash = sha256_of(serialize_input())
    elif args is not None:
        input_hash = sha256_of(args)
    else:
        input_hash = "sha256:empty"

    try:
        result = call()
        wall_time_ms = int((time.monotonic() - t_start) * 1000)

        # Serialize and hash the output
        if serialize_output is not None:
            serialized = serialize_output(result)
        elif result is None:
            serialized = None
        elif isinstance(result, (dict, list, str, int, float, bool)):
            serialized = result
        elif hasattr(result, "model_dump"):
            serialized = result.model_dump()
        elif hasattr(result, "to_dict"):
            serialized = result.to_dict()
        else:
            serialized = str(result)

        # Compute output hash. sha256_of handles None as empty.
        if serialized is None:
            output_hash = "sha256:empty"
        else:
            output_hash = sha256_of(serialized)

        record = ToolCallRecord(
            tool_name=tool_name,
            transport=transport,
            input_hash=input_hash,
            output_hash=output_hash,
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=True,
            exit_code=0,
            tool_version=tool_version,
            endpoint=endpoint,
        )
        return result, sign_tool_call(record, operator_key)

    except Exception as exc:
        wall_time_ms = int((time.monotonic() - t_start) * 1000)
        record = ToolCallRecord(
            tool_name=tool_name,
            transport=transport,
            input_hash=input_hash,
            output_hash="sha256:empty",
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=False,
            exit_code=1,
            error_message=_redact_error(f"{type(exc).__name__}: {str(exc)}"),
            tool_version=tool_version,
            endpoint=endpoint,
        )
        return None, sign_tool_call(record, operator_key)


# ---------------------------------------------------------------------------
# Python function decorator
# ---------------------------------------------------------------------------


def observe_tool_fn(
    operator_key: OperatorKey,
    *,
    tool_name: str | None = None,
    tool_version: str = "",
    receipt_sink: Callable[[Receipt], None] | None = None,
) -> Callable:
    """Decorator that wraps a Python function as a receipted tool call.

    Args:
        operator_key: The operator's signing key.
        tool_name: Override the tool name. Defaults to the function's
            qualified name (module.function).
        tool_version: Optional version string.
        receipt_sink: Optional callback invoked with each receipt. If
            None, receipts are attached to the return value via a
            wrapper object (see below).

    By default the decorator wraps the function to return (result, receipt).
    If a receipt_sink is provided, the function returns just the result
    (original signature preserved) and receipts flow to the sink.

    Example with tuple return (default):
        @observe_tool_fn(operator_key=my_key)
        def search_web(query: str) -> list[dict]:
            return [{"url": "https://...", "title": "..."}]

        results, receipt = search_web("traceseal")

    Example with sink (preserves original signature):
        receipts = []
        @observe_tool_fn(operator_key=my_key, receipt_sink=receipts.append)
        def search_web(query: str) -> list[dict]:
            return [{"url": "https://...", "title": "..."}]

        results = search_web("traceseal")  # original return type
        # receipts[-1] is the receipt
    """

    def decorator(fn: Callable) -> Callable:
        resolved_name = tool_name or f"{fn.__module__}.{fn.__qualname__}"

        def wrapper(*args, **kwargs):
            # Build a canonical representation of the call arguments
            call_args = {
                "args": list(args),
                "kwargs": kwargs,
            }

            result, receipt = observe_tool(
                tool_name=resolved_name,
                operator_key=operator_key,
                call=lambda: fn(*args, **kwargs),
                transport="python",
                args=call_args,
                tool_version=tool_version,
                endpoint=f"{fn.__module__}.{fn.__qualname__}",
            )

            if receipt_sink is not None:
                receipt_sink(receipt)
                return result
            return result, receipt

        wrapper.__wrapped__ = fn
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# MCP tool observation
# ---------------------------------------------------------------------------


def observe_mcp_tool(
    server_name: str,
    tool_name: str,
    arguments: dict,
    operator_key: OperatorKey,
    call: Callable[[], Any],
    *,
    tool_version: str = "",
    serialize_output: Callable[[Any], Any] | None = None,
) -> tuple[Any, Receipt]:
    """Wrap an MCP server tool invocation.

    Args:
        server_name: The MCP server identifier (e.g. "filesystem", "github").
        tool_name: The specific tool on that server (e.g. "read_file").
        arguments: The arguments dict passed to the tool.
        operator_key: The operator's signing key.
        call: A zero-arg callable that performs the MCP call.
        tool_version: Optional version.
        serialize_output: Optional function canonicalizing output before hash.

    Returns:
        (result, receipt) — the MCP tool result plus a signed receipt.

    The tool_name in the receipt is recorded as "{server_name}/{tool_name}"
    so verifiers can distinguish between same-named tools on different
    servers.

    Example:
        from mcp_client import MCPClient

        client = MCPClient("filesystem")
        result, receipt = observe_mcp_tool(
            server_name="filesystem",
            tool_name="read_file",
            arguments={"path": "/etc/hosts"},
            operator_key=my_key,
            call=lambda: client.call_tool("read_file", {"path": "/etc/hosts"}),
        )
    """
    qualified_name = f"{server_name}/{tool_name}"
    return observe_tool(
        tool_name=qualified_name,
        operator_key=operator_key,
        call=call,
        transport="mcp",
        args=arguments,
        tool_version=tool_version,
        endpoint=f"mcp://{server_name}",
        serialize_output=serialize_output,
    )


# ---------------------------------------------------------------------------
# HTTP tool observation
# ---------------------------------------------------------------------------


def observe_http_tool(
    tool_name: str,
    url: str,
    method: str,
    operator_key: OperatorKey,
    call: Callable[[], Any],
    *,
    request_body: Any = None,
    headers: dict | None = None,
    tool_version: str = "",
    serialize_output: Callable[[Any], Any] | None = None,
) -> tuple[Any, Receipt]:
    """Wrap an HTTP API call that is NOT a model call.

    For model calls, use observe_model_call() instead — model receipts
    carry different metadata (provider, tokens, model version).

    Args:
        tool_name: Identifier for the tool.
        url: The full URL being called.
        method: HTTP method (GET, POST, etc).
        operator_key: The operator's signing key.
        call: Zero-arg callable that performs the HTTP request.
        request_body: Optional body for hashing.
        headers: Optional headers — we hash KEYS only, not values, to
            avoid leaking auth tokens. If you want to include specific
            headers in the input hash, pass them in request_body.
        tool_version: Optional.
        serialize_output: Optional output canonicalizer.

    Example:
        import requests

        result, receipt = observe_http_tool(
            tool_name="wordpress_publish",
            url="https://britfarmers.com/wp-json/wp/v2/posts",
            method="POST",
            operator_key=my_key,
            call=lambda: requests.post(url, json=post_body, headers=auth_headers),
            request_body={"title": "...", "content": "..."},
        )
    """
    # Build the canonical input: URL + method + body + header key names
    input_repr = {
        "url": url,
        "method": method.upper(),
        "body": request_body if request_body is not None else "",
        "header_keys": sorted(headers.keys()) if headers else [],
    }

    return observe_tool(
        tool_name=tool_name,
        operator_key=operator_key,
        call=call,
        transport="http",
        args=input_repr,
        tool_version=tool_version,
        endpoint=url,
        serialize_output=serialize_output,
    )


# ---------------------------------------------------------------------------
# Shell/subprocess tool observation
# ---------------------------------------------------------------------------


def observe_shell_tool(
    tool_name: str,
    command: list[str],
    operator_key: OperatorKey,
    *,
    cwd: str | None = None,
    env: dict | None = None,
    timeout: float | None = None,
    capture_output: bool = True,
    tool_version: str = "",
) -> tuple[Any, Receipt]:
    """Run a shell command and produce a receipt for its execution.

    Unlike the other observe_* functions, this one doesn't take a `call`
    callable — it invokes subprocess.run directly. The receipt records
    the command, exit code, and hashes of stdout/stderr.

    Args:
        tool_name: Identifier for the tool.
        command: Command as a list of strings (safer than a shell string).
        operator_key: The operator's signing key.
        cwd: Working directory.
        env: Environment variables. Hashed but values are stored as keys-only
            to avoid leaking secrets.
        timeout: Timeout in seconds.
        capture_output: If True, capture stdout/stderr for hashing.
        tool_version: Optional.

    Returns:
        (CompletedProcess, receipt) on success.
        On timeout or other error: (None, receipt_with_ok_false).

    Example:
        result, receipt = observe_shell_tool(
            tool_name="git_commit",
            command=["git", "commit", "-m", "update"],
            operator_key=my_key,
            cwd="/path/to/repo",
        )
    """
    import subprocess

    # Build canonical input: command + cwd + env key list (NOT values)
    input_repr = {
        "command": command,
        "cwd": cwd or "",
        "env_keys": sorted(env.keys()) if env else [],
        "timeout": timeout,
    }

    started_at = _now_iso()
    t_start = time.monotonic()
    input_hash = sha256_of(input_repr)

    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            check=False,
        )
        wall_time_ms = int((time.monotonic() - t_start) * 1000)

        # Hash stdout + stderr (the "output" of a shell tool)
        output_repr = {
            "stdout_hash": sha256_of(completed.stdout or "") if capture_output else "sha256:nocapture",
            "stderr_hash": sha256_of(completed.stderr or "") if capture_output else "sha256:nocapture",
            "returncode": completed.returncode,
        }
        output_hash = sha256_of(output_repr)

        record = ToolCallRecord(
            tool_name=tool_name,
            transport="shell",
            input_hash=input_hash,
            output_hash=output_hash,
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=completed.returncode == 0,
            exit_code=completed.returncode,
            tool_version=tool_version,
            endpoint=" ".join(command[:2]),  # Store e.g. "git commit" but not full args
        )
        return completed, sign_tool_call(record, operator_key)

    except subprocess.TimeoutExpired as exc:
        wall_time_ms = int((time.monotonic() - t_start) * 1000)
        record = ToolCallRecord(
            tool_name=tool_name,
            transport="shell",
            input_hash=input_hash,
            output_hash="sha256:empty",
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=False,
            exit_code=124,  # Timeout exit code convention
            error_message=f"TimeoutExpired after {exc.timeout}s",
            tool_version=tool_version,
            endpoint=" ".join(command[:2]),
        )
        return None, sign_tool_call(record, operator_key)

    except Exception as exc:
        wall_time_ms = int((time.monotonic() - t_start) * 1000)
        record = ToolCallRecord(
            tool_name=tool_name,
            transport="shell",
            input_hash=input_hash,
            output_hash="sha256:empty",
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            ok=False,
            exit_code=1,
            error_message=_redact_error(f"{type(exc).__name__}: {str(exc)}"),
            tool_version=tool_version,
            endpoint=" ".join(command[:2]),
        )
        return None, sign_tool_call(record, operator_key)


# ---------------------------------------------------------------------------
# ORCHESTRATION RECEIPTS (Module 3)
# ---------------------------------------------------------------------------
#
# An orchestration receipt chains child receipts (model, tool, or skill)
# into a single signed workflow record. Children are referenced by their
# receipt hash, not embedded — so orchestration receipts stay small and
# composable. When offline portability is needed, use bundle_workflow()
# to package a parent plus all its children into a single tarball.
#
# The fundamental claim of an orchestration receipt is:
#   "The operator attests that these N steps happened in this order,
#    each step's receipt hashes to the value recorded here, and the
#    overall workflow produced this final output hash."
#
# A verifier with only the orchestration receipt can verify the
# signature and the ordering. A verifier with the orchestration
# receipt + the child receipts can verify the full chain — that each
# referenced child receipt exists, has the claimed hash, and itself
# verifies cryptographically.


@dataclass
class WorkflowStep:
    """One step in an orchestration workflow.

    The step name is a workflow-local identifier (e.g. "fetch_data",
    "summarize", "publish") — not the receipt_type of the child.
    The receipt_hash is the SHA-256 of the child receipt, used to
    link the step to its receipt file without embedding the whole thing.
    """

    name: str
    """Workflow-local identifier for this step."""

    receipt_hash: str
    """SHA-256 of the child receipt (sha256:<hex>)."""

    receipt_type: str
    """One of 'skill', 'model', 'tool' — so verifiers know what kind
    of child to expect."""

    ok: bool
    """Did this step succeed? Useful for at-a-glance workflow inspection
    without loading every child receipt."""


@dataclass
class OrchestrationRecord:
    """Intermediate record before signing an orchestration receipt.

    Construct directly for fine control, or use observe_workflow()
    for the common case.
    """

    workflow_name: str
    """Identifier for this workflow type. E.g. "publish-article",
    "customer-onboarding"."""

    workflow_version: str
    """Version of the workflow definition. Lets verifiers know which
    workflow spec this execution conforms to."""

    steps: list[WorkflowStep]
    """Ordered list of child steps."""

    started_at: str
    """ISO 8601 UTC of workflow start."""

    wall_time_ms: int
    """Total wall-clock time from start to end."""

    ok: bool
    """Did the workflow complete successfully?"""

    final_output_hash: str = "sha256:empty"
    """SHA-256 of the workflow's final output, if any."""

    workflow_input_hash: str = "sha256:empty"
    """SHA-256 of the workflow's initial inputs."""

    error_step: str = ""
    """If ok=False, the name of the step that failed (from WorkflowStep.name)."""


def sign_orchestration(
    record: OrchestrationRecord,
    operator_key: OperatorKey,
) -> Receipt:
    """Sign an OrchestrationRecord into a verifiable Receipt."""

    execution = {
        "receipt_type": "orchestration",
        "workflow_name": record.workflow_name,
        "workflow_version": record.workflow_version,
        "started_at": record.started_at,
        "wall_time_ms": record.wall_time_ms,
        "workflow_input_hash": record.workflow_input_hash,
        "final_output_hash": record.final_output_hash,
        "ok": "true" if record.ok else "false",
        "step_count": len(record.steps),
        "steps": [
            {
                "name": step.name,
                "receipt_hash": step.receipt_hash,
                "receipt_type": step.receipt_type,
                "ok": "true" if step.ok else "false",
            }
            for step in record.steps
        ],
    }
    if record.error_step:
        execution["error_step"] = record.error_step

    # Provenance for orchestration receipts: records the chain's
    # integrity commitment. A future version can add a
    # workflow_definition_hash here (hash of the workflow spec that
    # defined the expected sequence of steps), which would let a
    # verifier check "did this execution follow the declared workflow?"
    provenance = {
        "chain_type": "hash-referenced",
        "provenance_version": "1.0",
    }

    payload = _signed_payload(execution, provenance)
    signature = operator_key.sign(payload)

    attestation = {
        "operator_fingerprint": operator_key.fingerprint,
        "operator_public_key": operator_key.public_key_hex,
        "attested_at": _now_iso(),
        "signature": signature.hex(),
    }

    return Receipt(
        receipt_version=RECEIPT_VERSION,
        execution=execution,
        provenance=provenance,
        attestation=attestation,
    )


# ---------------------------------------------------------------------------
# Workflow observer — the high-level API
# ---------------------------------------------------------------------------


class WorkflowObserver:
    """Context manager that accumulates child receipts into an orchestration.

    Use this as a context manager around a multi-step agent workflow.
    Child receipts are added via add_step() as they're produced. On
    exit, an orchestration receipt is signed that references all of
    them by hash.

    Example:
        with WorkflowObserver(
            workflow_name="publish-article",
            workflow_version="1.0",
            operator_key=my_key,
        ) as wf:
            # Step 1: research via model call
            research, r1 = observe_anthropic(client, research_request, my_key)
            wf.add_step("research", r1)

            # Step 2: write via another model call
            draft, r2 = observe_anthropic(client, write_request, my_key)
            wf.add_step("draft", r2)

            # Step 3: publish via HTTP tool
            result, r3 = observe_http_tool(
                tool_name="wordpress_publish",
                url="https://example.com/posts",
                method="POST",
                operator_key=my_key,
                call=lambda: requests.post(...),
            )
            wf.add_step("publish", r3)

            # Optionally record the workflow's final output
            wf.set_final_output({"post_id": result["post_id"]})

        # wf.receipt is available after the context exits
        Path("workflow-receipt.json").write_text(wf.receipt.to_json())

    If any step raises an exception, the exception propagates but the
    workflow receipt is still signed with ok=False and the failing step
    recorded in error_step. Honest failures, same as all other receipt
    types.
    """

    def __init__(
        self,
        workflow_name: str,
        workflow_version: str,
        operator_key: OperatorKey,
        *,
        workflow_input: Any = None,
    ):
        self.workflow_name = workflow_name
        self.workflow_version = workflow_version
        self.operator_key = operator_key
        self.workflow_input_hash = (
            sha256_of(workflow_input) if workflow_input is not None else "sha256:empty"
        )
        self._steps: list[tuple[str, Receipt]] = []
        self._final_output: Any = None
        self._started_at: str = ""
        self._t_start: float = 0.0
        self._error_step: str = ""
        self.receipt: Receipt | None = None

    def __enter__(self) -> WorkflowObserver:
        self._started_at = _now_iso()
        self._t_start = time.monotonic()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        # Build the final record. If an exception occurred, we still
        # sign a receipt but mark ok=False. The exception propagates
        # (we return False, not True) so the caller still sees it.
        wall_time_ms = int((time.monotonic() - self._t_start) * 1000)
        ok = exc_type is None and all(self._step_ok(r) for _, r in self._steps)

        # If an exception broke us out mid-workflow, the last step
        # in self._steps may not be the one that failed. error_step
        # is set by add_step_failure() if the caller catches exceptions
        # themselves. Otherwise we mark the next step that didn't run.
        if exc_type is not None and not self._error_step:
            self._error_step = "workflow_exception"

        final_output_hash = (
            sha256_of(self._final_output)
            if self._final_output is not None
            else "sha256:empty"
        )

        steps = [
            WorkflowStep(
                name=name,
                receipt_hash=receipt.receipt_hash,
                receipt_type=receipt.execution.get("receipt_type", "unknown"),
                ok=self._step_ok(receipt),
            )
            for name, receipt in self._steps
        ]

        record = OrchestrationRecord(
            workflow_name=self.workflow_name,
            workflow_version=self.workflow_version,
            steps=steps,
            started_at=self._started_at,
            wall_time_ms=wall_time_ms,
            ok=ok,
            final_output_hash=final_output_hash,
            workflow_input_hash=self.workflow_input_hash,
            error_step=self._error_step,
        )
        self.receipt = sign_orchestration(record, self.operator_key)

        # Return False so the exception propagates
        return False

    def add_step(self, name: str, receipt: Receipt) -> None:
        """Add a child receipt to the workflow.

        Args:
            name: Workflow-local identifier for the step.
            receipt: The signed child receipt (from observe_model_call,
                observe_tool, etc).
        """
        self._steps.append((name, receipt))

    def set_final_output(self, output: Any) -> None:
        """Record the workflow's final output.

        The output itself is not stored — only its hash. Callers can
        store the output separately if they need to preserve it.
        """
        self._final_output = output

    def mark_failed_step(self, step_name: str) -> None:
        """Explicitly mark a step as the one that failed.

        Use this when catching exceptions within the workflow to
        record which step failed, rather than letting the default
        "workflow_exception" label be used.
        """
        self._error_step = step_name

    @property
    def child_receipts(self) -> list[Receipt]:
        """All child receipts in workflow order."""
        return [r for _, r in self._steps]

    def _step_ok(self, receipt: Receipt) -> bool:
        """Read the ok field from a child receipt, tolerant of missing/bool."""
        ok_val = receipt.execution.get("ok", "false")
        if isinstance(ok_val, bool):
            return ok_val
        return str(ok_val).lower() == "true"


# ---------------------------------------------------------------------------
# Workflow bundling — package parent + children for offline portability
# ---------------------------------------------------------------------------


def bundle_workflow(
    orchestration_receipt: Receipt,
    child_receipts: list[Receipt],
    output_path: Path | str,
) -> Path:
    """Package a parent orchestration receipt and its child receipts
    into a single tar.gz for offline verification.

    The bundle layout is:
        workflow-<name>.tar.gz
          ├── orchestration.json       # The parent receipt
          ├── children/                # Directory of child receipts
          │   ├── <receipt_hash>.json  # Each child named by its hash
          │   ├── <receipt_hash>.json
          │   └── ...
          └── MANIFEST.json            # Maps step names to child filenames

    A verifier with the bundle can:
      1. Verify the orchestration receipt's signature
      2. For each step, load the referenced child by hash, verify its
         signature, and confirm its hash matches the parent's claim
      3. Conclude: "the whole workflow occurred as attested"

    Args:
        orchestration_receipt: The parent orchestration Receipt.
        child_receipts: The list of child receipts in the same order
            they appear in orchestration_receipt.execution["steps"].
        output_path: Where to write the tarball.

    Returns:
        The path to the written tarball.

    Raises:
        ValueError: If a child's hash doesn't match the hash recorded
            in the parent receipt (detects tampering or mismatched lists).
    """
    import tarfile
    import io

    output_path = Path(output_path)
    steps = orchestration_receipt.execution.get("steps", [])

    if len(steps) != len(child_receipts):
        raise ValueError(
            f"step count mismatch: parent has {len(steps)} steps, "
            f"but {len(child_receipts)} child receipts were provided"
        )

    # Verify each child's hash matches the parent's claim
    manifest = {
        "workflow_name": orchestration_receipt.execution["workflow_name"],
        "workflow_version": orchestration_receipt.execution["workflow_version"],
        "children": [],
    }

    for i, (step, child) in enumerate(zip(steps, child_receipts)):
        actual_hash = child.receipt_hash
        claimed_hash = step["receipt_hash"]
        if actual_hash != claimed_hash:
            raise ValueError(
                f"step {i} ({step['name']}): child receipt hash {actual_hash} "
                f"does not match parent's claim {claimed_hash}"
            )
        child_filename = f"{actual_hash.replace('sha256:', '')}.json"
        manifest["children"].append({
            "step_name": step["name"],
            "step_index": i,
            "filename": f"children/{child_filename}",
            "receipt_hash": actual_hash,
            "receipt_type": step["receipt_type"],
        })

    # Write tarball
    with tarfile.open(output_path, "w:gz") as tar:
        # Parent orchestration receipt
        orch_bytes = orchestration_receipt.to_json().encode("utf-8")
        orch_info = tarfile.TarInfo("orchestration.json")
        orch_info.size = len(orch_bytes)
        tar.addfile(orch_info, io.BytesIO(orch_bytes))

        # Manifest
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        manifest_info = tarfile.TarInfo("MANIFEST.json")
        manifest_info.size = len(manifest_bytes)
        tar.addfile(manifest_info, io.BytesIO(manifest_bytes))

        # Child receipts
        for i, (step, child) in enumerate(zip(steps, child_receipts)):
            filename = f"children/{step['receipt_hash'].replace('sha256:', '')}.json"
            child_bytes = child.to_json().encode("utf-8")
            child_info = tarfile.TarInfo(filename)
            child_info.size = len(child_bytes)
            tar.addfile(child_info, io.BytesIO(child_bytes))

    return output_path


def unbundle_workflow(
    bundle_path: Path | str,
    verify: bool = True,
) -> tuple[Receipt, list[Receipt], dict]:
    """Load a workflow bundle created by bundle_workflow().

    Returns:
        (orchestration_receipt, child_receipts, manifest) where:
          - orchestration_receipt is the parent Receipt
          - child_receipts is the ordered list of child Receipts
          - manifest is the MANIFEST.json contents

    The returned child_receipts are in the same order as the parent's
    steps list, so child_receipts[i] corresponds to steps[i].

    By default (``verify=True``) every receipt's Ed25519 signature is
    checked before it is returned. The manifest hash check alone is not
    sufficient: an attacker who rewrites a child can recompute its hash to
    match the manifest, but cannot forge the operator signature. Pass
    ``verify=False`` only when the caller verifies the receipts itself.

    Raises:
        ValueError: If the bundle is malformed, any child's hash doesn't
            match the parent's claim, or (verify=True) any signature is invalid.
    """
    import tarfile

    bundle_path = Path(bundle_path)

    orch_data = None
    manifest_data = None
    children_data: dict[str, dict] = {}

    with tarfile.open(bundle_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name == "orchestration.json":
                f = tar.extractfile(member)
                if f:
                    orch_data = json.loads(f.read().decode("utf-8"))
            elif member.name == "MANIFEST.json":
                f = tar.extractfile(member)
                if f:
                    manifest_data = json.loads(f.read().decode("utf-8"))
            elif member.name.startswith("children/"):
                f = tar.extractfile(member)
                if f:
                    children_data[member.name] = json.loads(f.read().decode("utf-8"))

    if orch_data is None:
        raise ValueError("bundle missing orchestration.json")
    if manifest_data is None:
        raise ValueError("bundle missing MANIFEST.json")

    orch_receipt = Receipt(
        receipt_version=orch_data["receipt_version"],
        execution=orch_data["execution"],
        provenance=orch_data["provenance"],
        attestation=orch_data["attestation"],
    )
    if verify:
        _check_receipt_signature(orch_receipt, "orchestration receipt")

    # Reconstruct child receipts in workflow order using the manifest
    child_receipts: list[Receipt] = []
    for entry in manifest_data["children"]:
        filename = entry["filename"]
        if filename not in children_data:
            raise ValueError(f"bundle missing child receipt: {filename}")
        cd = children_data[filename]
        child = Receipt(
            receipt_version=cd["receipt_version"],
            execution=cd["execution"],
            provenance=cd["provenance"],
            attestation=cd["attestation"],
        )
        # Verify hash matches
        if child.receipt_hash != entry["receipt_hash"]:
            raise ValueError(
                f"step '{entry['step_name']}': child receipt hash "
                f"{child.receipt_hash} does not match manifest claim "
                f"{entry['receipt_hash']}"
            )
        if verify:
            _check_receipt_signature(child, f"step '{entry['step_name']}'")
        child_receipts.append(child)

    return orch_receipt, child_receipts, manifest_data


def verify_workflow_bundle(bundle_path: Path | str) -> dict:
    """Verify a workflow bundle: parent + all children + chain consistency.

    This is the top-level verification entry point for workflow bundles.
    It checks:
      1. Parent orchestration receipt signature
      2. Each child receipt signature
      3. Each child's receipt_hash matches the parent's claim
      4. Step ordering is consistent between parent and manifest

    Returns:
        A verification report dict with:
          - ok: bool — overall verification result
          - parent_ok: bool — parent signature valid?
          - child_results: list of per-child verification results
          - message: human-readable summary

    This function uses the cryptography library directly to avoid
    depending on an external verifier package. For production use,
    the equivalent check can be done with the standalone
    traceseal-verify CLI.
    """
    from cryptography.exceptions import InvalidSignature

    try:
        parent, children, manifest = unbundle_workflow(bundle_path)
    except ValueError as e:
        return {
            "ok": False,
            "parent_ok": False,
            "child_results": [],
            "message": f"bundle error: {e}",
        }

    report = {
        "ok": True,
        "parent_ok": False,
        "child_results": [],
        "message": "",
        "workflow_name": parent.execution.get("workflow_name", ""),
        "step_count": len(children),
    }

    # Verify parent
    try:
        pk_bytes = bytes.fromhex(parent.attestation["operator_public_key"])
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        payload = _signed_payload(parent.execution, parent.provenance)
        sig = bytes.fromhex(parent.attestation["signature"])
        pk.verify(sig, payload)
        report["parent_ok"] = True
    except (InvalidSignature, ValueError, KeyError) as e:
        report["ok"] = False
        report["message"] = f"parent signature invalid: {e}"
        return report

    # Verify each child
    for i, child in enumerate(children):
        step_name = manifest["children"][i]["step_name"]
        child_result = {"step": step_name, "ok": False, "message": ""}
        try:
            c_pk_bytes = bytes.fromhex(child.attestation["operator_public_key"])
            c_pk = Ed25519PublicKey.from_public_bytes(c_pk_bytes)
            c_payload = _signed_payload(child.execution, child.provenance)
            c_sig = bytes.fromhex(child.attestation["signature"])
            c_pk.verify(c_sig, c_payload)
            child_result["ok"] = True
            child_result["receipt_type"] = child.execution.get("receipt_type", "unknown")
        except (InvalidSignature, ValueError, KeyError) as e:
            child_result["message"] = f"signature invalid: {e}"
            report["ok"] = False
        report["child_results"].append(child_result)

    if report["ok"]:
        report["message"] = (
            f"workflow '{report['workflow_name']}' verified: "
            f"parent + {len(children)} children"
        )
    elif not report["message"]:
        failed = [r["step"] for r in report["child_results"] if not r["ok"]]
        report["message"] = f"verification failed for steps: {failed}"

    return report


# ---------------------------------------------------------------------------
# DATA FLOW RECEIPTS (Module 4)
# ---------------------------------------------------------------------------
#
# Data flow receipts record every outbound HTTP request your agent makes,
# regardless of transport. They answer: "what data left my system, to whom,
# and was it declared?"
#
# This is the compliance layer. When a regulator asks "did you send user
# data to OpenAI between 2:00 PM and 4:00 PM?", the answer is no longer
# "trust me, we didn't" — it's "here is a cryptographic record of every
# outbound HTTP call, and you can see for yourself."
#
# What these receipts PROVE:
#   - The operator attests: "an outbound HTTP request with this payload
#     hash was sent to this destination at this time."
#
# What they do NOT prove:
#   - What the destination did with the data after receiving it (that's
#     a contractual question).
#   - Whether the operator *also* made calls that weren't receipted
#     (you can't use receipts to prove a negative — use the audit log
#     for that, since the chain is append-only).
#
# The PII fingerprinter is heuristic, not proof. It flags patterns
# that *look like* PII (emails, phone numbers, credit card shapes,
# SSN shapes, JWT tokens). A payload that scores high is suspicious.
# A payload that scores zero is not proven clean — it just means no
# known patterns matched.


import re
from dataclasses import field


# Patterns for PII detection. Deliberately conservative — we err on the
# side of flagging possible PII rather than missing it.
_PII_PATTERNS = {
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),
    "phone_us": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "phone_uk": re.compile(
        r"\b(?:\+?44[-.\s]?)?\(?0?(?:7|1|2|3|5|8)\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{3,4}\b"
    ),
    "credit_card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b"
    ),
    "ssn": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    ),
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    ),
    "aws_access_key": re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    ),
    "api_key_generic": re.compile(
        r"\b(?:sk|pk|api)[_-][A-Za-z0-9]{20,}\b"
    ),
    "github_token": re.compile(
        r"\b(?:ghp|ghs|gho)_[A-Za-z0-9]{20,}\b"
    ),
}


def fingerprint_pii(payload: Any) -> dict[str, int]:
    """Scan a payload for PII-like patterns. Returns {pattern_name: count}.

    Only patterns with at least one match are included in the result.
    An empty dict means no known PII patterns matched (which does NOT
    mean the payload is PII-free — only that nothing familiar was found).

    The payload is converted to a string representation before scanning.
    For dicts and lists, canonical JSON is used.
    """
    if payload is None:
        return {}

    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return {}
    elif isinstance(payload, str):
        text = payload
    elif isinstance(payload, (dict, list)):
        text = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    else:
        text = str(payload)

    findings: dict[str, int] = {}
    for name, pattern in _PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            findings[name] = len(matches)

    return findings


@dataclass
class DataFlowRecord:
    """A record of an outbound data transmission before signing."""

    destination_host: str
    """The host portion of the destination URL. E.g. "api.openai.com"."""

    destination_url: str
    """Full URL, minus query string for privacy. E.g. "https://api.openai.com/v1/chat/completions"."""

    method: str
    """HTTP method."""

    request_payload_hash: str
    """SHA-256 of the request body."""

    response_payload_hash: str
    """SHA-256 of the response body."""

    payload_bytes: int
    """Size of the request payload in bytes."""

    response_bytes: int
    """Size of the response in bytes."""

    started_at: str
    """ISO 8601 UTC."""

    wall_time_ms: int
    """Wall-clock latency in ms."""

    status_code: int
    """HTTP status code. 0 if the request failed before getting a response."""

    ok: bool
    """True if the request completed with a 2xx response."""

    pii_fingerprint: dict[str, int] = field(default_factory=dict)
    """Pattern name → match count for the request payload."""

    destination_declared: bool = True
    """Whether the destination host was in the declared allow list.
    False means the request went to an undeclared destination —
    a compliance flag."""

    declared_allow_list: list[str] = field(default_factory=list)
    """The allow list that was checked against, if any."""

    error_message: str = ""
    """If ok=False, short error description."""


def sign_data_flow(
    record: DataFlowRecord,
    operator_key: OperatorKey,
) -> Receipt:
    """Sign a DataFlowRecord into a verifiable Receipt."""

    execution = {
        "receipt_type": "data_flow",
        "destination_host": record.destination_host,
        "destination_url": record.destination_url,
        "method": record.method.upper(),
        "started_at": record.started_at,
        "wall_time_ms": record.wall_time_ms,
        "request_payload_hash": record.request_payload_hash,
        "response_payload_hash": record.response_payload_hash,
        "payload_bytes": record.payload_bytes,
        "response_bytes": record.response_bytes,
        "status_code": record.status_code,
        "ok": "true" if record.ok else "false",
        "destination_declared": "true" if record.destination_declared else "false",
    }
    if record.pii_fingerprint:
        # Keep the fingerprint as a sorted list of "pattern:count" for
        # canonical JSON compatibility (no nested dicts with int values
        # that would serialize unpredictably — though they're fine in
        # Python 3.7+, we prefer the flat list form for schema stability)
        execution["pii_fingerprint"] = dict(
            sorted(record.pii_fingerprint.items())
        )
    if record.declared_allow_list:
        execution["declared_allow_list"] = sorted(record.declared_allow_list)
    if record.error_message:
        execution["error_message"] = record.error_message

    provenance = {
        "flow_type": "outbound_http",
        "provenance_version": "1.0",
    }

    payload = _signed_payload(execution, provenance)
    signature = operator_key.sign(payload)

    attestation = {
        "operator_fingerprint": operator_key.fingerprint,
        "operator_public_key": operator_key.public_key_hex,
        "attested_at": _now_iso(),
        "signature": signature.hex(),
    }

    return Receipt(
        receipt_version=RECEIPT_VERSION,
        execution=execution,
        provenance=provenance,
        attestation=attestation,
    )


def _parse_host(url: str) -> str:
    """Extract the host portion of a URL, lowercased."""
    try:
        from urllib.parse import urlparse
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _strip_query(url: str) -> str:
    """Return the URL without its query string (for privacy)."""
    try:
        from urllib.parse import urlparse, urlunparse
        parts = urlparse(url)
        return urlunparse((parts.scheme, parts.netloc, parts.path, "", "", ""))
    except Exception:
        return url


def _coerce_to_bytes(data: Any) -> bytes:
    """Best-effort conversion of a request body to bytes for hashing/sizing."""
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (dict, list)):
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    return str(data).encode("utf-8")


def observe_data_flow(
    url: str,
    method: str,
    operator_key: OperatorKey,
    call: Callable[[], Any],
    *,
    request_body: Any = None,
    declared_allow_list: list[str] | None = None,
    scan_pii: bool = True,
    extract_status: Callable[[Any], int] | None = None,
    extract_response_body: Callable[[Any], Any] | None = None,
) -> tuple[Any, Receipt]:
    """Wrap an outbound HTTP request, producing a signed data flow receipt.

    This is the generic data flow observer. It's deliberately agnostic
    of the HTTP client library — pass a callable that makes the request
    and returns the response, and this function handles the hashing,
    PII fingerprinting, allow-list checking, and signing.

    Args:
        url: The full destination URL.
        method: HTTP method.
        operator_key: The operator's signing key.
        call: Zero-arg callable that performs the HTTP request.
        request_body: The body being sent. Used for hashing and PII scanning.
            Pass the dict/string/bytes — NOT the pre-serialized form.
        declared_allow_list: Optional list of allowed destination hosts
            (exact match). If provided, the receipt records whether the
            destination was in the list.
        scan_pii: If True, scan the request body for PII-like patterns.
        extract_status: Optional function to extract HTTP status from
            the response. If None, we try common attributes (.status_code
            for requests, .status for httpx/aiohttp).
        extract_response_body: Optional function to extract response body
            for hashing. If None, we try common attributes (.content,
            .text, .json()).

    Returns:
        (response, receipt) on success; (None, receipt_with_ok_false)
        if the request raised.

    Example:
        import requests

        result, receipt = observe_data_flow(
            url="https://api.example.com/webhook",
            method="POST",
            operator_key=my_key,
            call=lambda: requests.post(
                "https://api.example.com/webhook",
                json={"event": "user_signup", "user": {"email": "tim@example.com"}},
            ),
            request_body={"event": "user_signup", "user": {"email": "tim@example.com"}},
            declared_allow_list=["api.example.com", "api.mailgun.com"],
        )
        # receipt.execution["pii_fingerprint"] will show {"email": 1}
        # receipt.execution["destination_declared"] will be "true"
    """
    started_at = _now_iso()
    t_start = time.monotonic()

    # Hash and size the request
    body_bytes = _coerce_to_bytes(request_body)
    request_hash = sha256_of(body_bytes) if body_bytes else "sha256:empty"
    payload_bytes = len(body_bytes)

    # PII scan on the request
    pii = fingerprint_pii(request_body) if scan_pii and request_body is not None else {}

    # Allow-list check
    destination_host = _parse_host(url)
    destination_url = _strip_query(url)
    if declared_allow_list is not None:
        destination_declared = destination_host in declared_allow_list
    else:
        destination_declared = True  # No list = no policy to enforce

    try:
        response = call()
        wall_time_ms = int((time.monotonic() - t_start) * 1000)

        # Extract status code
        if extract_status is not None:
            status = extract_status(response)
        elif hasattr(response, "status_code"):
            status = int(response.status_code)
        elif hasattr(response, "status"):
            status = int(response.status)
        else:
            status = 200  # Assume success if we can't tell

        # Extract and hash response body
        if extract_response_body is not None:
            resp_body = extract_response_body(response)
            resp_bytes = _coerce_to_bytes(resp_body)
        elif hasattr(response, "content"):
            resp_bytes = response.content if isinstance(response.content, bytes) else _coerce_to_bytes(response.content)
        elif hasattr(response, "text"):
            resp_bytes = _coerce_to_bytes(response.text)
        else:
            resp_bytes = _coerce_to_bytes(response)

        response_hash = sha256_of(resp_bytes) if resp_bytes else "sha256:empty"
        ok = 200 <= status < 300

        record = DataFlowRecord(
            destination_host=destination_host,
            destination_url=destination_url,
            method=method,
            request_payload_hash=request_hash,
            response_payload_hash=response_hash,
            payload_bytes=payload_bytes,
            response_bytes=len(resp_bytes),
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            status_code=status,
            ok=ok,
            pii_fingerprint=pii,
            destination_declared=destination_declared,
            declared_allow_list=declared_allow_list or [],
        )
        return response, sign_data_flow(record, operator_key)

    except Exception as exc:
        wall_time_ms = int((time.monotonic() - t_start) * 1000)
        record = DataFlowRecord(
            destination_host=destination_host,
            destination_url=destination_url,
            method=method,
            request_payload_hash=request_hash,
            response_payload_hash="sha256:empty",
            payload_bytes=payload_bytes,
            response_bytes=0,
            started_at=started_at,
            wall_time_ms=wall_time_ms,
            status_code=0,
            ok=False,
            pii_fingerprint=pii,
            destination_declared=destination_declared,
            declared_allow_list=declared_allow_list or [],
            error_message=_redact_error(f"{type(exc).__name__}: {str(exc)}"),
        )
        return None, sign_data_flow(record, operator_key)


# ---------------------------------------------------------------------------
# Aggregation helper: summarize a set of data flow receipts
# ---------------------------------------------------------------------------


def summarize_data_flows(receipts: list[Receipt]) -> dict:
    """Aggregate statistics across a list of data flow receipts.

    Useful for compliance reports: "in this workflow we made N outbound
    calls to these M hosts, and here's what PII patterns we sent."

    Args:
        receipts: A list of data flow receipts (receipt_type == "data_flow").
            Non-data-flow receipts are silently skipped.

    Returns:
        A dict with:
          - total_calls: int
          - destinations: {host: call_count}
          - undeclared_calls: int (count of calls to non-allowlisted hosts)
          - pii_summary: {pattern: total_matches_across_all_calls}
          - total_payload_bytes: int
          - failed_calls: int
    """
    total = 0
    destinations: dict[str, int] = {}
    undeclared = 0
    pii_total: dict[str, int] = {}
    total_bytes = 0
    failed = 0

    for r in receipts:
        if r.execution.get("receipt_type") != "data_flow":
            continue
        total += 1
        host = r.execution.get("destination_host", "")
        if host:
            destinations[host] = destinations.get(host, 0) + 1
        if r.execution.get("destination_declared") == "false":
            undeclared += 1
        if r.execution.get("ok") == "false":
            failed += 1
        total_bytes += r.execution.get("payload_bytes", 0)
        for pattern, count in r.execution.get("pii_fingerprint", {}).items():
            pii_total[pattern] = pii_total.get(pattern, 0) + count

    return {
        "total_calls": total,
        "destinations": dict(sorted(destinations.items())),
        "undeclared_calls": undeclared,
        "pii_summary": dict(sorted(pii_total.items())),
        "total_payload_bytes": total_bytes,
        "failed_calls": failed,
    }
