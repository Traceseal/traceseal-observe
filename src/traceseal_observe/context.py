"""Who acted, for whom, under what authority, and because of what.

A receipt says *what* happened. Auditors also ask:

  - which agent (and which version, in which deployment) did it?
  - on whose behalf?
  - who authorised it, with what scope, until when?
  - what caused it: which model response asked for this tool call?

This module adds a signed `context` object to every operational receipt
(model, tool, data_flow, orchestration, outcome) signed while a context is
active. It needs no change at the call sites:

    with agent_context(
        agent_id="support-bot", agent_version="2.3.1", tenant="acme",
        session_id=session.id,
        principal=Principal.user(user.id, pepper=PEPPER),
        authorization=Authorization(scopes=["refunds:write"], grant=grant_doc,
                                    expires_at="2026-11-01T00:00:00Z"),
    ):
        response, model_receipt = observe_anthropic(client, request, key)
        for call in requested_tool_calls(model_receipt):
            with caused_by(model_receipt, tool_call_id=call["id"]):
                result, tool_receipt = observe_tool(call["name"], key, ..., args=...)

Contexts nest; inner values override outer ones. They follow
contextvars semantics, so they are safe across threads and asyncio tasks
(a new thread starts empty unless you copy the context into it).

User principals are always recorded as keyed commitments, never raw
identifiers (the constructor refuses anything else for kind="user"):
    ref = "hmac-sha256:" + HMAC-SHA256(pepper, "<kind>:<id>")
so receipts can be shared without disclosing the user's identifier. They
are pseudonymous, not anonymous: the same user gets the same ref in every
receipt, so receipts about one person can be linked to each other, and
anything else in or around them (tenant, timing, content) may identify
them. Whoever holds the pepper can find every receipt about a person (GDPR
Art. 15 requests). Destroying the pepper stops anyone linking a ref back to
an identifier, while every signature stays valid.
"""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import re
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

CONTEXT_VERSION = "1.0"
PRINCIPAL_KINDS = frozenset({"user", "service", "agent", "organisation"})

_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_SCOPE_RE = re.compile(r"^[!-~]{1,128}$")
_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_RE = re.compile(r"^[0-9a-f]{16}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^(hmac-sha256:[0-9a-f]{64}|id:[^\x00-\x1f\x7f]{1,128})$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_LIST = 64

_CURRENT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "traceseal_receipt_context", default=None
)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or _TEXT_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be 1-128 printable characters")
    return value


# ---------------------------------------------------------------------------
# Principals and authorisation
# ---------------------------------------------------------------------------


def principal_ref(kind: str, principal_id: str, pepper: bytes) -> str:
    """The keyed commitment recorded for a principal."""
    if kind not in PRINCIPAL_KINDS:
        raise ValueError(f"principal kind must be one of {sorted(PRINCIPAL_KINDS)}")
    if not isinstance(principal_id, str) or not principal_id:
        raise ValueError("principal id must be a non-empty string")
    if not isinstance(pepper, (bytes, bytearray)) or len(pepper) < 16:
        raise ValueError("pepper must be at least 16 random bytes")
    digest = hmac.new(bytes(pepper), f"{kind}:{principal_id}".encode("utf-8"),
                      hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


@dataclass(frozen=True)
class Principal:
    """On whose behalf an agent acts (or who granted it authority)."""

    kind: str
    ref: str

    def __post_init__(self) -> None:
        if self.kind not in PRINCIPAL_KINDS:
            raise ValueError(f"principal kind must be one of {sorted(PRINCIPAL_KINDS)}")
        if not isinstance(self.ref, str) or _REF_RE.fullmatch(self.ref) is None:
            raise ValueError("principal ref must be hmac-sha256:<hex> or id:<public id>")
        if self.kind == "user" and not self.ref.startswith("hmac-sha256:"):
            raise ValueError("user principals must be keyed commitments (hmac-sha256:<hex>); "
                             "use Principal.user(user_id, pepper=...)")

    @classmethod
    def user(cls, user_id: str, *, pepper: bytes) -> Principal:
        return cls("user", principal_ref("user", user_id, pepper))

    @classmethod
    def committed(cls, kind: str, principal_id: str, *, pepper: bytes) -> Principal:
        return cls(kind, principal_ref(kind, principal_id, pepper))

    @classmethod
    def public(cls, kind: str, public_id: str) -> Principal:
        """A principal whose identifier is meant to be public, such as a
        service account or a partner organisation. Never use this for people."""
        if kind == "user":
            raise ValueError("users must be recorded as keyed commitments (Principal.user)")
        return cls(kind, f"id:{_text(public_id, 'public id')}")

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "ref": self.ref}


@dataclass(frozen=True)
class Authorization:
    """The authority an action ran under.

    grant: the authorisation artefact (an OAuth token's claims, a signed
      mandate, an approval record). Only its hash is recorded. Pass
      grant_hash instead if you have hashed it yourself.
    """

    scopes: tuple[str, ...] = ()
    grant: Any = None
    grant_hash: str = ""
    granted_by: Principal | None = None
    expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        from traceseal_observe import _require_strict_json, sha256_of

        scopes = list(self.scopes)
        if len(scopes) > _MAX_LIST or any(
            not isinstance(s, str) or _SCOPE_RE.fullmatch(s) is None for s in scopes
        ):
            raise ValueError("scopes must be at most 64 printable tokens without spaces")
        out: dict[str, Any] = {}
        if scopes:
            out["scopes"] = sorted(set(scopes))
        if self.grant is not None and self.grant_hash:
            raise ValueError("pass grant or grant_hash, not both")
        if self.grant is not None:
            _require_strict_json(self.grant, "grant")
            out["grant_hash"] = sha256_of(self.grant)
        elif self.grant_hash:
            if _SHA_RE.fullmatch(self.grant_hash) is None:
                raise ValueError("grant_hash must be sha256:<64 hex>")
            out["grant_hash"] = self.grant_hash
        if self.granted_by is not None:
            out["granted_by"] = self.granted_by.to_dict()
        if self.expires_at:
            if _UTC_RE.fullmatch(self.expires_at) is None:
                raise ValueError("expires_at must be UTC YYYY-MM-DDTHH:MM:SSZ")
            out["expires_at"] = self.expires_at
        if not out:
            raise ValueError("authorization is empty")
        return out


# ---------------------------------------------------------------------------
# The ambient context
# ---------------------------------------------------------------------------


def _receipt_hash(value: Any) -> str:
    from traceseal_observe import Receipt

    if isinstance(value, Receipt):
        return value.receipt_hash
    if isinstance(value, str) and _SHA_RE.fullmatch(value):
        return value
    raise ValueError("caused_by entries must be Receipts or sha256:<hex> receipt hashes")


def _build(fields: dict[str, Any]) -> dict[str, Any]:
    """Validate keyword fields into the canonical context fragment."""
    out: dict[str, Any] = {}
    agent = {}
    for key, name in (("agent_id", "id"), ("agent_version", "version"),
                      ("deployment", "deployment")):
        if fields.get(key) is not None:
            agent[name] = _text(fields[key], key)
    if agent:
        out["agent"] = agent
    if fields.get("principal") is not None:
        if not isinstance(fields["principal"], Principal):
            raise ValueError("principal must be a Principal")
        out["principal"] = fields["principal"].to_dict()
    for key in ("tenant", "session_id", "tool_call_id"):
        if fields.get(key) is not None:
            out[key] = _text(fields[key], key)
    trace = {}
    if fields.get("trace_id") is not None:
        if _TRACE_RE.fullmatch(str(fields["trace_id"])) is None or set(fields["trace_id"]) == {"0"}:
            raise ValueError("trace_id must be 32 lowercase hex, not all zero (W3C)")
        trace["trace_id"] = fields["trace_id"]
    for key in ("span_id", "parent_span_id"):
        if fields.get(key) is not None:
            if _SPAN_RE.fullmatch(str(fields[key])) is None or set(fields[key]) == {"0"}:
                raise ValueError(f"{key} must be 16 lowercase hex, not all zero (W3C)")
            trace[key] = fields[key]
    if trace:
        out["trace"] = trace
    if fields.get("authorization") is not None:
        if not isinstance(fields["authorization"], Authorization):
            raise ValueError("authorization must be an Authorization")
        out["authorization"] = fields["authorization"].to_dict()
    if fields.get("caused_by") is not None:
        causes = fields["caused_by"]
        if not isinstance(causes, (list, tuple)):
            causes = [causes]
        if len(causes) > _MAX_LIST:
            raise ValueError("at most 64 caused_by entries")
        hashes = [_receipt_hash(c) for c in causes]
        out["caused_by"] = list(dict.fromkeys(hashes))
    return out


_FIELDS = frozenset({
    "agent_id", "agent_version", "deployment", "principal", "tenant",
    "session_id", "trace_id", "span_id", "parent_span_id", "authorization",
    "caused_by", "tool_call_id",
})


@contextmanager
def agent_context(**fields: Any) -> Iterator[dict[str, Any]]:
    """Sign every operational receipt in this block with these context fields.

    Fields: agent_id, agent_version, deployment, principal (Principal),
    tenant, session_id, trace_id, span_id, parent_span_id (W3C hex),
    authorization (Authorization), caused_by (receipts or hashes),
    tool_call_id. Inner contexts override outer ones field by field; pass
    None to leave a field as it is.
    """
    unknown = set(fields) - _FIELDS
    if unknown:
        raise TypeError(f"unknown context fields: {sorted(unknown)}")
    fragment = _build(fields)
    merged = dict(_CURRENT.get() or {})
    for key, value in fragment.items():
        if key in ("agent", "trace") and key in merged:
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    token = _CURRENT.set(merged)
    try:
        yield dict(merged)
    finally:
        _CURRENT.reset(token)


def caused_by(*receipts: Any, tool_call_id: str | None = None):
    """Record that receipts signed in this block were caused by `receipts`
    (typically the model receipt whose response requested a tool call)."""
    return agent_context(caused_by=list(receipts), tool_call_id=tool_call_id)


def _otel_trace() -> dict[str, str]:
    """Trace/span ids of the current OpenTelemetry span, if any."""
    try:
        from opentelemetry import trace  # type: ignore
    except Exception:
        return {}
    try:
        ctx = trace.get_current_span().get_span_context()
        if not ctx.is_valid:
            return {}
        return {"trace_id": format(ctx.trace_id, "032x"), "span_id": format(ctx.span_id, "016x")}
    except Exception:
        return {}


def current_context() -> dict[str, Any] | None:
    """The signed `context` object a receipt signed now would carry."""
    ctx = dict(_CURRENT.get() or {})
    if "trace" not in ctx:
        otel = _otel_trace()
        if otel:
            ctx["trace"] = otel
    if not ctx:
        return None
    ctx["context_version"] = CONTEXT_VERSION
    return ctx


# ---------------------------------------------------------------------------
# Tool calls requested by a model response
# ---------------------------------------------------------------------------

MAX_TOOL_CALLS = 128


def _arguments_hash(arguments: Any) -> str:
    """Hash tool arguments the way observe_tool(args=...) hashes them."""
    import json

    from traceseal_observe import sha256_of

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except (ValueError, RecursionError):
            return sha256_of(arguments)
    return sha256_of(arguments)


def _call(call_id: Any, name: Any, arguments: Any) -> dict[str, str] | None:
    if not isinstance(call_id, str) or _TEXT_RE.fullmatch(call_id) is None:
        return None
    if not isinstance(name, str) or _TEXT_RE.fullmatch(name) is None:
        return None
    return {"id": call_id, "name": name, "input_hash": _arguments_hash(arguments)}


def extract_tool_calls(serialized: Any) -> list[dict[str, str]]:
    """Tool calls requested in a serialized (dict) model response.

    Anthropic Messages: content[] blocks of type tool_use.
    OpenAI Chat Completions: choices[0].message.tool_calls[].
    OpenAI Responses: output[] items of type function_call.
    """
    calls: list[dict[str, str] | None] = []
    if not isinstance(serialized, dict):
        return []
    content = serialized.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append(_call(block.get("id"), block.get("name"), block.get("input")))
    choices = serialized.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
            for tc in message["tool_calls"]:
                fn = tc.get("function") if isinstance(tc, dict) else None
                if isinstance(fn, dict):
                    calls.append(_call(tc.get("id"), fn.get("name"), fn.get("arguments")))
    output = serialized.get("output")
    if isinstance(output, list):
        for item in output:
            if isinstance(item, dict) and item.get("type") == "function_call":
                calls.append(_call(item.get("call_id"), item.get("name"), item.get("arguments")))
    return [c for c in calls if c is not None]


class ToolCallAccumulator:
    """Rebuilds requested tool calls from streamed chunks.

    Anthropic: content_block_start (tool_use id/name) + input_json_delta.
    OpenAI chat: choices[0].delta.tool_calls[] fragments keyed by index.
    """

    def __init__(self) -> None:
        self._anthropic: dict[int, dict[str, Any]] = {}
        self._openai: dict[int, dict[str, Any]] = {}

    def feed(self, chunk: Any) -> None:
        if not isinstance(chunk, dict):
            return
        kind = chunk.get("type")
        if kind == "content_block_start":
            block = chunk.get("content_block")
            if isinstance(block, dict) and block.get("type") == "tool_use":
                self._anthropic[chunk.get("index", len(self._anthropic))] = {
                    "id": block.get("id"), "name": block.get("name"), "json": [],
                }
        elif kind == "content_block_delta":
            delta = chunk.get("delta")
            entry = self._anthropic.get(chunk.get("index"))
            if entry is not None and isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                if isinstance(delta.get("partial_json"), str):
                    entry["json"].append(delta["partial_json"])
        elif kind is None:
            choices = chunk.get("choices")
            if not (isinstance(choices, list) and choices and isinstance(choices[0], dict)):
                return
            delta = choices[0].get("delta")
            if not isinstance(delta, dict) or not isinstance(delta.get("tool_calls"), list):
                return
            for tc in delta["tool_calls"]:
                if not isinstance(tc, dict):
                    continue
                entry = self._openai.setdefault(tc.get("index", 0),
                                                {"id": None, "name": None, "args": []})
                if tc.get("id"):
                    entry["id"] = tc["id"]
                fn = tc.get("function")
                if isinstance(fn, dict):
                    if fn.get("name"):
                        entry["name"] = fn["name"]
                    if isinstance(fn.get("arguments"), str):
                        entry["args"].append(fn["arguments"])

    def result(self) -> list[dict[str, str]]:
        calls = []
        for _, entry in sorted(self._anthropic.items(), key=lambda kv: kv[0]):
            calls.append(_call(entry["id"], entry["name"], "".join(entry["json"])))
        for _, entry in sorted(self._openai.items(), key=lambda kv: kv[0]):
            calls.append(_call(entry["id"], entry["name"], "".join(entry["args"])))
        return [c for c in calls if c is not None]


def requested_tool_calls(model_receipt: Any) -> list[dict[str, str]]:
    """The signed tool calls a model receipt says the model requested."""
    calls = model_receipt.execution.get("requested_tool_calls", [])
    return [dict(c) for c in calls] if isinstance(calls, list) else []
