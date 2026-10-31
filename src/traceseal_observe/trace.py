"""Verify who-did-what-because-of-what across a set of receipts.

    report = verify_trace(receipts, required_scopes={"issue_refund": "refunds:write"})

Checks, for every receipt carrying a signed `context` (see context.py):

  - the receipt's signature, and that its context is well formed;
  - causal links: each `caused_by` hash that is in the supplied set is
    resolved into a graph edge. Hash references are cryptographic: a receipt
    can only cite receipts that already existed when it was signed;
  - tool calls: a tool receipt with `tool_call_id` that cites a model receipt
    must match a call that model response requested. Reported per call:
        matched           — id, name and argument hash all agree
        arguments_differ  — the tool ran with different arguments than the
                            model asked for (the agent changed them)
        name_differs      — the id matched but the tool name did not
        not_requested     — the cited model response never asked for it
  - requested tool calls that no supplied tool receipt executed;
  - tool receipts with no model cause ("unprompted": the agent's own code
    acted, not the model);
  - authorisation: actions after `authorization.expires_at`, and, given
    `required_scopes`, actions whose context lacks the required scope.

Errors (report["ok"] False): bad signatures, malformed context, tool calls
that were not requested, expired or missing authorisation. The rest are
findings for an auditor to read, not failures.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from traceseal_observe import Receipt, verify_receipt_signature
from traceseal_observe.context import (
    CONTEXT_VERSION,
    MAX_TOOL_CALLS,
    PRINCIPAL_KINDS,
    principal_ref,
)

_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_CONTEXT_KEYS = frozenset({
    "context_version", "agent", "principal", "tenant", "session_id", "trace",
    "authorization", "caused_by", "tool_call_id",
})


class TraceError(ValueError):
    pass


def _time(value: Any) -> datetime | None:
    if isinstance(value, str) and _UTC_RE.fullmatch(value):
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return None


def _when(receipt: Receipt) -> datetime | None:
    ex = receipt.execution
    for key in ("started_at", "observed_at", "chained_at"):
        t = _time(ex.get(key))
        if t is not None:
            return t
    return _time(receipt.attestation.get("attested_at"))


def _check_principal(value: Any, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "ref"}
        or value["kind"] not in PRINCIPAL_KINDS
        or not isinstance(value["ref"], str)
        or not re.fullmatch(r"(hmac-sha256:[0-9a-f]{64}|id:[^\x00-\x1f\x7f]{1,128})", value["ref"])
    ):
        raise TraceError(f"{label} is malformed")


def check_context(ctx: Any) -> dict[str, Any]:
    """Validate a signed context object. Raises TraceError."""
    if not isinstance(ctx, dict) or ctx.get("context_version") != CONTEXT_VERSION:
        raise TraceError("context_version is missing or unsupported")
    unknown = set(ctx) - _CONTEXT_KEYS
    if unknown:
        raise TraceError(f"context has unknown fields {sorted(unknown)}")
    for key in ("tenant", "session_id", "tool_call_id"):
        if key in ctx and (not isinstance(ctx[key], str) or not _TEXT_RE.fullmatch(ctx[key])):
            raise TraceError(f"context.{key} is malformed")
    if "agent" in ctx:
        agent = ctx["agent"]
        if not isinstance(agent, dict) or not agent or set(agent) - {"id", "version", "deployment"} or any(
            not isinstance(v, str) or not _TEXT_RE.fullmatch(v) for v in agent.values()
        ):
            raise TraceError("context.agent is malformed")
    if "principal" in ctx:
        _check_principal(ctx["principal"], "context.principal")
    if "trace" in ctx:
        trace = ctx["trace"]
        if not isinstance(trace, dict) or not trace or set(trace) - {"trace_id", "span_id", "parent_span_id"}:
            raise TraceError("context.trace is malformed")
        if "trace_id" in trace and not re.fullmatch(r"[0-9a-f]{32}", str(trace["trace_id"])):
            raise TraceError("context.trace.trace_id is malformed")
        for key in ("span_id", "parent_span_id"):
            if key in trace and not re.fullmatch(r"[0-9a-f]{16}", str(trace[key])):
                raise TraceError(f"context.trace.{key} is malformed")
    if "authorization" in ctx:
        auth = ctx["authorization"]
        if not isinstance(auth, dict) or not auth or set(auth) - {"scopes", "grant_hash", "granted_by", "expires_at"}:
            raise TraceError("context.authorization is malformed")
        if "scopes" in auth and (
            not isinstance(auth["scopes"], list)
            or any(not isinstance(s, str) for s in auth["scopes"])
            or auth["scopes"] != sorted(set(auth["scopes"]))
        ):
            raise TraceError("context.authorization.scopes is malformed")
        if "grant_hash" in auth and not _SHA_RE.fullmatch(str(auth["grant_hash"])):
            raise TraceError("context.authorization.grant_hash is malformed")
        if "granted_by" in auth:
            _check_principal(auth["granted_by"], "context.authorization.granted_by")
        if "expires_at" in auth and _time(auth["expires_at"]) is None:
            raise TraceError("context.authorization.expires_at is malformed")
    if "caused_by" in ctx and (
        not isinstance(ctx["caused_by"], list)
        or not 1 <= len(ctx["caused_by"]) <= 64
        or any(not isinstance(h, str) or not _SHA_RE.fullmatch(h) for h in ctx["caused_by"])
    ):
        raise TraceError("context.caused_by is malformed")
    return ctx


def _requested_calls(receipt: Receipt) -> list[dict[str, str]]:
    calls = receipt.execution.get("requested_tool_calls")
    if calls is None:
        return []
    if (
        not isinstance(calls, list)
        or len(calls) > MAX_TOOL_CALLS
        or any(
            not isinstance(c, dict)
            or set(c) != {"id", "name", "input_hash"}
            or not all(isinstance(v, str) for v in c.values())
            or not _SHA_RE.fullmatch(c["input_hash"])
            for c in calls
        )
    ):
        raise TraceError("requested_tool_calls is malformed")
    return calls


def _label(receipt: Receipt) -> str:
    ex = receipt.execution
    kind = ex.get("receipt_type", "?")
    name = ex.get("tool_name") or ex.get("model") or ex.get("workflow_name") or ex.get(
        "destination_host") or ex.get("outcome_status") or ""
    seq = ex.get("chain_seq")
    return f"{kind}:{name}" + (f"#{seq}" if seq is not None else "")


def verify_trace(
    receipts: list[Receipt],
    *,
    required_scopes: dict[str, str | list[str]] | None = None,
) -> dict[str, Any]:
    """Verify context, causality and authorisation across receipts.

    required_scopes maps a tool_name to the scope (or list of scopes, all
    required) its receipts' context.authorization must carry.
    Never raises on bad input; read report["ok"], ["errors"], ["findings"].
    """
    report: dict[str, Any] = {
        "ok": False,
        "count": 0,
        "errors": [],
        "warnings": [],
        "nodes": [],
        "edges": [],
        "unresolved_causes": [],
        "tool_calls": [],
        "unexecuted_tool_calls": [],
        "unprompted_tool_receipts": [],
        "agents": {},
        "principals": {},
    }
    errors, warnings = report["errors"], report["warnings"]
    if not isinstance(receipts, list) or not receipts:
        errors.append("no receipts supplied")
        return report

    by_hash: dict[str, Receipt] = {}
    contexts: dict[str, dict[str, Any]] = {}
    calls_by_model: dict[str, list[dict[str, str]]] = {}
    for index, receipt in enumerate(receipts):
        label = f"receipt[{index}]"
        if not isinstance(receipt, Receipt):
            errors.append(f"{label}: not a Receipt")
            continue
        try:
            verify_receipt_signature(receipt, label)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        digest = receipt.receipt_hash
        if digest in by_hash:
            continue
        by_hash[digest] = receipt
        label = _label(receipt)
        ctx = receipt.execution.get("context")
        if ctx is not None:
            try:
                contexts[digest] = check_context(ctx)
            except TraceError as exc:
                errors.append(f"{label}: {exc}")
        if receipt.execution.get("receipt_type") == "model":
            try:
                calls_by_model[digest] = _requested_calls(receipt)
            except TraceError as exc:
                errors.append(f"{label}: {exc}")
    report["count"] = len(by_hash)

    executed: set[tuple[str, str]] = set()
    for digest, receipt in by_hash.items():
        ctx = contexts.get(digest, {})
        label = _label(receipt)
        agent = ctx.get("agent", {}).get("id")
        principal = ctx.get("principal", {}).get("ref")
        report["nodes"].append({
            "hash": digest,
            "label": label,
            "receipt_type": receipt.execution.get("receipt_type"),
            "agent": agent,
            "principal": principal,
            "session_id": ctx.get("session_id"),
            "trace_id": ctx.get("trace", {}).get("trace_id"),
        })
        if agent:
            report["agents"][agent] = report["agents"].get(agent, 0) + 1
        if principal:
            report["principals"][principal] = report["principals"].get(principal, 0) + 1

        causes = ctx.get("caused_by", [])
        for cause in causes:
            if cause in by_hash:
                report["edges"].append({"from": cause, "to": digest})
            else:
                report["unresolved_causes"].append({"receipt": digest, "cause": cause})

        # -- authorisation ------------------------------------------------
        auth = ctx.get("authorization")
        when = _when(receipt)
        if auth and "expires_at" in auth and when is not None and when > _time(auth["expires_at"]):
            errors.append(f"{label}: acted at {when:%Y-%m-%dT%H:%M:%SZ}, after its "
                          f"authorization expired at {auth['expires_at']}")
        tool_name = receipt.execution.get("tool_name")
        if required_scopes and receipt.execution.get("receipt_type") == "tool" and tool_name in required_scopes:
            needed = required_scopes[tool_name]
            needed = [needed] if isinstance(needed, str) else list(needed)
            held = set((auth or {}).get("scopes", []))
            missing = [s for s in needed if s not in held]
            if missing:
                errors.append(f"{label}: missing required scope(s) {missing}")

        # -- tool calls ---------------------------------------------------
        if receipt.execution.get("receipt_type") != "tool":
            continue
        model_causes = [c for c in causes if c in calls_by_model]
        call_id = ctx.get("tool_call_id")
        if not model_causes:
            if call_id is not None and not causes:
                warnings.append(f"{label}: tool_call_id without caused_by; cannot check it")
            if not any(c not in by_hash for c in causes):
                report["unprompted_tool_receipts"].append(digest)
            continue
        if call_id is None:
            warnings.append(f"{label}: caused by a model receipt but has no tool_call_id")
            continue
        for model_hash in model_causes:
            match = next((c for c in calls_by_model[model_hash] if c["id"] == call_id), None)
            entry = {"tool_receipt": digest, "model_receipt": model_hash, "tool_call_id": call_id}
            if match is None:
                entry["status"] = "not_requested"
                errors.append(f"{label}: tool_call_id {call_id!r} was not requested by the cited model response")
            else:
                executed.add((model_hash, call_id))
                if match["input_hash"] != receipt.execution.get("input_hash"):
                    entry["status"] = "arguments_differ"
                    warnings.append(f"{label}: ran with different arguments than the model requested")
                elif match["name"] != tool_name:
                    entry["status"] = "name_differs"
                    warnings.append(f"{label}: model asked for {match['name']!r}, receipt names {tool_name!r}")
                else:
                    entry["status"] = "matched"
            report["tool_calls"].append(entry)

    for model_hash, calls in calls_by_model.items():
        for call in calls:
            if (model_hash, call["id"]) not in executed:
                report["unexecuted_tool_calls"].append(
                    {"model_receipt": model_hash, "id": call["id"], "name": call["name"]}
                )

    report["ok"] = not errors
    return report


def find_receipts_for_principal(
    receipts: list[Receipt], kind: str, principal_id: str, pepper: bytes
) -> list[Receipt]:
    """Receipts whose context names this principal, either as the
    principal or as the grantor of the authorization (GDPR Art. 15 lookups)."""
    ref = principal_ref(kind, principal_id, pepper)
    out = []
    for receipt in receipts:
        ctx = receipt.execution.get("context")
        if not isinstance(ctx, dict):
            continue
        refs = {
            (ctx.get("principal") or {}).get("ref"),
            ((ctx.get("authorization") or {}).get("granted_by") or {}).get("ref"),
        }
        if ref in refs:
            out.append(receipt)
    return out


# ---------------------------------------------------------------------------
# CLI: traceseal-trace
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    from traceseal_observe.chain import load_receipt

    parser = argparse.ArgumentParser(prog="traceseal-trace",
                                     description="Verify agent context, causality and authorisation.")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify receipts")
    v.add_argument("receipts", nargs="+")
    v.add_argument("--require-scope", action="append", default=[],
                   metavar="TOOL=SCOPE", help="require SCOPE on every TOOL receipt")
    v.add_argument("--json", action="store_true")
    f = sub.add_parser("find-principal", help="list receipts about one principal")
    f.add_argument("receipts", nargs="+")
    f.add_argument("--kind", default="user", choices=sorted(PRINCIPAL_KINDS))
    f.add_argument("--id", required=True, dest="principal_id")
    f.add_argument("--pepper-file", required=True)
    args = parser.parse_args(argv)

    try:
        paths = list(args.receipts)
        receipts = [load_receipt(p) for p in paths]
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    if args.command == "find-principal":
        pepper = Path(args.pepper_file).read_bytes()
        matches = find_receipts_for_principal(receipts, args.kind, args.principal_id, pepper)
        hit = {r.receipt_hash for r in matches}
        for path, receipt in zip(paths, receipts):
            if receipt.receipt_hash in hit:
                print(path)
        return 0

    required: dict[str, list[str]] = {}
    for item in args.require_scope:
        tool, _, scope = item.partition("=")
        if not tool or not scope:
            print(f"[ERROR] --require-scope expects TOOL=SCOPE, got {item!r}", file=sys.stderr)
            return 2
        required.setdefault(tool, []).append(scope)
    report = verify_trace(receipts, required_scopes=required)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["ok"] else 1
    labels = {n["hash"]: n["label"] for n in report["nodes"]}
    print(f"[{'OK' if report['ok'] else 'FAIL'}] {report['count']} receipts, "
          f"{len(report['edges'])} causal links, agents: {report['agents'] or '-'}")
    for call in report["tool_calls"]:
        print(f"  {labels.get(call['model_receipt'])} -> {labels.get(call['tool_receipt'])}"
              f"  [{call['tool_call_id']}] {call['status']}")
    for call in report["unexecuted_tool_calls"]:
        print(f"  requested, not executed: {call['name']} [{call['id']}]"
              f" from {labels.get(call['model_receipt'])}")
    for digest in report["unprompted_tool_receipts"]:
        print(f"  unprompted (no model cause): {labels.get(digest)}")
    for error in report["errors"]:
        print(f"  ERROR: {error}")
    for warning in report["warnings"]:
        print(f"  warning: {warning}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
