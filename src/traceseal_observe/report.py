"""Evidence packs: verify receipts, map the findings to obligations, sign it.

    traceseal-report build receipts/ --checkpoint cp.txt --output pack/ \
        --require-approval issue_refund --operator-key ops.key \
        --operator-pubkey <hex of the operator key(s) the receipts must come from>

produces a directory an auditor can take away:

    pack/
      report.md        human-readable findings and control mapping
      report.json      the same, machine-readable, with every verifier report
                       and the analysis options the pack was built with
      receipts/        copies of every receipt examined
      checkpoints/     checkpoints and timestamp tokens supplied
      manifest.json    SHA-256 of every file above
      pack.receipt.json  operator-signed evidence_pack receipt over the manifest

and `traceseal-report verify-pack pack/ --operator-pubkey <hex>` checks,
offline, the manifest, the pack signature against a key you pinned, every
receipt signature, and re-runs the analysis over the pack's receipts and
checkpoints to confirm that report.json's findings follow from them.

The control mapping says what evidence exists for each obligation and
whether the verifiers found problems. It is not a conformity assessment,
not a certification and not legal advice: it shows where the evidence is,
and where it isn't. Each control says who the obligation applies to.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from traceseal_observe import Receipt, summarize_data_flows, verify_receipt_signature

PACK_VERSION = "1.1"
HIGH_RISK_DATES = ("Applies from 2 December 2027 (Annex III) and 2 August 2028 (Annex I), "
                   "as amended by Regulation (EU) 2026/1744.")
LEGAL_NOTICE = (
    "This pack maps cryptographically verified evidence to obligations. It is informational "
    "only: it is not legal advice, not a conformity assessment, not a certification, and not "
    "a finding that any obligation is met. 'evidence' means relevant records exist and passed "
    "verification; it does not mean the obligation is satisfied. Whether an obligation applies "
    "depends on your role, whether the system is high-risk, and national law. Laws and dates "
    "change: check the current texts and obtain advice from qualified counsel."
)
# Time fields inside the signed execution body. attestation.attested_at is
# outside the v1 signature (anyone holding a receipt can edit it), so it is
# never used for period or time calculations.
_TIME_KEYS = ("chained_at", "started_at", "observed_at", "decided_at", "aware_at",
              "recorded_at", "verified_at", "reobserved_at")
_UTC_FMT = "%Y-%m-%dT%H:%M:%SZ"
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_OPERATIONAL_TYPES = ("model", "tool", "data_flow", "orchestration", "outcome",
                      "oversight", "policy_decision", "erasure", "incident")
RETENTION_DAYS = 183


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        return None
    try:
        return datetime.strptime(value, _UTC_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _when(r: Receipt) -> str | None:
    """The receipt's signed time, or None when it has none (unknown)."""
    ex = r.execution if isinstance(r.execution, dict) else {}
    for key in _TIME_KEYS:
        value = ex.get(key)
        if _parse_utc(value) is not None:
            return value
    return None


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _days(a: str, b: str) -> float:
    start, end = _parse_utc(a), _parse_utc(b)
    if start is None or end is None:
        return 0.0
    return (end - start).total_seconds() / 86400


def _normalise_keys(keys: Any, label: str) -> list[str]:
    if isinstance(keys, str):
        keys = [keys]
    out = []
    for k in keys or ():
        if not isinstance(k, str) or not _HEX64.fullmatch(k.strip()):
            raise ValueError(f"{label}: {k!r} is not a 64-hex Ed25519 public key")
        out.append(k.strip().lower())
    return sorted(set(out))


def _check_receipt(r: Any, label: str) -> None:
    """Shape checks plus verify_receipt_signature; raises ValueError only."""
    if not isinstance(r, Receipt):
        raise ValueError(f"{label}: not a receipt")
    for field in ("execution", "provenance", "attestation"):
        if not isinstance(getattr(r, field), dict):
            raise ValueError(f"{label}: malformed receipt ({field} is not an object)")
    if not isinstance(r.receipt_version, str):
        raise ValueError(f"{label}: malformed receipt (receipt_version is not a string)")
    for field in ("operator_public_key", "signature", "operator_fingerprint"):
        if not isinstance(r.attestation.get(field, ""), str):
            raise ValueError(f"{label}: malformed receipt (attestation.{field} is not a string)")
    try:
        verify_receipt_signature(r, label)
    except ValueError:
        raise
    except Exception as exc:  # hostile content must not escape as anything else
        raise ValueError(f"{label}: signature check error: {type(exc).__name__}") from None
    ex = r.execution
    for field in ("receipt_type", "chain_id"):
        if field in ex and not isinstance(ex[field], str):
            raise ValueError(f"{label}: malformed receipt (execution.{field} is not a string)")


def _signer(r: Receipt) -> str:
    return r.attestation.get("operator_public_key", "").lower()


def _short(r: Receipt) -> str:
    try:
        return r.receipt_hash[:23]
    except Exception:
        return "?"


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def _robust(fn: Callable[[list[Receipt]], Any], items: list[Receipt], what: str,
            failures: list[str]) -> Any:
    """Run a verifier; if hostile input makes it raise, isolate and skip the
    receipts that make it raise on their own, and report them as failures."""
    try:
        return fn(items)
    except Exception:
        pass
    kept = []
    for r in items:
        try:
            fn([r])
            kept.append(r)
        except Exception as exc:
            failures.append(f"{what}: receipt {_short(r)} could not be analysed "
                            f"({type(exc).__name__}: {exc})")
    try:
        return fn(kept)
    except Exception as exc:
        failures.append(f"{what} could not run ({type(exc).__name__}: {exc})")
        return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyse(
    receipts: list[Receipt],
    *,
    checkpoints: list[str] = (),
    checkpoint_timestamps: dict[str, list[bytes]] | None = None,
    tsa_trust_anchors: list[Any] = (),
    witness_vkeys: list[str] = (),
    required_scopes: dict[str, Any] | None = None,
    require_approval: Any = (),
    require_policy: dict[str, str] | None = None,
    min_review_seconds: int | None = None,
    now: str | None = None,
    operator_keys: Iterable[str] | None = None,
    reviewer_keys: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run every verifier and build the evidence summary and control map.

    operator_keys pins the Ed25519 public keys (hex) the receipts must be
    signed by. Receipts signed by any other key are listed in
    `foreign_key_receipts`, excluded from the analysis, and make `ok` false.
    Never raises on hostile receipt content: it is reported instead.
    """
    from traceseal_observe.chain import ChainError, _resolve_checkpoint, verify_chain
    from traceseal_observe.incident import incident_status
    from traceseal_observe.trace import verify_trace

    pin = _normalise_keys(operator_keys, "operator_keys") if operator_keys is not None else None
    signature_failures: list[str] = []
    analysis_failures: list[str] = []
    warnings: list[str] = []
    valid: list[Receipt] = []
    for i, r in enumerate(receipts):
        try:
            _check_receipt(r, f"receipt[{i}]")
            valid.append(r)
        except ValueError as exc:
            signature_failures.append(str(exc))

    foreign = []
    if pin is not None:
        foreign = [{"receipt": r.receipt_hash, "public_key": _signer(r)}
                   for r in valid if _signer(r) not in pin]
        valid = [r for r in valid if _signer(r) in pin]

    by_type: dict[str, int] = {}
    for r in valid:
        t = r.execution.get("receipt_type", "skill")
        by_type[t] = by_type.get(t, 0) + 1
    times = sorted(t for t in (_when(r) for r in valid) if t)
    untimed = sum(1 for r in valid if _when(r) is None)

    # -- chains --------------------------------------------------------------
    chains: dict[str, list[Receipt]] = {}
    unchained_ops = 0
    for r in valid:
        cid = r.execution.get("chain_id")
        if cid is not None and "chain_seq" in r.execution:
            chains.setdefault(cid, []).append(r)
        elif r.execution.get("receipt_type") in _OPERATIONAL_TYPES:
            unchained_ops += 1
    chain_reports = {}
    chain_extra = {}
    stamps = checkpoint_timestamps or {}
    for cid, members in chains.items():
        keys = sorted({_signer(m) for m in members}
                      | {m.execution["next_public_key"] for m in members
                         if m.execution.get("receipt_type") == "chain_key_rotation"
                         and isinstance(m.execution.get("next_public_key"), str)})
        chosen = None
        for note in checkpoints:
            try:
                _resolve_checkpoint(note, keys, cid, witness_vkeys)
            except (ChainError, ValueError):
                continue
            except Exception:  # hostile checkpoint text
                continue
            chosen = note
        try:
            chain_reports[cid] = verify_chain(
                members, checkpoint=chosen,
                checkpoint_timestamps=stamps.get(chosen, []) if chosen else (),
                tsa_trust_anchors=tsa_trust_anchors, witness_vkeys=witness_vkeys,
            )
        except Exception as exc:
            chain_reports[cid] = {"ok": False, "count": len(members), "first_seq": None,
                                  "last_seq": None, "gaps": [], "forks": [],
                                  "errors": [f"chain could not be verified ({type(exc).__name__})"],
                                  "warnings": [], "rotations": [], "compromised_seqs": [],
                                  "checkpoint": None}
        rep = chain_reports[cid]
        cp = rep.get("checkpoint") or {}
        chain_times = sorted(t for t in (_parse_utc(m.execution.get("chained_at")) for m in members) if t)
        span = (chain_times[-1] - chain_times[0]).total_seconds() / 86400 if len(chain_times) > 1 else 0
        chain_extra[cid] = {
            "span_days": round(span, 1),
            # Trusted time: a verified checkpoint that anchors these receipts and
            # carries a verified TSA token or witness cosignature.
            "trusted_time": bool(rep["ok"] and cp.get("anchored")
                                 and (cp.get("timestamps") or cp.get("witnesses"))),
        }

    # -- signer keys: are they one operator? -------------------------------------
    signer_keys = sorted({_signer(r) for r in valid})
    parent = {k: k for k in signer_keys}

    def find(k: str) -> str:
        while parent.setdefault(k, k) != k:
            k = parent[k]
        return k

    for rep in chain_reports.values():
        for rot in rep.get("rotations") or ():
            a, b = rot.get("previous_public_key"), rot.get("next_public_key")
            if isinstance(a, str) and isinstance(b, str):
                parent[find(a.lower())] = find(b.lower())
    groups = {find(k) for k in signer_keys}
    if pin is None and len(groups) > 1:
        warnings.append(
            f"receipts are signed by {len(signer_keys)} keys not all linked by a verified chain "
            "rotation, and no operator key was pinned: anyone can add receipts signed by their "
            "own key. Pin the operator key(s) with operator_keys / --operator-pubkey.")
    if untimed:
        warnings.append(f"{untimed} receipt(s) carry no signed time; they are not counted in the period.")

    trace = _robust(lambda rs: verify_trace(rs, required_scopes=required_scopes,
                                            require_approval=require_approval,
                                            require_policy=require_policy,
                                            min_review_seconds=min_review_seconds,
                                            reviewer_keys=reviewer_keys),
                    valid, "trace", analysis_failures)
    if trace is None:
        trace = {"ok": False, "errors": ["trace verification could not run"], "warnings": [],
                 "tool_calls": [], "unexecuted_tool_calls": [], "unprompted_tool_receipts": [],
                 "unresolved_causes": [], "agents": {}, "oversight": [], "policy_decisions": []}
    incident_receipts = [r for r in valid if r.execution.get("receipt_type") == "incident"]
    incidents = _robust(lambda rs: incident_status(rs, now=now), incident_receipts,
                        "incidents", analysis_failures) or []
    flows = _robust(summarize_data_flows, valid, "data flows", analysis_failures)
    if flows is None:
        flows = {"total_calls": 0, "destinations": {}, "undeclared_calls": 0, "pii_summary": {},
                 "total_payload_bytes": 0, "failed_calls": 0}
    models: dict[str, int] = {}
    served: dict[str, int] = {}
    tools: dict[str, int] = {}
    for r in valid:
        ex = r.execution
        if ex.get("receipt_type") == "model":
            name = f"{_text(ex.get('provider'))}/{_text(ex.get('model'))}"
            models[name] = models.get(name, 0) + 1
            if ex.get("served_model"):
                sm = _text(ex["served_model"])
                served[sm] = served.get(sm, 0) + 1
        if ex.get("receipt_type") == "tool":
            tn = _text(ex.get("tool_name", "?"))
            tools[tn] = tools.get(tn, 0) + 1
    erasures = [r for r in valid if r.execution.get("receipt_type") == "erasure"]
    with_context = sum(1 for r in valid if isinstance(r.execution.get("context"), dict))

    summary = {
        "receipts": len(receipts),
        "valid_signatures": len(valid) + len(foreign),
        "signature_failures": signature_failures,
        "analysis_failures": analysis_failures,
        "operator_keys": pin,
        "foreign_key_receipts": foreign,
        "signer_keys": signer_keys,
        "warnings": warnings,
        "by_type": dict(sorted(by_type.items())),
        "period": {"first": times[0] if times else None, "last": times[-1] if times else None,
                   "days": round(_days(times[0], times[-1]), 1) if len(times) > 1 else 0,
                   "basis": "signed receipt times (attested_at is never used)"},
        "chains": {cid: {**{k: rep.get(k) for k in ("ok", "count", "first_seq", "last_seq", "gaps",
                                                    "forks", "errors", "warnings", "rotations",
                                                    "compromised_seqs", "checkpoint")},
                         **chain_extra[cid]}
                   for cid, rep in chain_reports.items()},
        "unchained_operational_receipts": unchained_ops,
        "with_context": with_context,
        "models_requested": dict(sorted(models.items())),
        "models_served": dict(sorted(served.items())),
        "tools": dict(sorted(tools.items())),
        "data_flows": flows,
        "trace": {k: trace.get(k, [] if k != "ok" else False)
                  for k in ("ok", "errors", "warnings", "tool_calls",
                            "unexecuted_tool_calls", "unprompted_tool_receipts",
                            "unresolved_causes", "agents", "oversight",
                            "policy_decisions")},
        "incidents": incidents,
        "erasures": [{"hash": r.receipt_hash, "reason": r.execution.get("reason"),
                      "objects": r.execution.get("object_count"),
                      "retention_overridden": r.execution.get("retention_overridden")}
                     for r in erasures],
    }
    summary["controls"] = map_controls(summary)
    summary["legal_notice"] = LEGAL_NOTICE
    summary["ok"] = bool(
        not signature_failures
        and not analysis_failures
        and not foreign
        and all(rep["ok"] for rep in chain_reports.values())
        and trace["ok"]
        and not any(i.get("missed_deadlines") or i.get("problems") for i in incidents)
    )
    return summary


def _status(evidence: bool, issues: list[str], *, partial: bool = False) -> tuple[str, list[str]]:
    if issues:
        return "issues", list(issues)
    if evidence and partial:
        return "partial", []
    return ("evidence" if evidence else "no evidence"), []


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def map_controls(s: dict[str, Any]) -> list[dict[str, Any]]:
    """Map the verified evidence to obligations. Informational only.

    A trace error is never dropped: errors a specific row claims (oversight,
    authorisation, policy) appear there, and *every* trace error appears on
    Art. 26(5) and NIST AI RMF; errors no specific row claims also appear on
    Art. 12 and ISO/IEC 42001.
    """
    chains = s["chains"]
    chain_issues = [
        f"chain {cid}: " + "; ".join(
            ([f"missing seq {lo}..{hi}" for lo, hi in rep["gaps"]] + rep["errors"])[:3])
        for cid, rep in chains.items() if not rep["ok"]
    ]
    anchored = [cid for cid, rep in chains.items()
                if rep.get("checkpoint") and rep["checkpoint"].get("anchored")]
    trusted = [cid for cid, rep in chains.items()
               if rep.get("checkpoint") and (rep["checkpoint"].get("timestamps")
                                             or rep["checkpoint"].get("witnesses"))]
    trace = s["trace"]
    trace_errors = [str(e) for e in trace["errors"]]
    if not trace["ok"] and not trace_errors:
        trace_errors = ["trace verification failed"]
    # Routing to the specific rows below is a convenience; it is not what keeps
    # an error visible (see the docstring).
    oversight_errors = [e for e in trace_errors if any(w in e for w in (
        "approval", "human", "reviewer", "stopped", "rejected", "countersignature"))]
    authz_errors = [e for e in trace_errors if "scope" in e or "expired" in e]
    policy_errors = [e for e in trace_errors if "policy" in e]
    claimed = set(oversight_errors) | set(authz_errors) | set(policy_errors)
    unclaimed = [e for e in trace_errors if e not in claimed]
    foreign = s.get("foreign_key_receipts") or []
    integrity = (list(s["signature_failures"]) + list(s.get("analysis_failures") or [])
                 + ([f"{len(foreign)} receipt(s) signed by a key outside the pinned operator keys"]
                    if foreign else []))
    missed = [f"{i.get('category')} {str(i.get('head', ''))[:15]}: {d.get('basis')} due {d.get('due')}"
              for i in s["incidents"] for d in i.get("missed_deadlines", [])] + [
        f"{i.get('category')} {str(i.get('head', ''))[:15]}: {p}"
        for i in s["incidents"] for p in i.get("problems", [])]
    # An incident receipt that could not be analysed may belong to any regime.
    incident_failures = [f for f in s.get("analysis_failures") or [] if f.startswith("incidents")]
    ops = sum(n for t, n in s["by_type"].items() if t not in ("skill",))
    period_days = s["period"]["days"]
    flows = s["data_flows"]
    unchained = s["unchained_operational_receipts"]
    retention_chains = [cid for cid, rep in chains.items()
                        if rep.get("trusted_time") and (rep.get("span_days") or 0) >= RETENTION_DAYS]
    if period_days >= RETENTION_DAYS and retention_chains:
        retention_status = "evidence"
    elif ops == 0:
        retention_status = "no evidence"
    else:
        retention_status = "partial"

    def control(framework, ref, title, status, evidence, notes="", applies_to=""):
        problems: list[str] = []
        if isinstance(status, tuple):
            status, problems = status
            problems = _dedupe(problems)
        return {"framework": framework, "ref": ref, "title": title, "status": status,
                "evidence": evidence, "notes": notes, "problems": problems,
                "applies_to": applies_to}

    high_risk = "Providers of high-risk AI systems. " + HIGH_RISK_DATES
    deployer = "Deployers of high-risk AI systems. " + HIGH_RISK_DATES
    out = [
        control("EU AI Act", "Art. 12", "Record-keeping: automatic logging of events",
                _status(ops > 0, _dedupe(chain_issues + integrity + unclaimed), partial=unchained > 0),
                f"{ops} signed operational receipts; {len(chains)} chain(s); "
                f"{len(anchored)} anchored to a checkpoint; {len(trusted)} with trusted time "
                f"(TSA/witness); {s['unchained_operational_receipts']} receipts outside any chain.",
                ("Unchained receipts cannot show completeness. " if unchained else "")
                + "".join(w + " " for w in s.get("warnings") or [])
                + "Art. 12 is a design duty on the system; these receipts are evidence that "
                  "logging operated, not a finding that the logging design is sufficient.",
                high_risk),
        control("EU AI Act", "Art. 12(2)", "Logs enable risk identification, post-market and "
                "deployer monitoring",
                _status(s["with_context"] > 0,
                        integrity + [e for e in trace_errors if "context" in e] + unclaimed),
                f"{s['with_context']} receipts carry signed agent/principal/trace context; "
                f"inputs and outputs committed by hash.",
                "The extra logging content of Art. 12(3) applies only to remote biometric "
                "identification systems and is not assessed here.",
                high_risk),
        control("EU AI Act", "Art. 14 / 26(2)", "Human oversight",
                _status(bool(trace["oversight"]), oversight_errors),
                f"{len(trace['oversight'])} human decisions "
                f"({sum(1 for o in trace['oversight'] if o['reviewer_signed'] is True)} reviewer-signed).",
                "Records that oversight took place; whether the oversight measures and the "
                "reviewers' competence meet Art. 14 and 26(2) is not assessed.",
                "Art. 14: providers (design). Art. 26(2): deployers (assigning competent people). "
                + HIGH_RISK_DATES),
        control("EU AI Act", "Art. 19 / 26(6)", "Logs kept for at least six months",
                retention_status,
                f"This pack covers {period_days} days ({s['period']['first']} .. {s['period']['last']}) "
                f"by signed receipt times; {len(retention_chains)} chain(s) span six months under "
                "trusted time (anchored checkpoint with a verified TSA token or witness cosignature).",
                "'evidence' needs at least 183 days resting on trusted time; otherwise 'partial'. "
                "A checkpoint's trusted time proves the receipts existed by then, not when each was "
                "made. Retention is shown by the operator's archive and vault policy; a pack shows the "
                "period it covers. Art. 26(6) is subject to Union and national data-protection law, "
                "and logs must be kept under the deployer's control.",
                "Art. 19: providers. Art. 26(6): deployers. " + HIGH_RISK_DATES),
        control("EU AI Act", "Art. 26(5)", "Deployer monitoring of operation",
                _status(ops > 0, _dedupe(trace_errors + integrity)),
                f"{len(trace['unprompted_tool_receipts'])} tool actions without a model cause; "
                f"{sum(1 for c in trace['tool_calls'] if c['status'] == 'arguments_differ')} with changed arguments; "
                f"{len(trace['unexecuted_tool_calls'])} requested calls not executed; "
                f"{len(trace['policy_decisions'])} automated policy decisions.",
                "Monitoring must follow the provider's instructions for use; this is supporting "
                "evidence only.",
                deployer),
        control("EU AI Act", "Art. 72", "Post-market monitoring",
                _status(s["by_type"].get("outcome", 0) + len(s["incidents"]) > 0, []),
                f"{s['by_type'].get('outcome', 0)} outcome receipts; {len(s['incidents'])} incident(s).",
                "Input to a post-market monitoring plan; not the plan itself.",
                high_risk),
        control("EU AI Act", "Art. 73", "Serious incident reporting",
                _status(any(i["category"] == "serious_incident" for i in s["incidents"]),
                        [m for m in missed if m.startswith("serious_incident")] + incident_failures),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'serious_incident')} serious incident(s) recorded.",
                "No incidents recorded is not evidence that none occurred.",
                high_risk + " Deployers inform the provider immediately (Art. 26(5))."),
        control("GDPR", "Art. 5(1)(c), 25", "Supports data minimisation / data protection by design",
                "evidence" if ops else "no evidence",
                "Receipts hold hashes, not values; principals are keyed (pseudonymised) commitments. "
                f"PII patterns seen in outbound payloads: {flows['pii_summary'] or 'none detected'}.",
                "Pseudonymised data is still personal data (Art. 4(5), Recital 26). Hashes of short "
                "or guessable values can be reversed by guessing.",
                "Controllers processing personal data."),
        control("GDPR", "Art. 17", "Supports the right to erasure",
                _status(bool(s["erasures"]), []),
                f"{len(s['erasures'])} signed erasure receipt(s) "
                f"({sum(1 for e in s['erasures'] if e['retention_overridden'] == 'true')} overriding retention).",
                "Crypto-shredding is a technical erasure measure; it does not reach backups or copies "
                "held by others. Refusing or delaying erasure must rest on an Art. 17(3) exception.",
                "Controllers processing personal data."),
        control("GDPR", "Art. 30, 44", "Input to records of processing / transfer assessment",
                _status(flows["total_calls"] > 0, []),
                f"{flows['total_calls']} outbound data flows to {len(flows['destinations'])} host(s); "
                f"{flows['undeclared_calls']} to undeclared destinations.",
                "Supporting input only: a record of processing needs purposes, categories and "
                "recipients, and a host name does not establish where data is processed.",
                "Controllers and processors."),
        control("GDPR", "Art. 33 / 34", "Personal data breach notification",
                _status(any(i["category"] == "personal_data_breach" for i in s["incidents"]),
                        [m for m in missed if m.startswith("personal_data_breach")] + incident_failures),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'personal_data_breach')} breach record(s).",
                "Only the Art. 33 notification is checked against its deadline; Art. 34 "
                "communication to data subjects is listed, not tracked.",
                "Controllers; processors notify the controller (Art. 33(2))."),
        control("NIS2", "Art. 23", "Significant incident reporting",
                _status(any(i["category"] == "significant_incident" for i in s["incidents"]),
                        [m for m in missed if m.startswith("significant_incident")] + incident_failures),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'significant_incident')} significant incident(s).",
                "Checked against the 24h/72h limits only; national transposition may differ.",
                "Essential and important entities under national NIS2 law."),
        control("DORA", "Art. 19", "Major ICT-related incident reporting",
                _status(any(i["category"] == "major_ict_incident" for i in s["incidents"]),
                        [m for m in missed if m.startswith("major_ict_incident")] + incident_failures),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'major_ict_incident')} major ICT incident(s).",
                "Checked against the 4-hour-from-classification rule where classified_at is "
                "recorded; otherwise the 24-hour limit is shown as unconfirmed, not missed. "
                + (f"{sum(len(i.get('unconfirmed_deadlines', [])) for i in s['incidents'])} "
                   "unconfirmed deadline(s)." if any(i.get('unconfirmed_deadlines') for i in s['incidents']) else ""),
                "EU financial entities within DORA's scope."),
        control("ISO/IEC 42001", "Annex A", "AI system event logging and monitoring",
                _status(ops > 0, _dedupe(chain_issues + integrity + unclaimed), partial=unchained > 0),
                "Same evidence as EU AI Act Art. 12 and 26(5).",
                "Voluntary standard; certification is a matter for an accredited body.",
                "Organisations adopting the standard."),
        control("NIST AI RMF", "MEASURE / MANAGE", "Tracking, monitoring and incident response",
                _status(ops > 0, _dedupe(chain_issues + integrity + trace_errors + missed)),
                "Same evidence as EU AI Act Art. 12, 72 and 73.",
                "Voluntary framework.",
                "Organisations adopting the framework."),
    ]
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(s: dict[str, Any]) -> str:
    lines = ["# TraceSeal evidence pack", ""]
    lines.append(f"**Overall:** {'all checks passed' if s['ok'] else 'ISSUES FOUND'}  ")
    p = s["period"]
    lines.append(f"**Period:** {p['first']} .. {p['last']} ({p['days']} days)  ")
    lines.append(f"**Receipts:** {s['receipts']} ({s['valid_signatures']} with valid signatures)  ")
    pin = s.get("operator_keys")
    lines.append("**Operator keys:** " + (", ".join(k[:16] + "…" for k in pin) if pin else
                                         "not pinned (any signer accepted)"))
    lines += ["", "> **Legal notice.** " + LEGAL_NOTICE, "", "## Controls", "",
              "| Framework | Ref | Obligation | Applies to | Status | Evidence |",
              "|---|---|---|---|---|---|"]
    for c in s["controls"]:
        note = f" _{c['notes']}_" if c["notes"] else ""
        problems = (" **Problems:** " + "; ".join(c["problems"][:3])) if c["problems"] else ""
        cell = f"{c['evidence']}{note}{problems}".replace("|", "\\|")
        who = c.get("applies_to", "").replace("|", "\\|")
        lines.append(f"| {c['framework']} | {c['ref']} | {c['title']} | {who} | **{c['status']}** | {cell} |")
    lines += ["", "## Receipts by type", ""]
    lines += [f"- {t}: {n}" for t, n in s["by_type"].items()]
    lines += ["", "## Chains", ""]
    if not s["chains"]:
        lines.append("- none (receipts were not chained: completeness cannot be shown)")
    for cid, rep in s["chains"].items():
        cp = rep.get("checkpoint") or {}
        lines.append(f"- `{cid}`: {'complete' if rep['ok'] else 'NOT complete'}, seq "
                     f"{rep['first_seq']}..{rep['last_seq']}, gaps {rep['gaps'] or 'none'}, "
                     "checkpoint " + ("anchored" if cp.get("anchored") else
                                      "verified, not anchored" if cp.get("verified") else "none")
                     + (f", {len(cp.get('timestamps', []))} TSA token(s)" if cp.get("timestamps") else "")
                     + (f", key rotations {len(rep['rotations'])}" if rep["rotations"] else ""))
        for e in rep["errors"][:10]:
            lines.append(f"  - ERROR: {e}")
    t = s["trace"]
    lines += ["", "## Agent actions", ""]
    lines.append(f"- Agents: {t['agents'] or 'not recorded'}")
    lines.append(f"- Models requested: {s['models_requested'] or 'none'}; served: {s['models_served'] or 'not recorded'}")
    lines.append(f"- Tools: {s['tools'] or 'none'}")
    statuses: dict[str, int] = {}
    for c in t["tool_calls"]:
        statuses[c["status"]] = statuses.get(c["status"], 0) + 1
    lines.append(f"- Tool calls linked to model requests: {statuses or 'none'}")
    lines.append(f"- Requested but not executed: {len(t['unexecuted_tool_calls'])}; "
                 f"tool actions without a model cause: {len(t['unprompted_tool_receipts'])}")
    lines.append(f"- Human decisions: {len(t['oversight'])}; policy decisions: {len(t['policy_decisions'])}")
    for e in t["errors"][:20]:
        lines.append(f"  - ERROR: {e}")
    for w in t["warnings"][:20]:
        lines.append(f"  - warning: {w}")
    f = s["data_flows"]
    lines += ["", "## Data flows", "", f"- {f['total_calls']} outbound calls; destinations: {f['destinations'] or 'none'}",
              f"- undeclared destinations: {f['undeclared_calls']}; PII patterns: {f['pii_summary'] or 'none detected'}"]
    lines += ["", "## Incidents", ""]
    if not s["incidents"]:
        lines.append("- none recorded")
    for i in s["incidents"]:
        lines.append(f"- {i['category']} ({i['severity']}, {i['status']}): {i['title'] or i['head'][:23]}; "
                     f"aware {i['aware_at']}, first reported {i['first_reported_at'] or 'not yet'}")
        for d in i["missed_deadlines"]:
            lines.append(f"  - MISSED: {d['basis']} due {d['due']}")
        for d in i.get("unconfirmed_deadlines", []):
            lines.append(f"  - UNCONFIRMED: {d['basis']} 24-hour limit {d['due']} passed before the "
                         f"first report; record classified_at to check the actual deadline")
        for o in i.get("related_obligations", []):
            lines.append(f"  - Follow-up (not tracked): {o['basis']}: {o['step']} ({o['timing']})")
    if s["signature_failures"]:
        lines += ["", "## Signature failures", ""] + [f"- {e}" for e in s["signature_failures"]]
    if s.get("analysis_failures"):
        lines += ["", "## Analysis failures", ""] + [f"- {e}" for e in s["analysis_failures"]]
    if s.get("foreign_key_receipts"):
        lines += ["", "## Receipts signed by keys outside the pinned operator keys", ""]
        lines += [f"- {f['receipt'][:23]} signed by {f['public_key'][:16]}…"
                  for f in s["foreign_key_receipts"]]
    if s.get("warnings"):
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in s["warnings"]]
    lines += ["", "## Legal notice", "", LEGAL_NOTICE]
    signer = s.get("pack_signer") or "<operator public key hex, obtained out of band>"
    lines += ["", "## Verify this pack", "",
              "Obtain the operator's public key from a source you trust (not from this pack), then:",
              "", "```bash", f"traceseal-report verify-pack <this directory> --operator-pubkey {signer}",
              "```", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Building and verifying packs
# ---------------------------------------------------------------------------

_UNREADABLE = None  # placeholder fields for a receipt file that could not be parsed


def _load_receipt_lenient(path: Path) -> Receipt:
    """Load a receipt file; a file that is not a receipt becomes a placeholder
    that fails the signature check, so it is reported rather than raised."""
    from traceseal_observe.chain import load_receipt

    try:
        return load_receipt(path)
    except Exception:
        return Receipt(_UNREADABLE, _UNREADABLE, _UNREADABLE, _UNREADABLE)


def _pem(cert: Any) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.PEM).decode("ascii")


def _registry_json(registry: Any) -> Any:
    """A reviewer key registry as plain JSON (sets and frozensets become
    sorted lists), so it round-trips through report.json for verify-pack."""
    if not isinstance(registry, dict):
        return registry
    return {ref: (sorted(v) if isinstance(v, (set, frozenset, list, tuple)) else v)
            for ref, v in registry.items()}


def _read_reviewer_keys(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    from traceseal_observe.oversight import normalize_reviewer_keys
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"--reviewer-keys: {exc}") from exc
    normalize_reviewer_keys(data)  # validate early
    return data


def build_pack(
    output: Path | str,
    receipt_paths: list[Path],
    *,
    operator_key: Any = None,
    checkpoint_paths: list[Path] = (),
    timestamp_paths: dict[Path, list[Path]] | None = None,
    **analysis_kwargs: Any,
) -> dict[str, Any]:
    """Copy receipts and checkpoints into `output`, analyse them, and sign the
    manifest with `operator_key` (unsigned packs fail verify-pack).

    The analysis options are recorded in report.json["analysis_options"] so
    verify-pack can re-derive the findings.
    """
    from traceseal_observe import sign_execution_receipt

    unknown = set(analysis_kwargs) - {"tsa_trust_anchors", "witness_vkeys", "required_scopes",
                                      "require_approval", "require_policy", "min_review_seconds",
                                      "now", "operator_keys", "reviewer_keys"}
    if unknown:
        raise TypeError(f"unknown analysis options {sorted(unknown)}")
    out = Path(output)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} is not empty")
    (out / "receipts").mkdir(parents=True, exist_ok=True)
    (out / "checkpoints").mkdir(exist_ok=True)
    receipts = []
    for i, path in enumerate(receipt_paths):
        receipts.append(_load_receipt_lenient(Path(path)))
        shutil.copyfile(path, out / "receipts" / f"{i:06d}-{Path(path).name}")
    notes, stamps, cp_records = [], {}, []
    for i, path in enumerate(checkpoint_paths):
        note = Path(path).read_text("utf-8")
        notes.append(note)
        rel = f"checkpoints/{i:03d}-{Path(path).name}"
        shutil.copyfile(path, out / rel)
        tokens, token_rels = [], []
        for j, tpath in enumerate((timestamp_paths or {}).get(Path(path), [])):
            tokens.append(Path(tpath).read_bytes())
            trel = f"checkpoints/{i:03d}-{j:03d}-{Path(tpath).name}"
            shutil.copyfile(tpath, out / trel)
            token_rels.append(trel)
        stamps.setdefault(note, []).extend(tokens)
        cp_records.append({"file": rel, "timestamps": token_rels})
    generated_at = datetime.now(timezone.utc).strftime(_UTC_FMT)
    kwargs = dict(analysis_kwargs)
    kwargs.setdefault("now", generated_at)
    if kwargs.get("operator_keys") is not None:
        kwargs["operator_keys"] = _normalise_keys(kwargs["operator_keys"], "operator_keys")
    approval = kwargs.get("require_approval") or ()
    options = {
        "checkpoints": cp_records,
        "tsa_trust_anchors_pem": [_pem(c) for c in kwargs.get("tsa_trust_anchors") or ()],
        "witness_vkeys": list(kwargs.get("witness_vkeys") or ()),
        "required_scopes": kwargs.get("required_scopes"),
        "require_approval": [approval] if isinstance(approval, str) else sorted(approval),
        "require_policy": kwargs.get("require_policy"),
        "min_review_seconds": kwargs.get("min_review_seconds"),
        "now": kwargs["now"],
        "operator_keys": kwargs.get("operator_keys"),
        "reviewer_keys": _registry_json(kwargs.get("reviewer_keys")),
    }
    summary = analyse(receipts, checkpoints=notes, checkpoint_timestamps=stamps, **kwargs)
    summary["pack_version"] = PACK_VERSION
    summary["generated_at"] = generated_at
    summary["analysis_options"] = options
    summary["pack_signer"] = operator_key.public_key_hex if operator_key is not None else None
    (out / "report.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str))
    (out / "report.md").write_text(render_markdown(summary))
    files = sorted(p for p in out.rglob("*") if p.is_file())
    manifest = {
        "pack_version": PACK_VERSION,
        "files": {p.relative_to(out).as_posix(): _sha256_file(p) for p in files},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    if operator_key is not None:
        receipt = sign_execution_receipt(
            {
                "receipt_type": "evidence_pack",
                "pack_version": PACK_VERSION,
                "manifest_hash": _sha256_file(out / "manifest.json"),
                "file_count": len(manifest["files"]),
                "receipt_count": len(receipts),
                "period_start": summary["period"]["first"] or "",
                "period_end": summary["period"]["last"] or "",
                "verification_ok": "true" if summary["ok"] else "false",
            },
            {"provenance_version": "1.0", "provider_attestation": "none"},
            operator_key,
        )
        (out / "pack.receipt.json").write_text(receipt.to_json())
    return summary


class _PathError(ValueError):
    pass


def _safe_rel(rel: Any) -> PurePosixPath:
    """A manifest path: relative, POSIX, normalised, no '..'."""
    if not isinstance(rel, str) or not rel or "\x00" in rel or "\\" in rel:
        raise _PathError(f"unsafe path {rel!r}")
    p = PurePosixPath(rel)
    if p.is_absolute() or PureWindowsPath(rel).is_absolute() or PureWindowsPath(rel).drive:
        raise _PathError(f"absolute path refused: {rel!r}")
    if any(part in ("..", ".", "") for part in rel.split("/")) or str(p) != rel:
        raise _PathError(f"path with '..' or non-normal components refused: {rel!r}")
    return p


def _safe_read(root: Path, rel: str, *, limit: int = 64 << 20) -> bytes:
    """Read root/rel without following symlinks and without leaving root."""
    p = _safe_rel(rel)
    cur = root
    for part in p.parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            raise _PathError(f"missing file {rel}") from None
        except OSError as exc:
            raise _PathError(f"cannot read {rel}: {type(exc).__name__}") from None
        if stat.S_ISLNK(st.st_mode):
            raise _PathError(f"symlink refused: {rel}")
    if not stat.S_ISREG(st.st_mode):
        raise _PathError(f"not a regular file: {rel}")
    real = os.path.realpath(cur)
    if os.path.commonpath([real, str(root)]) != str(root):
        raise _PathError(f"path resolves outside the pack: {rel}")
    if st.st_size > limit:
        raise _PathError(f"file too large: {rel}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(cur, flags)
    except OSError as exc:
        raise _PathError(f"cannot read {rel}: {type(exc).__name__}") from None
    with os.fdopen(fd, "rb") as fh:
        return fh.read(limit + 1)


def _walk(root: Path, problems: list[str]) -> set[str]:
    """Regular files under root; symlinks and special files are refused, never followed."""
    found: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + filenames:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                problems.append(f"symlink refused: {rel}")
                if name in dirnames:
                    dirnames.remove(name)
            elif stat.S_ISREG(st.st_mode):
                found.add(rel)
            elif not stat.S_ISDIR(st.st_mode):
                problems.append(f"not a regular file: {rel}")
    return found


def _receipt_from_bytes(data: bytes, label: str) -> Receipt:
    """Parse a receipt; raises ValueError (never anything else) if it is not one."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError(f"{label}: not valid JSON") from None
    if not isinstance(obj, dict):
        raise ValueError(f"{label}: not a JSON object")
    try:
        return Receipt(obj["receipt_version"], obj["execution"], obj["provenance"], obj["attestation"])
    except KeyError as exc:
        raise ValueError(f"{label}: missing {exc}") from None


def _fp(public_key: str) -> str:
    return public_key[:16] + "…"


def verify_pack(
    directory: Path | str,
    expected_keys: Iterable[str] | str | None,
    *,
    trust_signer_in_pack: bool = False,
    now: str | None = None,
    require_approval: Any = (),
    require_policy: dict[str, str] | None = None,
    required_scopes: dict[str, Any] | None = None,
    reviewer_keys: dict[str, Any] | None = None,
    min_review_seconds: int | None = None,
) -> dict[str, Any]:
    """Offline check of a pack. Never raises on hostile pack content.

    Two analyses run. The first re-derives the pack's own findings with the
    options recorded at build time; report.json and report.md must match
    it byte for byte, so nothing in them can be edited. The second is the
    AUDITOR's: it runs on the pack's receipts with the auditor's clock
    (`now`, default: the current time), the pinned operator keys, the
    auditor's reviewer key registry if given, and the auditor's
    requirements added to the recorded ones. Its verdict is
    `auditor_result`, and the CLI's exit code follows it, so an operator
    cannot pick a convenient date or drop a requirement to make a pack pass.

    expected_keys: the operator Ed25519 public key(s) (hex) the pack must be
    signed by, obtained out of band. Required: pass None only together with
    trust_signer_in_pack=True, in which case any valid signer is accepted
    and the result says `pinned: False`.

    Checks: every manifest path is relative, inside the pack and not a
    symlink; every file matches the manifest and no unlisted file exists;
    pack.receipt.json exists, is validly signed by a pinned key and covers
    this manifest, file count and receipt count; every receipt signature;
    and the findings in report.json (overall ok, every control status,
    receipt counts, period) are re-derived by re-running analyse() over
    receipts/ and checkpoints/ with the options recorded at build time.

    Returns ok (the pack is intact and its report follows from its
    contents), pack_result ("passed" / "ISSUES FOUND": what the pack itself
    found), signed, pinned, signer, files, receipts, problems, warnings.
    """
    from traceseal_observe.timestamp import load_certificates

    pins = _normalise_keys(expected_keys, "expected_keys") if expected_keys is not None else []
    if not pins and not trust_signer_in_pack:
        raise ValueError("verify_pack needs expected_keys (the operator public key(s) obtained "
                         "out of band), or trust_signer_in_pack=True")
    problems: list[str] = []
    warnings: list[str] = []
    result: dict[str, Any] = {"ok": False, "pack_result": None, "auditor_result": None,
                              "auditor_findings": [], "analysis_options": None,
                              "signed": False, "pinned": False,
                              "signer": None, "files": 0, "receipts": 0,
                              "problems": problems, "warnings": warnings}
    try:
        root = Path(os.path.realpath(directory))
        if not root.is_dir():
            problems.append(f"{directory} is not a directory")
            return result
    except OSError as exc:
        problems.append(f"cannot open pack: {type(exc).__name__}")
        return result

    # -- manifest ---------------------------------------------------------------
    try:
        manifest_bytes = _safe_read(root, "manifest.json")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        problems.append(f"manifest unreadable: {exc}")
        return result
    listed = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(listed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in listed.items()):
        problems.append("manifest malformed: 'files' must map paths to sha256 digests")
        return result
    result["files"] = len(listed)
    contents: dict[str, bytes] = {}
    for rel, digest in sorted(listed.items()):
        try:
            data = _safe_read(root, rel)
        except _PathError as exc:
            problems.append(str(exc))
            continue
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            problems.append(f"file changed: {rel}")
        else:
            contents[rel] = data
    actual = _walk(root, problems)
    extra = actual - set(listed) - {"manifest.json", "pack.receipt.json"}
    problems += [f"file not in manifest: {rel}" for rel in sorted(extra)]
    receipt_files = sorted(rel for rel in contents if rel.startswith("receipts/"))
    result["receipts"] = len(receipt_files)

    # -- pack signature (mandatory) ----------------------------------------------
    pack_receipt = None
    try:
        pack_bytes = _safe_read(root, "pack.receipt.json")
    except _PathError as exc:
        problems.append("pack is not signed (pack.receipt.json missing)" if "missing" in str(exc)
                        else f"pack.receipt.json: {exc}")
    else:
        try:
            pack_receipt = _receipt_from_bytes(pack_bytes, "pack receipt")
            _check_receipt(pack_receipt, "pack receipt")
        except ValueError as exc:
            problems.append(str(exc))
            pack_receipt = None
    if pack_receipt is not None:
        ex = pack_receipt.execution
        signer = _signer(pack_receipt)
        result["signer"] = signer
        if ex.get("receipt_type") != "evidence_pack":
            problems.append("pack receipt is not an evidence_pack receipt")
        elif ex.get("manifest_hash") != "sha256:" + hashlib.sha256(manifest_bytes).hexdigest():
            problems.append("pack receipt does not cover this manifest")
        else:
            result["signed"] = True
        if ex.get("file_count") != len(listed):
            problems.append(f"pack receipt records {ex.get('file_count')!r} files, manifest lists {len(listed)}")
        if ex.get("receipt_count") != len(receipt_files):
            problems.append(f"pack receipt records {ex.get('receipt_count')!r} receipts, "
                            f"pack holds {len(receipt_files)} (receipts removed or added?)")
        if pins:
            if signer in pins:
                result["pinned"] = True
            else:
                problems.append(f"pack is signed by {_fp(signer)}, which is not an expected operator key")
        else:
            warnings.append(f"SIGNER NOT PINNED: the pack signature was checked against the key the "
                            f"pack itself names ({signer}). Anyone can re-sign a pack with their own "
                            "key; confirm this key belongs to the operator out of band.")

    # -- receipts ---------------------------------------------------------------
    receipts = []
    for rel in receipt_files:
        try:
            r = _receipt_from_bytes(contents[rel], rel)
        except ValueError as exc:
            problems.append(str(exc))
            r = Receipt(_UNREADABLE, _UNREADABLE, _UNREADABLE, _UNREADABLE)  # as build_pack does
        receipts.append(r)
        try:
            _check_receipt(r, rel)
        except ValueError as exc:
            problems.append(str(exc))

    # -- re-derive the findings ------------------------------------------------------
    report = None
    if "report.json" not in contents:
        problems.append("report.json missing or not covered by the manifest")
    else:
        try:
            report = json.loads(contents["report.json"].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            report = None
        if not isinstance(report, dict):
            problems.append("report.json is not a JSON object")
            report = None
    if report is not None:
        options = report.get("analysis_options")
        if not isinstance(options, dict):
            problems.append("report.json records no analysis_options (pack built before 1.6?); "
                            "its findings cannot be re-derived")
        else:
            try:
                notes, stamps = [], {}
                for cp in options.get("checkpoints") or []:
                    note = contents[cp["file"]].decode("utf-8")
                    notes.append(note)
                    stamps.setdefault(note, []).extend(contents[t] for t in cp.get("timestamps") or [])
                anchors = []
                for pem in options.get("tsa_trust_anchors_pem") or []:
                    anchors.extend(load_certificates(pem.encode("ascii")))
                derived = analyse(
                    receipts, checkpoints=notes, checkpoint_timestamps=stamps,
                    tsa_trust_anchors=anchors, witness_vkeys=options.get("witness_vkeys") or [],
                    required_scopes=options.get("required_scopes"),
                    require_approval=options.get("require_approval") or [],
                    require_policy=options.get("require_policy"),
                    min_review_seconds=options.get("min_review_seconds"),
                    now=options.get("now"), operator_keys=options.get("operator_keys"),
                    reviewer_keys=options.get("reviewer_keys"),
                )
            except Exception as exc:
                problems.append(f"findings could not be re-derived ({type(exc).__name__}: {exc})")
            else:
                problems += _compare(report, derived)
                problems += _compare_rendered(report, derived, contents)
                result["analysis_options"] = _options_summary(options)
                recorded_now = _parse_time(options.get("now"))
                latest = _parse_time(derived["period"].get("last"))
                if recorded_now is None:
                    problems.append("analysis_options.now is missing or malformed")
                elif latest is not None and recorded_now < latest:
                    problems.append(f"the pack was analysed 'as of' {options.get('now')}, before its own "
                                    f"latest receipt ({derived['period']['last']}): a back-dated analysis")
                result["pack_result"] = "passed" if derived["ok"] else "ISSUES FOUND"
                if pack_receipt is not None and \
                        pack_receipt.execution.get("verification_ok") != ("true" if derived["ok"] else "false"):
                    problems.append(f"pack receipt says verification_ok="
                                    f"{pack_receipt.execution.get('verification_ok')!r}, but the "
                                    f"re-derived result is {'passed' if derived['ok'] else 'ISSUES FOUND'}")
                if options.get("operator_keys") is None:
                    warnings.append("the pack was built without an operator key pin: receipts from "
                                    "any signer were analysed")
                # -- the auditor's own analysis ------------------------------------
                try:
                    approvals = set(options.get("require_approval") or [])
                    approvals |= {require_approval} if isinstance(require_approval, str) \
                        else set(require_approval or ())
                    auditor = analyse(
                        receipts, checkpoints=notes, checkpoint_timestamps=stamps,
                        tsa_trust_anchors=anchors, witness_vkeys=options.get("witness_vkeys") or [],
                        required_scopes={**(options.get("required_scopes") or {}),
                                         **(required_scopes or {})} or None,
                        require_approval=sorted(approvals),
                        require_policy={**(options.get("require_policy") or {}),
                                        **(require_policy or {})} or None,
                        min_review_seconds=max(
                            [v for v in (options.get("min_review_seconds"), min_review_seconds)
                             if isinstance(v, int)], default=None),
                        now=now or _now_utc(),
                        operator_keys=pins or options.get("operator_keys"),
                        reviewer_keys=(reviewer_keys if reviewer_keys is not None
                                       else options.get("reviewer_keys")),
                    )
                except Exception as exc:
                    problems.append(f"auditor analysis failed ({type(exc).__name__}: {exc})")
                else:
                    result["auditor_result"] = "passed" if auditor["ok"] else "ISSUES FOUND"
                    result["auditor_findings"] = _findings(auditor)
    problems[:] = _dedupe(problems)
    result["ok"] = not problems
    return result


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _options_summary(options: dict[str, Any]) -> dict[str, Any]:
    keys = ("now", "operator_keys", "require_approval", "require_policy", "required_scopes",
            "min_review_seconds", "witness_vkeys")
    out = {k: options.get(k) for k in keys}
    out["reviewer_keys"] = sorted(options.get("reviewer_keys") or {}) or None
    out["checkpoints"] = len(options.get("checkpoints") or [])
    return out


def _findings(summary: dict[str, Any]) -> list[str]:
    out = [f"{c['framework']} {c['ref']}: {c['status']}" + (
        f" ({'; '.join(c['problems'][:2])})" if c.get("problems") else "")
        for c in summary["controls"] if c["status"] == "issues"]
    out += [f"incident {i.get('category')}: MISSED {d.get('basis')} due {d.get('due')}"
            for i in summary["incidents"] for d in i.get("missed_deadlines", [])]
    out += [f"trace: {e}" for e in summary["trace"]["errors"][:20]]
    return _dedupe(out)


def _expected_report(report: dict[str, Any], derived: dict[str, Any]) -> dict[str, Any]:
    expected = dict(derived)
    for k in ("pack_version", "generated_at", "analysis_options", "pack_signer"):
        if k in report:
            expected[k] = report[k]
    return expected


def _compare_rendered(report: dict[str, Any], derived: dict[str, Any],
                      contents: dict[str, bytes]) -> list[str]:
    """report.json and report.md must be exactly what build_pack writes for
    the re-derived findings: no field or sentence can be edited."""
    out = []
    expected = _expected_report(report, derived)
    want_json = json.dumps(expected, indent=2, sort_keys=True, default=str).encode("utf-8")
    if contents.get("report.json") != want_json:
        try:
            normalised = json.loads(want_json)
        except ValueError:
            normalised = {}
        changed = sorted(k for k in set(normalised) | set(report)
                         if normalised.get(k) != report.get(k))
        out.append("report.json does not match the re-derived findings"
                   + (f" (fields: {', '.join(changed[:8])})" if changed else ""))
    want_md = render_markdown(expected).encode("utf-8")
    if "report.md" not in contents:
        out.append("report.md missing or not covered by the manifest")
    elif contents["report.md"] != want_md:
        out.append("report.md does not match the re-derived findings")
    return out


def _compare(report: dict[str, Any], derived: dict[str, Any]) -> list[str]:
    out = []
    if report.get("ok") is not derived["ok"]:
        out.append(f"report.json says ok={report.get('ok')!r}, re-derived ok={derived['ok']}")
    for field in ("receipts", "valid_signatures"):
        if report.get(field) != derived[field]:
            out.append(f"report.json says {field}={report.get(field)!r}, re-derived {derived[field]}")
    period = report.get("period") if isinstance(report.get("period"), dict) else {}
    for field in ("first", "last", "days"):
        if period.get(field) != derived["period"][field]:
            out.append(f"report.json period.{field}={period.get(field)!r}, "
                       f"re-derived {derived['period'][field]!r}")
    stated = {}
    controls = report.get("controls")
    if isinstance(controls, list):
        for c in controls:
            if isinstance(c, dict):
                stated[(_text(c.get("framework")), _text(c.get("ref")))] = c.get("status")
    else:
        out.append("report.json controls are malformed")
    for c in derived["controls"]:
        key = (c["framework"], c["ref"])
        if key not in stated:
            out.append(f"report.json is missing control {key[0]} {key[1]}")
        elif stated[key] != c["status"]:
            out.append(f"control {key[0]} {key[1]}: report.json says {stated[key]!r}, "
                       f"re-derived {c['status']!r}")
    extra = set(stated) - {(c["framework"], c["ref"]) for c in derived["controls"]}
    out += [f"report.json lists unknown control {a} {b}" for a, b in sorted(extra)]
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceseal-report",
                                     description="Build or verify an evidence pack.")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("inputs", nargs="+", help="receipt files or directories")
    b.add_argument("--output", required=True)
    b.add_argument("--checkpoint", action="append", default=[])
    b.add_argument("--checkpoint-timestamp", action="append", default=[], metavar="CHECKPOINT=TOKEN")
    b.add_argument("--tsa-root", action="append", default=[])
    b.add_argument("--witness-vkey", action="append", default=[])
    b.add_argument("--require-approval", action="append", default=[])
    b.add_argument("--require-policy", action="append", default=[], metavar="TOOL=POLICY")
    b.add_argument("--require-scope", action="append", default=[], metavar="TOOL=SCOPE")
    b.add_argument("--min-review-seconds", type=int)
    b.add_argument("--reviewer-keys", metavar="FILE",
                   help="JSON map of reviewer ref to Ed25519 public key(s); countersignatures "
                        "count as reviewer-signed only when the key is registered")
    b.add_argument("--operator-key", help="raw Ed25519 key file to sign the pack")
    b.add_argument("--operator-pubkey", action="append", default=[], metavar="HEX",
                   help="pin the operator public key(s) receipts must be signed by (repeatable); "
                        "receipts signed by other keys are excluded and fail the pack")
    v = sub.add_parser("verify-pack")
    v.add_argument("directory")
    v.add_argument("--operator-pubkey", action="append", default=[], metavar="HEX",
                   help="operator public key the pack must be signed by, obtained out of band "
                        "(repeatable). Required unless --trust-signer-in-pack.")
    v.add_argument("--trust-signer-in-pack", action="store_true",
                   help="accept whichever key signed the pack (NOT pinned: anyone can re-sign a pack)")
    v.add_argument("--now", help="the auditor's 'as of' time (UTC YYYY-MM-DDTHH:MM:SSZ); "
                                 "default: the current time")
    v.add_argument("--require-approval", action="append", default=[])
    v.add_argument("--require-policy", action="append", default=[], metavar="TOOL=POLICY")
    v.add_argument("--require-scope", action="append", default=[], metavar="TOOL=SCOPE")
    v.add_argument("--min-review-seconds", type=int)
    v.add_argument("--reviewer-keys", metavar="FILE",
                   help="the auditor's reviewer key registry (overrides the one in the pack)")
    args = parser.parse_args(argv)

    if args.command == "verify-pack":
        if not args.operator_pubkey and not args.trust_signer_in_pack:
            print("traceseal-report verify-pack: refusing to verify without a pinned signer. Pass "
                  "--operator-pubkey <hex> with the operator's public key obtained out of band, or "
                  "--trust-signer-in-pack to accept whichever key signed the pack (unsafe: anyone "
                  "can re-sign a pack).", file=sys.stderr)
            return 2
        vpairs = lambda items: {k: v for k, _, v in (i.partition("=") for i in items)}  # noqa: E731
        try:
            if args.now is not None and _parse_time(args.now) is None:
                raise ValueError("--now must be UTC YYYY-MM-DDTHH:MM:SSZ")
            result = verify_pack(args.directory, args.operator_pubkey or None,
                                 trust_signer_in_pack=args.trust_signer_in_pack,
                                 now=args.now, require_approval=args.require_approval,
                                 require_policy=vpairs(args.require_policy) or None,
                                 required_scopes=vpairs(args.require_scope) or None,
                                 reviewer_keys=_read_reviewer_keys(args.reviewer_keys),
                                 min_review_seconds=args.min_review_seconds)
        except ValueError as exc:
            print(f"traceseal-report verify-pack: {exc}", file=sys.stderr)
            return 2
        for w in result["warnings"]:
            print(f"WARNING: {w}")
        signer = result.get("signer")
        sig = ("valid" if result["signed"] else "INVALID OR ABSENT")
        pin = ("pinned" if result["pinned"] else "NOT PINNED") if signer else ""
        print(f"[{'OK' if result['ok'] else 'FAIL'}] {result['files']} files, {result['receipts']} receipts, "
              f"pack signature: {sig}" + (f" by {_fp(signer)} ({pin})" if signer else ""))
        print(f"  pack result (as built): {result['pack_result'] or 'unknown (not re-derived)'}")
        print(f"  auditor result (your clock and requirements): "
              f"{result['auditor_result'] or 'unknown'}")
        opts = result.get("analysis_options") or {}
        if opts:
            print("  recorded analysis options: " + ", ".join(
                f"{k}={v}" for k, v in opts.items() if v not in (None, [], {}, 0)))
        for finding in result["auditor_findings"][:30]:
            print(f"  - {finding}")
        for problem in result["problems"]:
            print(f"  {problem}")
        if not result["ok"]:
            return 1
        return 0 if result["auditor_result"] == "passed" else 3

    from traceseal_observe import OperatorKey
    from traceseal_observe.chain import _read_certs

    paths: list[Path] = []
    for item in args.inputs:
        p = Path(item)
        paths += sorted(p.rglob("*.json")) if p.is_dir() else [p]
    stamps: dict[Path, list[Path]] = {}
    for item in args.checkpoint_timestamp:
        cp, _, token = item.partition("=")
        stamps.setdefault(Path(cp), []).append(Path(token))
    pairs = lambda items: {k: v for k, _, v in (i.partition("=") for i in items)}  # noqa: E731
    try:
        summary = build_pack(
            args.output, paths,
            operator_key=OperatorKey.load_from_file(args.operator_key) if args.operator_key else None,
            checkpoint_paths=[Path(c) for c in args.checkpoint], timestamp_paths=stamps,
            tsa_trust_anchors=_read_certs(args.tsa_root), witness_vkeys=args.witness_vkey,
            required_scopes=pairs(args.require_scope), require_approval=args.require_approval,
            require_policy=pairs(args.require_policy), min_review_seconds=args.min_review_seconds,
            operator_keys=args.operator_pubkey or None,
            reviewer_keys=_read_reviewer_keys(args.reviewer_keys),
        )
    except (OSError, ValueError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    print(f"[{'OK' if summary['ok'] else 'ISSUES'}] wrote {args.output}: "
          f"{summary['valid_signatures']} receipts, {len(summary['chains'])} chain(s)")
    if not args.operator_key:
        print("  WARNING: pack is unsigned (no --operator-key); verify-pack will reject it")
    for w in summary["warnings"]:
        print(f"  WARNING: {w}")
    for c in summary["controls"]:
        print(f"  {c['framework']} {c['ref']}: {c['status']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
