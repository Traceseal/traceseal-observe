"""Compliance evidence packs: verify everything, map it to obligations, sign it.

    traceseal-report build receipts/ --checkpoint cp.txt --output pack/ \
        --require-approval issue_refund --operator-key ops.key

produces a directory an auditor can take away:

    pack/
      report.md        human-readable findings and control mapping
      report.json      the same, machine-readable, with every verifier report
      receipts/        copies of every receipt examined
      checkpoints/     checkpoints and timestamp tokens supplied
      manifest.json    SHA-256 of every file above
      pack.receipt.json  operator-signed evidence_pack receipt over the manifest

and `traceseal-report verify-pack pack/` re-checks the manifest, the pack
signature and every receipt signature, offline.

The control mapping says what evidence exists for each obligation and
whether the verifiers found problems. It is not a conformity assessment
and not legal advice: it shows where the evidence is, and where it isn't.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from traceseal_observe import Receipt, summarize_data_flows, verify_receipt_signature

PACK_VERSION = "1.0"
_TIME_KEYS = ("started_at", "observed_at", "decided_at", "aware_at", "chained_at")


def _when(r: Receipt) -> str | None:
    for key in _TIME_KEYS:
        value = r.execution.get(key)
        if isinstance(value, str) and len(value) == 20:
            return value
    return r.attestation.get("attested_at")


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _days(a: str, b: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (datetime.strptime(b, fmt) - datetime.strptime(a, fmt)).total_seconds() / 86400


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
) -> dict[str, Any]:
    """Run every verifier and build the evidence summary and control map."""
    from traceseal_observe.chain import ChainError, _resolve_checkpoint, verify_chain
    from traceseal_observe.incident import incident_status
    from traceseal_observe.trace import verify_trace

    signature_failures = []
    valid: list[Receipt] = []
    for i, r in enumerate(receipts):
        try:
            verify_receipt_signature(r, f"receipt[{i}]")
            valid.append(r)
        except ValueError as exc:
            signature_failures.append(str(exc))

    by_type: dict[str, int] = {}
    for r in valid:
        t = r.execution.get("receipt_type", "skill")
        by_type[t] = by_type.get(t, 0) + 1
    times = sorted(t for t in (_when(r) for r in valid) if t)

    # -- chains --------------------------------------------------------------
    chains: dict[str, list[Receipt]] = {}
    unchained_ops = 0
    for r in valid:
        cid = r.execution.get("chain_id")
        if cid is not None and "chain_seq" in r.execution:
            chains.setdefault(cid, []).append(r)
        elif r.execution.get("receipt_type") in (
            "model", "tool", "data_flow", "orchestration", "outcome",
            "oversight", "policy_decision", "erasure", "incident",
        ):
            unchained_ops += 1
    chain_reports = {}
    stamps = checkpoint_timestamps or {}
    for cid, members in chains.items():
        keys = sorted({m.attestation["operator_public_key"] for m in members}
                      | {m.execution["next_public_key"] for m in members
                         if m.execution.get("receipt_type") == "chain_key_rotation"})
        chosen = None
        for note in checkpoints:
            try:
                _resolve_checkpoint(note, keys, cid, witness_vkeys)
            except (ChainError, ValueError):
                continue
            chosen = note
        chain_reports[cid] = verify_chain(
            members, checkpoint=chosen,
            checkpoint_timestamps=stamps.get(chosen, []) if chosen else (),
            tsa_trust_anchors=tsa_trust_anchors, witness_vkeys=witness_vkeys,
        )

    trace = verify_trace(valid, required_scopes=required_scopes,
                         require_approval=require_approval, require_policy=require_policy,
                         min_review_seconds=min_review_seconds)
    incidents = incident_status([r for r in valid if r.execution.get("receipt_type") == "incident"], now=now)
    flows = summarize_data_flows(valid)
    models: dict[str, int] = {}
    served: dict[str, int] = {}
    tools: dict[str, int] = {}
    for r in valid:
        ex = r.execution
        if ex.get("receipt_type") == "model":
            models[f"{ex.get('provider')}/{ex.get('model')}"] = models.get(f"{ex.get('provider')}/{ex.get('model')}", 0) + 1
            if ex.get("served_model"):
                served[ex["served_model"]] = served.get(ex["served_model"], 0) + 1
        if ex.get("receipt_type") == "tool":
            tools[ex.get("tool_name", "?")] = tools.get(ex.get("tool_name", "?"), 0) + 1
    erasures = [r for r in valid if r.execution.get("receipt_type") == "erasure"]
    with_context = sum(1 for r in valid if isinstance(r.execution.get("context"), dict))

    summary = {
        "receipts": len(receipts),
        "valid_signatures": len(valid),
        "signature_failures": signature_failures,
        "by_type": dict(sorted(by_type.items())),
        "period": {"first": times[0] if times else None, "last": times[-1] if times else None,
                   "days": round(_days(times[0], times[-1]), 1) if len(times) > 1 else 0},
        "chains": {cid: {k: rep[k] for k in ("ok", "count", "first_seq", "last_seq", "gaps",
                                             "forks", "errors", "warnings", "rotations",
                                             "compromised_seqs", "checkpoint")}
                   for cid, rep in chain_reports.items()},
        "unchained_operational_receipts": unchained_ops,
        "with_context": with_context,
        "models_requested": dict(sorted(models.items())),
        "models_served": dict(sorted(served.items())),
        "tools": dict(sorted(tools.items())),
        "data_flows": flows,
        "trace": {k: trace[k] for k in ("ok", "errors", "warnings", "tool_calls",
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
    summary["ok"] = (
        not signature_failures
        and all(rep["ok"] for rep in chain_reports.values())
        and trace["ok"]
        and not any(i["missed_deadlines"] for i in incidents)
    )
    return summary


def _status(evidence: bool, issues: list[str]) -> tuple[str, list[str]]:
    if issues:
        return "issues", list(issues)
    return ("evidence" if evidence else "no evidence"), []


def map_controls(s: dict[str, Any]) -> list[dict[str, Any]]:
    """Map the verified evidence to obligations. Informational only."""
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
    oversight_errors = [e for e in trace["errors"] if any(w in e for w in (
        "approval", "human", "reviewer", "stopped", "rejected", "countersignature"))]
    authz_errors = [e for e in trace["errors"] if "scope" in e or "expired" in e]
    policy_errors = [e for e in trace["errors"] if "policy" in e]
    missed = [f"{i['category']} {i['head'][:15]}: {d['basis']} due {d['due']}"
              for i in s["incidents"] for d in i["missed_deadlines"]]
    ops = sum(n for t, n in s["by_type"].items() if t not in ("skill",))
    period_days = s["period"]["days"]
    flows = s["data_flows"]

    def control(framework, ref, title, status, evidence, notes=""):
        problems: list[str] = []
        if isinstance(status, tuple):
            status, problems = status
        return {"framework": framework, "ref": ref, "title": title, "status": status,
                "evidence": evidence, "notes": notes, "problems": problems}

    out = [
        control("EU AI Act", "Art. 12", "Record-keeping: automatic logging of events",
                _status(ops > 0, chain_issues + s["signature_failures"]),
                f"{ops} signed operational receipts; {len(chains)} chain(s); "
                f"{len(anchored)} anchored to a checkpoint; {len(trusted)} with trusted time "
                f"(TSA/witness); {s['unchained_operational_receipts']} receipts outside any chain.",
                "Unchained receipts cannot show completeness." if s["unchained_operational_receipts"] else ""),
        control("EU AI Act", "Art. 12(2)-(3)", "Logs identify situations, inputs and persons involved",
                _status(s["with_context"] > 0, []),
                f"{s['with_context']} receipts carry signed agent/principal/trace context; "
                f"inputs and outputs committed by hash."),
        control("EU AI Act", "Art. 14", "Human oversight",
                _status(bool(trace["oversight"]), oversight_errors),
                f"{len(trace['oversight'])} human decisions "
                f"({sum(1 for o in trace['oversight'] if o['reviewer_signed'])} reviewer-signed)."),
        control("EU AI Act", "Art. 19 / 26(6)", "Logs kept for at least six months",
                "evidence" if period_days >= 183 else ("no evidence" if ops == 0 else "partial"),
                f"This pack covers {period_days} days ({s['period']['first']} .. {s['period']['last']}).",
                "Retention is shown by the operator's archive and vault policy; a pack shows the period it covers."),
        control("EU AI Act", "Art. 26(5)", "Deployer monitoring of operation",
                _status(ops > 0, authz_errors + policy_errors),
                f"{len(trace['unprompted_tool_receipts'])} tool actions without a model cause; "
                f"{sum(1 for c in trace['tool_calls'] if c['status'] == 'arguments_differ')} with changed arguments; "
                f"{len(trace['unexecuted_tool_calls'])} requested calls not executed; "
                f"{len(trace['policy_decisions'])} automated policy decisions."),
        control("EU AI Act", "Art. 72", "Post-market monitoring",
                _status(s["by_type"].get("outcome", 0) + len(s["incidents"]) > 0, []),
                f"{s['by_type'].get('outcome', 0)} outcome receipts; {len(s['incidents'])} incident(s)."),
        control("EU AI Act", "Art. 73", "Serious incident reporting",
                _status(any(i["category"] == "serious_incident" for i in s["incidents"]),
                        [m for m in missed if m.startswith("serious_incident")]),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'serious_incident')} serious incident(s) recorded.",
                "No incidents recorded is not evidence that none occurred."),
        control("GDPR", "Art. 5(1)(c), 25", "Data minimisation / privacy by design",
                "evidence" if ops else "no evidence",
                "Receipts hold hashes, not values; principals are keyed commitments. "
                f"PII patterns seen in outbound payloads: {flows['pii_summary'] or 'none detected'}."),
        control("GDPR", "Art. 17", "Right to erasure",
                _status(bool(s["erasures"]), []),
                f"{len(s['erasures'])} signed erasure receipt(s) "
                f"({sum(1 for e in s['erasures'] if e['retention_overridden'] == 'true')} overriding retention)."),
        control("GDPR", "Art. 30, 44", "Records of processing / transfers",
                _status(flows["total_calls"] > 0, []),
                f"{flows['total_calls']} outbound data flows to {len(flows['destinations'])} host(s); "
                f"{flows['undeclared_calls']} to undeclared destinations.",
                "Hosts are recorded; their jurisdictions must be mapped by the operator."),
        control("GDPR", "Art. 33", "Personal data breach notification (72h)",
                _status(any(i["category"] == "personal_data_breach" for i in s["incidents"]),
                        [m for m in missed if m.startswith("personal_data_breach")]),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'personal_data_breach')} breach record(s)."),
        control("NIS2", "Art. 23", "Incident reporting (24h / 72h)",
                _status(any(i["category"] == "significant_incident" for i in s["incidents"]),
                        [m for m in missed if m.startswith("significant_incident")]),
                f"{sum(1 for i in s['incidents'] if i['category'] == 'significant_incident')} significant incident(s)."),
        control("ISO/IEC 42001", "Annex A", "AI system event logging and monitoring",
                _status(ops > 0, chain_issues),
                "Same evidence as EU AI Act Art. 12 and 26(5)."),
        control("NIST AI RMF", "MEASURE / MANAGE", "Tracking, monitoring and incident response",
                _status(ops > 0, chain_issues + missed),
                "Same evidence as EU AI Act Art. 12, 72 and 73."),
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
    lines.append(f"**Receipts:** {s['receipts']} ({s['valid_signatures']} with valid signatures)")
    lines += ["", "> Informational mapping of verified evidence to obligations. Not a",
              "> conformity assessment and not legal advice.", "", "## Controls", "",
              "| Framework | Ref | Obligation | Status | Evidence |", "|---|---|---|---|---|"]
    for c in s["controls"]:
        note = f" _{c['notes']}_" if c["notes"] else ""
        problems = (" **Problems:** " + "; ".join(c["problems"][:3])) if c["problems"] else ""
        cell = f"{c['evidence']}{note}{problems}".replace("|", "\\|")
        lines.append(f"| {c['framework']} | {c['ref']} | {c['title']} | **{c['status']}** | {cell} |")
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
    if s["signature_failures"]:
        lines += ["", "## Signature failures", ""] + [f"- {e}" for e in s["signature_failures"]]
    lines += ["", "## Verify this pack", "", "```bash", "traceseal-report verify-pack <this directory>", "```", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Building and verifying packs
# ---------------------------------------------------------------------------


def build_pack(
    output: Path | str,
    receipt_paths: list[Path],
    *,
    operator_key: Any = None,
    checkpoint_paths: list[Path] = (),
    timestamp_paths: dict[Path, list[Path]] | None = None,
    **analysis_kwargs: Any,
) -> dict[str, Any]:
    from traceseal_observe import sign_execution_receipt
    from traceseal_observe.chain import load_receipt

    out = Path(output)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} is not empty")
    (out / "receipts").mkdir(parents=True, exist_ok=True)
    (out / "checkpoints").mkdir(exist_ok=True)
    receipts = []
    for i, path in enumerate(receipt_paths):
        receipts.append(load_receipt(path))
        shutil.copyfile(path, out / "receipts" / f"{i:06d}-{Path(path).name}")
    notes, stamps = [], {}
    for path in checkpoint_paths:
        note = Path(path).read_text("utf-8")
        notes.append(note)
        shutil.copyfile(path, out / "checkpoints" / Path(path).name)
        tokens = []
        for tpath in (timestamp_paths or {}).get(Path(path), []):
            tokens.append(Path(tpath).read_bytes())
            shutil.copyfile(tpath, out / "checkpoints" / Path(tpath).name)
        stamps[note] = tokens
    summary = analyse(receipts, checkpoints=notes, checkpoint_timestamps=stamps, **analysis_kwargs)
    summary["pack_version"] = PACK_VERSION
    summary["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    (out / "report.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str))
    (out / "report.md").write_text(render_markdown(summary))
    files = sorted(p for p in out.rglob("*") if p.is_file())
    manifest = {
        "pack_version": PACK_VERSION,
        "files": {str(p.relative_to(out)): _sha256_file(p) for p in files},
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    if operator_key is not None:
        receipt = sign_execution_receipt(
            {
                "receipt_type": "evidence_pack",
                "pack_version": PACK_VERSION,
                "manifest_hash": _sha256_file(out / "manifest.json"),
                "file_count": len(manifest["files"]),
                "period_start": summary["period"]["first"] or "",
                "period_end": summary["period"]["last"] or "",
                "verification_ok": "true" if summary["ok"] else "false",
            },
            {"provenance_version": "1.0", "provider_attestation": "none"},
            operator_key,
        )
        (out / "pack.receipt.json").write_text(receipt.to_json())
    return summary


def verify_pack(directory: Path | str) -> dict[str, Any]:
    """Offline check of a pack: manifest hashes, pack signature, receipts."""
    from traceseal_observe.chain import load_receipt

    d = Path(directory)
    problems: list[str] = []
    try:
        manifest = json.loads((d / "manifest.json").read_text("utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "problems": [f"manifest unreadable: {exc}"]}
    listed = manifest.get("files", {})
    for rel, digest in listed.items():
        path = d / rel
        if not path.is_file():
            problems.append(f"missing file {rel}")
        elif _sha256_file(path) != digest:
            problems.append(f"file changed: {rel}")
    actual = {str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()}
    extra = actual - set(listed) - {"manifest.json", "pack.receipt.json"}
    problems += [f"file not in manifest: {rel}" for rel in sorted(extra)]
    signed = False
    if (d / "pack.receipt.json").exists():
        receipt = load_receipt(d / "pack.receipt.json")
        try:
            verify_receipt_signature(receipt, "pack receipt")
            if receipt.execution.get("manifest_hash") != _sha256_file(d / "manifest.json"):
                problems.append("pack receipt does not cover this manifest")
            else:
                signed = True
        except ValueError as exc:
            problems.append(str(exc))
    for path in sorted((d / "receipts").glob("*.json")):
        try:
            verify_receipt_signature(load_receipt(path), path.name)
        except ValueError as exc:
            problems.append(str(exc))
    return {"ok": not problems, "signed": signed, "files": len(listed), "problems": problems}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="traceseal-report",
                                     description="Build or verify a compliance evidence pack.")
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
    b.add_argument("--operator-key", help="raw Ed25519 key file to sign the pack")
    v = sub.add_parser("verify-pack")
    v.add_argument("directory")
    args = parser.parse_args(argv)

    if args.command == "verify-pack":
        result = verify_pack(args.directory)
        print(f"[{'OK' if result['ok'] else 'FAIL'}] {result.get('files', 0)} files, "
              f"pack signature: {'valid' if result.get('signed') else 'absent'}")
        for problem in result["problems"]:
            print(f"  {problem}")
        return 0 if result["ok"] else 1

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
    summary = build_pack(
        args.output, paths,
        operator_key=OperatorKey.load_from_file(args.operator_key) if args.operator_key else None,
        checkpoint_paths=[Path(c) for c in args.checkpoint], timestamp_paths=stamps,
        tsa_trust_anchors=_read_certs(args.tsa_root), witness_vkeys=args.witness_vkey,
        required_scopes=pairs(args.require_scope), require_approval=args.require_approval,
        require_policy=pairs(args.require_policy), min_review_seconds=args.min_review_seconds,
    )
    print(f"[{'OK' if summary['ok'] else 'ISSUES'}] wrote {args.output}: "
          f"{summary['valid_signatures']} receipts, {len(summary['chains'])} chain(s)")
    for c in summary["controls"]:
        print(f"  {c['framework']} {c['ref']}: {c['status']}")
    return 0 if summary["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
