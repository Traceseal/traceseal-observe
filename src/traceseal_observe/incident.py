"""Incident receipts and regulatory reporting deadlines.

When an agent causes harm, regulators want to know what happened, when you
became aware of it, and when you reported it. An `incident` receipt is a
signed, chainable record of each stage, pointing at the receipts involved.

    incident = sign_incident(
        category="serious_incident", severity="high", status="detected",
        aware_at="2026-10-01T09:30:00Z",
        affected_receipts=[tool_receipt], description=internal_writeup,
        operator_key=chain.signer,
    )
    update = sign_incident(..., status="reported", supersedes=incident,
                           report_reference=submitted_report, regulator="DE-MSA")

reporting_deadlines() computes the statutory deadlines that run from
awareness. They are informational, not legal advice. Check the current text
of the regulation and any national rules before relying on them.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

INCIDENT_VERSION = "1.0"
INCIDENT_CATEGORIES = frozenset({
    "serious_incident",       # EU AI Act Art. 3(49), reported under Art. 73
    "personal_data_breach",   # GDPR Art. 4(12), Art. 33
    "significant_incident",   # NIS2 Art. 23
    "major_ict_incident",     # DORA Art. 19 (timelines set by its technical standards)
    "malfunction",
    "other",
})
INCIDENT_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
INCIDENT_STATUSES = frozenset({"detected", "reported", "mitigated", "closed"})

_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")


def _utc(value: str, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def reporting_deadlines(
    category: str, aware_at: str, *, death: bool = False, widespread: bool = False
) -> list[dict[str, str]]:
    """Statutory notification deadlines that run from awareness.

    serious_incident (EU AI Act Art. 73): 15 days (73(2)); 2 days for a
      widespread infringement or critical-infrastructure disruption (73(3));
      10 days in the event of a death (73(4)). The shortest applicable applies.
    personal_data_breach (GDPR Art. 33(1)): 72 hours.
    significant_incident (NIS2 Art. 23(4)): early warning 24 hours, incident
      notification 72 hours (final report one month after the notification,
      not computed here).
    major_ict_incident (DORA): set by the delegated technical standards; not
      computed.
    """
    if category not in INCIDENT_CATEGORIES:
        raise ValueError(f"category must be one of {sorted(INCIDENT_CATEGORIES)}")
    aware = _utc(aware_at, "aware_at")
    out: list[dict[str, str]] = []
    if category == "serious_incident":
        days, basis = 15, "EU AI Act Art. 73(2)"
        if death:
            days, basis = 10, "EU AI Act Art. 73(4)"
        if widespread:
            days, basis = 2, "EU AI Act Art. 73(3)"
        out.append({"regime": "EU AI Act", "step": "report to market surveillance authority",
                    "basis": basis, "due": _fmt(aware + timedelta(days=days))})
    elif category == "personal_data_breach":
        out.append({"regime": "GDPR", "step": "notify supervisory authority",
                    "basis": "GDPR Art. 33(1)", "due": _fmt(aware + timedelta(hours=72))})
    elif category == "significant_incident":
        out.append({"regime": "NIS2", "step": "early warning", "basis": "NIS2 Art. 23(4)(a)",
                    "due": _fmt(aware + timedelta(hours=24))})
        out.append({"regime": "NIS2", "step": "incident notification", "basis": "NIS2 Art. 23(4)(b)",
                    "due": _fmt(aware + timedelta(hours=72))})
    return out


def sign_incident(
    *,
    category: str,
    severity: str,
    status: str,
    aware_at: str,
    operator_key: Any,
    title: str | None = None,
    detected_at: str | None = None,
    affected_receipts: Any = (),
    description: Any = None,
    report_reference: Any = None,
    regulator: str | None = None,
    reported_at: str | None = None,
    supersedes: Any = None,
    death: bool = False,
    widespread: bool = False,
) -> Any:
    """Sign an incident record (one per stage; link stages with supersedes).

    title is signed in clear: keep it free of personal data. description and
    report_reference are hashed. Deadlines from reporting_deadlines() are
    signed too, so the record shows which deadline the operator worked to.
    """
    from traceseal_observe import _now_iso, _require_strict_json, sha256_of, sign_execution_receipt
    from traceseal_observe.context import _receipt_hash

    if category not in INCIDENT_CATEGORIES:
        raise ValueError(f"category must be one of {sorted(INCIDENT_CATEGORIES)}")
    if severity not in INCIDENT_SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(INCIDENT_SEVERITIES)}")
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"status must be one of {sorted(INCIDENT_STATUSES)}")
    aware = _utc(aware_at, "aware_at")
    execution: dict[str, Any] = {
        "receipt_type": "incident",
        "incident_version": INCIDENT_VERSION,
        "category": category,
        "severity": severity,
        "status": status,
        "aware_at": aware_at,
        "recorded_at": _now_iso(),
    }
    if detected_at is not None:
        if _utc(detected_at, "detected_at") > aware:
            raise ValueError("detected_at is after aware_at")
        execution["detected_at"] = detected_at
    if title is not None:
        if not isinstance(title, str) or _TEXT_RE.fullmatch(title) is None:
            raise ValueError("title must be 1-128 printable characters")
        execution["title"] = title
    affected = [_receipt_hash(r) for r in (affected_receipts or ())]
    if len(affected) > 64:
        raise ValueError("at most 64 affected receipts")
    if affected:
        execution["affected_receipt_hashes"] = list(dict.fromkeys(affected))
    if description is not None:
        _require_strict_json(description, "description")
        execution["description_hash"] = sha256_of(description)
    if report_reference is not None:
        _require_strict_json(report_reference, "report_reference")
        execution["report_reference_hash"] = sha256_of(report_reference)
    if regulator is not None:
        if not isinstance(regulator, str) or _TEXT_RE.fullmatch(regulator) is None:
            raise ValueError("regulator must be 1-128 printable characters")
        execution["regulator"] = regulator
    if status == "reported":
        reported_at = reported_at or execution["recorded_at"]
    if reported_at is not None:
        if _utc(reported_at, "reported_at") < aware:
            raise ValueError("reported_at is before aware_at")
        execution["reported_at"] = reported_at
    if supersedes is not None:
        execution["supersedes"] = _receipt_hash(supersedes)
    deadlines = reporting_deadlines(category, aware_at, death=death, widespread=widespread)
    if deadlines:
        execution["deadlines"] = deadlines
    provenance = {"provenance_version": "1.0", "provider_attestation": "none"}
    return sign_execution_receipt(execution, provenance, operator_key)


def incident_status(incidents: list[Any], *, now: str | None = None) -> list[dict[str, Any]]:
    """Collapse incident receipts into current state per incident, and flag
    deadlines that passed without a 'reported' record."""
    from traceseal_observe import _now_iso

    moment = _utc(now or _now_iso(), "now")
    by_hash = {r.receipt_hash: r for r in incidents}
    superseded = {r.execution.get("supersedes") for r in incidents}
    out = []
    for digest, r in by_hash.items():
        if digest in superseded:
            continue
        history = [r]
        cursor = r.execution.get("supersedes")
        while cursor in by_hash:
            history.append(by_hash[cursor])
            cursor = by_hash[cursor].execution.get("supersedes")
        reported = [h.execution["reported_at"] for h in history if "reported_at" in h.execution]
        first_report = min(reported) if reported else None
        overdue = []
        for d in r.execution.get("deadlines", []):
            due = _utc(d["due"], "due")
            if first_report is not None:
                if _utc(first_report, "reported_at") > due:
                    overdue.append({**d, "reported_late": first_report})
            elif moment > due:
                overdue.append({**d, "unreported": True})
        out.append({
            "head": digest,
            "category": r.execution.get("category"),
            "severity": r.execution.get("severity"),
            "status": r.execution.get("status"),
            "title": r.execution.get("title"),
            "aware_at": r.execution.get("aware_at"),
            "first_reported_at": first_report,
            "stages": len(history),
            "deadlines": r.execution.get("deadlines", []),
            "missed_deadlines": overdue,
            "affected_receipts": r.execution.get("affected_receipt_hashes", []),
        })
    return out
