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

reporting_deadlines() computes the latest permissible times for the
statutory notifications that run from awareness, each with the legal
qualifier ("immediately", "without undue delay") that governs it.
related_obligations() lists the follow-up duties. All of it is
informational, not legal advice: whether a regime applies to you, national
rules and later amendments must be checked with counsel.
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
    "major_ict_incident",     # DORA Art. 19; timelines in Delegated Regulation (EU) 2025/301
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


# Where an obligation applies at all depends on who you are (provider,
# deployer, controller, processor, essential/important entity, financial
# entity), on national transposition, and, for the AI Act, on whether the
# system is high-risk. These notes travel with every computed deadline.
AI_ACT_HIGH_RISK_APPLICATION = (
    "Applies to providers of high-risk AI systems (deployers inform the provider "
    "immediately, Art. 26(5)). As amended by Regulation (EU) 2026/1744: from "
    "2 December 2027 for Annex III systems and 2 August 2028 for Annex I systems."
)
LEGAL_NOTICE = (
    "Informational, not legal advice. Deadlines are computed from aware_at as "
    "the latest permissible time; the law asks for notification without undue "
    "delay or immediately, so report as early as you can. Whether a regime "
    "applies, national rules and any later amendment must be checked with "
    "counsel. Only the first report is checked against deadlines; follow-up "
    "obligations are listed, not tracked."
)


def reporting_deadlines(
    category: str, aware_at: str, *, death: bool = False, widespread: bool = False,
    classified_at: str | None = None,
) -> list[dict[str, str]]:
    """Statutory notification deadlines that run from awareness.

    Every entry is the *latest* permissible time ("due") with the legal
    qualifier that governs it ("qualifier"). Reporting at the due time can
    still be late where the law says "immediately" or "without undue delay".

    serious_incident (EU AI Act Art. 73, high-risk systems only): immediately
      after a causal link is established or reasonably likely, and no later
      than 15 days (73(2)); 2 days for a widespread infringement or a serious
      incident under Art. 3(49)(b) (73(3)); 10 days in the event of a death
      (73(4)). The shortest applicable applies.
    personal_data_breach (GDPR Art. 33(1)): without undue delay and, where
      feasible, not later than 72 hours.
    significant_incident (NIS2 Art. 23(4)): early warning without undue delay
      and within 24 hours, incident notification within 72 hours.
    major_ict_incident (DORA Art. 19, Delegated Regulation (EU) 2025/301
      Art. 5): initial notification within 4 hours of classifying the
      incident as major and no later than 24 hours after awareness; if the
      incident is classified as major only after those 24 hours, within 4
      hours of that classification (Art. 5(2)). Pass classified_at to get
      the actual deadline. Without it the due time is the 24-hour limit,
      marked "definitive": "false", and incident_status() reports it as
      unconfirmed rather than missed.

    Follow-up obligations without a fixed time from awareness (GDPR Art. 34,
    NIS2 final report, DORA intermediate and final reports) are returned by
    related_obligations().
    """
    if category not in INCIDENT_CATEGORIES:
        raise ValueError(f"category must be one of {sorted(INCIDENT_CATEGORIES)}")
    if classified_at is not None and category != "major_ict_incident":
        raise ValueError("classified_at applies to major_ict_incident only")
    aware = _utc(aware_at, "aware_at")
    out: list[dict[str, str]] = []
    if category == "serious_incident":
        days, basis = 15, "EU AI Act Art. 73(2)"
        if death:
            days, basis = 10, "EU AI Act Art. 73(4)"
        if widespread:
            days, basis = 2, "EU AI Act Art. 73(3)"
        out.append({"regime": "EU AI Act", "step": "report to market surveillance authority",
                    "basis": basis, "due": _fmt(aware + timedelta(days=days)),
                    "qualifier": "immediately after establishing a causal link or its reasonable "
                                 "likelihood, and no later than the due time; an initial "
                                 "incomplete report may be followed by a complete one (73(5)). "
                                 + AI_ACT_HIGH_RISK_APPLICATION})
    elif category == "personal_data_breach":
        out.append({"regime": "GDPR", "step": "notify supervisory authority",
                    "basis": "GDPR Art. 33(1)", "due": _fmt(aware + timedelta(hours=72)),
                    "qualifier": "without undue delay and, where feasible, not later than 72 hours; "
                                 "not required where the breach is unlikely to result in a risk; "
                                 "a late notification must give the reasons for the delay. "
                                 "Controllers only; processors notify the controller (33(2))."})
    elif category == "significant_incident":
        out.append({"regime": "NIS2", "step": "early warning", "basis": "NIS2 Art. 23(4)(a)",
                    "due": _fmt(aware + timedelta(hours=24)),
                    "qualifier": "without undue delay and in any event within 24 hours; "
                                 "national transposition and CSIRT procedures may add requirements."})
        out.append({"regime": "NIS2", "step": "incident notification", "basis": "NIS2 Art. 23(4)(b)",
                    "due": _fmt(aware + timedelta(hours=72)),
                    "qualifier": "without undue delay and in any event within 72 hours; "
                                 "national transposition may add requirements."})
    elif category == "major_ict_incident":
        rule = ("within 4 hours of classifying the incident as major, and no later than 24 hours "
                "after awareness; where it is classified as major only after 24 hours, within 4 "
                "hours of that classification (Art. 5(2)). Check the current RTS text and your "
                "competent authority's procedures.")
        entry = {"regime": "DORA", "step": "initial notification",
                 "basis": "DORA Art. 19(4); Delegated Regulation (EU) 2025/301 Art. 5"}
        if classified_at is None:
            entry.update(due=_fmt(aware + timedelta(hours=24)), definitive="false",
                         qualifier=rule + " Classification time not recorded: the due time is "
                                          "the 24-hour limit and may be earlier or later.")
        else:
            classified = _utc(classified_at, "classified_at")
            if classified < aware:
                raise ValueError("classified_at is before aware_at")
            outer = aware + timedelta(hours=24)
            four = classified + timedelta(hours=4)
            due = four if classified > outer else min(four, outer)
            entry.update(due=_fmt(due), classified_at=classified_at, qualifier=rule)
        out.append(entry)
    return out


def related_obligations(category: str) -> list[dict[str, str]]:
    """Follow-up obligations with no fixed time from awareness. Listed in
    incident receipts and evidence packs so they are not forgotten; they are
    not checked against reports."""
    if category not in INCIDENT_CATEGORIES:
        raise ValueError(f"category must be one of {sorted(INCIDENT_CATEGORIES)}")
    if category == "serious_incident":
        return [
            {"regime": "EU AI Act", "basis": "EU AI Act Art. 26(5)",
             "step": "deployer informs the provider, then importer/distributor and authority",
             "timing": "immediately"},
            {"regime": "EU AI Act", "basis": "EU AI Act Art. 73(6)",
             "step": "investigation, risk assessment and corrective action; do not alter the "
                     "system in a way that affects later evaluation before informing authorities",
             "timing": "without delay"},
        ]
    if category == "personal_data_breach":
        return [
            {"regime": "GDPR", "basis": "GDPR Art. 34",
             "step": "communicate to data subjects where the breach is likely to result in a "
                     "high risk to their rights and freedoms",
             "timing": "without undue delay"},
            {"regime": "GDPR", "basis": "GDPR Art. 33(5)",
             "step": "document the breach, its effects and the remedial action",
             "timing": "always, including breaches not notified"},
        ]
    if category == "significant_incident":
        return [
            {"regime": "NIS2", "basis": "NIS2 Art. 23(1)",
             "step": "notify recipients of the service where the incident is likely to "
                     "adversely affect them",
             "timing": "without undue delay"},
            {"regime": "NIS2", "basis": "NIS2 Art. 23(4)(c)",
             "step": "intermediate report", "timing": "on request of the CSIRT or authority"},
            {"regime": "NIS2", "basis": "NIS2 Art. 23(4)(d)",
             "step": "final report",
             "timing": "no later than one month after the incident notification"},
        ]
    if category == "major_ict_incident":
        return [
            {"regime": "DORA", "basis": "Delegated Regulation (EU) 2025/301 Art. 5",
             "step": "intermediate report",
             "timing": "within 72 hours of the initial notification, and when status changes"},
            {"regime": "DORA", "basis": "Delegated Regulation (EU) 2025/301 Art. 5",
             "step": "final report",
             "timing": "within one month of the latest intermediate report"},
            {"regime": "DORA", "basis": "DORA Art. 19(3)",
             "step": "inform affected clients where the incident affects their financial interests",
             "timing": "without undue delay"},
        ]
    return []


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
    classified_at: str | None = None,
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
    if classified_at is not None:
        execution["classified_at"] = classified_at
    if supersedes is not None:
        execution["supersedes"] = _receipt_hash(supersedes)
    deadlines = reporting_deadlines(category, aware_at, death=death, widespread=widespread,
                                    classified_at=classified_at)
    if deadlines:
        execution["deadlines"] = deadlines
    related = related_obligations(category)
    if related:
        execution["related_obligations"] = related
    provenance = {"provenance_version": "1.0", "provider_attestation": "none"}
    return sign_execution_receipt(execution, provenance, operator_key)


def _definitive(d: dict[str, str], category: Any) -> bool:
    # 1.5.1 DORA records carry no classification time and no flag.
    if d.get("definitive") == "false":
        return False
    return not (category == "major_ict_incident" and "classified_at" not in d)


def _strictest_deadlines(history: list[Any]) -> list[dict[str, str]]:
    """Resolve each (regime, step) deadline across every stage of an incident.

    A later stage must not loosen a deadline an earlier stage established
    (for example a closing record that omits death, widespread or
    classified_at). Definitive deadlines win over unconfirmed ones; among
    the same kind, the earliest due time wins."""
    best: dict[tuple[str, str], dict[str, str]] = {}
    for h in history:
        category = h.execution.get("category")
        for d in h.execution.get("deadlines", []):
            key = (d.get("regime", ""), d.get("step", ""))
            rank = (0 if _definitive(d, category) else 1, _utc(d["due"], "due"))
            cur = best.get(key)
            if cur is None or rank < (0 if _definitive(cur, category) else 1, _utc(cur["due"], "due")):
                best[key] = d
    return list(best.values())


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
        unconfirmed = []
        deadlines = _strictest_deadlines(history)
        for d in deadlines:
            due = _utc(d["due"], "due")
            if not _definitive(d, r.execution.get("category")):
                # The real deadline depends on a fact the record doesn't hold
                # (e.g. DORA classification time): never call it missed.
                if (first_report is not None and _utc(first_report, "reported_at") > due) or (
                        first_report is None and moment > due):
                    unconfirmed.append({**d, "first_reported_at": first_report})
                continue
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
            "deadlines": deadlines,
            "missed_deadlines": overdue,
            "unconfirmed_deadlines": unconfirmed,
            "related_obligations": r.execution.get("related_obligations", []),
            "affected_receipts": r.execution.get("affected_receipt_hashes", []),
        })
    return out
