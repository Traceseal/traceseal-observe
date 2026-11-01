# Incidents and Compliance Evidence Packs

## Incident receipts

```python
detected = sign_incident(
    category="serious_incident",      # serious_incident | personal_data_breach | significant_incident
    severity="high",                  #   | major_ict_incident | malfunction | other
    status="detected",                # detected | reported | mitigated | closed
    aware_at="2026-10-01T09:30:00Z",  # statutory clocks run from awareness
    title="refund agent paid duplicate claims",   # signed in clear: keep personal data out
    affected_receipts=[tool_receipt], description=internal_writeup,          # hashed
    operator_key=chain.signer, widespread=False, death=False,
)
reported = sign_incident(..., status="reported", supersedes=detected,
                         report_reference=submitted_report, regulator="DE-BNetzA")
```

Each stage is its own chainable receipt, linked to the previous stage by
`supersedes`. Receipts sign the deadlines `reporting_deadlines()`
computed, so the record shows which deadline the operator worked to:

| Category | Latest time from awareness | Governing rule | Basis |
|---|---|---|---|
| `serious_incident` | 15 days; 10 days if a death; 2 days if widespread or Art. 3(49)(b) | *immediately* once a causal link is established or reasonably likely; high-risk systems only, from 2 Dec 2027 (Annex III) / 2 Aug 2028 (Annex I) | EU AI Act Art. 73(2)–(4) |
| `personal_data_breach` | 72 hours | *without undue delay* and, where feasible, within 72 h | GDPR Art. 33(1) |
| `significant_incident` | early warning 24 h, notification 72 h | *without undue delay*; national transposition may add rules | NIS2 Art. 23(4) |
| `major_ict_incident` | initial notification: 4 h from classification, no later than 24 h from awareness; 4 h from a classification made after 24 h | pass `classified_at`; without it the 24 h limit is reported as *unconfirmed*, never as missed | DORA Art. 19; Delegated Regulation (EU) 2025/301 Art. 5(1)–(2) |

Each deadline is signed with its `qualifier`. The due time is the **latest
permissible** time: reporting at it can still be late where the law says
"immediately" or "without undue delay". Report as early as you can.

`related_obligations()` lists the follow-up duties that have no fixed time
from awareness, and incident receipts carry them: AI Act Art. 26(5) and
73(6); GDPR Art. 33(5) and 34; NIS2 Art. 23(1) and the intermediate and
final reports; DORA intermediate and final reports and client
information. They are listed, not checked.

`incident_status()` collapses the stages and reports first notifications
that passed unreported or were reported late. So that a later or edited
stage can't hide a missed deadline:

- An incident is identified by its **root** stage (the end of the
  `supersedes` chain) and keeps the root's category. A stage of another
  category in the chain is reported in `problems` (an error in evidence
  packs), and `sign_incident` refuses to supersede a stage of another
  category: open a new incident instead.
- Deadlines are **recomputed** from the root category, the **earliest**
  `aware_at` of any stage, and the strictest facts any stage signs
  (`death`, `widespread`, the earliest `classified_at`). Signed `deadlines`
  can only make a deadline stricter (an earlier due time); a later due
  time, or an empty or missing `deadlines` field, changes nothing. Across
  stages the strictest deadline wins.
- Only stages with `status="reported"` of the root category count as a
  report, and only with a `reported_at` at or after the earliest
  `aware_at`. A report dated before the root stage's own `aware_at` is
  reported in `problems`.
- DORA deadlines without a classification time stay *unconfirmed*, never
  missed.
- Malformed values (a non-UTC `reported_at` or `aware_at`, a `supersedes`
  that isn't a receipt hash, a deadline without `due`) never crash the
  analysis: they are ignored and listed in `problems`. These deadlines are
informational, not legal advice: whether a regime applies to you, national
rules and later amendments must be checked with counsel. See
[LEGAL.md](LEGAL.md).

## Evidence packs

```bash
traceseal-report build receipts/ \
    --checkpoint cp.txt --checkpoint-timestamp cp.txt=cp.tsr --tsa-root tsa-root.pem \
    --require-approval issue_refund --require-policy send_email=pii-filter \
    --operator-key ops.key --output pack/
traceseal-report verify-pack pack/
```

`build` runs every verifier over the receipts:
- signatures;
- `verify_chain` per chain, with whichever supplied checkpoint belongs to
  that chain, including key rotations;
- `verify_trace` for causality, authorisation, oversight and policy;
- incident deadlines;
- data-flow summaries.

It then writes:

```
pack/
  report.md          findings and the control map, for people
  report.json        the same plus every verifier report, for machines
  receipts/          copies of every receipt examined
  checkpoints/       checkpoints and timestamp tokens supplied
  manifest.json      SHA-256 of every file
  pack.receipt.json  operator-signed evidence_pack receipt over the manifest
```

`verify-pack` re-checks everything offline:
- every file against the manifest;
- that no unlisted file was added;
- the pack signature;
- every receipt signature.

### The control map

Each row gives an obligation, its status, the evidence counted, and the
problems found:

| Status | Meaning |
|---|---|
| `evidence` | relevant evidence exists and the verifiers found no problem with it |
| `issues` | the verifiers found problems; they are listed in the row |
| `partial` | some evidence, but not enough on its own, e.g. a pack covering less than six months for Art. 19 |
| `no evidence` | nothing in this pack speaks to it |

Rows cover:
- **EU AI Act:** Art. 12, 12(2)–(3), 14, 19 / 26(6), 26(5), 72, 73;
- **GDPR:** Art. 5(1)(c) / 25, 17, 30 / 44, 33;
- **NIS2:** Art. 23;
- **ISO/IEC 42001** (Annex A event logging and monitoring);
- **NIST AI RMF** (MEASURE / MANAGE).

The map shows where the evidence is and where it is missing. It is **not
a conformity assessment and not legal advice**. "No incidents recorded"
is not evidence that none happened. Retention is shown by the operator's
archive and vault policy; a pack only shows the period it covers.
