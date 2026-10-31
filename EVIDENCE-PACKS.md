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

| Category | Deadline from awareness | Basis |
|---|---|---|
| `serious_incident` | 15 days; 10 days if a death; 2 days if widespread or critical infrastructure | EU AI Act Art. 73(2)–(4) |
| `personal_data_breach` | 72 hours | GDPR Art. 33(1) |
| `significant_incident` | early warning 24 h, notification 72 h | NIS2 Art. 23(4) |
| `major_ict_incident` | set by DORA's technical standards; not computed | DORA Art. 19 |

These deadlines are informational, not legal advice. Check the
regulation's current text and any national rules. `incident_status()`
collapses the stages and reports deadlines that passed unreported or were
reported late.

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
