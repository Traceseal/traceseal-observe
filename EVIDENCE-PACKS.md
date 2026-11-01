# Incidents and Evidence Packs

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
    --operator-pubkey <operator public key hex> \
    --operator-key ops.key --output pack/
traceseal-report verify-pack pack/ --operator-pubkey <operator public key hex>
```

`build` runs these verifiers over the receipts:
- signatures (receipts whose JSON is not a valid receipt are reported as
  signature failures, never a crash);
- with `--operator-pubkey` (repeatable; `operator_keys=` in Python), the
  signer pin: receipts signed by any other key are listed under
  `foreign_key_receipts`, excluded from the analysis, and make the pack
  fail. Keys reached by a chain rotation must be pinned too. Without a pin,
  receipts from more than one key that are not linked by a verified chain
  rotation produce a warning, because anyone can add receipts signed by a
  key of their own;
- `verify_chain` per chain, with whichever supplied checkpoint belongs to
  that chain, including key rotations;
- `verify_trace` for causality, authorisation, oversight and policy;
- incident deadlines;
- data-flow summaries.

A receipt that makes a verifier raise is skipped and reported under
`analysis_failures`, which fails the pack.

The period a pack covers comes only from **signed** time fields
(`chained_at`, `started_at`, `observed_at`, `decided_at`, `aware_at`,
`recorded_at`, `verified_at`, `reobserved_at`). The unsigned
`attestation.attested_at` is never used, and a missing or malformed time
counts as unknown. These are still the operator's own clock: see trusted
time below.

It then writes:

```
pack/
  report.md          findings and the control map, for people
  report.json        the same plus every verifier report and the analysis
                     options used (analysis_options), for machines
  receipts/          copies of every receipt examined
  checkpoints/       checkpoints and timestamp tokens supplied
  manifest.json      SHA-256 of every file
  pack.receipt.json  operator-signed evidence_pack receipt over the manifest,
                     with file and receipt counts and the overall result
```

A pack built without `--operator-key` is unsigned, and `verify-pack`
rejects it.

### What `verify-pack` checks

`verify-pack` works offline. You must say whose signature you expect:
pass the operator's public key, obtained **out of band** (from their
operator key directory, a contract, a previous audit — not from the pack),
with `--operator-pubkey` (repeatable). Without it the command refuses and
exits 2. `--trust-signer-in-pack` accepts whichever key signed the pack;
the result is then reported as `pinned: false` with a warning, because
anyone can re-sign a pack with a key of their own.

It checks:
- **paths:** every manifest path is relative, has no `..` component and
  resolves inside the pack; symlinks are never followed, whether listed in
  the manifest or found anywhere in the pack (including `receipts/`);
- every file against the manifest, and that no unlisted file was added;
- the **pack signature, which is mandatory:** `pack.receipt.json` must
  exist, verify, be signed by a pinned key, and cover this manifest, its
  file count and the number of receipts in `receipts/` (so removing a
  receipt together with its manifest entry is detected);
- every receipt signature;
- **the findings:** it re-runs the analysis over `receipts/` and
  `checkpoints/` with the options recorded in `report.json`
  (checkpoints and their timestamp tokens, TSA roots, witness keys,
  required approvals, scopes and policies, minimum review time, the
  operator-key pin, and the analysis time), and requires the overall
  result, every control status, the receipt counts and the period to
  match `report.json`, and the pack receipt's `verification_ok` to match.
  Each mismatch is reported as a problem. Packs without recorded options
  (built before 1.6.0) fail this check.
- **the report files themselves:** `report.json` and `report.md` must be
  byte for byte what `build` writes for the re-derived findings, so no
  field, note or sentence in them can be edited;
- **the analysis time:** an "as of" time earlier than the pack's own
  latest receipt is a back-dated analysis and fails.

Then it runs **the auditor's analysis** over the same receipts. It uses:
- **your clock:** `--now`, by default the current time, so deadlines are
  judged as of today, not as of whenever the operator chose;
- **the pinned operator keys:** receipts signed by other keys are excluded;
- **your reviewer registry:** `--reviewer-keys`, if given, replaces the
  operator's;
- **your requirements:** `--require-approval`, `--require-policy`,
  `--require-scope` and `--min-review-seconds` are added to the ones
  recorded.

Its verdict is the **auditor result**, and the exit code follows it. The
operator cannot make a pack pass by picking a convenient date or by
leaving a requirement out.

Hostile content (a manifest that is a list, a pack receipt that is not
JSON, fields of the wrong type) is reported as a problem, never a crash.

The output shows both whether the pack is intact and what the pack itself
found:

```
[OK] 6 files, 4 receipts, pack signature: valid by 1f2e3d4c5b6a7980… (pinned)
  pack result (as built): passed
  auditor result (your clock and requirements): ISSUES FOUND
  recorded analysis options: now=2026-10-01T00:00:00Z, operator_keys=[…]
  - incident serious_incident: MISSED EU AI Act Art. 73(2) due 2026-10-16T00:00:00Z
```

Exit codes: `0` intact and the auditor result passed; `3` intact but the
auditor result shows issues; `1` the pack failed verification; `2` usage
error (including no pinned signer).

What `verify-pack` does **not** do: it does not make the operator's
receipts true. It shows that the pack is unmodified since the pinned key
signed it and that its findings follow from the receipts and options it
contains. Whether the recorded options (which TSA roots and witnesses
were trusted) are right is for the auditor to judge; they are printed, and
the auditor can add requirements and supply their own clock and reviewer
registry. Stop/resume decisions in different chains are ordered by the
operator's signed times, and the report warns when a verdict rests on
that.

### The control map

Each row gives an obligation, its status, the evidence counted, and the
problems found:

| Status | Meaning |
|---|---|
| `evidence` | relevant evidence exists and the verifiers found no problem with it |
| `issues` | the verifiers found problems; they are listed in the row |
| `partial` | some evidence, but not enough on its own (see the rules below) |
| `no evidence` | nothing in this pack speaks to it |

Rules worth knowing:
- **Trace errors are never dropped.** Errors that a specific row claims
  (oversight on Art. 14 / 26(2)) appear there; every trace error appears
  on Art. 26(5) and NIST AI RMF, and any error no specific row claims also
  appears on Art. 12 and ISO/IEC 42001. Signature failures, analysis
  failures and receipts from unpinned keys appear on Art. 12, 26(5),
  ISO/IEC 42001 and NIST.
- **Art. 12** is `partial`, not `evidence`, when any operational receipt
  is outside a chain: unchained receipts cannot show completeness.
- **Art. 19 / 26(6)** is `evidence` only when the period is at least 183
  days **and** rests on trusted time: a chain spanning at least 183 days
  whose checkpoint anchors its receipts and carries a verified RFC 3161
  timestamp or witness cosignature. Otherwise it is `partial`. A
  checkpoint's trusted time proves that the receipts existed by then, not
  when each one was made.

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
