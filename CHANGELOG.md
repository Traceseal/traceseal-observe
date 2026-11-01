# Changelog

All notable changes to `traceseal-observe`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Every addition
keeps the `RECEIPT-SPEC.md` v1.0 envelope: receipts from earlier versions
verify unchanged, and new receipts verify with any v1 verifier.

## [1.5.1] — 2026-11-01

Legal-accuracy review of every regulatory reference. No change to receipt
formats or signatures: receipts from 1.5.0 verify unchanged.

### Changed
- **EU AI Act dates.** The Digital Omnibus on AI (Regulation (EU) 2026/1744)
  postponed the high-risk obligations to 2 December 2027 (Annex III) and
  2 August 2028 (Annex I). The docs, deadlines and evidence packs now say
  so, and that Arts. 12, 14, 19, 26, 72 and 73 apply to high-risk systems
  only.
- **Deadlines carry their legal qualifier.** Every deadline from
  `reporting_deadlines()` now includes a `qualifier` ("immediately",
  "without undue delay", "where feasible"), and the docs say the due time
  is the latest permissible time, not a target.
- **Evidence-pack controls** now say who each obligation applies to
  (`applies_to`), carry a full legal notice (`legal_notice`), and are
  reworded where they overstated:
  - Art. 12(3) dropped: it covers remote biometric identification only.
  - Art. 14 became "Art. 14 / 26(2)".
  - GDPR Art. 30/44 data flows are marked as supporting input only.
  - Principal commitments are described as pseudonymised, not anonymised.
  - Crypto-shredding is described as a technical erasure measure.
- `CAPTURE.md` no longer claims the transport proves nothing left the
  system. It records what passes through clients configured with it.

### Added
- **DORA.** `major_ict_incident` computes the 24-hour outer limit for the
  initial notification (Delegated Regulation (EU) 2025/301 Art. 5).
- **`related_obligations()`** lists follow-up duties, and incident receipts
  carry them: AI Act Art. 26(5) and 73(6); GDPR Art. 33(5) and 34; NIS2
  Art. 23(1) and the final report; DORA intermediate and final reports.
- **`LEGAL.md`**: scope, no warranty, what the evidence can and cannot show,
  status of each regime, personal data. It ships in the package.
- New `DORA Art. 19` control in evidence packs.

## [1.5.0] — 2026-11-01

### Added
- **Receipt chains** (`chain.py`, `traceseal-chain`). Every operational
  receipt carries a signed `chain_seq`, `chain_prev_hash` and `chained_at`.
  - Checkpoints are RFC 6962 Merkle roots in C2SP signed-note format, with
    inclusion and consistency proofs.
  - `verify_chain` reports gaps, forks, broken links, checkpoint anchoring,
    witness cosignatures and time-window coverage.
  - Chains persist crash-safely.
  - Interop is checked against Go's `sumdb/note` and `sumdb/tlog`.
- **Key rotation and compromise.** A chained, dual-signed
  `chain_key_rotation` hands a chain to a new key.
  `compromised_after_seq` flags receipts signed by a compromised key.
- **Trusted time** (`timestamp.py`). RFC 3161 tokens over checkpoints and
  receipts, verified offline: CMS signature, ESS binding, TSA EKU,
  certificate path. ETSI qualified-statement and best-practice-policy
  signals for eIDAS. Interop is checked against OpenSSL's TSA. Start-of-window
  evidence comes from a timestamped earlier checkpoint.
- **Streaming model receipts:** `observe_model_stream`,
  `observe_anthropic_stream`, `observe_openai_stream`.
- **Response metadata on model receipts:** `served_model`, `response_id`,
  `stop_reason`, `system_fingerprint`, and `requested_tool_calls` (also
  reassembled from streams).
- **Agent context** (`context.py`). `agent_context()` and `caused_by()`
  sign agent identity, a principal commitment (HMAC under a pepper),
  tenant, session, W3C trace ids (picked up from OpenTelemetry),
  authorisation and causal links into every operational receipt.
- **Trace verification** (`trace.py`, `traceseal-trace`):
  - tool calls matched against model requests, with changed arguments,
    unrequested calls, unexecuted requests and unprompted actions;
  - scope and expiry checks;
  - principal lookups.
- **Human oversight and policy decisions** (`oversight.py`):
  - `oversight` receipts, with an optional reviewer countersignature, and
    `policy_decision` receipts;
  - required-approval and required-policy checks;
  - execution after a rejection, a stop or a deny is an error;
  - rubber-stamp detection.
- **Evidence vault** (`vault.py`):
  - encrypted payload escrow under receipt hashes;
  - shred domains with KMS-wrappable keys, retention floors, `delete_after`
    and legal holds;
  - crypto-shredding with signed `erasure` receipts;
  - HPKE sealed disclosure, including the post-quantum ML-KEM-768+X25519
    suite.
- **Incidents** (`incident.py`). `incident` receipts with AI Act Art. 73,
  GDPR Art. 33 and NIS2 Art. 23 deadlines, and late or missing report
  detection.
- **Evidence packs** (`report.py`, `traceseal-report`). Everything is
  verified, then mapped to EU AI Act, GDPR, NIS2, ISO/IEC 42001 and NIST
  AI RMF obligations. The pack is a signed, manifest-checked directory.
- **Capture** (`capture.py`). `ReceiptTransport` and
  `AsyncReceiptTransport` for httpx/httpx2 sign a `data_flow` receipt for
  every SDK request, and can block undeclared destinations.
- **Async API** (`aio.py`): `aobserve_model_call`, `aobserve_tool`,
  `aobserve_model_stream`, and `aobserve_anthropic` / `aobserve_openai`
  with stream variants.
- **OpenTelemetry** (`otel.py`). GenAI semantic-convention attributes,
  `record_receipt` and `OTelSink`.
- **KMS/HSM signing.** `RemoteOperatorKey` verifies every remote signature
  before use.
- **Operator key directory** (`directory.py`, `traceseal-keys`). A signed
  `.well-known/traceseal/operator-keys.json`.
- **PII patterns:** IBAN (validated), international E.164 phone numbers,
  IPv4.
- **CI:** Python 3.9–3.13 and minimum-`cryptography` jobs.
- **Specs:** RECEIPT-CHAINS, TRUSTED-TIME, KEY-MANAGEMENT, AGENT-CONTEXT,
  HUMAN-OVERSIGHT, EVIDENCE-VAULT, EVIDENCE-PACKS, CAPTURE.

### Fixed
- A streamed response no longer produces a receipt over the stream
  object's `repr`. `observe_model_call` returns the stream untouched with
  an honest "output not observed" receipt. `observe_anthropic` and
  `observe_openai` refuse `stream=True` before calling the provider.
- Provider wrappers record the client's real `base_url` (gateways,
  proxies) instead of a hard-coded endpoint, with credentials and query
  strings removed.
- The test suite runs without the private `traceseal-log` checkout: those
  tests skip.

### Changed
- Dependency floor raised to `cryptography>=42`; the timestamp verifier
  needs it. New extras: `timestamp`, `disclosure`, `otel`.
- All operational signing goes through one shared path, which applies
  the chain and context.

## [1.4.0]

- Model identity, resolution and publisher receipts; outcome receipts;
  tool-definition hashes.
