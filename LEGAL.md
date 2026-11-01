# Legal notice and scope

**Last reviewed:** 1 November 2026. Laws and dates change; check the
current texts.

## 1. What TraceSeal is, and what it is not

TraceSeal is open-source software that produces and verifies
cryptographic records ("receipts") of what an AI system did. Receipts are
**evidence**. They help you show what happened; they do not decide
whether what happened was lawful.

TraceSeal, its documentation, its evidence packs and its control mapping
are **not**:

- legal advice, or a substitute for advice from qualified counsel;
- a conformity assessment, a certification, an audit opinion or a
  quality-management system under the EU AI Act or any other law;
- a finding that any obligation is met. A control marked `evidence`
  means relevant records exist and passed verification, nothing more;
- a determination of whether your AI system is high-risk, or of whether
  you are a provider, deployer, controller, processor, essential or
  important entity, or financial entity.

Using TraceSeal does not by itself make anyone compliant with any law.
You remain responsible for your obligations, for how you configure and
operate the software, and for the conclusions you draw from its output.

## 2. No warranty, limitation of liability

The software is licensed under the Apache License 2.0 ([notice](LICENSE),
[full text](https://www.apache.org/licenses/LICENSE-2.0)) and is
provided **"AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, express
or implied (Section 7). To the extent permitted by law, no contributor is
liable for any damages arising from its use, including regulatory fines,
missed reporting deadlines or loss of evidence (Section 8). This includes
the regulatory references, deadlines and mappings in the code and
documentation. Nothing in this notice limits liability that cannot be
limited by law.

## 3. What the evidence can and cannot show

Receipts and chains can show, cryptographically, that a key holder signed
specific records, in a specific order, and that none of them were later
altered, removed or inserted without detection. Trusted timestamps show
that records existed by a given time.

They cannot show:

- that the operator who held the signing key recorded everything, or
  recorded it honestly. A receipt is an attestation by its signer;
- anything about activity that did not pass through instrumented code
  (for example traffic through an unconfigured HTTP client);
- that a human reviewer understood what they approved, or that oversight
  measures were adequate;
- that an outcome actually happened, or that no incident occurred.

Whether a court or authority accepts receipts as evidence, and how much
weight it gives them, depends on the forum and national procedural law.
Only *qualified* electronic time stamps from a provider on the EU trusted
list carry the presumption of accuracy in eIDAS Art. 41(2). Other
timestamps are admissible (Art. 41(1)) without that presumption.

## 4. Regulatory references in this project

Every regulatory reference in the code and documentation is informational.
The ones that matter most:

| Regime | What TraceSeal references | Status (as reviewed) |
|---|---|---|
| EU AI Act (Regulation (EU) 2024/1689) | Arts. 12, 14, 19, 26, 72, 73 | High-risk obligations only. As amended by Regulation (EU) 2026/1744: they apply from **2 December 2027** (Annex III) and **2 August 2028** (Annex I). Art. 50 transparency duties (telling people they deal with AI, marking AI-generated content) are separate; TraceSeal does not perform them. |
| GDPR (Regulation (EU) 2016/679) | Arts. 4(5), 5, 15, 17, 25, 30, 33, 34 | In force. |
| NIS2 (Directive (EU) 2022/2555) | Art. 23 | Applies through national transposition, which may differ. |
| DORA (Regulation (EU) 2022/2554) | Art. 19; Delegated Regulation (EU) 2025/301 | In force for financial entities in scope. |
| eIDAS (Regulation (EU) 910/2014, as amended by (EU) 2024/1183) | Art. 41 | In force. |
| ISO/IEC 42001, NIST AI RMF | event logging, monitoring | Voluntary. |

**Deadlines.** `reporting_deadlines()` computes the *latest* permissible
time for first notifications. The law usually requires notification
"immediately" or "without undue delay", so reporting at the computed time
can still be late. Follow-up obligations are listed by
`related_obligations()` but not checked. A missing incident record is not
evidence that no incident occurred.

## 5. Personal data

- TraceSeal runs in your environment. It does not send receipts or
  payloads to TraceSeal. Timestamping sends hashes only, to the
  timestamp authority you configure. Model and tool calls go wherever your
  code sends them.
- You are the controller (or processor) for any personal data in
  receipts, the evidence vault and evidence packs.
- Principal commitments and hashes are **pseudonymised, not anonymised**.
  They stay personal data for anyone who holds the pepper or can guess
  the input (GDPR Art. 4(5), Recital 26). Treat receipts accordingly.
- Crypto-shredding makes vault payloads unreadable. It is a technical
  erasure measure, not a legal determination that Art. 17 is satisfied,
  and it does not reach backups or copies held elsewhere. Retaining data
  after an erasure request must rest on an Art. 17(3) exception that
  applies to you.
- Retention floors (for example six months under AI Act Art. 19 / 26(6))
  are subject to Union and national data-protection law.

## 6. Before you rely on TraceSeal for a regulatory purpose

1. Get advice from qualified counsel in each relevant jurisdiction on
   which regimes apply to you, and in what role.
2. Check the current text of each law and of any national rules,
   guidance and technical standards.
3. Define your own reporting procedures. Do not rely on computed deadlines
   alone.
4. Test that your instrumentation covers the activity you need to
   evidence.
5. Protect and manage signing keys as described in
   [KEY-MANAGEMENT](KEY-MANAGEMENT.md). Evidence is only as trustworthy as
   its keys.

## 7. Trademarks

"TraceSeal" is the project's name. The Apache License 2.0 does not grant
permission to use it beyond what its Section 6 allows.
Regulations, standards and frameworks are named only to describe what the
software relates to; no endorsement by any authority or standards body is
implied.
