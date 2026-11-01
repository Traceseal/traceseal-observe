# Trusted Time: RFC 3161 and eIDAS Timestamps

Every TraceSeal receipt carries the operator's own clock claim (`started_at`,
`chained_at`, `attested_at`). Under a dispute or an audit, "our server's
clock said so" is weak evidence. A **time-stamping authority (TSA)** is an
independent party that signs "this hash existed at this time" (RFC 3161).
In the EU, a *qualified* time stamp from a qualified trust service provider
has a legal presumption that its date, time and data integrity are accurate
(eIDAS Regulation (EU) 910/2014 as amended by (EU) 2024/1183, Art. 41(2)).

```bash
pip install "traceseal-observe[timestamp]"   # adds asn1crypto for CMS parsing
```

## What to timestamp

**Checkpoints, not individual receipts.** One token over a chain
checkpoint covers every receipt up to that checkpoint, through the Merkle
root and the hash links. So the cost is one TSA request per checkpoint
(for example every minute, or every 1,000 receipts), whatever the agent's
volume.

```python
from traceseal_observe.timestamp import timestamp_checkpoint

checkpoint = chain.checkpoint()
token = timestamp_checkpoint(checkpoint, "https://tsa.example/",
                             headers={"Authorization": "Bearer ..."})  # if the TSA needs it
Path(f"checkpoints/{chain.size}.txt").write_text(checkpoint)
Path(f"checkpoints/{chain.size}.tsr").write_bytes(token)
```

The token covers the checkpoint **body**: the origin, size and root lines,
without signature lines. A witness cosignature added later doesn't change
what was timestamped.

Individual receipts can also be stamped directly:
`request_timestamp(url, digest=receipt_digest(receipt))`.

## What it buys you

| Question | Without a TSA | With a timestamped checkpoint |
|---|---|---|
| Were these receipts created later and backdated? | the operator's clock | **No later than the TSA's genTime.** Receipt hashes are fixed by the token. |
| Is anything from before the window hidden in it? | `chained_at` claims | **Provable** with a start checkpoint stamped before the window opened (`start_basis: "trusted_time"`, RECEIPT-CHAINS.md §1.4) |
| Is the tail of the window complete? | `chained_at` claims | `published_checkpoint`. Still assumes the operator stamped its current checkpoint promptly; see RECEIPT-CHAINS.md §1.4. |
| Does the signer's clock run ahead? | undetectable | flagged when `chained_at` is later than a trusted time that already covers the receipt |

## Verifying

```bash
traceseal-chain timestamp-verify --checkpoint cp.txt --timestamp cp.tsr --tsa-root tsa-root.pem
traceseal-chain verify receipts/*.json --checkpoint cp.txt \
    --checkpoint-timestamp cp.tsr --tsa-root tsa-root.pem
```

```python
from traceseal_observe.timestamp import verify_timestamp_token, checkpoint_body, load_certificates

info = verify_timestamp_token(token, data=checkpoint_body(checkpoint),
                              trust_anchors=load_certificates(Path("tsa-root.pem").read_bytes()))
info["gen_time"], info["policy"], info["etsi_qualified_statement"]
```

The verifier checks:
- the TimeStampResp status, the TSTInfo version, the message imprint and
  the nonce;
- the CMS signature over the signed attributes;
- the `contentType` and `messageDigest` attributes;
- the ESS signing-certificate binding (v1 or v2);
- that the TSA certificate has exactly one EKU, `id-kp-timeStamping`, and
  that it is critical;
- a certificate path to *your* trust anchors, with every certificate valid
  at genTime.

Signatures can be RSA PKCS#1 v1.5, RSA-PSS, ECDSA or Ed25519, with SHA-256,
SHA-384 or SHA-512.

Interoperability: tokens issued by `openssl ts -reply` (ESS v1 and v2,
SHA-256 and SHA-512, with and without embedded certificates) verify, and
`openssl ts -verify` accepts tokens over TraceSeal checkpoint bodies.

**Not checked:** certificate revocation (CRL/OCSP), and TSA status on a
trusted list at genTime. Tokens that must stay verifiable after the TSA
certificate expires need archive timestamps (RFC 4998, ETSI EN 319 102-1),
which aren't implemented.

## eIDAS qualified timestamps

1. Pick a qualified trust service provider that offers *qualified
   electronic time stamps*. They are listed on the EU Member State trusted
   lists; browse them with the European Commission's eIDAS dashboard.
2. Use that service's TSA URL (often authenticated: pass `headers=`).
3. Give auditors the TSA certificates from the trusted-list entry as
   `--tsa-root`.

The verification report includes two signals:
- `etsi_best_practice_policy`: the token uses the ETSI EN 319 421
  best-practices policy OID `0.4.0.2023.1.1`.
- `etsi_qualified_statement`: the TSTInfo carries the ETSI EN 319 422
  `esi4-qtstStatement-1` extension (`0.4.0.19422.1.1`), the TSA's own
  statement that this is an EU qualified time stamp.

Whether the provider *is* qualified is decided by the trusted list, which
this library doesn't fetch or parse. The trust anchors you pass are the
decision. Treat `etsi_qualified_statement` as the TSA's claim, confirmed
only by anchoring to a trusted-list entry.

## Mapping to obligations

This mapping is informational, not legal advice.

- **EU AI Act Art. 12 (record-keeping) and Art. 19 / 26(6) (keeping logs
  for at least 6 months):** independent evidence of *when* logged events
  occurred, and that the log wasn't rewritten afterwards.
- **eIDAS Art. 41(2):** the legal presumption applies to qualified time
  stamps only.
- **DORA / NIS2 incident timelines:** a timestamped checkpoint fixes the
  state of the agent's log before an incident report was written.
