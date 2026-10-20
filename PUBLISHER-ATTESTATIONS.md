# TraceSeal publisher artefact attestation profile

This additive profile supplies offline Ed25519 publisher signatures for Open
Registry canonical model identities. It reuses TraceSeal's compact sorted-key
JSON encoder and hardened private-key loader, but it is deliberately not a
TraceSeal operator-receipt envelope.

## Claim separation

- A publisher attestation means the holder of one publisher key authorised the
  exact signed artefact statement.
- A TraceSeal identity receipt means an operator key evaluated specified
  publisher evidence alongside canonical identity evidence.
- A TraceSeal identity witness means another key re-verified that supplied
  publisher evidence and independently re-observed the selected source bytes.
- A C2SP log witness proves checkpoint consistency only.

None establishes legal identity, platform-account ownership, model safety,
licence interpretation, full-model equivalence or trusted time.

## Publisher identity

The canonical public key is 32 raw Ed25519 bytes encoded as 64 lowercase hex
characters. The domain-specific fingerprint is the complete digest:

```text
ed25519: + lowercase_hex(SHA-256(raw-public-key))
```

This full fingerprint is intentionally distinct from historical skill-receipt
display fields. Verifiers recompute it from the embedded key. Optional display
metadata is `unsigned_unverified` and cannot alter the fingerprint.

## Signed statement

The publisher signs the UTF-8 compact sorted-key encoding, without a newline,
of exactly `attestation_version` and `statement`:

```json
{
  "attestation_version": "1.0",
  "statement": {
    "artifact": {
      "artifact_type": "model",
      "canonical_id": "sha256:<64 lowercase hex>",
      "equivalence_root": "sha256:<64 lowercase hex>"
    },
    "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
    "publisher": {
      "fingerprint": "ed25519:<64 lowercase hex>"
    },
    "statement_type": "model_artifact_authorisation"
  }
}
```

The complete attestation adds `signature.algorithm`, `public_key`, recomputed
`fingerprint` and 64-byte lowercase-hex signature. Unknown or duplicate JSON
keys, alternative algorithms, malformed hex and non-UTC times fail closed.
`issued_at` is a signed clock claim, not trusted time or replay prevention.

The current Phase 2A.1 identity establishes only four selected files. The
publisher statement therefore has no licence, manifest or full-content field.
A valid signature bound to a different current canonical/equivalence record is
`publisher_attestation_stale`; statement mutation is
`publisher_signature_invalid`.

## Offline CLI

```text
publisher-attest sign \
  --identity IDENTITY \
  --huggingface-observation HF_OBSERVATION \
  --modelscope-observation MS_OBSERVATION \
  --key PUBLISHER_KEY \
  --output ATTESTATION \
  [--issued-at UTC]

publisher-attest verify \
  --identity IDENTITY \
  --huggingface-observation HF_OBSERVATION \
  --modelscope-observation MS_OBSERVATION \
  ATTESTATION
```

Signing re-derives canonical identity first. The private key is descriptor-
pinned and must be a same-owner, owner-only regular file with one link. Output
is a new mode-0600 file and is never overwritten. Both commands are offline;
they perform no repository import, artefact download, cache write or log
publication.

## TraceSeal identity commitment

`traceseal-identity sign` and `witness` accept repeatable
`--publisher-attestation` files. When present, signed execution includes:

- `publisher_evidence_root`;
- `publisher_evidence_status`;
- ordered `publisher_attestation_hashes`.

The original canonical identity remains unchanged. The witness reconstructs
the attachment and independently verifies every publisher signature,
fingerprint and current-artefact binding before source re-observation and
countersigning. Historical/no-publisher receipts retain their exact prior
execution contract.

Platform organisation evidence and publisher signatures remain separate.
The additive Phase 2A.3 repository-scoped account-to-key discovery profile is
specified in [PUBLISHER-BINDINGS.md](PUBLISHER-BINDINGS.md). Revocation,
account-wide delegation, multisignature policy and governed transparency
publication remain outside both profiles.
