# Evidence Vault

Receipts carry hashes, so they can be shared without leaking data. Disputes
and regulator requests eventually need the payload itself: the prompt, the
tool arguments, the response. The evidence vault keeps those payloads
encrypted, erasable and provable.

```python
from traceseal_observe.vault import EvidenceVault, LocalKEK, open_disclosure, verify_disclosure

vault = EvidenceVault.open("/var/lib/agent/vault", kek=LocalKEK(kek_bytes), min_retention_days=183)

response, receipt = observe_anthropic(client, request, signer)
vault.put_for(receipt, "input_hash", request, domain=f"tenant:{tenant}")    # refuses a mismatch
vault.put_for(receipt, "output_hash", response.model_dump(), domain=f"tenant:{tenant}")
```

## Design

| Property | How |
|---|---|
| Provable against receipts | Payloads are stored under `sha256_of(value)`, the hash receipts already commit to. `put_for` refuses a value that doesn't match the receipt. |
| Encrypted at rest | AES-256-GCM per payload. The associated data binds the domain and the hash, so ciphertexts can't be swapped. |
| Erasable at the right granularity | One data key per **shred domain**: a tenant, a user (use the principal commitment), or a retention period. |
| KMS-ready | Data keys are wrapped by a key-encryption key: `LocalKEK`, or `KMSKEK(wrap_fn, unwrap_fn)` for a cloud KMS or HSM. `KMSKEK` only wraps: the wrapped data keys still live in the vault directory (see Crypto-shredding for what that means for backups). |
| Retention | `min_retention_days` sets a floor (AI Act Art. 19 / 26(6), for high-risk systems: at least six months for logs, unless Union or national law, in particular data-protection law, provides otherwise). A reopened vault can't lower it. Optional per-domain `delete_after` (GDPR Art. 5(1)(e)) is applied by `enforce_retention()`. |
| Legal hold | `set_legal_hold(domain)` blocks every shred, including expiry and overrides. |
| Disclosure | `disclose(hash, auditor_public_key)` seals one payload with HPKE (RFC 9180): X25519, or the post-quantum hybrid ML-KEM-768+X25519. The auditor runs `open_disclosure()`, which re-checks the hash. |

## Crypto-shredding

```python
erasure_receipt = vault.shred("principal:hmac-sha256:…", operator_key=chain.signer,
                              reason="data_subject_request")
```

1. The domain's wrapped data key is overwritten and deleted, which makes
   its payloads unreadable.
2. The payload files are deleted.
3. A signed, chainable **`erasure` receipt** records:
   - `domain_hash`: `hmac-sha256:…`, an HMAC-SHA256 of the domain name
     under a secret per-vault salt (`domain_salt` in `vault.json`, created
     on first open, also for vaults made by older versions). A receipt
     holder can't confirm a guessed name (`tenant:acme`,
     `principal:<ref from another receipt>`). `vault.domain_hash(name)`
     gives the vault holder the value to look up. Opening a vault with
     1.6 marks it version 1.1 so older releases refuse it instead of
     dropping the salt. `erasure_version` is `"1.1"`;
   - `object_count`, and `objects_root`, a commitment to the sorted list
     of destroyed payload hashes;
   - `reason`: `data_subject_request`, `retention_expired` or `other`;
   - `retention_overridden`: `"true"` if the shred happened before
     `retain_until` with `override_retention=True`. A legal retention duty
     can outweigh an erasure request (GDPR Art. 17(3)(b)), so this choice
     is recorded rather than hidden. `override_retention=True` without
     `operator_key` raises: an override always leaves a signed receipt. Keeping data after an erasure request
     must rest on an Art. 17(3) exception that applies to you.

All receipts remain valid after shredding: the signatures were over
hashes. `erasure_covers(erasure_receipt, hashes, h)` shows a given payload
was in the erased set.

**What deleting a file does not do:** securely erase it from SSDs,
snapshots or backups. That is why the scheme destroys *keys*. A *wrapped*
data key recovered from a backup can still be unwrapped while the
key-encryption key exists. **This is true with `KMSKEK` as well:** the KMS
only wraps and unwraps, the wrapped data keys are files in the vault, so a
pre-shred backup restored next to the same KMS key reads everything back.
For a shred to reach backups, after shredding call
`vault.rotate_kek(new_kek)` (a new KMS key or key version) and then
destroy the old KEK (schedule deletion of the old key version). Until the
old KEK is destroyed, backups taken before the shred remain readable.

**The vault directory is not anonymised.** Domain records
(`domains/<sha256(name)>.json`) hold the domain name in clear, and both
they and `objects/<sha256(name)>/` are named by a plain SHA-256 of the
name. Protect the directory and its backups as personal data.

## Auditor side

```python
value = open_disclosure(bundle, auditor_private_key)    # raises unless hash matches
assert verify_disclosure(value, receipt, "input_hash")   # and the receipt commits to it
```

Then verify the receipt itself with `traceseal-verify`.

## Limits

- One process owns a vault directory at a time. Add locking or a database
  backend for multi-writer deployments.
- Payload hashes are unsalted, as in receipts. A low-entropy payload
  (`"yes"`) can be guessed from its hash. Keep that in mind when deciding
  what receipts may be published.
