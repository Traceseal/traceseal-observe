# Receipt Chains and Streaming Model Receipts

**Version:** 1.0 (additive to RECEIPT-SPEC.md v1.0)
**Status:** Draft

This document defines two additions to the v1 receipt envelope. Neither one
changes the envelope, canonical JSON or signature algorithm. Receipts without
these fields keep their existing meaning.

1. **Receipt chains**: signed sequence fields that make *missing* receipts
   detectable, plus RFC 6962 checkpoints and proofs.
2. **Streaming and response metadata** on `model` receipts.

---

## 1. Receipt chains

### 1.1 Problem

A valid signature shows that a receipt is authentic. It says nothing about
receipts that were never shown. An operator who hands an auditor 40 of the
42 receipts from a session gives them 40 valid signatures, and the auditor
has no way to see that two are missing. A chain closes that gap for one
signer stream.

### 1.2 Chained fields

A chained receipt has these fields inside `execution`, where the existing
signature covers them:

| Field | Type | Rule |
|---|---|---|
| `chain_version` | string | `"1.0"` |
| `chain_id` | string | `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`; names the stream (an agent, a worker) |
| `chain_seq` | integer | 1, 2, 3, … with no gaps, per (operator key, `chain_id`) |
| `chain_prev_hash` | string | `"genesis"` if and only if `chain_seq` is 1; otherwise the `receipt_hash` of receipt `chain_seq - 1` |
| `chained_at` | string | UTC `YYYY-MM-DDTHH:MM:SSZ`; equal to `attestation.attested_at` at signing |

`receipt_hash` is `sha256_of(receipt)`: SHA-256 of the canonical JSON of
the whole receipt, attestation included. So each link also commits to the
previous receipt's otherwise-unsigned `attested_at`.

Only the operational types `model`, `tool`, `data_flow`, `orchestration` and
`outcome` are chained, plus the chain's own `chain_key_rotation` (§1.6). Domain-profile receipts (resolution, identity,
selection) have strict field sets. A chained signer refuses to sign them
rather than leave them silently outside the chain.

### 1.3 Merkle tree and checkpoints

Receipts are the leaves of an RFC 6962 / RFC 9162 Merkle tree, in
`chain_seq` order:

```
leaf_hash(receipt) = SHA-256(0x00 || raw 32-byte digest of receipt_hash)
node_hash(l, r)    = SHA-256(0x01 || l || r)
```

A **checkpoint** is a C2SP signed note (`c2sp.org/tlog-checkpoint`,
`c2sp.org/signed-note`):

```
traceseal.io/chain/<sha256 hex of operator public key>/<chain_id>
<tree size N>
<base64 Merkle root over receipts 1..N>

— <same origin line> <base64(4-byte key hash || 64-byte Ed25519 signature)>
```

The signature covers the three body lines, each ending in a newline. The key
hash is `SHA-256(origin || "\n" || 0x01 || public_key)[:4]`, and the
verifier key string is `origin+<keyhash hex>+base64(0x01 || public_key)`.
Standard signed-note tooling accepts these. The format has been
cross-checked against Go's `golang.org/x/mod/sumdb/note`, and the roots and
proofs against `golang.org/x/mod/sumdb/tlog`.

A C2SP witness may add `cosignature/v1` lines (key algorithm `0x04`, signed
message `"cosignature/v1\ntime <unix seconds>\n" || body`). Verifiers check
the witnesses they require and ignore other signature lines.

### 1.4 Verification

Given a set of receipts, a verifier:

1. Verifies each receipt's v1 signature and the fields in §1.2.
2. Requires one `chain_id` and one operator public key across the set.
3. Groups by `chain_seq`. Two *different* receipts at one position are a
   **fork** (equivocation): INVALID. Identical copies are deduplicated.
4. For each pair of consecutive positions present, requires
   `chain_prev_hash` to equal the earlier `receipt_hash`. Missing positions
   are reported as **gaps**, and a set with gaps is not complete.
5. Optionally verifies a checkpoint for size `N`:
   - If the set is exactly receipts 1..N (or more), recomputes the root.
     A mismatch means the checkpointed history is a different one: INVALID.
   - Otherwise it needs an **inclusion proof** for the highest supplied
     `chain_seq ≤ N`. Because of the hash links, that one proof anchors
     every earlier receipt in the contiguous segment.
6. Optionally verifies RFC 3161 timestamp tokens over a checkpoint's body
   (the three note lines, without signature lines, so a later witness
   cosignature doesn't change what was timestamped). See TRUSTED-TIME.md.
7. Optionally checks a time **window** `[start, end]`: are all receipts
   created in the window in the supplied set? Each edge reports its
   **basis**, from strongest to weakest:

   | Edge | Basis | Evidence |
   |---|---|---|
   | start | `genesis` | the segment starts at `chain_seq` 1 |
   | start | `trusted_time` | a *start checkpoint* of size `M ≥ first_seq − 1`, with a TSA token or witness cosignature dated at or before `start`, shown consistent with the main checkpoint by a consistency proof. Receipts 1..M existed before the window opened, so anything created later has a higher `chain_seq`. This rests on the TSA or witness, not on the operator. |
   | start | `signer_clock` | the first receipt's `chained_at` is before `start` |
   | end | `published_checkpoint` | the segment ends at the head of an anchored checkpoint carrying a TSA token or witness cosignature dated at or after `end` |
   | end | `signer_clock` | the last receipt's `chained_at` is after `end` |

   A window is `complete` when both edges have a basis and there are no
   gaps or errors.

   **The end edge is weaker than it looks.** A TSA or witness time is an
   *upper* bound: it proves the checkpoint existed by then, not that it was
   the newest checkpoint then. Both end bases assume the operator was honest
   *at the time*, i.e. it put the current time in `chained_at` and
   timestamped or witnessed its current checkpoint promptly. That is the
   threat model chains are built for: logs that are altered *after the
   fact*, once someone wants something to disappear. An operator dishonest
   from the start can leave actions out of the chain entirely, and no log
   format can detect that.

A **consistency proof** (RFC 9162 §2.1.4) shows that a checkpoint of size
`N` extends an earlier checkpoint of size `M`. A witness checks this before
cosigning.

### 1.5 What chains prove, and what they don't

**Prove:**
- Within a chain, no receipt was removed, inserted or replaced after the fact.
- No two conflicting histories were shown for the same position (provided the
  verifier sees both).
- Once a checkpoint of size `N` is held by someone other than the operator,
  every receipt up to `N` is pinned. Dropping receipts from the tail is then
  detectable.

**Don't prove:**
- That every action was chained. An action signed with an unchained key, or
  never signed, is simply outside the chain. That part is policy: require
  all agent receipts to be chained and checkpointed.
- Anything about the tail after the newest checkpoint someone else holds.
  Publish checkpoints often (for example every N receipts or every minute)
  and send them to a witness, a customer or an auditor.
- That `chained_at` is true time. It is a signed clock claim. RFC 3161 /
  eIDAS timestamps and witness cosignatures on checkpoints are the stronger
  evidence (§1.4 step 7).

### 1.6 Key rotation and compromise

A chain outlives any one signing key. `ReceiptChain.rotate_key(new_key)`
appends a chained `chain_key_rotation` receipt, **signed by the outgoing
key**, with these fields:

| Field | Rule |
|---|---|
| `rotation_version` | `"1.0"` |
| `rotation_reason` | `"scheduled"` or `"compromise"` |
| `previous_public_key` | the signing key of this receipt |
| `next_public_key` | the incoming key; signs every later receipt |
| `next_key_acceptance` | the incoming key's Ed25519 signature over canonical JSON `{chain_id, chain_prev_hash, chain_seq, next_public_key, previous_public_key, purpose: "traceseal-chain-key-acceptance/1"}`, binding its consent to this exact position in this chain |
| `previous_key_compromised_after_seq` | optional, with `compromise` only: an integer `X` < this `chain_seq` |

Verifiers start from the key that signed the first supplied receipt (or
the `operator_public_key` they already trust). They accept a different key
only right after a valid rotation, and treat any other key change as an
error. A key change hidden inside a gap is a warning, because the rotation
can't be checked.

`previous_key_compromised_after_seq = X` declares receipts `X+1 .. k−1`
(where `k` is the rotation's `chain_seq`) untrustworthy. They are listed in
`compromised_seqs`. The declaration is signed by the compromised key, so an
attacker holding that key could sign a rotation too. Two different
rotations at one position are then a fork. The defence is checkpoints that
reached third parties before the compromise.

Checkpoints are signed by whichever key is current, under that key's
origin line. Verifiers resolve the signing key from the origin among the
chain's keys. After a rotation, a C2SP witness therefore sees a new origin.
The rotation receipt is what links the two.

### 1.7 Operator API

```python
from traceseal_observe import OperatorKey, ReceiptChain, observe_anthropic

key = OperatorKey.load_from_file("~/.traceseal/keys/operator.key")
chain = ReceiptChain.open("/var/lib/agent/chain", key, "support-agent")
signer = chain.signer                    # use wherever an OperatorKey goes

response, receipt = observe_anthropic(client, request, signer)

checkpoint = chain.checkpoint()          # C2SP note; send it off-box
token = timestamp_checkpoint(checkpoint, "https://tsa.example/")  # RFC 3161
chain.rotate_key(new_key)                # chained, dual-signed handover
proof = chain.inclusion_proof(seq=17)    # for disclosing a partial segment
consistency = chain.consistency_proof(old_size=100)
```

`ReceiptChain.open` keeps a small directory: `chain.json`, an append-only
`receipt-hashes.bin` (32 bytes per receipt, fsynced before the receipt is
returned), and an exclusive lock so one process owns a chain at a time. Run
one chain per worker. The chain stores hashes only, so keeping the receipts
themselves is the operator's job. A receipt that is signed and then lost
shows up as a gap, which is the honest result.

### 1.8 Auditor CLI

```bash
traceseal-chain verify receipts/*.json --checkpoint checkpoint.txt
traceseal-chain verify receipts/*.json --checkpoint cp.txt \
    --inclusion-proof proof.json --witness-vkey '<witness vkey>' \
    --window-start 2026-10-01T14:00:00Z --window-end 2026-10-01T16:00:00Z
```

The exit code is 0 only if the chain is complete and, when a window is
given, the window is covered. Trusted-time evidence:

```bash
traceseal-chain timestamp --checkpoint cp.txt --tsa-url https://tsa.example/ --output cp.tsr
traceseal-chain verify receipts/*.json \
    --checkpoint cp.txt --checkpoint-timestamp cp.tsr --tsa-root tsa-root.pem \
    --start-checkpoint cp-0959.txt --start-timestamp cp-0959.tsr \
    --start-consistency-proof consistency.json \
    --inclusion-proof proof.json \
    --window-start 2026-10-01T10:00:00Z --window-end 2026-10-01T12:00:00Z
```

---

## 2. Streaming and response metadata on `model` receipts

### 2.1 Response metadata

`model` receipts may carry these optional signed strings (1–256 characters;
longer values are left out, never truncated):

| Field | Source |
|---|---|
| `served_model` | the model the provider reported in its response (`model`) |
| `response_id` | the provider's response or message id |
| `stop_reason` | `stop_reason` (Anthropic) or `choices[0].finish_reason` (OpenAI) |
| `system_fingerprint` | OpenAI `system_fingerprint` |

`model` stays the model the operator *requested*. `served_model` is what
the provider *said* it served, recorded by the operator. It is not signed by
the provider.

### 2.2 Streams

| Field | Rule |
|---|---|
| `response_mode` | `"stream"` |
| `stream_chunk_count` | number of chunks received |
| `stream_complete` | `"true"` if the stream reached its end, `"false"` if it was closed early or failed |

For a stream, `output_hash = sha256_of([chunk_1, …, chunk_n])`, the hash of
the canonical JSON array of the serialized chunks *actually received*, in
order. Anyone holding the chunks can recompute it. `ok` is `"false"` only if
the call or the stream raised an error. A stream the caller deliberately
stopped has `ok: "true"` and `stream_complete: "false"`.

If `observe_model_call` gets a stream back with no serializer, it does not
hash the stream object. It returns the stream unconsumed and signs
`ok: "false"`, `output_hash: "sha256:empty"`, `response_mode: "stream"`, with
an error saying the output was not observed. `observe_anthropic` and
`observe_openai` refuse `stream=True` before calling the provider. Use
`observe_anthropic_stream` / `observe_openai_stream` / `observe_model_stream`
instead.
