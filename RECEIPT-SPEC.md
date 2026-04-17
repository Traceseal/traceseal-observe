# Traceseal Execution Receipt Specification

**Version:** 1.0
**Status:** Draft
**Date:** April 2026

## Abstract

An Execution Receipt is a signed, self-contained JSON document that
proves a specific piece of code ran inside a specific sandbox and
produced a specific result. A third party can verify the receipt
without access to the operator's machine, the original code, or
any private keys. Verification requires only the receipt file itself.

This specification defines the receipt format, the signing convention,
and the verification algorithm. It is intentionally minimal: any
developer who reads this document can implement a receipt verifier
in any programming language without needing access to the Traceseal
source code or any proprietary tooling.

## 1. Purpose

AI agents execute code on behalf of users, enterprises, and automated
systems. Today there is no standard way to answer the question: "can
you prove what your agent was running, who authorized the code, and
what it produced?"

An Execution Receipt answers that question cryptographically. It
contains three sections:

- **Execution** — what ran (skill identity, sandbox configuration,
  input/output hashes, timing, exit status)
- **Provenance** — who authorized the code (publisher identity,
  per-file content hashes, transparency log reference)
- **Attestation** — the operator's ed25519 signature over both,
  asserting "this execution occurred as described"

A verifier checks the attestation signature, confirms internal
consistency, and concludes: "the operator attests that this signed
code ran inside this sandbox and produced this output hash." Trust
in the operator's identity and the publisher's identity is a separate
policy decision outside the scope of this specification.

## 2. Receipt Format

A receipt is a JSON object with four top-level fields:

```json
{
  "receipt_version": "1.0",
  "execution": { ... },
  "provenance": { ... },
  "attestation": { ... }
}
```

### 2.1 receipt_version

A string. MUST be `"1.0"` for receipts conforming to this
specification. Verifiers MUST reject receipts with unrecognized
versions.

### 2.2 execution

A JSON object describing what was executed. All fields are REQUIRED
unless marked optional.

|Field                 |Type   |Description                                                                                                                                                |
|----------------------|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
|`skill_name`          |string |The name of the skill that was executed.                                                                                                                   |
|`skill_version`       |string |The version of the skill (semver).                                                                                                                         |
|`skill_manifest_hash` |string |SHA-256 hash of the signed manifest (`"sha256:<hex>"`). Links the execution to a specific signed code artifact.                                            |
|`timestamp`           |string |ISO 8601 UTC timestamp of the execution.                                                                                                                   |
|`inputs_hash`         |string |SHA-256 hash of the canonical JSON representation of the inputs passed to the skill. `"sha256:empty"` if no inputs.                                        |
|`outputs_hash`        |string |SHA-256 hash of the canonical JSON representation of the skill's return value. `"sha256:empty"` if no output.                                              |
|`exit_code`           |integer|Process exit code. 0 for success, -1 if the process did not start.                                                                                         |
|`wall_time_ms`        |integer|Wall-clock execution time in milliseconds.                                                                                                                 |
|`ok`                  |string |`"true"` if the execution succeeded, `"false"` otherwise. Encoded as a string, not a JSON boolean, for canonical JSON compatibility.                       |
|`sandbox_profile_hash`|string |SHA-256 hash of the sandbox configuration (bwrap argument list + environment). Allows a verifier to check whether the sandbox matched a known-good profile.|
|`audit_entry_hash`    |string |SHA-256 hash of the audit log entry this receipt was generated from. Links the receipt back to the operator's hash-chained audit log.                      |
|`entry_point_name`    |string |*(Optional)* For bundle skills with multiple entry points, the name of the entry point that was dispatched. Omitted for single-entry-point skills.         |

**Note on input/output privacy:** The receipt contains *hashes* of
inputs and outputs, not the values themselves. A verifier who has the
original input can recompute `inputs_hash` and confirm it matches the
receipt, proving "this specific input was used." A verifier without
the original input can only confirm "some input with this hash was
used." This is deliberate: receipts can be shared publicly without
leaking the data that was processed.

### 2.3 provenance

A JSON object describing who authorized the code. All fields are
OPTIONAL because a receipt may be generated from an unsigned skill
(in which case provenance is sparse). However, a receipt with full
provenance is significantly more useful to a verifier.

|Field                        |Type   |Description                                                                                                                                                                    |
|-----------------------------|-------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`manifest_hash`              |string |SHA-256 hash of the signed manifest. MUST match `execution.skill_manifest_hash` when both are present.                                                                         |
|`publisher_fingerprint`      |string |The publisher's key fingerprint (`"ed25519:<hex>"`). Identifies who signed the code.                                                                                           |
|`publisher_public_key`       |string |The publisher's raw ed25519 public key, hex-encoded. Allows a verifier to independently verify the manifest signature if they have the `skill.lock` and `skill.lock.sig` files.|
|`published_at`               |string |ISO 8601 UTC timestamp of when the skill was signed.                                                                                                                           |
|`artifacts`                  |object |Map of `{filename: "sha256:<hex>"}` for every file covered by the manifest. Allows a verifier to check whether specific source files match expected hashes.                    |
|`transparency_log_seq`       |integer|Sequence number in the transparency log where this manifest was recorded.                                                                                                      |
|`transparency_log_entry_hash`|string |Hash of the transparency log entry. Allows a verifier with access to the log to confirm the entry exists and is valid.                                                         |

### 2.4 attestation

A JSON object containing the operator's cryptographic signature over
the execution and provenance sections.

|Field                 |Type  |Description                                                                                                                                                              |
|----------------------|------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|`operator_fingerprint`|string|The operator's key fingerprint (`"ed25519:<hex>"`). Identifies who is attesting to this execution.                                                                       |
|`operator_public_key` |string|The operator's raw ed25519 public key, hex-encoded. Embedded in the receipt so verification is self-contained — the verifier does not need to look up the key separately.|
|`attested_at`         |string|ISO 8601 UTC timestamp of when the receipt was generated and signed.                                                                                                     |
|`signature`           |string|Hex-encoded ed25519 signature over the **signed payload** (see §3).                                                                                                      |

## 3. Signing Convention

The **signed payload** is the canonical JSON encoding of a JSON object
containing exactly two fields:

```json
{
  "execution": <the execution object from §2.2>,
  "provenance": <the provenance object from §2.3>
}
```

The canonical JSON encoding follows these rules:

1. Keys are sorted lexicographically at every nesting level.
1. No whitespace between tokens (compact encoding).
1. No trailing newline.
1. Strings are UTF-8 encoded.
1. Integers are encoded without leading zeros.
1. No JSON booleans or nulls — use `"true"`, `"false"`, `""` strings
   instead. This matches the Traceseal audit log convention and
   ensures byte-deterministic encoding across implementations.

The **signature** is computed as:

```
signature = ed25519_sign(operator_private_key, canonical_json_bytes)
```

The signature is hex-encoded in the receipt's `attestation.signature`
field.

## 4. Verification Algorithm

A verifier receives a receipt (a JSON file) and performs these checks
in order. If any check fails, the receipt is INVALID.

### Step 1: Structure check

Verify that the receipt is a JSON object with fields `receipt_version`,
`execution`, `provenance`, and `attestation`, all of which are JSON
objects (except `receipt_version`, which is a string).

Verify that `receipt_version` is `"1.0"`.

### Step 2: Manifest hash consistency

If both `execution.skill_manifest_hash` and `provenance.manifest_hash`
are present and non-empty, verify they are equal. A mismatch indicates
the execution and provenance sections refer to different code
artifacts, which is either a bug or tampering.

### Step 3: Load the operator's public key

Read `attestation.operator_public_key` (hex-encoded raw ed25519 public
key, 32 bytes). Decode it. If the key is malformed, the receipt is
INVALID.

### Step 4: Reconstruct the signed payload

Construct the JSON object:

```json
{
  "execution": <receipt.execution>,
  "provenance": <receipt.provenance>
}
```

Encode it as canonical JSON following the rules in §3.

### Step 5: Verify the signature

Verify the ed25519 signature:

```
ed25519_verify(
  operator_public_key,
  canonical_json_bytes,
  hex_decode(attestation.signature)
)
```

If verification fails, the receipt is INVALID — either the payload was
tampered with after signing, or the signature was not produced by the
claimed operator key.

### Step 6: Receipt is VALID

If all checks pass, the receipt is cryptographically valid. The
verifier can conclude:

> "The holder of ed25519 key `attestation.operator_fingerprint` attests
> that skill `execution.skill_name` version `execution.skill_version`,
> signed by publisher `provenance.publisher_fingerprint`, was executed
> at `execution.timestamp` inside a sandbox with profile hash
> `execution.sandbox_profile_hash`, receiving input with hash
> `execution.inputs_hash` and producing output with hash
> `execution.outputs_hash`."

**What this does NOT prove:**

- That the operator's key is who they claim to be (key distribution
  is outside this spec).
- That the publisher's key is who they claim to be.
- That the sandbox actually enforced the declared profile (the receipt
  records what the operator *claims* the sandbox was; a compromised
  operator could lie).
- That the inputs or outputs had any particular content (the receipt
  contains hashes, not values).

These are policy questions for the verifier. The receipt provides the
cryptographic primitive; trust decisions are built on top of it.

## 5. Canonical JSON Reference Implementation

For interoperability, here is a reference implementation of the
canonical JSON encoder in Python:

```python
import json

def canonical_dumps(obj: dict) -> bytes:
    """Encode a dict as canonical JSON bytes.

    Rules:
    - Keys sorted lexicographically at every level
    - Compact encoding (no whitespace)
    - No booleans or nulls (use "true", "false", "" strings)
    - UTF-8 encoded
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
```

And a reference implementation of the verification algorithm:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def verify_receipt(receipt: dict) -> bool:
    """Verify a receipt. Returns True if valid, False otherwise."""
    if receipt.get("receipt_version") != "1.0":
        return False

    execution = receipt.get("execution")
    provenance = receipt.get("provenance")
    attestation = receipt.get("attestation")

    if not all([execution, provenance, attestation]):
        return False

    # Manifest hash consistency
    exec_hash = execution.get("skill_manifest_hash", "")
    prov_hash = provenance.get("manifest_hash", "")
    if exec_hash and prov_hash and exec_hash != prov_hash:
        return False

    # Load operator public key
    try:
        pk_bytes = bytes.fromhex(attestation["operator_public_key"])
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    except (ValueError, KeyError):
        return False

    # Reconstruct signed payload
    payload = canonical_dumps({
        "execution": execution,
        "provenance": provenance,
    })

    # Verify signature
    try:
        sig = bytes.fromhex(attestation["signature"])
        pk.verify(sig, payload)
        return True
    except Exception:
        return False
```

## 6. Security Considerations

### 6.1 Operator trust

The receipt proves that the operator's key signed the attestation.
It does NOT prove the operator is honest. A malicious operator could
generate a receipt for an execution that never happened, or for a
sandbox profile they didn't actually use. The receipt is an
*attestation*, not a *proof of execution* in the zero-knowledge
sense.

In practice, trust in the operator is established through out-of-band
mechanisms: the operator's key is published in a directory, the
operator has a contractual relationship with the verifier, or the
operator's key is endorsed by a certificate authority. This
specification does not prescribe a key distribution mechanism.

### 6.2 Publisher trust

The provenance section includes the publisher's fingerprint and
public key. A verifier who trusts the publisher can independently
verify that the manifest hash in the receipt matches a known-good
skill artifact. A verifier who does not know the publisher treats
the provenance as informational.

### 6.3 Replay protection

Each receipt includes a timestamp (`execution.timestamp` and
`attestation.attested_at`) and an `audit_entry_hash` linking it to a
specific position in the operator's hash-chained audit log. A verifier
who has access to the operator's audit log (or a previous receipt from
the same operator) can detect replayed or out-of-order receipts by
checking the hash chain. A verifier without audit log access cannot
detect replays; they can only verify that the receipt is internally
consistent.

### 6.4 Privacy

Receipts contain hashes of inputs and outputs, not the values
themselves. This allows receipts to be shared publicly or submitted
to compliance systems without leaking the data that was processed.
If a verifier needs to confirm specific input/output content, the
operator provides the original data separately and the verifier
recomputes the hash.

The `artifacts` field in provenance contains per-file content hashes,
which may reveal information about the skill's source code structure
(file names and their hashes). Operators who need to conceal source
code structure should omit the `artifacts` field from provenance. A
receipt without `artifacts` is still verifiable; it simply provides
less provenance detail.

## 7. IANA Considerations

This specification does not require any IANA actions. The `ed25519:`
fingerprint prefix and `sha256:` hash prefix are conventions within
the Traceseal ecosystem and do not conflict with existing IANA
registries.

## 8. Acknowledgments

The Execution Receipt format builds on prior work in software supply
chain security, particularly Sigstore's approach to transparency logs
and The Update Framework's approach to signed metadata. The key
insight specific to this specification is applying these techniques
to *runtime execution* of AI agent code, not just to software
distribution.

## Appendix A: Complete Receipt Example

The following is a real receipt generated from a signed skill bundle
running under strict kernel-namespace isolation on Debian 13:

```json
{
  "attestation": {
    "attested_at": "2026-04-15T04:47:40Z",
    "operator_fingerprint": "ed25519:f19bc125dcfdb2eb91e98da98d45bb7a",
    "operator_public_key": "810607ba665917155d0a52fb604f660b...",
    "signature": "5ea122fa1e844dee3e306b33324622656844d1eb..."
  },
  "execution": {
    "audit_entry_hash": "sha256:a4925b7ffc095c7f01ececf52dbf5c7e...",
    "entry_point_name": "send",
    "exit_code": 0,
    "inputs_hash": "sha256:62622f40e9d9c8d1b7c22872afa93e0e...",
    "ok": "true",
    "outputs_hash": "sha256:86f2cb0244095f3c23457befd14ab2ff...",
    "sandbox_profile_hash": "sha256:daa6f3c401b03e9d7d53d905c4fe415c...",
    "skill_manifest_hash": "sha256:00741b31401d97c121a54a6e5662085d...",
    "skill_name": "skill-bundle-demo",
    "skill_version": "0.1.0",
    "timestamp": "2026-04-15T04:47:13Z",
    "wall_time_ms": 167
  },
  "provenance": {
    "artifacts": {
      "README.md": "sha256:4c8a7c4fb39ae14df360a865f22233302e...",
      "SKILL.md": "sha256:4ad81a32a7764de475e764e7ee05db3cfb...",
      "capabilities.yaml": "sha256:44068ffb7c6db88720ece40c23a53bb0...",
      "scripts/check_inbox.py": "sha256:c660bc97f71fe9f0547ff4800c96a167...",
      "scripts/send_email.py": "sha256:80275e4f5fb343b5741ffb3a10f728de...",
      "scripts/setup_webhook.py": "sha256:af2904552dbb063d0ce89e797154dc7b..."
    },
    "manifest_hash": "sha256:00741b31401d97c121a54a6e5662085d...",
    "published_at": "2026-04-15T04:47:13Z",
    "publisher_fingerprint": "ed25519:bf68325fb554f7f05afa2bf800a6d42d",
    "publisher_public_key": "3a5e3b2627acadc4b4f5fe41ea587087...",
    "transparency_log_entry_hash": "sha256:cc3986a5241234a4e9517f25cec6f4c7...",
    "transparency_log_seq": 1
  },
  "receipt_version": "1.0"
}
```

This receipt was verified by a third party using a separate
`TRACESEAL_HOME` with no access to the operator's audit log,
keys, or machine. The verification command:

```bash
traceseal-verify receipt.json
```

Output:

```
[OK] receipt.json
  skill:     skill-bundle-demo v0.1.0
  operator:  ed25519:f19bc125dcfdb2eb91e98da98d45bb7a
  publisher: ed25519:bf68325fb554f7f05afa2bf800a6d42d
```
