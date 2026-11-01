# Operator Key Management

A receipt is only as trustworthy as the operator key that signed it. A raw
key file on the agent's disk is fine for development. In production, the
key should live in a KMS or HSM, be rotated on a schedule, and have a
documented compromise procedure.

## Keys in a KMS or HSM: `RemoteOperatorKey`

```python
from traceseal_observe import RemoteOperatorKey

key = RemoteOperatorKey(
    "prod-operator",
    public_key=public_key,          # Ed25519PublicKey, 32 raw bytes, or 64 hex chars
    sign_fn=lambda message: ...,    # returns a 64-byte Ed25519 signature over `message`
)
```

`RemoteOperatorKey` works everywhere an `OperatorKey` does: every
`observe_*` function, `WorkflowObserver`, `sign_outcome` and
`ReceiptChain`. **Every signature the remote signer returns is verified
against the configured public key before it is used.** A misconfigured
signer fails closed and never yields unverifiable receipts. Typical causes:
the wrong key, a pre-hash Ed25519ph variant, or a DER-wrapped signature.

TraceSeal receipts use **pure Ed25519 over the exact message bytes**. Your
KMS/HSM key must be Ed25519, and it must sign raw data, not a digest.

### Provider recipes

The snippets below show the shape of the integration. They were **not run
against live services** while writing this guide. Check the provider's
current documentation for exact key-spec and algorithm names. The signature
check in `RemoteOperatorKey` tells you immediately if anything is wrong.

**Google Cloud KMS** (key algorithm `EC_SIGN_ED25519`):

```python
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.cloud import kms

client = kms.KeyManagementServiceClient()
name = "projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1"
public_key = load_pem_public_key(client.get_public_key(request={"name": name}).pem.encode())

key = RemoteOperatorKey(
    "gcp-operator",
    public_key=public_key,
    # Ed25519 keys sign the raw data, so pass `data`, not `digest`.
    sign_fn=lambda m: client.asymmetric_sign(request={"name": name, "data": m}).signature,
)
```

**AWS KMS:** create an Ed25519 key and sign with the pure-Ed25519 signing
algorithm and `MessageType="RAW"`. Fetch the public key with
`get_public_key` (DER SubjectPublicKeyInfo →
`load_der_public_key`). Pass `lambda m: kms.sign(KeyId=..., Message=m,
MessageType="RAW", SigningAlgorithm=<Ed25519 algorithm>)["Signature"]`.

**PKCS#11 HSMs** (YubiHSM 2, Thales Luna, SoftHSM 2.6+…): an
`CKK_EC_EDWARDS` key on curve Ed25519, signed with mechanism `CKM_EDDSA`
and no parameters. With `python-pkcs11`:
`sign_fn=lambda m: priv.sign(m, mechanism=Mechanism.EDDSA)`.

Every remote signature costs one KMS round trip, per receipt and per
checkpoint. A chain has one current key that signs both. If that latency
is too much for an agent's hot path, use an HSM close to the agent, or a
local key with frequent scheduled rotation.

## Rotation

```python
rotation_receipt = chain.rotate_key(new_key)          # reason="scheduled"
```

The rotation is a chained `chain_key_rotation` receipt:
- signed by the **outgoing** key;
- carrying the **incoming** key's signature that accepts this exact
  position in this exact chain, so nobody can rotate a chain onto a key
  they don't hold, or replay an acceptance elsewhere.

From the next receipt on, `chain.signer` signs with the new key; nothing
else in your code changes. Verifiers follow the handover and reject any
key change that doesn't come through a valid rotation.

Persistent chains record the rotation crash-safely. If the process dies
mid-rotation, reopening resolves it: if the rotation receipt's hash reached
disk, the rotation happened, and you reopen with the new key. Otherwise it
didn't, and you reopen with the old key.

Suggested policy: rotate every 90 days, and whenever a person with key
access leaves.

## Compromise

```python
chain.rotate_key(new_key, reason="compromise", compromised_after_seq=1840)
```

This declares that receipts after `chain_seq` 1840 that the old key signed
must not be trusted. Verifiers list them under `compromised_seqs`, the CLI
prints them, and a checkpoint signed by the old key after that point is
flagged.

Be clear about what this can and can't do. The declaration is signed by
the compromised key, and an attacker holding that key can sign things too.
What makes receipts up to 1840 trustworthy is a **checkpoint covering them
that reached a third party before the compromise**: a witness, a TSA token
(TRUSTED-TIME.md), or an auditor. Anything the attacker signs afterwards
either conflicts with that checkpoint (a fork) or sits after it (and is
flagged as compromised).

Compromise checklist:
1. Revoke or disable the old key in the KMS/HSM.
2. `rotate_key(..., reason="compromise", compromised_after_seq=<last receipt you can vouch for>)`.
   Use the size of the last checkpoint that reached a third party.
3. Publish and timestamp a fresh checkpoint.
4. Tell the auditors and customers who hold your earlier checkpoints.

## Not yet covered

- A published operator-key directory (for example a `.well-known`
  document bound to the organisation's domain or an eIDAS electronic seal).
  Today, a verifier's trust in the *first* key is established out of band.
- Hybrid or post-quantum signatures.
