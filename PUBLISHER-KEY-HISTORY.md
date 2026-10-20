# TraceSeal publisher key-history profile

This additive Phase 2A.4 profile gives Open Registry an offline signing and
verification boundary for publisher key rotation and revocation. It reuses the
Phase 2A.2 Ed25519 envelope, full derived fingerprint, strict UTC-seconds time
and compact sorted-key JSON. It does not alter the TraceSeal v1 operator
envelope, ordinary verifier, transparency log or C2SP checkpoint witness.

## Compatible document evolution

The fixed provider path remains
`.well-known/open-registry/publisher.json`. Exact Phase 2A.3
`binding_version: "1.0"` documents still verify. A repository that needs key
history may instead publish one strict wrapper with:

- `publisher_history_version: "1.0"`;
- one unchanged signed v1 binding for every key;
- zero to 16 planned rotations;
- zero to 17 revocations.

The two top-level formats have distinct discriminators. Duplicate/unknown keys
or an ambiguous mixture fail closed.

## Rotation and revocation claims

A planned rotation commits version, exact repository-scoped subject, old/new
fingerprints and `effective_at`. K1 authorises the compact canonical bytes and
K2 accepts exactly those bytes. Both signatures and their embedded public keys
are independently verified. Neither one-sided proposal nor new-key takeover is
continuity proof.

`key_self_revocation` is signed by its affected key. `platform_revocation` has
no key signature and becomes provider-control evidence only when freshly read
from the pinned repository; an offline copy is explicitly labelled supplied.
Reason is one of `compromised`, `retired`, `lost` or `other`.

Signed times are key-holder claims. The state machine does not use them to pick
a fork, establish trusted chronology or decide whether an artefact predates a
compromise.

## State and roots

The history verifier requires one connected linear chain, limited to 16 edges.
It rejects self-rotation, cycles, forks, merges, disconnected bindings,
duplicates and cross-scope statements. Predecessors are `superseded`; the leaf
is `active`; a revocation overrides the state of its exact key to `revoked`.
Revoking an old predecessor does not undo a valid two-key handover.

The continuity root is SHA-256 over compact sorted-key JSON of chain-ordered key
states, rotations, semantic revocations, current fingerprint/status and profile
version. Provider-pinned observations also commit the exact document, subject,
fixed path, source identity, typed revision and statement hashes. One or two
observations are provider-sorted before the aggregate key-history root is
derived; all must agree on continuity state.

## Offline commands

```text
publisher-key rotate-propose \
  --old-key OLD --new-public-key NEW_PUBLIC_HEX \
  --provider huggingface|modelscope --account ACCOUNT \
  --repository ACCOUNT/REPOSITORY --output PROPOSAL \
  [--effective-at UTC]

publisher-key rotate-accept \
  --proposal PROPOSAL --new-key NEW --output ROTATION

publisher-key revoke \
  --key KEY --provider huggingface|modelscope --account ACCOUNT \
  --repository ACCOUNT/REPOSITORY \
  --reason compromised|retired|lost|other --output REVOCATION \
  [--effective-at UTC]

publisher-key platform-revoke \
  --fingerprint FINGERPRINT --provider huggingface|modelscope \
  --account ACCOUNT --repository ACCOUNT/REPOSITORY \
  --reason compromised|retired|lost|other --output REVOCATION \
  [--effective-at UTC]

publisher-key assemble \
  --binding BINDING [--binding BINDING ...] \
  [--rotation ROTATION ...] [--revocation REVOCATION ...] \
  --provider huggingface|modelscope \
  --repository ACCOUNT/REPOSITORY --output HISTORY

publisher-key verify \
  --document HISTORY --provider huggingface|modelscope \
  --repository ACCOUNT/REPOSITORY

publisher-key verify-provider \
  --provider huggingface|modelscope \
  --repository ACCOUNT/REPOSITORY --output HISTORY_EVIDENCE

publisher-key log-events \
  --history-evidence HISTORY_EVIDENCE --document HISTORY \
  --provider huggingface|modelscope \
  --repository ACCOUNT/REPOSITORY --output LOG_EVENTS
```

Only `verify-provider` uses a network. It has no origin override and performs a
fresh bounded read through the existing fixed-origin adapters. All other
commands are offline. Private-key loading is descriptor-pinned, owner-only,
regular-file/no-hardlink/no-symlink. Outputs are create-once mode 0600, and no
command uploads or mutates provider state.

## TraceSeal identity commitment and witness

When explicit verified history evidence is supplied, a
`model_identity_observation` profile 1.1 receipt signs an all-or-nothing tuple:

- `current_publisher_fingerprint`;
- `publisher_key_history_root`;
- `publisher_key_status` (`active` or `revoked`).

Historical receipts without this tuple remain valid. A partial or malformed
tuple is profile-invalid and cannot fall back to legacy semantics.

The identity witness independently reconstructs history before countersigning.
It signs `publisher_key_history_witness_method` as either:

- `publisher_key_history_rederivation` for supplied canonical documents; or
- `platform_key_history_reobservation` after fresh provider retrieval.

Changed provider bytes, revision, chain, signatures or state refuse with no
cosignature. The witness does not make a historical artefact signature invalid;
it verifies signature validity and key status as separate facts.

## Governed transparency publication

Phase 2A.5 derives strict `publisher_identity_history` event descriptors from
the exact verified Phase 2A.4 document. Binding, chain-ordered rotations and
semantic revocations each commit the exact signed statement hash, repository-
scoped provider/account hashes, predecessor continuity root and resulting
continuity root. `publisher-key log-events` is offline and never appends or
uploads; the TraceSeal log's separate local operator tool performs the governed
append and produces RFC 6962 inclusion evidence.

A witnessed history bundle is independently checked by the identity signer and
witness. It must prove every entry under a signed checkpoint carrying a valid
C2SP cosignature/v1, reconstruct one increasing-sequence predecessor chain and
end at the supplied Phase 2A.4 continuity root/current key/status. A valid fork
is `publisher_history_equivocation`, not a timestamp-ranking problem.

The identity receipt signs the optional all-or-nothing log tuple:

- `publisher_history_log_entry_hashes` in predecessor order;
- `publisher_history_log_evidence_root`;
- `publisher_history_log_root`;
- `publisher_history_log_status=checkpoint_witnessed_unforked`.

The countersignature adds
`publisher_history_log_witness_method=log_evidence_offline_verified`. This
means the supplied inclusion/checkpoint/witness evidence was independently
verified without network access. `live_log_checkpoint_reobserved` is reserved
for a future fixed-origin live check and is not emitted by this phase.

## Boundaries

Key history changes publisher-evidence and receipt hashes, never the canonical
model ID. There is no automatic provider/log publication, mutable revocation
flag, trust score, global PKI, policy routing or deployment. Governed
publication adds external ordering and fork visibility; it does not turn signed
time into trusted time or prevent replay. The unchanged C2SP tlog witness proves
checkpoint consistency, while Open Registry separately detects conflicting
publisher branches and publisher/provider evidence establishes event semantics.
