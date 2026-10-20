# TraceSeal model-identity receipt extension

This additive v1 profile defines `model_identity_observation` and
`model_identity_cosignature`. It retains TraceSeal's existing four-section
envelope, canonical JSON, Ed25519 keys, signature payload and ordinary verifier.
It does not introduce a new cryptographic format.

New receipts use additive domain profile `1.1`, declared by signed
`execution.receipt_profile_version`. Historical identity receipts without the
marker retain their original profile semantics.

## Evidence input

Open Registry supplies one deterministic canonical identity plus separately
normalised Hugging Face and ModelScope observations. TraceSeal independently
recomputes:

- each source metadata hash and observation root;
- provider-specific revision hash;
- complete source observation hash;
- fixed comparison-profile hash;
- registry-neutral content-derived canonical ID;
- selected-file equivalence root.

Only four fixed small files participate. Their logical paths and public model
IDs are hashed. Provider hash algorithms and origins remain explicit; only
locally calculated full SHA-256 supports the
`selected_files_equivalent` claim.

## `model_identity_observation`

The operator receipt signs:

- identity version and canonical identity hash;
- comparison profile hash and four-file count;
- `selected_files_equivalent` level;
- equivalence evidence root;
- complete canonical identity evidence hash;
- ordered complete source-observation hashes.

Phase 2A.2 may additionally commit to a separately validated publisher
attachment through `publisher_evidence_root`, `publisher_evidence_status` and
ordered `publisher_attestation_hashes`. Those fields are present only when the
operator explicitly supplies publisher attestations. They do not alter the
canonical artefact identity.

Phase 2A.3 may additionally commit to separately validated repository-scoped
platform binding through `publisher_binding_count`,
`publisher_binding_root` and `publisher_binding_status`. Those fields are
present only when explicit binding evidence is supplied and do not disclose the
repository identity or alter canonical artefact identity.

Phase 2A.4 may additionally commit to separately validated publisher key
history through the all-or-nothing signed tuple
`current_publisher_fingerprint`, `publisher_key_history_root` and
`publisher_key_status`. The latter is `active` or `revoked`; predecessor states
remain in the supplied history evidence. A partial tuple is profile-invalid,
while historical receipts with no tuple retain their prior semantics.

Phase 2A.5 may additionally commit witnessed publisher-history publication
through `publisher_history_log_entry_hashes`,
`publisher_history_log_evidence_root`, `publisher_history_log_root` and
`publisher_history_log_status=checkpoint_witnessed_unforked`. The entire tuple
is optional for backwards compatibility but all-or-nothing when present. It is
valid only beside a matching Phase 2A.4 key-history tuple.

Provenance states `equivalence_scope=selected_files_only` and
`provider_truth=not_attested`. The signature proves that the key holder attested
to those exact derived values. It does not prove that either provider supplied
truthful data and does not cover weights or unselected repository files.

Profile `1.1` additionally signs `execution.observed_at` in exact UTC
RFC3339-seconds form (`YYYY-MM-DDTHH:MM:SSZ`). This is the operator's claimed
source-observation time. It is excluded from the canonical artefact identity,
comparison evidence root and source observations.

## `model_identity_cosignature`

The witness:

1. re-derives the canonical identity and both supplied observations;
2. verifies the original TraceSeal signature and exact evidence binding;
3. refuses the original public key/fingerprint;
4. checks separately disclosed public IDs against the signed identity hashes;
5. enforces the configured observation-time gap;
6. creates fresh proxy-free, non-caching source clients;
7. independently repeats Hugging Face and ModelScope metadata, file-list and
   four selected-file requests;
8. streams local SHA-256 and reconstructs both observations;
9. distinguishes a typed revision change (`source_changed`) from selected byte
   disagreement (`selected_file_mismatch`);
10. rebuilds and compares the complete canonical identity;
11. only then signs a separate confirmation receipt.

When the original commits to publisher evidence, the witness first rebuilds
that attachment from the supplied publisher attestations, recomputes every
embedded public-key fingerprint, verifies Ed25519 and checks canonical-
artefact/equivalence binding. It never trusts the original status field alone.

When the original also commits publisher binding evidence, the witness requires
the corresponding expected provider repository identities, independently
retrieves the fixed binding document with fresh source adapters, verifies its
publisher signature and exact signed subject, then rebuilds and compares the
complete binding root. A successful cosignature signs
`publisher_binding_witness_method=platform_binding_reobservation`. A supplied
document checked without platform retrieval remains the weaker
`binding_evidence_rederivation` claim and is not labelled platform-bound by the
witness.

When key-history evidence is committed, the witness also verifies every
embedded historical binding, old/new rotation signature, self-revocation
signature, platform-revocation method, exact subject and bounded linear chain.
It then rebuilds the continuity and aggregate roots. Supplied documents produce
the signed method `publisher_key_history_rederivation`; fresh fixed-origin
retrieval produces `platform_key_history_reobservation`. Changed history or
state refuses without creating a cosignature.

When witnessed log evidence is supplied, the witness independently verifies
each governed leaf, RFC 6962 inclusion path, TraceSeal checkpoint signature and
C2SP cosignature/v1, then reconstructs publisher predecessor continuity and
refuses any fork. It compares terminal continuity/current state to the Phase
2A.4 evidence and signs
`publisher_history_log_witness_method=log_evidence_offline_verified`. The log
cosignature proves an append-only checkpoint, not publisher truth; publisher
signatures and provider re-observation remain separate checks.

The signed claim is
`selected_file_evidence_independently_reobserved_and_confirmed` with
`witness_method=remote_source_reobservation`. It is stronger than supplied-
bundle re-derivation but remains bounded source observation, not provider truth
or full-artifact verification.

For a profile `1.1` original, the cosignature signs the resolver's
`resolver_observed_at` and the witness's independently set `reobserved_at`.
Freshness is derived from those two signed claims. Historical originals retain
the old envelope-time basis and historical cosignature shape.

## CLI

```text
traceseal-identity sign \
  --identity IDENTITY \
  --huggingface-observation HF_OBSERVATION \
  --modelscope-observation MS_OBSERVATION \
  --key KEY \
  --output RECEIPT \
  [--observed-at UTC] \
  [--publisher-attestation ATTESTATION ...] \
  [--publisher-binding-evidence BINDING_EVIDENCE] \
  [--publisher-key-history-evidence HISTORY_EVIDENCE] \
  [--publisher-history-log-evidence HISTORY_LOG_EVIDENCE]

traceseal-identity witness \
  --identity IDENTITY \
  --huggingface-observation HF_OBSERVATION \
  --modelscope-observation MS_OBSERVATION \
  --receipt RECEIPT \
  --huggingface-model ID \
  --modelscope-model ID \
  --key INDEPENDENT_KEY \
  --output COSIGNATURE \
  [--max-observation-gap-seconds 300] \
  [--publisher-attestation ATTESTATION ...] \
  [--publisher-binding-evidence BINDING_EVIDENCE] \
  [--huggingface-binding-repository ID] \
  [--modelscope-binding-repository ID] \
  [--publisher-key-history-evidence HISTORY_EVIDENCE] \
  [--huggingface-key-history-repository ID] \
  [--modelscope-key-history-repository ID] \
  [--huggingface-key-history-document DOCUMENT] \
  [--modelscope-key-history-document DOCUMENT] \
  [--publisher-history-log-evidence HISTORY_LOG_EVIDENCE]
```

There is no origin option. Production origins are fixed inside the adapters;
base URL injection exists only in programmatic test construction. Input and key
handling reuse the Phase 2A.0 bounded, symlink-safe loader. Outputs are new
mode-0600 files and are never overwritten. All signature, identity, key,
freshness and source checks finish before output creation.

The witness performs no retry, persistence, cache write, repository import,
manifest/blob creation or artefact retention. It makes only the bounded source
requests required by the four-file profile. Remote logical paths use the same
strict ASCII segment alphabet as the Open Registry observer; traversal,
percent forms, Unicode controls and duplicate entries fail closed.

## Signed time, attestation time and replay

Profile `1.1` signs `observed_at` in the operator receipt and
`resolver_observed_at` plus `reobserved_at` in the witness receipt. The witness
also signs `original_attested_at`, the maximum gap and the complete original
receipt hash. All times are deliberately excluded from canonical identity.
Observations are not claimed simultaneous.

TraceSeal v1 still signs execution plus provenance, not envelope
`attested_at`. The new signed time is a key-holder claim, not proof of clock
accuracy. Standalone receipts remain replayable without external retention or
a governed log-inclusion policy.

## Transparency log

No identity receipt or publisher event is automatically published. Phase 2A.5
can commit a separately supplied portable inclusion bundle generated by an
isolated/local TraceSeal log. Production log and witness keys are pinned in the
identity CLI; programmatic key injection exists only for deterministic local
tests. The existing C2SP checkpoint witness proves append-only log consistency
only and is unchanged. It must never be described as independently re-observing
model identity or publisher evidence.

Publisher signature format, semantics and offline commands are specified in
[PUBLISHER-ATTESTATIONS.md](PUBLISHER-ATTESTATIONS.md).
Repository-scoped publisher/account discovery is specified in
[PUBLISHER-BINDINGS.md](PUBLISHER-BINDINGS.md).
Publisher rotation/revocation documents, state and witness methods are specified
in [PUBLISHER-KEY-HISTORY.md](PUBLISHER-KEY-HISTORY.md).
