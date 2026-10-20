# TraceSeal model-resolution receipt extension

This additive v1 extension defines two `execution.receipt_type` values. It does
not change the TraceSeal v1 four-section envelope, canonical JSON convention,
Ed25519 key format, signature payload or ordinary verification algorithm.

New receipts use domain profile `1.1`, declared by signed
`execution.receipt_profile_version`. Historical resolution receipts without
that marker retain their pre-1.1 semantics and remain verifiable.

## `model_resolution`

The operator receipt signs the deterministic values independently derivable
from an Open Registry model-resolution evidence bundle:

- model identity hash;
- resolver version hash (indirectly through the evidence root);
- candidate-set hash;
- policy hash;
- decision hash, reason and selected source;
- selected revision hash;
- evidence strength;
- evidence root;
- complete canonical evidence-bundle hash.

Its provenance states `attestation_scope=operator_resolution_evidence` and
`provider_truth=not_attested`. A valid signature proves that the holder of the
operator key attested to those exact values. It does not prove that a remote
provider returned the claimed metadata or artefacts.

Profile `1.1` additionally requires signed `execution.observed_at` in exact UTC
RFC3339-seconds form (`YYYY-MM-DDTHH:MM:SSZ`). It is the operator's claimed
resolution-observation time. It is not trusted wall-clock time and does not
enter the deterministic Open Registry evidence root.

## `model_resolution_cosignature`

The witness command accepts the evidence bundle and original receipt. Before
signing it:

1. verifies the original TraceSeal signature;
2. independently recomputes the resolver descriptor and policy hashes;
3. recomputes native content-set/commit/revision hashes or the remote revision
   hash from the bundle;
4. reconstructs the ordered candidates, selected-source rule and decision hash;
5. recomputes the evidence root and full bundle hash;
6. compares every corresponding original receipt field;
7. refuses when the witness key fingerprint equals the original signer.

The cosignature's claim is
`resolution_evidence_independently_rederived_and_confirmed`. It does not claim
provider truth. Distinct keys on one host establish key separation only; actual
operator independence requires separate custody and an evidence copy outside
the original signer's write authority.

When the original receipt is profile `1.1`, a new offline cosignature records
the resolver's signed `resolver_observed_at`, its independently set
`verified_at`, and `witness_method=supplied_evidence_rederivation` inside the
signed execution. Historical originals continue to produce the historical
cosignature shape.

Phase 2A.1 adds a second construction using the same
`model_resolution_cosignature` discriminator. `witness-reobserve` verifies the
same original receipt and bundle, then independently fetches the public model
metadata from the fixed Hugging Face origin using a fresh non-caching client.
It confirms the raw revision against the privacy-preserving signed revision
hash before signing. Its execution states
`witness_method=remote_source_reobservation`; its claim is
`remote_source_revision_independently_reobserved_and_confirmed`.

The original offline witness remains byte/semantically unchanged and uses
`method=open_registry_resolution_evidence_v1`. These methods are not
interchangeable. A changed live revision is reported as `source_changed`, which
does not invalidate the original historical signature.

Phase 2B.0 adds a strictly additive policy-selection profile to these same two
receipt types. Signed execution declares `policy_selection_version=1.0` and
commits the canonical policy hash, candidate-set hash, evaluation root,
decision hash, full evidence-bundle hash, decision status, selected provider
and stable decision reason. Version 1.0 has an exact field set: unknown or
partial fields are invalid and cannot fall back to the historical resolution
profile.

The corresponding cosignature uses
`witness_method=policy_decision_rederivation`. The witness independently
normalises the policy, validates and sorts every candidate, evaluates each hard
requirement, reruns the lexicographic preferences and final tie-break, and
compares the resulting complete signed execution. It does not trust the
resolver's selected source. This method re-evaluates supplied, already-verified
normalised evidence offline; it is not fresh provider re-observation.

For a profile `1.1` original, the re-observation cosignature records signed
`resolver_observed_at` and independently set signed `reobserved_at`; freshness
is derived from those two claims. It also retains `original_attested_at` as
legacy envelope metadata and signs the complete original receipt hash. The
operator-selected maximum gap is 1 through 86,400 seconds (default 300).
Historical originals retain the old `attested_at` freshness basis. No
simultaneity, trusted clock, replay prevention or provider-signed truth is
claimed.

## CLI and file safety

```text
traceseal-resolution sign --evidence FILE --key KEY --output RECEIPT [--observed-at UTC]
traceseal-resolution witness --evidence FILE --receipt RECEIPT --key KEY --output COSIGNATURE
traceseal-resolution witness-reobserve --evidence FILE --receipt RECEIPT --model ID --key KEY --output COSIGNATURE
```

Inputs are bounded regular files opened without following the leaf symlink.
Keys must be owner-held, single-link, regular 32-byte files with no group/other
permissions. Outputs are new mode-0600 files and are never overwritten. All
semantic checks complete before output creation. Errors use fixed logical codes
and do not print paths, evidence values or operating-system messages.

Signing, ordinary verification and the original witness require no network.
`witness-reobserve` makes only its documented bounded public Hugging Face
metadata request. Transparency-log publication is a separate optional operation
and is not implemented by this extension.

The policy-selection command is likewise offline:

```text
traceseal-selection sign --evidence FILE --key KEY --output RECEIPT [--observed-at UTC]
traceseal-selection witness --evidence FILE --receipt RECEIPT --key KEY --output COSIGNATURE
```
