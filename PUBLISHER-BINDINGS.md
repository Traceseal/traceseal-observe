# TraceSeal publisher/account binding profile

This additive Phase 2A.3 profile reuses the Phase 2A.2 publisher Ed25519
signature envelope and Open Registry's source adapters. It does not alter the
TraceSeal v1 receipt envelope, operator-key semantics, verifier, transparency
log or C2SP checkpoint witness.

## Fixed repository-scoped statement

The only discovery path is:

```text
.well-known/open-registry/publisher.json
```

The publisher signs compact UTF-8 sorted-key JSON containing version `1.0`,
strict UTC `issued_at`, full derived Ed25519 fingerprint and an exact subject:

- provider: `huggingface` or `modelscope`;
- account;
- qualified repository;
- scope: `repository`.

The public key, derived fingerprint and signature use the existing publisher
attestation envelope. Unknown/duplicate JSON keys, non-canonical keys or
signatures, unsafe identities, control/format characters and non-UTC times fail
closed. Go and Python assert the same fixed key, canonical payload, signature,
document hash and binding-root vectors.

A locally supplied valid document proves only `publisher_key_self_claimed` via
`binding_evidence_rederivation`. It becomes `publisher_key_platform_bound` only
when the production adapter retrieves those exact bytes from the repository
named in the signed subject at a pinned provider revision. This remains
repository-scoped platform-control evidence, not provider-native key
verification, legal identity or account-wide authority.

## Commands

Generate a document offline:

```text
publisher-bind generate \
  --provider huggingface|modelscope \
  --account ACCOUNT \
  --repository ACCOUNT/REPOSITORY \
  --key PUBLISHER_KEY \
  --output BINDING \
  [--issued-at UTC]
```

The command prints the one fixed publication path and performs no upload. The
key loader is the existing descriptor-pinned, owner-only, no-symlink/no-hardlink
TraceSeal loader. Output is create-once mode 0600.

Retrieve and verify from a fixed production origin:

```text
publisher-bind verify \
  --provider huggingface|modelscope \
  --repository ACCOUNT/REPOSITORY \
  --output BINDING_EVIDENCE
```

No endpoint flag exists. Test-only constructors inject local fixture origins.
The verifier uses fresh proxy-free clients, strips credentials/cookies, refuses
unsafe redirects, bounds the document to 64 KiB and creates no model, cache,
manifest, blob or remote state.

## Binding root and TraceSeal commitment

The privacy-preserving binding set contains one or two entries for the same
publisher fingerprint. Entries are sorted by provider and subject hash and
retain only provider, full fingerprint, typed/hashed revision and hashes of the
fixed path, source identity, signed subject, signed statement and document. Its
root is full SHA-256 over compact sorted-key JSON of version, bindings,
fingerprint and status, excluding the root itself.

`traceseal-identity sign --publisher-binding-evidence ...` adds signed
`publisher_binding_count`, `publisher_binding_root` and
`publisher_binding_status` fields. The identity witness takes the same evidence
plus the expected provider repositories, independently refetches each binding,
rebuilds the complete set and signs
`publisher_binding_witness_method=platform_binding_reobservation` only on exact
agreement. Changed, removed, copied, malformed or differently keyed evidence
produces no cosignature.

This commitment changes the identity receipt hash, not the content-derived
canonical model ID. Historical and no-binding Phase 2A receipts retain their
prior shape and verification semantics.

## Claim boundaries

Hugging Face GPG commit verification is separate evidence about a GPG commit
key associated with a Hugging Face account. Trusted Publishers/OIDC is separate
write-side evidence that an authorised CI identity obtained a short-lived
repository token. Neither binds this Ed25519 publisher key without an explicit
cryptographic bridge. The inspected official ModelScope client exposes
revisioned public file retrieval and SHA-256 but no equivalent public
account-to-key verification surface.

The additive key-rotation/revocation wrapper is specified separately in
[PUBLISHER-KEY-HISTORY.md](PUBLISHER-KEY-HISTORY.md); this exact v1 binding
remains valid and unchanged. Account-wide delegation, historical retention and
generic tlog publication remain outside the binding profile. A signed
`issued_at` is a key-holder clock claim, not trusted time or replay prevention. Provider
authentication relies on the host's DNS and TLS trust stores; there is no DNS
pinning or independent transport witness. ModelScope discovery starts from its
public `master` API view and then pins the binding file's exact commit, so a
differently exposed default branch fails closed.
