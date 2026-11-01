"""RFC 3161 trusted timestamps for receipts and chain checkpoints.

A TraceSeal signature carries the operator's own clock claim. A timestamp
token from an independent Time-Stamping Authority (TSA) adds a third party's
signed statement that a given hash existed by a given time.

Timestamping a chain checkpoint is the efficient pattern. One token pins
every receipt up to that checkpoint: they had all been recorded by genTime.
A token taken BEFORE a window opens proves nothing from after the window
start is hidden before the segment. A token can't prove the tail of a
window is complete: it shows the checkpoint existed by genTime, not that it
was the newest (see RECEIPT-CHAINS.md §1.4 and TRUSTED-TIME.md).

EU eIDAS: a *qualified* electronic time stamp is an RFC 3161 token from a
qualified trust service provider (QTSP) listed on an EU Member State
trusted list (eIDAS Art. 41-42, ETSI EN 319 421/422). This module verifies
tokens against the trust anchors you supply and reports the ETSI
best-practice policy OID and the EN 319 422 qualified-statement extension
when present. Whether the TSA is actually qualified is decided by the EU
Trusted List, which this module does not fetch.

Requires the optional dependency asn1crypto:
    pip install "traceseal-observe[timestamp]"

What verification checks:
  - TimeStampResp status, TSTInfo version, message imprint, nonce
  - the CMS SignedData signature over the signed attributes
  - the contentType and messageDigest signed attributes
  - the ESS signing-certificate (v1 or v2) attribute binds the TSA cert
  - the TSA cert has exactly one EKU, id-kp-timeStamping, marked critical
  - a certificate path to a supplied trust anchor, with every certificate
    valid at genTime and every issuer a CA
What it does NOT check: certificate revocation (CRL/OCSP). Long-term
validation of tokens past TSA certificate expiry needs archive timestamps
(RFC 4998 / ETSI EN 319 102).
"""

from __future__ import annotations

import hashlib
import secrets
import urllib.request
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_ETSI_BEST_PRACTICE_POLICY = "0.4.0.2023.1.1"
OID_ETSI_QTST_STATEMENT = "0.4.0.19422.1.1"

_HASHES = {
    "sha256": (hashlib.sha256, hashes.SHA256),
    "sha384": (hashlib.sha384, hashes.SHA384),
    "sha512": (hashlib.sha512, hashes.SHA512),
}
_MAX_RESPONSE_BYTES = 1 << 20
_MAX_CHAIN_DEPTH = 6


class TimestampError(ValueError):
    """A timestamp token could not be obtained or did not verify."""


def _asn1():
    try:
        from asn1crypto import algos, cms, core, tsp
    except ImportError:  # pragma: no cover - exercised only without the extra
        raise TimestampError(
            "RFC 3161 support needs asn1crypto: "
            'pip install "traceseal-observe[timestamp]"'
        ) from None
    return algos, cms, core, tsp


def _imprint(data: bytes | None, digest: bytes | None, algorithm: str) -> bytes:
    if algorithm not in _HASHES:
        raise TimestampError(f"hash algorithm must be one of {sorted(_HASHES)}")
    if (data is None) == (digest is None):
        raise TimestampError("pass exactly one of data or digest")
    if digest is not None:
        if len(digest) != _HASHES[algorithm][0]().digest_size:
            raise TimestampError(f"digest length does not match {algorithm}")
        return bytes(digest)
    return _HASHES[algorithm][0](data).digest()


# ---------------------------------------------------------------------------
# Requesting
# ---------------------------------------------------------------------------


def build_timestamp_request(
    *,
    data: bytes | None = None,
    digest: bytes | None = None,
    hash_algorithm: str = "sha256",
    nonce: int | None = None,
    policy: str | None = None,
) -> tuple[bytes, int]:
    """DER TimeStampReq (certReq=true) and the nonce it carries."""
    algos, _cms, _core, tsp = _asn1()
    if nonce is None:
        nonce = secrets.randbits(63)
    request = {
        "version": "v1",
        "message_imprint": {
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algorithm}),
            "hashed_message": _imprint(data, digest, hash_algorithm),
        },
        "nonce": nonce,
        "cert_req": True,
    }
    if policy is not None:
        request["req_policy"] = policy
    return tsp.TimeStampReq(request).dump(), nonce


def parse_timestamp_response(
    response_der: bytes, *, nonce: int | None = None
) -> bytes:
    """Return the TimeStampToken DER from a TimeStampResp, or raise.

    Only checks the status and the nonce. Call verify_timestamp_token for
    the signature, certificate path and imprint.
    """
    _algos, _cms, core, tsp = _asn1()
    try:
        # Read PKIStatusInfo first: a refusal carries no token, and
        # asn1crypto's TimeStampResp will not parse without one.
        outer = core.Sequence.load(response_der, strict=True)
        status_info = tsp.PKIStatusInfo.load(outer.contents, strict=False)
        status = status_info["status"].native
    except Exception as exc:
        raise TimestampError(f"timestamp response is not valid DER: {exc}") from None
    if status not in ("granted", "granted_with_mods"):
        text = status_info["status_string"].native
        raise TimestampError(f"TSA refused the request: {status} {text or ''}".strip())
    try:
        response = tsp.TimeStampResp.load(response_der, strict=True)
        token = response["time_stamp_token"]
    except Exception as exc:
        raise TimestampError(f"timestamp response is not valid DER: {exc}") from None
    if token.native is None:
        raise TimestampError("TSA response has no token")
    if nonce is not None:
        info = _tst_info(token)
        if info["nonce"].native != nonce:
            raise TimestampError("TSA response nonce does not match the request")
    return token.dump()


def request_timestamp(
    tsa_url: str,
    *,
    data: bytes | None = None,
    digest: bytes | None = None,
    hash_algorithm: str = "sha256",
    policy: str | None = None,
    timeout: float = 15.0,
    headers: dict[str, str] | None = None,
) -> bytes:
    """Ask an RFC 3161 TSA (HTTP transport, RFC 3161 §3.4) for a token.

    Returns the TimeStampToken DER. The token is not trusted until it has
    been verified with verify_timestamp_token and your trust anchors.
    `headers` can carry TSA credentials; they are never put into receipts.
    """
    if not tsa_url.startswith(("https://", "http://")):
        raise TimestampError("tsa_url must be an http(s) URL")
    body, nonce = build_timestamp_request(
        data=data, digest=digest, hash_algorithm=hash_algorithm, policy=policy
    )
    request = urllib.request.Request(
        tsa_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/timestamp-query", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
    except OSError as exc:
        raise TimestampError(f"TSA request failed: {type(exc).__name__}") from None
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise TimestampError("TSA response is too large")
    token = parse_timestamp_response(payload, nonce=nonce)
    # Fail early if the TSA timestamped something else.
    info = _tst_info(_load_token(token))
    if info["message_imprint"]["hashed_message"].native != _imprint(
        data, digest, hash_algorithm
    ):
        raise TimestampError("TSA token does not cover the requested hash")
    return token


# ---------------------------------------------------------------------------
# Verifying
# ---------------------------------------------------------------------------


def _load_token(token_der: bytes):
    _algos, cms, _core, _tsp = _asn1()
    try:
        token = cms.ContentInfo.load(token_der, strict=True)
        if token["content_type"].native != "signed_data":
            raise TimestampError("timestamp token is not CMS SignedData")
        return token
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"timestamp token is not valid DER: {exc}") from None


def _tst_info(token):
    signed = token["content"]
    encap = signed["encap_content_info"]
    if encap["content_type"].dotted != OID_TST_INFO:
        raise TimestampError("token does not contain TSTInfo")
    return encap["content"].parsed


def _signed_attr(attrs, name: str):
    found = [a for a in attrs if a["type"].native == name]
    if len(found) != 1 or len(found[0]["values"]) != 1:
        raise TimestampError(f"signed attribute {name} must appear exactly once")
    return found[0]["values"][0]


def _verify_signature(public_key, signature: bytes, message: bytes, sig_algo: str,
                      hash_name: str, pss_params) -> None:
    hash_cls = _HASHES.get(hash_name, (None, None))[1]
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_cls is None:
                raise TimestampError(f"unsupported digest {hash_name}")
            if sig_algo == "rsassa_pss":
                mgf_hash = pss_params["mask_gen_algorithm"]["parameters"]["algorithm"].native
                salt = pss_params["salt_length"].native
                if mgf_hash != hash_name:
                    raise TimestampError("RSA-PSS MGF hash differs from the digest")
                public_key.verify(signature, message,
                                  padding.PSS(padding.MGF1(hash_cls()), salt), hash_cls())
            elif sig_algo == "rsassa_pkcs1v15":
                public_key.verify(signature, message, padding.PKCS1v15(), hash_cls())
            else:
                raise TimestampError(f"unsupported RSA signature {sig_algo}")
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if sig_algo != "ecdsa" or hash_cls is None:
                raise TimestampError(f"unsupported EC signature {sig_algo}")
            public_key.verify(signature, message, ec.ECDSA(hash_cls()))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            if sig_algo != "ed25519":
                raise TimestampError(f"unsupported signature {sig_algo} for Ed25519 key")
            public_key.verify(signature, message)
        else:
            raise TimestampError("unsupported TSA key type")
    except InvalidSignature:
        raise TimestampError("TSA signature is invalid") from None


def _check_tsa_certificate(cert: x509.Certificate) -> None:
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    except x509.ExtensionNotFound:
        raise TimestampError("TSA certificate has no extended key usage") from None
    if not eku.critical or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise TimestampError(
            "TSA certificate must have exactly one EKU, id-kp-timeStamping, critical"
        )
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not (ku.digital_signature or ku.content_commitment):
            raise TimestampError("TSA certificate key usage forbids signing")
    except x509.ExtensionNotFound:
        pass


def _valid_at(cert: x509.Certificate, when: datetime) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(
            cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
        )
    except x509.ExtensionNotFound:
        return False


def _issued_by(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _path_length(cert: x509.Certificate) -> int | None:
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value.path_length
    except x509.ExtensionNotFound:
        return None


def _can_sign_certs(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign)
    except x509.ExtensionNotFound:
        return True


def _check_path_constraints(path: list[x509.Certificate]) -> list[x509.Certificate]:
    """RFC 5280 §6.1.4: each CA's pathLenConstraint bounds the number of
    intermediate CA certificates below it (the end-entity cert not counted);
    CAs with a KeyUsage extension must assert keyCertSign."""
    for index, ca in enumerate(path[1:], start=1):
        if not _can_sign_certs(ca):
            raise TimestampError("a CA in the path lacks keyCertSign")
        limit = _path_length(ca)
        below = index - 1  # CA certificates between this CA and the TSA cert
        if limit is not None and below > limit:
            raise TimestampError("certificate path length constraint violated")
    return path


def _build_path(leaf, pool, anchors, when) -> list[x509.Certificate]:
    anchor_der = {a.public_bytes(_der()) for a in anchors}
    path = [leaf]
    current = leaf
    for _ in range(_MAX_CHAIN_DEPTH):
        if current.public_bytes(_der()) in anchor_der:
            return _check_path_constraints(path)
        for anchor in anchors:
            if _issued_by(current, anchor):
                if not _valid_at(anchor, when) or not _is_ca(anchor):
                    raise TimestampError("trust anchor is not a CA valid at genTime")
                return _check_path_constraints(path + [anchor])
        issuer = next(
            (c for c in pool if c is not current and _issued_by(current, c)), None
        )
        if issuer is None:
            break
        if not _is_ca(issuer) or not _valid_at(issuer, when):
            raise TimestampError("intermediate certificate is not a CA valid at genTime")
        path.append(issuer)
        current = issuer
    raise TimestampError("TSA certificate does not chain to a trusted anchor")


def _der():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def verify_timestamp_token(
    token_der: bytes,
    *,
    data: bytes | None = None,
    digest: bytes | None = None,
    trust_anchors: Iterable[x509.Certificate],
    intermediates: Iterable[x509.Certificate] = (),
    nonce: int | None = None,
    required_policy: str | None = None,
) -> dict[str, Any]:
    """Verify an RFC 3161 TimeStampToken over `data` (or its `digest`).

    `intermediates` are extra certificates to build the path with: CA
    intermediates, or the TSA certificate itself when the token was issued
    without certificates (certReq=false).

    `trust_anchors` are the TSA root certificates you trust. For eIDAS
    qualified timestamps, take them from the EU Trusted List entry of the
    qualified TSA you use. Raises TimestampError on any failure.

    Returns {gen_time, gen_time_unix, policy, serial_number, hash_algorithm,
    tsa_subject, tsa_certificate_sha256, etsi_best_practice_policy,
    etsi_qualified_statement, accuracy_seconds}.
    """
    _asn1()  # a missing optional dependency is reported as such
    try:
        return _verify_timestamp_token(
            token_der,
            data=data,
            digest=digest,
            trust_anchors=trust_anchors,
            intermediates=intermediates,
            nonce=nonce,
            required_policy=required_policy,
        )
    except TimestampError:
        raise
    except Exception as exc:
        # Hostile ASN.1 shapes (empty SEQUENCEs, absent optional fields,
        # wrong CHOICE arms) must fail verification, never escape as
        # IndexError/KeyError/TypeError to a caller that promised not to raise.
        raise TimestampError(f"timestamp token is malformed ({type(exc).__name__})") from None


def _verify_timestamp_token(
    token_der,
    *,
    data,
    digest,
    trust_anchors,
    intermediates,
    nonce,
    required_policy,
) -> dict[str, Any]:
    _algos, cms, _core, _tsp = _asn1()
    anchors = list(trust_anchors)
    if not anchors:
        raise TimestampError("at least one trust anchor is required")
    token = _load_token(token_der)
    signed = token["content"]
    info = _tst_info(token)
    if info["version"].native != "v1":
        raise TimestampError("unsupported TSTInfo version")

    hash_name = info["message_imprint"]["hash_algorithm"]["algorithm"].native
    expected = _imprint(data, digest, hash_name)
    if info["message_imprint"]["hashed_message"].native != expected:
        raise TimestampError("token does not cover this data")
    if nonce is not None and info["nonce"].native != nonce:
        raise TimestampError("token nonce does not match")
    policy = info["policy"].dotted
    if required_policy is not None and policy != required_policy:
        raise TimestampError(f"token policy {policy} is not {required_policy}")
    gen_time = info["gen_time"].native
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    signer_infos = signed["signer_infos"]
    if len(signer_infos) != 1:
        raise TimestampError("token must have exactly one signer")
    signer = signer_infos[0]
    attrs = signer["signed_attrs"]
    if not attrs.native:
        raise TimestampError("token has no signed attributes")
    if _signed_attr(attrs, "content_type").dotted != OID_TST_INFO:
        raise TimestampError("signed contentType is not TSTInfo")

    digest_name = signer["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        raise TimestampError(f"unsupported signer digest {digest_name}")
    econtent = signed["encap_content_info"]["content"].contents
    if _signed_attr(attrs, "message_digest").native != _HASHES[digest_name][0](
        econtent
    ).digest():
        raise TimestampError("messageDigest does not match TSTInfo")

    # Locate the TSA certificate named by the SignerIdentifier.
    included = signed["certificates"] if signed["certificates"].native else []
    pool_asn1 = [c.chosen for c in included if c.name == "certificate"]
    pool = [x509.load_der_x509_certificate(c.dump()) for c in pool_asn1]
    from asn1crypto import x509 as asn1_x509

    for extra in intermediates:
        pool.append(extra)
        pool_asn1.append(asn1_x509.Certificate.load(extra.public_bytes(_der())))
    sid = signer["sid"]
    leaf = None
    for asn1_cert, cert in zip(pool_asn1, pool):
        if sid.name == "issuer_and_serial_number":
            if (
                asn1_cert.issuer == sid.chosen["issuer"]
                and asn1_cert.serial_number == sid.chosen["serial_number"].native
            ):
                leaf = cert
        elif asn1_cert.key_identifier == sid.chosen.native:
            leaf = cert
    if leaf is None:
        raise TimestampError("TSA certificate is not included in the token")

    # ESS signing-certificate binds the signer certificate (RFC 3161 §2.4.1,
    # RFC 5816). Accept v2 (any hash) or v1 (SHA-1).
    leaf_der = leaf.public_bytes(_der())
    names = {a["type"].native for a in attrs}
    if "signing_certificate_v2" in names:
        certs = _signed_attr(attrs, "signing_certificate_v2")["certs"]
        if len(certs) < 1:
            raise TimestampError("ESS signing-certificate-v2 lists no certificate")
        ess = certs[0]
        algo = ess["hash_algorithm"]["algorithm"].native
        if algo not in _HASHES:
            raise TimestampError(f"unsupported ESS hash {algo}")
        bound = _HASHES[algo][0](leaf_der).digest()
    elif "signing_certificate" in names:
        certs = _signed_attr(attrs, "signing_certificate")["certs"]
        if len(certs) < 1:
            raise TimestampError("ESS signing-certificate lists no certificate")
        ess = certs[0]
        bound = hashlib.sha1(leaf_der).digest()
    else:
        raise TimestampError("token lacks the ESS signing-certificate attribute")
    if ess["cert_hash"].native != bound:
        raise TimestampError("ESS signing-certificate does not match the TSA certificate")

    sig_algo = signer["signature_algorithm"].signature_algo
    signed_bytes = b"\x31" + attrs.dump()[1:]  # [0] IMPLICIT -> SET OF
    _verify_signature(
        leaf.public_key(),
        signer["signature"].native,
        signed_bytes,
        sig_algo,
        digest_name,
        signer["signature_algorithm"]["parameters"],
    )

    _check_tsa_certificate(leaf)
    if not _valid_at(leaf, gen_time):
        raise TimestampError("TSA certificate was not valid at genTime")
    path = _build_path(leaf, pool, anchors, gen_time)

    accuracy = None
    if info["accuracy"].native:
        acc = info["accuracy"].native
        accuracy = (acc.get("seconds") or 0) + (acc.get("millis") or 0) / 1000 + (
            acc.get("micros") or 0
        ) / 1_000_000
    extensions = info["extensions"].native or []
    qualified = any(
        ext["extn_id"] == OID_ETSI_QTST_STATEMENT for ext in extensions
    ) if extensions else False
    return {
        "gen_time": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gen_time_unix": int(gen_time.timestamp()),
        "policy": policy,
        "serial_number": info["serial_number"].native,
        "hash_algorithm": hash_name,
        "tsa_subject": leaf.subject.rfc4514_string(),
        "tsa_certificate_sha256": "sha256:" + hashlib.sha256(leaf_der).hexdigest(),
        "chain_length": len(path),
        "etsi_best_practice_policy": policy == OID_ETSI_BEST_PRACTICE_POLICY,
        "etsi_qualified_statement": qualified,
        "accuracy_seconds": accuracy,
    }


# ---------------------------------------------------------------------------
# TraceSeal helpers
# ---------------------------------------------------------------------------


def checkpoint_body(note: str) -> bytes:
    """The bytes a checkpoint timestamp covers: the note body (origin, size,
    root), without signature lines, so later witness cosignatures don't
    change what was timestamped."""
    if not isinstance(note, str) or "\n\n" not in note:
        raise TimestampError("not a signed checkpoint note")
    return note[: note.index("\n\n") + 1].encode("utf-8")


def timestamp_checkpoint(note: str, tsa_url: str, **kwargs: Any) -> bytes:
    """Get an RFC 3161 token over a chain checkpoint's body."""
    return request_timestamp(tsa_url, data=checkpoint_body(note), **kwargs)


def receipt_digest(receipt: Any) -> bytes:
    """32-byte SHA-256 digest of a receipt (its receipt_hash), for
    timestamping individual receipts with request_timestamp(digest=...)."""
    value = receipt.receipt_hash
    return bytes.fromhex(value[7:])


def load_certificates(pem_or_der: bytes) -> list[x509.Certificate]:
    """Load one or more certificates from PEM (possibly concatenated) or DER."""
    if b"-----BEGIN CERTIFICATE-----" in pem_or_der:
        return x509.load_pem_x509_certificates(pem_or_der)
    return [x509.load_der_x509_certificate(pem_or_der)]
