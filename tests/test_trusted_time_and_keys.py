"""RFC 3161 timestamps, remote (KMS/HSM) signers and chain key rotation."""

from __future__ import annotations

import datetime as dt
import hashlib
import json

import pytest

asn1crypto = pytest.importorskip("asn1crypto")
from asn1crypto import cms, core, tsp  # noqa: E402
from asn1crypto import x509 as ax509  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from traceseal_observe import (  # noqa: E402
    ChainError,
    OperatorKey,
    ReceiptChain,
    RemoteOperatorKey,
    observe_tool,
    verify_chain,
    verify_receipt_signature,
)
from traceseal_observe import chain as chain_mod  # noqa: E402
from traceseal_observe.timestamp import (  # noqa: E402
    OID_ETSI_BEST_PRACTICE_POLICY,
    OID_ETSI_QTST_STATEMENT,
    TimestampError,
    build_timestamp_request,
    checkpoint_body,
    parse_timestamp_response,
    receipt_digest,
    request_timestamp,
    verify_timestamp_token,
)

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# A local test TSA
# ---------------------------------------------------------------------------


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public_key, signing_key, *, ca, eku=None, eku_critical=True,
          not_before=NOW - dt.timedelta(days=365), not_after=NOW + dt.timedelta(days=365),
          path_length=None):
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
                       critical=True)
    )
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=eku_critical)
    return b.sign(signing_key, hashes.SHA256())


class TSA:
    def __init__(self, kind="ec", **cert_kw):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert("Test Root", "Test Root", self.root_key.public_key(),
                          self.root_key, ca=True)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = _cert("Test Intermediate", "Test Root",
                                  self.int_key.public_key(), self.root_key, ca=True)
        if kind == "rsa":
            self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
        self.kind = kind
        cert_kw.setdefault("eku", [ExtendedKeyUsageOID.TIME_STAMPING])
        self.cert = _cert("Test TSA", "Test Intermediate", self.key.public_key(),
                          self.int_key, ca=False, **cert_kw)
        self.serial = 0

    def token(self, *, data=None, digest=None, gen_time=NOW, nonce=None,
              policy="1.2.3.4.1", extensions=None, ess="v2", ess_hash=None,
              tamper_digest=False, include_intermediate=True, include_certs=True):
        if digest is None:
            digest = hashlib.sha256(data).digest()
        self.serial += 1
        info = {
            "version": "v1",
            "policy": policy,
            "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                                "hashed_message": digest},
            "serial_number": self.serial,
            "gen_time": gen_time,
        }
        if nonce is not None:
            info["nonce"] = nonce
        if extensions:
            info["extensions"] = extensions
        tst = tsp.TSTInfo(info)
        tst_der = tst.dump()
        cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        acert = ax509.Certificate.load(cert_der)
        if ess == "v2":
            ess_attr = {"type": "signing_certificate_v2", "values": [
                {"certs": [{"cert_hash": ess_hash or hashlib.sha256(cert_der).digest()}]}]}
        else:
            ess_attr = {"type": "signing_certificate", "values": [
                {"certs": [{"cert_hash": ess_hash or hashlib.sha1(cert_der).digest()}]}]}
        md = hashlib.sha256(tst_der).digest()
        if tamper_digest:
            md = b"\x00" * 32
        attrs = cms.CMSAttributes([
            {"type": "content_type", "values": ["tst_info"]},
            {"type": "message_digest", "values": [md]},
            ess_attr,
        ])
        to_sign = attrs.dump()
        if self.kind == "rsa":
            sig = self.key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
            sig_alg = {"algorithm": "sha256_rsa"}
        else:
            sig = self.key.sign(to_sign, ec.ECDSA(hashes.SHA256()))
            sig_alg = {"algorithm": "sha256_ecdsa"}
        signer = cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": {
                "issuer": acert.issuer, "serial_number": acert.serial_number}}),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": sig_alg,
            "signature": sig,
        })
        certs = [acert]
        if include_intermediate:
            certs.append(ax509.Certificate.load(
                self.intermediate.public_bytes(serialization.Encoding.DER)))
        signed_body = {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "tst_info", "content": tst},
            "signer_infos": [signer],
        }
        if include_certs:
            signed_body["certificates"] = certs
        signed = cms.SignedData(signed_body)
        return cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump()

    def response(self, token=None, status="granted"):
        status_der = tsp.PKIStatusInfo({"status": status}).dump()
        if token is None:  # asn1crypto won't build a token-less response
            return core.Sequence.load(b"\x30" + bytes([len(status_der)]) + status_der).dump()
        return tsp.TimeStampResp({"status": {"status": status},
                                  "time_stamp_token": cms.ContentInfo.load(token)}).dump()


@pytest.fixture(scope="module")
def tsa():
    return TSA()


# ---------------------------------------------------------------------------
# RFC 3161
# ---------------------------------------------------------------------------


class TestTimestampTokens:
    @pytest.mark.parametrize("kind", ["ec", "rsa"])
    def test_valid_token(self, kind):
        t = TSA(kind)
        info = verify_timestamp_token(t.token(data=b"hello"), data=b"hello",
                                      trust_anchors=[t.root])
        assert info["gen_time"] == "2026-10-01T12:00:00Z"
        assert info["gen_time_unix"] == int(NOW.timestamp())
        assert info["policy"] == "1.2.3.4.1"
        assert info["chain_length"] == 3
        assert info["tsa_subject"] == "CN=Test TSA"
        assert not info["etsi_qualified_statement"]

    def test_digest_input_and_receipt_digest(self, tsa):
        key = OperatorKey.generate()
        receipt = observe_tool("t", key, lambda: 1)[1]
        d = receipt_digest(receipt)
        assert verify_timestamp_token(tsa.token(digest=d), digest=d, trust_anchors=[tsa.root])

    def test_wrong_data(self, tsa):
        with pytest.raises(TimestampError, match="does not cover"):
            verify_timestamp_token(tsa.token(data=b"a"), data=b"b", trust_anchors=[tsa.root])

    def test_untrusted_root(self, tsa):
        other = TSA()
        with pytest.raises(TimestampError, match="chain"):
            verify_timestamp_token(tsa.token(data=b"a"), data=b"a", trust_anchors=[other.root])

    def test_intermediate_supplied_separately(self, tsa):
        token = tsa.token(data=b"a", include_intermediate=False)
        with pytest.raises(TimestampError, match="chain"):
            verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root])
        assert verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root],
                                      intermediates=[tsa.intermediate])

    def test_token_without_certificates(self, tsa):
        """certReq=false tokens: the auditor supplies the TSA certificate."""
        token = tsa.token(data=b"a", include_certs=False)
        with pytest.raises(TimestampError, match="not included"):
            verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root])
        assert verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root],
                                      intermediates=[tsa.cert, tsa.intermediate])

    def test_tampered_signed_attributes(self, tsa):
        with pytest.raises(TimestampError, match="messageDigest"):
            verify_timestamp_token(tsa.token(data=b"a", tamper_digest=True), data=b"a",
                                   trust_anchors=[tsa.root])

    def test_flipped_signature_byte(self, tsa):
        token = bytearray(tsa.token(data=b"a"))
        parsed = cms.ContentInfo.load(bytes(token))
        sig = parsed["content"]["signer_infos"][0]["signature"].native
        i = bytes(token).index(sig)
        token[i + 10] ^= 1
        with pytest.raises(TimestampError):
            verify_timestamp_token(bytes(token), data=b"a", trust_anchors=[tsa.root])

    def test_ess_binding(self, tsa):
        with pytest.raises(TimestampError, match="ESS"):
            verify_timestamp_token(tsa.token(data=b"a", ess_hash=b"\x01" * 32), data=b"a",
                                   trust_anchors=[tsa.root])
        assert verify_timestamp_token(tsa.token(data=b"a", ess="v1"), data=b"a",
                                      trust_anchors=[tsa.root])

    def test_eku_rules(self):
        for kw in ({"eku": None}, {"eku_critical": False},
                   {"eku": [ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.CODE_SIGNING]}):
            t = TSA(**kw)
            with pytest.raises(TimestampError, match="EKU|extended key usage"):
                verify_timestamp_token(t.token(data=b"a"), data=b"a", trust_anchors=[t.root])

    def test_path_length_constraint_enforced(self):
        """A CA with pathLenConstraint=0 may not issue further CAs (review finding)."""
        t = TSA()
        constrained_key = ec.generate_private_key(ec.SECP256R1())
        constrained = _cert("Constrained CA", "Test Root", constrained_key.public_key(),
                            t.root_key, ca=True, path_length=0)
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        rogue = _cert("Test Intermediate", "Constrained CA", rogue_key.public_key(),
                      constrained_key, ca=True)
        t.cert = _cert("Test TSA", "Test Intermediate", t.key.public_key(), rogue_key,
                       ca=False, eku=[ExtendedKeyUsageOID.TIME_STAMPING])
        token = t.token(data=b"a", include_intermediate=False)
        with pytest.raises(TimestampError, match="path length"):
            verify_timestamp_token(token, data=b"a", trust_anchors=[t.root],
                                   intermediates=[rogue, constrained])
        # pathLenConstraint=0 still allows issuing the end-entity TSA cert.
        ok = TSA()
        ok_int_key = ec.generate_private_key(ec.SECP256R1())
        ok.intermediate = _cert("Test Intermediate", "Test Root", ok_int_key.public_key(),
                                ok.root_key, ca=True, path_length=0)
        ok.cert = _cert("Test TSA", "Test Intermediate", ok.key.public_key(), ok_int_key,
                        ca=False, eku=[ExtendedKeyUsageOID.TIME_STAMPING])
        assert verify_timestamp_token(ok.token(data=b"a"), data=b"a", trust_anchors=[ok.root])

    def test_cert_must_be_valid_at_gen_time(self):
        t = TSA(not_before=NOW + dt.timedelta(days=1))
        with pytest.raises(TimestampError, match="genTime"):
            verify_timestamp_token(t.token(data=b"a"), data=b"a", trust_anchors=[t.root])

    def test_nonce_and_policy(self, tsa):
        token = tsa.token(data=b"a", nonce=42, policy=OID_ETSI_BEST_PRACTICE_POLICY)
        info = verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root], nonce=42,
                                      required_policy=OID_ETSI_BEST_PRACTICE_POLICY)
        assert info["etsi_best_practice_policy"]
        with pytest.raises(TimestampError, match="nonce"):
            verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root], nonce=43)
        with pytest.raises(TimestampError, match="policy"):
            verify_timestamp_token(token, data=b"a", trust_anchors=[tsa.root],
                                   required_policy="1.2.3")

    def test_etsi_qualified_statement_reported(self, tsa):
        ext = [{"extn_id": OID_ETSI_QTST_STATEMENT, "critical": False,
                "extn_value": core.Null().dump()}]
        info = verify_timestamp_token(tsa.token(data=b"a", extensions=ext), data=b"a",
                                      trust_anchors=[tsa.root])
        assert info["etsi_qualified_statement"]

    def test_garbage_and_missing_anchors(self, tsa):
        with pytest.raises(TimestampError):
            verify_timestamp_token(b"\x30\x03\x02\x01\x01", data=b"a", trust_anchors=[tsa.root])
        with pytest.raises(TimestampError, match="anchor"):
            verify_timestamp_token(tsa.token(data=b"a"), data=b"a", trust_anchors=[])


class TestTimestampProtocol:
    def test_request_shape(self):
        der, nonce = build_timestamp_request(data=b"x", nonce=7)
        req = tsp.TimeStampReq.load(der)
        assert req["message_imprint"]["hashed_message"].native == hashlib.sha256(b"x").digest()
        assert req["nonce"].native == 7 and req["cert_req"].native is True
        with pytest.raises(TimestampError):
            build_timestamp_request(data=b"x", digest=b"y")
        with pytest.raises(TimestampError):
            build_timestamp_request(digest=b"short")

    def test_response_parsing(self, tsa):
        token = tsa.token(data=b"x", nonce=9)
        assert parse_timestamp_response(tsa.response(token), nonce=9) == token
        with pytest.raises(TimestampError, match="nonce"):
            parse_timestamp_response(tsa.response(token), nonce=10)
        with pytest.raises(TimestampError, match="refused"):
            parse_timestamp_response(tsa.response(status="rejection"))

    def test_request_timestamp_over_http(self, tsa, monkeypatch):
        sent = {}

        class FakeResponse:
            def __init__(self, body):
                self.body = body

            def read(self, n):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(request, timeout):
            sent["headers"] = dict(request.header_items())
            req = tsp.TimeStampReq.load(request.data)
            digest = req["message_imprint"]["hashed_message"].native
            return FakeResponse(tsa.response(tsa.token(digest=digest,
                                                       nonce=req["nonce"].native)))

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        token = request_timestamp("https://tsa.example/", data=b"payload")
        assert sent["headers"]["Content-type"] == "application/timestamp-query"
        assert verify_timestamp_token(token, data=b"payload", trust_anchors=[tsa.root])
        with pytest.raises(TimestampError, match="URL"):
            request_timestamp("file:///etc/passwd", data=b"x")


# ---------------------------------------------------------------------------
# Remote signers
# ---------------------------------------------------------------------------


class TestRemoteOperatorKey:
    def _remote(self):
        sk = Ed25519PrivateKey.generate()
        calls = []

        def sign(message):
            calls.append(message)
            return sk.sign(message)

        pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
        return RemoteOperatorKey("kms", public_key=pub.hex(), sign_fn=sign), calls

    def test_signs_receipts_and_chains(self):
        key, calls = self._remote()
        receipt = observe_tool("t", key, lambda: 1)[1]
        verify_receipt_signature(receipt)
        chain = ReceiptChain(key, "kms-chain")
        rs = [observe_tool("t", chain.signer, lambda: i)[1] for i in range(3)]
        report = verify_chain(rs, checkpoint=chain.checkpoint())
        assert report["ok"] and len(calls) == 5  # 1 + 3 receipts + 1 checkpoint

    def test_bad_remote_signature_fails_closed(self):
        other = Ed25519PrivateKey.generate()
        pub = Ed25519PrivateKey.generate().public_key()
        key = RemoteOperatorKey("bad", public_key=pub, sign_fn=other.sign)
        with pytest.raises(ValueError, match="does not verify"):
            observe_tool("t", key, lambda: 1)
        short = RemoteOperatorKey("short", public_key=pub, sign_fn=lambda m: b"x")
        with pytest.raises(ValueError, match="malformed"):
            short.sign(b"m")

    def test_constructor_validation(self):
        with pytest.raises(ValueError):
            RemoteOperatorKey("x", public_key="ab", sign_fn=lambda m: m)
        with pytest.raises(ValueError):
            RemoteOperatorKey("x", public_key=b"\x00" * 31, sign_fn=lambda m: m)
        with pytest.raises(ValueError):
            RemoteOperatorKey("x", public_key=b"\x00" * 32, sign_fn=None)


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------


def _tool(signer, i):
    return observe_tool("t", signer, lambda: {"i": i}, args={"i": i})[1]


class TestRotation:
    def test_rotation_hands_over_signing(self):
        k1, k2 = OperatorKey.generate("k1"), OperatorKey.generate("k2")
        chain = ReceiptChain(k1, "rot")
        rs = [_tool(chain.signer, 0), _tool(chain.signer, 1)]
        rot = chain.rotate_key(k2)
        rs += [rot, _tool(chain.signer, 2)]
        assert rot.attestation["operator_public_key"] == k1.public_key_hex
        assert rs[-1].attestation["operator_public_key"] == k2.public_key_hex
        assert chain.signer.fingerprint == k2.fingerprint
        assert chain.operator_public_key == k2.public_key_hex
        report = verify_chain(rs, operator_public_key=k1.public_key_hex,
                              checkpoint=chain.checkpoint())
        assert report["ok"], report["errors"]
        assert [k["first_seq"] for k in report["operator_keys"]] == [1, 4]
        assert report["head_public_key"] == k2.public_key_hex
        assert report["rotations"][0]["reason"] == "scheduled"
        assert report["checkpoint"]["signed_by"] == k2.fingerprint

    def test_old_checkpoint_still_verifies_after_rotation(self):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "rot")
        rs = [_tool(chain.signer, i) for i in range(2)]
        old_cp = chain.checkpoint()
        rs.append(chain.rotate_key(k2))
        rs.append(_tool(chain.signer, 9))
        report = verify_chain(rs, checkpoint=chain.checkpoint(),
                              start_checkpoint=old_cp,
                              start_consistency_proof=chain.consistency_proof(2))
        assert report["ok"], report["errors"]
        assert report["start_checkpoint"]["consistent"]

    def test_key_change_without_rotation_is_an_error(self):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "x")
        r1 = _tool(chain.signer, 0)
        chain._key = k2  # simulate a signer swapping keys without a rotation
        r2 = _tool(chain.signer, 1)
        report = verify_chain([r1, r2])
        assert not report["ok"]
        assert any("chain key at this point" in e for e in report["errors"])

    def test_forged_acceptance_rejected(self):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "x")
        r1 = _tool(chain.signer, 0)
        rot = chain.rotate_key(k2)
        # Re-sign the rotation with k1 but a bogus acceptance: still k1-valid,
        # but the incoming key never agreed.
        ex = dict(rot.execution)
        ex["next_key_acceptance"] = "00" * 64
        forged = chain_mod._sign_unchained(ex, rot.provenance, k1, rot.attestation["attested_at"])
        report = verify_chain([r1, forged])
        assert any("did not accept" in e for e in report["errors"])

    def test_compromise_flags_receipts(self):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "x")
        rs = [_tool(chain.signer, i) for i in range(4)]
        rs.append(chain.rotate_key(k2, reason="compromise", compromised_after_seq=2))
        rs.append(_tool(chain.signer, 5))
        report = verify_chain(rs)
        assert report["ok"]
        assert report["compromised_seqs"] == [[3, 4]]
        assert any("declared compromised" in w for w in report["warnings"])

    def test_rotation_argument_checks(self):
        k1 = OperatorKey.generate()
        chain = ReceiptChain(k1, "x")
        with pytest.raises(ChainError):
            chain.rotate_key(k1)
        with pytest.raises(ChainError):
            chain.rotate_key(OperatorKey.generate(), reason="whim")
        with pytest.raises(ChainError):
            chain.rotate_key(OperatorKey.generate(), compromised_after_seq=0)
        with pytest.raises(ChainError):
            chain.rotate_key(OperatorKey.generate(), reason="compromise",
                             compromised_after_seq=5)
        with pytest.raises(ChainError):
            chain.rotate_key(chain.signer)
        assert chain.size == 0

    def test_user_cannot_append_a_rotation_type(self):
        chain = ReceiptChain(OperatorKey.generate(), "x")
        from traceseal_observe import sign_execution_receipt

        with pytest.raises(ValueError):
            sign_execution_receipt({"receipt_type": "chain_key_rotation"}, {}, chain.signer)

    def test_persistent_rotation_and_crash_recovery(self, tmp_path):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        with ReceiptChain.open(tmp_path / "c", k1, "p") as chain:
            rs = [_tool(chain.signer, 0)]
            rs.append(chain.rotate_key(k2))
        with pytest.raises(ChainError, match="operator key"):
            ReceiptChain.open(tmp_path / "c", k1)
        with ReceiptChain.open(tmp_path / "c", k2) as chain:
            rs.append(_tool(chain.signer, 1))
        assert verify_chain(rs)["ok"]
        header = json.loads((tmp_path / "c" / "chain.json").read_text())
        assert header["key_history"] == [k1.public_key_hex]

    def test_crash_before_rotation_commits(self, tmp_path):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain.open(tmp_path / "c", k1, "p")
        _tool(chain.signer, 0)

        def boom(digest):
            raise OSError("disk gone")

        chain._persist = boom
        with pytest.raises(OSError):
            chain.rotate_key(k2)
        chain.close()
        assert "pending_rotation" in json.loads((tmp_path / "c" / "chain.json").read_text())
        with ReceiptChain.open(tmp_path / "c", k1) as reopened:  # rotation never happened
            assert reopened.size == 1 and reopened.operator_public_key == k1.public_key_hex

    def test_crash_after_rotation_hash_persisted(self, tmp_path):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain.open(tmp_path / "c", k1, "p")
        _tool(chain.signer, 0)
        real_write = chain._write_header
        writes = []

        def flaky_write():
            writes.append(1)
            if len(writes) == 2:  # the post-commit header write
                raise OSError("power cut")
            real_write()

        chain._write_header = flaky_write
        with pytest.raises(OSError):
            chain.rotate_key(k2)
        chain.close()
        with ReceiptChain.open(tmp_path / "c", k2) as reopened:  # rotation committed
            assert reopened.size == 2


# ---------------------------------------------------------------------------
# Chains + trusted time
# ---------------------------------------------------------------------------


def _timed_chain(key, times, chain_id="w"):
    chain = ReceiptChain(key, chain_id)
    out = []
    for t in times:
        original = chain_mod._sign_unchained

        def at_time(execution, provenance, k, attested_at, _t=t):
            execution["chained_at"] = _t
            return original(execution, provenance, k, _t)

        chain_mod._sign_unchained = at_time
        try:
            out.append(_tool(chain.signer, t))
        finally:
            chain_mod._sign_unchained = original
    return chain, out


def _gt(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class TestChainTrustedTime:
    TIMES = ["2026-10-01T13:00:00Z", "2026-10-01T13:30:00Z", "2026-10-01T14:30:00Z",
             "2026-10-01T15:00:00Z", "2026-10-01T16:30:00Z"]
    WINDOW = ("2026-10-01T14:00:00Z", "2026-10-01T16:00:00Z")

    def test_checkpoint_timestamp_verified(self, tsa):
        chain, rs = _timed_chain(OperatorKey.generate(), self.TIMES)
        note = chain.checkpoint()
        token = tsa.token(data=checkpoint_body(note), gen_time=_gt("2026-10-01T16:31:00Z"))
        report = verify_chain(rs, checkpoint=note, checkpoint_timestamps=[token],
                              tsa_trust_anchors=[tsa.root], window=self.WINDOW)
        assert report["ok"], report["errors"]
        assert report["checkpoint"]["timestamps"][0]["gen_time"] == "2026-10-01T16:31:00Z"
        assert report["window"]["end_basis"] == "published_checkpoint"
        assert report["window"]["start_basis"] == "genesis"

    def test_timestamp_without_anchors_or_over_other_data(self, tsa):
        chain, rs = _timed_chain(OperatorKey.generate(), self.TIMES)
        note = chain.checkpoint()
        assert not verify_chain(rs, checkpoint=note,
                                checkpoint_timestamps=[tsa.token(data=b"x")])["ok"]
        report = verify_chain(rs, checkpoint=note, checkpoint_timestamps=[tsa.token(data=b"x")],
                              tsa_trust_anchors=[tsa.root])
        assert any("does not cover" in e for e in report["errors"])

    def test_witness_cosignature_does_not_change_what_was_timestamped(self, tsa):
        chain, rs = _timed_chain(OperatorKey.generate(), self.TIMES)
        note = chain.checkpoint()
        token = tsa.token(data=checkpoint_body(note))
        cosigned = note + "— witness.example AAAA\n"
        assert checkpoint_body(cosigned) == checkpoint_body(note)
        assert verify_timestamp_token(token, data=checkpoint_body(cosigned),
                                      trust_anchors=[tsa.root])

    def test_start_edge_proven_by_trusted_time(self, tsa):
        key = OperatorKey.generate()
        chain, rs = _timed_chain(key, self.TIMES)
        start_cp = chain.checkpoint(2)  # receipts 1..2 existed ...
        start_token = tsa.token(data=checkpoint_body(start_cp),
                                gen_time=_gt("2026-10-01T13:59:00Z"))  # ... before 14:00
        end_cp = chain.checkpoint()
        end_token = tsa.token(data=checkpoint_body(end_cp), gen_time=_gt("2026-10-01T16:31:00Z"))
        segment = rs[2:]  # disclose only seq 3..5
        kwargs = dict(checkpoint=end_cp, checkpoint_timestamps=[end_token],
                      tsa_trust_anchors=[tsa.root], inclusion_proof=chain.inclusion_proof(5),
                      window=self.WINDOW)

        # The signer's own clock says seq 3 (14:30) is inside the window,
        # so without trusted evidence the start edge is not covered.
        report = verify_chain(segment, **kwargs)
        assert report["ok"] and report["window"]["start_basis"] is None
        assert not report["window"]["complete"]

        report = verify_chain(segment, start_checkpoint=start_cp,
                              start_checkpoint_timestamps=[start_token],
                              start_consistency_proof=chain.consistency_proof(2), **kwargs)
        assert report["ok"], report["errors"]
        assert report["window"]["start_basis"] == "trusted_time"
        assert report["window"]["complete"]
        assert report["window"]["receipts_in_window"] == 2

    def test_start_checkpoint_too_late_or_inconsistent(self, tsa):
        key = OperatorKey.generate()
        chain, rs = _timed_chain(key, self.TIMES)
        start_cp = chain.checkpoint(2)
        late = tsa.token(data=checkpoint_body(start_cp), gen_time=_gt("2026-10-01T14:01:00Z"))
        end_cp = chain.checkpoint()
        base = dict(checkpoint=end_cp, inclusion_proof=chain.inclusion_proof(5),
                    tsa_trust_anchors=[tsa.root], window=self.WINDOW, start_checkpoint=start_cp)
        report = verify_chain(rs[2:], start_checkpoint_timestamps=[late],
                              start_consistency_proof=chain.consistency_proof(2), **base)
        assert report["window"]["start_basis"] is None

        other, _ = _timed_chain(key, ["2026-10-01T10:00:00Z", "2026-10-01T10:01:00Z"])
        foreign = other.checkpoint()  # same key, same chain id, other history
        report = verify_chain(rs[2:], **{**base, "start_checkpoint": foreign},
                              start_consistency_proof=chain.consistency_proof(2))
        assert not report["ok"]
        report = verify_chain(rs[2:], **base)  # no consistency proof
        assert any("start_consistency_proof is required" in e for e in report["errors"])

    def test_signer_clock_ahead_of_trusted_time_warned(self, tsa):
        chain, rs = _timed_chain(OperatorKey.generate(), self.TIMES)
        note = chain.checkpoint()
        token = tsa.token(data=checkpoint_body(note), gen_time=_gt("2026-10-01T15:00:00Z"))
        report = verify_chain(rs, checkpoint=note, checkpoint_timestamps=[token],
                              tsa_trust_anchors=[tsa.root])
        assert any("signer clock ahead" in w for w in report["warnings"])


class TestCli:
    def test_verify_with_timestamps_and_rotation(self, tsa, tmp_path, capsys):
        k1, k2 = OperatorKey.generate(), OperatorKey.generate()
        chain = ReceiptChain(k1, "cli")
        rs = [_tool(chain.signer, 0), chain.rotate_key(k2), _tool(chain.signer, 1)]
        paths = []
        for r in rs:
            p = tmp_path / f"{r.execution['chain_seq']}.json"
            p.write_text(r.to_json())
            paths.append(str(p))
        note = chain.checkpoint()
        (tmp_path / "cp.txt").write_text(note)
        (tmp_path / "cp.tsr").write_bytes(tsa.token(data=checkpoint_body(note)))
        (tmp_path / "root.pem").write_bytes(tsa.root.public_bytes(serialization.Encoding.PEM))
        args = ["verify", *paths, "--checkpoint", str(tmp_path / "cp.txt"),
                "--checkpoint-timestamp", str(tmp_path / "cp.tsr"),
                "--tsa-root", str(tmp_path / "root.pem"),
                "--operator-public-key", k1.public_key_hex]
        assert chain_mod.main(args) == 0
        out = capsys.readouterr().out
        assert "key rotation at seq 2 (scheduled)" in out
        assert "tsa=2026-10-01T12:00:00Z" in out

        assert chain_mod.main(["timestamp-verify", "--checkpoint", str(tmp_path / "cp.txt"),
                               "--timestamp", str(tmp_path / "cp.tsr"),
                               "--tsa-root", str(tmp_path / "root.pem")]) == 0
        assert "existed by 2026-10-01T12:00:00Z" in capsys.readouterr().out
        other = TSA()
        (tmp_path / "other.pem").write_bytes(other.root.public_bytes(serialization.Encoding.PEM))
        assert chain_mod.main(["timestamp-verify", "--checkpoint", str(tmp_path / "cp.txt"),
                               "--timestamp", str(tmp_path / "cp.tsr"),
                               "--tsa-root", str(tmp_path / "other.pem")]) == 1
