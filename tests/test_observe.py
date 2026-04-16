"""Tests for traceseal-observe."""

from __future__ import annotations

import json

import pytest

from traceseal_observe import (
    ModelCallRecord,
    OperatorKey,
    Receipt,
    canonical_dumps,
    observe_model_call,
    public_key_fingerprint,
    sha256_of,
    sign_model_call,
)


@pytest.fixture
def key():
    return OperatorKey.generate("test-operator")


class TestCanonicalJSON:
    def test_sorted_keys(self):
        assert canonical_dumps({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_compact(self):
        assert b" " not in canonical_dumps({"key": "value"})

    def test_deterministic(self):
        d = {"a": 1, "b": {"d": 4, "c": 3}}
        assert canonical_dumps(d) == canonical_dumps(d)


class TestHashing:
    def test_sha256_of_string(self):
        assert sha256_of("hello").startswith("sha256:")

    def test_sha256_of_bytes(self):
        assert sha256_of(b"hello").startswith("sha256:")

    def test_sha256_of_dict_is_canonical(self):
        """Hashing {'a':1,'b':2} and {'b':2,'a':1} should produce the same hash."""
        h1 = sha256_of({"a": 1, "b": 2})
        h2 = sha256_of({"b": 2, "a": 1})
        assert h1 == h2


class TestOperatorKey:
    def test_generate(self):
        k = OperatorKey.generate("alice")
        assert k.name == "alice"
        assert k.fingerprint.startswith("ed25519:")
        assert len(k.public_key_hex) == 64  # 32 bytes hex-encoded

    def test_sign_verify_roundtrip(self):
        k = OperatorKey.generate("alice")
        msg = b"hello world"
        sig = k.sign(msg)
        # Verify with the public key
        k.public_key.verify(sig, msg)  # raises on failure

    def test_from_raw_bytes(self):
        k1 = OperatorKey.generate("alice")
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        raw = k1.private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        k2 = OperatorKey.from_raw_bytes("alice", raw)
        assert k1.fingerprint == k2.fingerprint


class TestModelCallReceipt:
    def test_sign_produces_valid_receipt(self, key):
        record = ModelCallRecord(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            input_hash="sha256:abc",
            output_hash="sha256:def",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=500,
            ok=True,
            input_tokens=10,
            output_tokens=20,
        )
        receipt = sign_model_call(record, key)
        assert receipt.receipt_version == "1.0"
        assert receipt.execution["receipt_type"] == "model"
        assert receipt.execution["provider"] == "anthropic"
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["input_tokens"] == 10
        assert receipt.attestation["operator_fingerprint"] == key.fingerprint
        assert len(receipt.attestation["signature"]) == 128  # 64 bytes hex

    def test_failed_call_records_error(self, key):
        record = ModelCallRecord(
            provider="openai",
            model="gpt-4",
            api_endpoint="https://api.openai.com/v1/chat/completions",
            input_hash="sha256:xyz",
            output_hash="sha256:empty",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=1200,
            ok=False,
            exit_code=429,
            error_message="RateLimitError: too many requests",
        )
        receipt = sign_model_call(record, key)
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["exit_code"] == 429
        assert "error_message" in receipt.execution

    def test_receipt_hash_is_deterministic(self, key):
        record = ModelCallRecord(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            input_hash="sha256:abc",
            output_hash="sha256:def",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=500,
            ok=True,
        )
        r = sign_model_call(record, key)
        # Hash of the receipt should be stable across calls
        assert r.receipt_hash == sha256_of(r.to_dict())


class TestObserveModelCall:
    def test_successful_call(self, key):
        """observe_model_call wraps a successful call."""

        def fake_api_call():
            return {"response": "Hello from model", "usage": {"input_tokens": 5, "output_tokens": 10}}

        response, receipt = observe_model_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            operator_key=key,
            call=fake_api_call,
            serialize_request=lambda: {"model": "claude-sonnet-4-20250514", "messages": []},
            extract_input_tokens=lambda r: r["usage"]["input_tokens"],
            extract_output_tokens=lambda r: r["usage"]["output_tokens"],
        )

        assert response["response"] == "Hello from model"
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["input_tokens"] == 5
        assert receipt.execution["output_tokens"] == 10
        assert receipt.execution["input_hash"] != "sha256:empty"
        assert receipt.execution["output_hash"] != "sha256:empty"

    def test_failed_call_still_produces_receipt(self, key):
        """When the API call raises, we still get a signed failure receipt."""

        def fake_api_call():
            raise RuntimeError("API call failed")

        response, receipt = observe_model_call(
            provider="openai",
            model="gpt-4",
            api_endpoint="https://api.openai.com/v1/chat/completions",
            operator_key=key,
            call=fake_api_call,
            serialize_request=lambda: {"model": "gpt-4"},
        )

        assert response is None
        assert receipt.execution["ok"] == "false"
        assert "API call failed" in receipt.execution["error_message"]
        # Receipt is still signed — even failures are sealed
        assert len(receipt.attestation["signature"]) == 128

    def test_without_serialize_request_uses_empty_hash(self, key):
        response, receipt = observe_model_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            operator_key=key,
            call=lambda: {"ok": True},
        )
        assert receipt.execution["input_hash"] == "sha256:empty"

    def test_receipt_to_json_is_valid(self, key):
        response, receipt = observe_model_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            operator_key=key,
            call=lambda: {"ok": True},
            serialize_request=lambda: {"messages": []},
        )
        json_str = receipt.to_json()
        parsed = json.loads(json_str)
        assert parsed["receipt_version"] == "1.0"
        assert parsed["execution"]["receipt_type"] == "model"


class TestSignatureVerification:
    """Sanity-check that receipts signed by this library verify correctly."""

    def test_valid_signature_verifies(self, key):
        record = ModelCallRecord(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            input_hash="sha256:abc",
            output_hash="sha256:def",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=100,
            ok=True,
        )
        receipt = sign_model_call(record, key)

        # Reconstruct the signed payload
        payload = canonical_dumps({
            "execution": receipt.execution,
            "provenance": receipt.provenance,
        })

        # Verify with the key's public key
        sig = bytes.fromhex(receipt.attestation["signature"])
        key.public_key.verify(sig, payload)  # raises on failure

    def test_tampered_execution_breaks_signature(self, key):
        record = ModelCallRecord(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            input_hash="sha256:abc",
            output_hash="sha256:def",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=100,
            ok=True,
        )
        receipt = sign_model_call(record, key)

        # Tamper with execution
        tampered_execution = dict(receipt.execution)
        tampered_execution["model"] = "gpt-4"  # lie about which model was called

        payload = canonical_dumps({
            "execution": tampered_execution,
            "provenance": receipt.provenance,
        })
        sig = bytes.fromhex(receipt.attestation["signature"])

        from cryptography.exceptions import InvalidSignature
        with pytest.raises(InvalidSignature):
            key.public_key.verify(sig, payload)


class TestModelCallStatusDetection:
    """Test that HTTP error status codes are detected as failures."""

    def test_401_response_marked_not_ok(self, key):
        """A response with status_code=401 should produce ok=false."""

        class FakeErrorResponse:
            status_code = 401
            content = b"Unauthorized"

            def model_dump(self):
                return {"error": "unauthorized"}

        response, receipt = observe_model_call(
            provider="minimax",
            model="MiniMax-M2.7",
            api_endpoint="https://api.minimax.io/v1/text/chatcompletion_v2",
            operator_key=key,
            call=lambda: FakeErrorResponse(),
        )
        assert response is not None  # call didn't raise
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["exit_code"] == 401
        assert "401" in receipt.execution.get("error_message", "")

    def test_200_response_still_ok(self, key):
        """A response with status_code=200 should remain ok=true."""

        class FakeOkResponse:
            status_code = 200

            def model_dump(self):
                return {"content": "hello"}

        response, receipt = observe_model_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            operator_key=key,
            call=lambda: FakeOkResponse(),
        )
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["exit_code"] == 0

    def test_no_status_attribute_defaults_ok(self, key):
        """A response without any status attribute defaults to ok=true."""

        response, receipt = observe_model_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.anthropic.com/v1/messages",
            operator_key=key,
            call=lambda: {"content": "hello"},
        )
        assert receipt.execution["ok"] == "true"

    def test_custom_status_extractor(self, key):
        """The extract_status_code callback overrides auto-detection."""

        class WeirdResponse:
            my_code = 503

        response, receipt = observe_model_call(
            provider="custom",
            model="weird-model",
            api_endpoint="https://api.weird.com/v1/chat",
            operator_key=key,
            call=lambda: WeirdResponse(),
            extract_status_code=lambda r: r.my_code,
        )
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["exit_code"] == 503
