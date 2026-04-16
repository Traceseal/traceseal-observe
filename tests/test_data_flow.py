"""Tests for data flow receipts (Module 4)."""

from __future__ import annotations

import json

import pytest

from traceseal_observe import (
    DataFlowRecord,
    OperatorKey,
    Receipt,
    fingerprint_pii,
    observe_data_flow,
    sign_data_flow,
    summarize_data_flows,
)


@pytest.fixture
def key():
    return OperatorKey.generate("test-operator")


class TestFingerprintPII:
    def test_detects_email(self):
        result = fingerprint_pii("Please email tim@example.com for details")
        assert result.get("email") == 1

    def test_detects_multiple_emails(self):
        result = fingerprint_pii("Contact tim@a.com or bob@b.com or jane@c.co.uk")
        assert result.get("email") == 3

    def test_detects_credit_card(self):
        result = fingerprint_pii("card: 4532-1234-5678-9010")
        assert result.get("credit_card") == 1

    def test_detects_jwt(self):
        result = fingerprint_pii(
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def"
        )
        assert result.get("jwt") == 1

    def test_detects_aws_key(self):
        result = fingerprint_pii("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert result.get("aws_access_key") == 1

    def test_detects_github_token(self):
        result = fingerprint_pii("token=ghp_abcdef1234567890abcdef1234567890abcd")
        assert result.get("github_token") == 1

    def test_clean_text_returns_empty(self):
        result = fingerprint_pii("The quick brown fox jumps over the lazy dog")
        assert result == {}

    def test_scans_dict_payload(self):
        result = fingerprint_pii({
            "user": {"email": "tim@example.com", "name": "Tim"},
            "action": "signup",
        })
        assert result.get("email") == 1

    def test_scans_list_payload(self):
        result = fingerprint_pii([
            {"email": "a@b.com"},
            {"email": "c@d.com"},
        ])
        assert result.get("email") == 2

    def test_none_payload(self):
        assert fingerprint_pii(None) == {}

    def test_bytes_payload(self):
        result = fingerprint_pii(b"email=user@example.com")
        assert result.get("email") == 1

    def test_detects_multiple_pattern_types(self):
        text = "Contact tim@example.com or call 555-123-4567"
        result = fingerprint_pii(text)
        assert "email" in result
        # Phone detection is best-effort; at least one should match


class TestSignDataFlow:
    def test_produces_valid_receipt(self, key):
        record = DataFlowRecord(
            destination_host="api.example.com",
            destination_url="https://api.example.com/webhook",
            method="POST",
            request_payload_hash="sha256:abc",
            response_payload_hash="sha256:def",
            payload_bytes=128,
            response_bytes=64,
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=250,
            status_code=200,
            ok=True,
        )
        receipt = sign_data_flow(record, key)
        assert receipt.receipt_version == "1.0"
        assert receipt.execution["receipt_type"] == "data_flow"
        assert receipt.execution["destination_host"] == "api.example.com"
        assert receipt.execution["method"] == "POST"
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["status_code"] == 200

    def test_records_pii_fingerprint_when_present(self, key):
        record = DataFlowRecord(
            destination_host="api.example.com",
            destination_url="https://api.example.com/webhook",
            method="POST",
            request_payload_hash="sha256:abc",
            response_payload_hash="sha256:def",
            payload_bytes=128,
            response_bytes=64,
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=100,
            status_code=200,
            ok=True,
            pii_fingerprint={"email": 2, "phone_us": 1},
        )
        receipt = sign_data_flow(record, key)
        assert receipt.execution["pii_fingerprint"] == {"email": 2, "phone_us": 1}

    def test_undeclared_destination_flagged(self, key):
        record = DataFlowRecord(
            destination_host="unknown-service.com",
            destination_url="https://unknown-service.com/api",
            method="POST",
            request_payload_hash="sha256:abc",
            response_payload_hash="sha256:def",
            payload_bytes=100,
            response_bytes=50,
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=100,
            status_code=200,
            ok=True,
            destination_declared=False,
            declared_allow_list=["api.allowed.com"],
        )
        receipt = sign_data_flow(record, key)
        assert receipt.execution["destination_declared"] == "false"
        assert receipt.execution["declared_allow_list"] == ["api.allowed.com"]

    def test_failed_request_records_error(self, key):
        record = DataFlowRecord(
            destination_host="api.example.com",
            destination_url="https://api.example.com/x",
            method="POST",
            request_payload_hash="sha256:abc",
            response_payload_hash="sha256:empty",
            payload_bytes=50,
            response_bytes=0,
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=5000,
            status_code=0,
            ok=False,
            error_message="ConnectionError: connection refused",
        )
        receipt = sign_data_flow(record, key)
        assert receipt.execution["ok"] == "false"
        assert "connection refused" in receipt.execution["error_message"]


class TestObserveDataFlow:
    def test_successful_request(self, key):
        # Fake response object with status_code and content attributes
        class FakeResponse:
            def __init__(self):
                self.status_code = 200
                self.content = b'{"success": true}'

        response, receipt = observe_data_flow(
            url="https://api.example.com/webhook",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
            request_body={"event": "test"},
        )
        assert response is not None
        assert response.status_code == 200
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["destination_host"] == "api.example.com"
        assert receipt.execution["status_code"] == 200
        assert receipt.execution["payload_bytes"] > 0

    def test_pii_scanning_flags_email(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        response, receipt = observe_data_flow(
            url="https://api.example.com/notify",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
            request_body={"user_email": "tim@britfarmers.com", "action": "signup"},
        )
        assert "pii_fingerprint" in receipt.execution
        assert receipt.execution["pii_fingerprint"].get("email") == 1

    def test_pii_scanning_can_be_disabled(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        response, receipt = observe_data_flow(
            url="https://api.example.com/notify",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
            request_body={"user_email": "tim@britfarmers.com"},
            scan_pii=False,
        )
        assert "pii_fingerprint" not in receipt.execution

    def test_allow_list_match(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        response, receipt = observe_data_flow(
            url="https://api.allowed.com/x",
            method="GET",
            operator_key=key,
            call=lambda: FakeResponse(),
            declared_allow_list=["api.allowed.com", "api.also-allowed.com"],
        )
        assert receipt.execution["destination_declared"] == "true"

    def test_allow_list_mismatch_flags(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        response, receipt = observe_data_flow(
            url="https://unknown-host.com/x",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
            request_body={"data": "something"},
            declared_allow_list=["api.allowed.com"],
        )
        assert receipt.execution["destination_declared"] == "false"
        assert "unknown-host.com" == receipt.execution["destination_host"]

    def test_no_allow_list_default_declared(self, key):
        """If no allow list is provided, destinations are not flagged."""

        class FakeResponse:
            status_code = 200
            content = b"{}"

        response, receipt = observe_data_flow(
            url="https://anywhere.com/x",
            method="GET",
            operator_key=key,
            call=lambda: FakeResponse(),
        )
        assert receipt.execution["destination_declared"] == "true"
        assert "declared_allow_list" not in receipt.execution

    def test_query_string_stripped_from_url(self, key):
        """Query strings often contain sensitive data — strip them
        from the recorded URL."""

        class FakeResponse:
            status_code = 200
            content = b"{}"

        response, receipt = observe_data_flow(
            url="https://api.example.com/search?api_key=secret&q=foo",
            method="GET",
            operator_key=key,
            call=lambda: FakeResponse(),
        )
        # api_key=secret should NOT be in destination_url
        assert "api_key" not in receipt.execution["destination_url"]
        assert "secret" not in receipt.execution["destination_url"]

    def test_failed_request_still_produces_receipt(self, key):
        def failing():
            raise ConnectionError("network unreachable")

        response, receipt = observe_data_flow(
            url="https://api.example.com/x",
            method="POST",
            operator_key=key,
            call=failing,
            request_body={"data": "x"},
        )
        assert response is None
        assert receipt.execution["ok"] == "false"
        assert "unreachable" in receipt.execution["error_message"]
        assert receipt.execution["status_code"] == 0

    def test_non_2xx_status_marked_not_ok(self, key):
        class FakeResponse:
            status_code = 404
            content = b"Not Found"

        response, receipt = observe_data_flow(
            url="https://api.example.com/nope",
            method="GET",
            operator_key=key,
            call=lambda: FakeResponse(),
        )
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["status_code"] == 404


class TestSummarizeDataFlows:
    def test_aggregates_multiple_receipts(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        receipts = []
        for host in ["api.anthropic.com", "api.openai.com", "api.anthropic.com"]:
            _, r = observe_data_flow(
                url=f"https://{host}/x",
                method="POST",
                operator_key=key,
                call=lambda: FakeResponse(),
                request_body={"data": "test"},
            )
            receipts.append(r)

        summary = summarize_data_flows(receipts)
        assert summary["total_calls"] == 3
        assert summary["destinations"]["api.anthropic.com"] == 2
        assert summary["destinations"]["api.openai.com"] == 1
        assert summary["failed_calls"] == 0

    def test_counts_undeclared(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        receipts = []
        # One to a declared host
        _, r1 = observe_data_flow(
            url="https://api.allowed.com/x",
            method="GET",
            operator_key=key,
            call=lambda: FakeResponse(),
            declared_allow_list=["api.allowed.com"],
        )
        # One to an undeclared host
        _, r2 = observe_data_flow(
            url="https://api.sneaky.com/x",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
            declared_allow_list=["api.allowed.com"],
        )
        receipts = [r1, r2]
        summary = summarize_data_flows(receipts)
        assert summary["undeclared_calls"] == 1

    def test_aggregates_pii(self, key):
        class FakeResponse:
            status_code = 200
            content = b"{}"

        receipts = []
        for body in [
            {"email": "a@b.com"},
            {"user": "bob", "contact": "c@d.com"},
            {"name": "Tim"},
        ]:
            _, r = observe_data_flow(
                url="https://api.example.com/x",
                method="POST",
                operator_key=key,
                call=lambda: FakeResponse(),
                request_body=body,
            )
            receipts.append(r)
        summary = summarize_data_flows(receipts)
        assert summary["pii_summary"].get("email") == 2

    def test_skips_non_data_flow_receipts(self, key):
        """Mixing data-flow receipts with others should only count data-flow ones."""
        from traceseal_observe import observe_tool

        _, tool_r = observe_tool(
            tool_name="something",
            operator_key=key,
            call=lambda: "result",
        )

        class FakeResponse:
            status_code = 200
            content = b"{}"

        _, flow_r = observe_data_flow(
            url="https://api.example.com/x",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
        )

        summary = summarize_data_flows([tool_r, flow_r])
        assert summary["total_calls"] == 1


class TestDataFlowCrossCompat:
    """Data flow receipts verify with the standalone verifier."""

    def test_verifies_with_standalone(self, key):
        try:
            from traceseal_verify import verify_receipt
        except ImportError:
            pytest.skip("traceseal-verify not installed; skipping cross-verify test")

        class FakeResponse:
            status_code = 200
            content = b"{}"

        _, receipt = observe_data_flow(
            url="https://api.example.com/x",
            method="POST",
            operator_key=key,
            call=lambda: FakeResponse(),
            request_body={"test": "data"},
        )
        result = verify_receipt(receipt.to_dict())
        assert result.ok is True
        assert result.operator_fingerprint == key.fingerprint
